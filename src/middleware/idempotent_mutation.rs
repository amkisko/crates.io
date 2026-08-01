//! Request buffering, serialization, and terminal-response storage for mutation IDs.

use crate::app::AppState;
use crate::auth::authenticate_api_token_id;
use crate::models::ApiMfaChallenge;
use crate::util::errors::{bad_request, server_error};
use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use http::{HeaderValue, Method, StatusCode, header};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Maximum terminal body retained for an idempotent mutation response.
const MAX_TERMINAL_RESPONSE_BYTES: usize = 1024 * 1024;

/// Header carrying the preflight mutation record identifier.
pub const CARGO_MUTATION_ID_HEADER: &str = "cargo-mutation-id";

/// Exact raw request facts observed before endpoint parsing.
#[derive(Debug)]
pub struct IdempotentMutation {
    /// Opaque preflight mutation record identifier.
    pub id: String,
    /// HTTP method observed on the final request.
    pub method: Method,
    /// Absolute-path endpoint observed on the final request.
    pub endpoint: String,
    /// SHA-256 computed from the received raw request body.
    pub request_sha256: Vec<u8>,
    /// Number of received raw request-body bytes.
    pub request_size: i64,
    /// Whether this record promises terminal response replay.
    pub idempotent_final: bool,
    validated: AtomicBool,
    executing: AtomicBool,
    completed: AtomicBool,
}

impl IdempotentMutation {
    /// Marks the parsed endpoint operation as matching the raw preflight descriptor.
    pub fn validate_execution(&self) {
        self.validated.store(true, Ordering::Release);
    }

    /// Enters execution inside the endpoint's effect transaction.
    pub async fn begin_execution(
        &self,
        conn: &diesel_async::AsyncPgConnection,
    ) -> crate::util::errors::AppResult<()> {
        if !self.validated.load(Ordering::Acquire) {
            return Err(server_error(
                "mutation execution began before endpoint validation",
            ));
        }
        let challenge = ApiMfaChallenge::find(&self.id, conn)
            .await?
            .ok_or_else(|| bad_request("Cargo-Mutation-Id is unknown or expired"))?;
        debug_assert!(self.idempotent_final);
        let began = challenge.begin_execution(conn).await?;
        if !began {
            return Err(Box::new(MutationExecutionInProgress));
        }
        self.executing.store(true, Ordering::Release);
        Ok(())
    }

    /// Durably consumes a core-only grant before the endpoint begins effects.
    pub async fn begin_core_execution(&self, app: &AppState) -> crate::util::errors::AppResult<()> {
        if !self.validated.load(Ordering::Acquire) {
            return Err(server_error(
                "mutation execution began before endpoint validation",
            ));
        }
        debug_assert!(!self.idempotent_final);
        let conn = app.db_write().await?;
        let challenge = ApiMfaChallenge::find(&self.id, &conn)
            .await?
            .ok_or_else(|| bad_request("Cargo-Mutation-Id is unknown or expired"))?;
        if !challenge.begin_core_execution(&conn).await? {
            return Err(Box::new(MutationExecutionInProgress));
        }
        self.executing.store(true, Ordering::Release);
        Ok(())
    }

    fn execution_authorized(&self) -> bool {
        self.executing.load(Ordering::Acquire)
    }

    /// Stores a JSON terminal response in the endpoint's effect transaction.
    pub async fn finish_json<T: Serialize>(
        &self,
        status: StatusCode,
        value: &T,
        conn: &diesel_async::AsyncPgConnection,
    ) -> crate::util::errors::AppResult<()> {
        if !self.execution_authorized() {
            return Err(server_error("mutation execution was not started"));
        }
        if !self.idempotent_final {
            self.completed.store(true, Ordering::Release);
            return Ok(());
        }
        let challenge = ApiMfaChallenge::find(&self.id, conn)
            .await?
            .ok_or_else(|| bad_request("Cargo-Mutation-Id is unknown or expired"))?;
        let body = serde_json::to_vec(value).map_err(server_error)?;
        if body.len() > MAX_TERMINAL_RESPONSE_BYTES {
            return Err(server_error(
                "mutation response exceeds replay storage limit",
            ));
        }
        let stored = challenge
            .store_terminal_response(
                i32::from(status.as_u16()),
                json!([["content-type", "application/json"]]),
                body,
                conn,
            )
            .await?;
        if !stored {
            return Err(server_error(
                "Cargo-Mutation-Id outcome could not be committed",
            ));
        }
        self.completed.store(true, Ordering::Release);
        Ok(())
    }

    fn execution_completed(&self) -> bool {
        self.completed.load(Ordering::Acquire)
    }
}

#[derive(Debug)]
struct MutationExecutionInProgress;

impl fmt::Display for MutationExecutionInProgress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("mutation execution is already in progress")
    }
}

impl crate::util::errors::AppError for MutationExecutionInProgress {
    fn response(&self) -> Response {
        execution_in_progress_response()
    }
}

/// Validates bounded mutation requests and dispatches them to transactional endpoints.
pub async fn middleware(State(app): State<AppState>, request: Request, next: Next) -> Response {
    let Some(id) = request
        .headers()
        .get(CARGO_MUTATION_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
    else {
        return next.run(request).await;
    };

    if !(22..=128).contains(&id.len())
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return crate::util::errors::bad_request("invalid Cargo-Mutation-Id").into_response();
    }

    let (mut request_parts, request_body) = request.into_parts();
    request_parts.extensions.insert(app.clone());

    let mut conn = match app.db_write().await {
        Ok(conn) => conn,
        Err(error) => return server_error(error).into_response(),
    };
    // Token lookup updates `last_used_at`; release this connection before the
    // ordinary endpoint authenticates the same token.
    let token_id = match authenticate_api_token_id(&request_parts, &mut conn).await {
        Ok(token_id) => token_id,
        Err(error) => return error.into_response(),
    };
    drop(conn);

    let result: Result<Response, crate::util::errors::BoxedAppError> = async move {
        let state_conn = app.db_write().await?;

        // Resolve the preflight before accepting its body. This bounds the
        // allocation by the authenticated descriptor and rejects unknown
        // mutation IDs without buffering attacker-selected bytes.
        let mut challenge = ApiMfaChallenge::find(&id, &state_conn)
            .await?
            .ok_or_else(|| bad_request("Cargo-Mutation-Id is unknown or expired"))?;
        if challenge.api_token_id != Some(token_id) {
            return Err(bad_request(
                "Cargo-Mutation-Id belongs to a different credential",
            ));
        }
        let expected_size = challenge
            .request_size
            .and_then(|size| usize::try_from(size).ok())
            .ok_or_else(|| bad_request("Cargo-Mutation-Id is not a mutation preflight"))?;
        if request_parts
            .headers
            .contains_key(http::header::CONTENT_ENCODING)
        {
            return Err(bad_request(
                "mutation authorization version 1 does not permit Content-Encoding",
            ));
        }
        let declared_size = request_parts
            .headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok())
            .ok_or_else(|| bad_request("mutation request requires a valid Content-Length"))?;
        if declared_size != expected_size {
            return Err(bad_request(
                "mutation Content-Length does not match its preflight descriptor",
            ));
        }
        let expected_content_type = challenge
            .descriptor_json
            .as_ref()
            .and_then(|descriptor| descriptor.get("content_type"))
            .and_then(serde_json::Value::as_str);
        let actual_content_type = request_parts
            .headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok());
        if actual_content_type != expected_content_type {
            return Err(bad_request(
                "mutation Content-Type does not match its preflight descriptor",
            ));
        }

        let request_method = request_parts.method.clone();
        let request_endpoint = request_parts
            .uri
            .path_and_query()
            .map(|target| target.as_str())
            .unwrap_or_else(|| request_parts.uri.path())
            .to_owned();
        if challenge.request_method.as_deref() != Some(request_method.as_str())
            || challenge.request_endpoint.as_deref() != Some(request_endpoint.as_str())
        {
            return Err(bad_request(
                "mutation method or request target does not match its preflight descriptor",
            ));
        }

        // Claim only after authenticating the credential and validating every
        // bounded request fact available before reading the body. The receive
        // lease then bounds body receipt and digest validation.
        let state = challenge
            .mutation_state
            .as_deref()
            .ok_or_else(|| bad_request("Cargo-Mutation-Id is not a versioned mutation record"))?;
        if state == "ready" && challenge.idempotent_final {
            if let Some(deadline) = challenge.begin_receiving(&state_conn).await? {
                challenge.mutation_state = Some("receiving".into());
                challenge.receive_expires_at = Some(deadline);
            } else {
                // Another request can win the ready -> receiving CAS between
                // our load and update. Observe its state instead of
                // misreporting that race as an expired grant.
                challenge = ApiMfaChallenge::find(&id, &state_conn)
                    .await?
                    .ok_or_else(|| bad_request("Cargo-Mutation-Id is unknown or expired"))?;
            }
        }
        let state = challenge
            .mutation_state
            .as_deref()
            .ok_or_else(|| bad_request("Cargo-Mutation-Id is not a versioned mutation record"))?;
        match state {
            "receiving" => {
                if challenge
                    .receive_expires_at
                    .is_none_or(|deadline| deadline <= chrono::Utc::now())
                {
                    challenge.expire_receiving(&state_conn).await?;
                    return Err(bad_request("Cargo-Mutation-Id receive lease is expired"));
                }
            }
            "executing" => return Ok(execution_in_progress_response()),
            "terminal" => {}
            "pending" => return Err(bad_request("Cargo-Mutation-Id is not ready")),
            "denied" => return Err(bad_request("Cargo-Mutation-Id was denied")),
            "consumed" => return Err(bad_request("Cargo-Mutation-Id was already consumed")),
            "expired" => return Err(bad_request("Cargo-Mutation-Id is expired")),
            "ready" if !challenge.idempotent_final && challenge.expires_at > chrono::Utc::now() => {
            }
            "ready" => return Err(bad_request("Cargo-Mutation-Id grant is expired")),
            _ => {
                return Err(server_error(
                    "Cargo-Mutation-Id has an invalid lifecycle state",
                ));
            }
        }
        let bytes = to_bytes(request_body, expected_size)
            .await
            .map_err(|_| bad_request("mutation request exceeds its preflight size"))?;
        if bytes.len() != expected_size {
            return Err(bad_request(
                "mutation request length does not match its preflight descriptor",
            ));
        }
        let context = Arc::new(IdempotentMutation {
            id: id.clone(),
            method: request_method,
            endpoint: request_endpoint,
            request_sha256: Sha256::digest(&bytes).to_vec(),
            request_size: challenge.request_size.unwrap_or_default(),
            idempotent_final: challenge.idempotent_final,
            validated: AtomicBool::new(false),
            executing: AtomicBool::new(false),
            completed: AtomicBool::new(false),
        });
        if challenge.request_sha256.as_deref() != Some(context.request_sha256.as_slice()) {
            return Err(bad_request(
                "mutation request does not match its preflight descriptor",
            ));
        }
        if let Some(response) = replay_response(&challenge) {
            return Ok(response);
        }
        drop(state_conn);
        let mut request = Request::from_parts(request_parts, Body::from(bytes));
        request.extensions_mut().insert(context.clone());

        let response = next.run(request).await;
        if !response.status().is_success() {
            return Ok(response);
        }
        if context.execution_authorized() && context.execution_completed() {
            return Ok(response);
        }
        Err(server_error(
            "mutation endpoint returned success without committing its outcome",
        ))
    }
    .await;

    result.unwrap_or_else(IntoResponse::into_response)
}

fn execution_in_progress_response() -> Response {
    let mut response = (
        StatusCode::TOO_EARLY,
        "mutation execution is already in progress",
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    response
}

/// Rebuilds a stored terminal response.
pub fn replay_response(challenge: &ApiMfaChallenge) -> Option<Response> {
    let status = StatusCode::from_u16(u16::try_from(challenge.response_status?).ok()?).ok()?;
    let mut response = Response::builder().status(status);
    let headers: Vec<(String, String)> =
        serde_json::from_value(challenge.response_headers.clone()?).ok()?;
    for (name, value) in headers {
        response = response.header(name, value);
    }
    response
        .body(Body::from(challenge.response_body.clone()?))
        .ok()
}
