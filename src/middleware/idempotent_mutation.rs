//! Request buffering, serialization, and terminal-response storage for mutation IDs.

use crate::app::AppState;
use crate::auth::authenticate_api_token_id;
use crate::models::ApiMfaChallenge;
use crate::util::errors::{bad_request, server_error};
use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use diesel::sql_types::{BigInt, Text};
use diesel_async::{AsyncConnection, RunQueryDsl};
use http::{HeaderMap, Method, StatusCode};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

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
    authorized: AtomicBool,
}

impl IdempotentMutation {
    /// Allows the middleware to retain the endpoint's terminal response.
    pub fn authorize_execution(&self) {
        self.authorized.store(true, Ordering::Release);
    }

    fn execution_authorized(&self) -> bool {
        AtomicBool::load(&self.authorized, Ordering::Acquire)
    }
}

#[derive(diesel::QueryableByName)]
struct AdvisoryLock {
    #[diesel(sql_type = BigInt)]
    lock_key: i64,
}

/// Serializes requests sharing a mutation ID and stores their terminal response.
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

    if id.len() > 128
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return crate::util::errors::bad_request("invalid Cargo-Mutation-Id").into_response();
    }

    let (mut request_parts, request_body) = request.into_parts();
    request_parts.extensions.insert(app.clone());

    let mut conn = match app.db_write().await {
        Ok(conn) => conn,
        Err(error) => return server_error(error).into_response(),
    };
    // Token lookup updates `last_used_at`; finish that transaction before the
    // advisory-lock transaction so the ordinary endpoint can authenticate the
    // same token without waiting on our row lock.
    let token_id = match authenticate_api_token_id(&request_parts, &mut conn).await {
        Ok(token_id) => token_id,
        Err(error) => return error.into_response(),
    };

    let result = conn
        .transaction::<Response, crate::util::errors::BoxedAppError, _>(async move |conn| {
            let lock = diesel::sql_query(
                "SELECT hashtextextended($1, 0) AS lock_key, \
                 pg_advisory_xact_lock(hashtextextended($1, 0))",
            )
            .bind::<Text, _>(&id)
            .get_result::<AdvisoryLock>(conn)
            .await?;
            let _ = lock.lock_key;

            // Resolve the preflight before accepting its body. This bounds the
            // allocation by the authenticated descriptor and rejects unknown
            // mutation IDs without buffering attacker-selected bytes.
            let challenge = ApiMfaChallenge::find_active(&id, conn)
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
                method: request_parts.method.clone(),
                endpoint: request_parts.uri.path().to_owned(),
                request_sha256: Sha256::digest(&bytes).to_vec(),
                request_size: challenge.request_size.unwrap_or_default(),
                authorized: AtomicBool::new(false),
            });
            if challenge.request_method.as_deref() != Some(context.method.as_str())
                || challenge.request_endpoint.as_deref() != Some(context.endpoint.as_str())
                || challenge.request_sha256.as_deref() != Some(context.request_sha256.as_slice())
            {
                return Err(bad_request(
                    "mutation request does not match its preflight descriptor",
                ));
            }
            if let Some(response) = replay_response(&challenge) {
                return Ok(response);
            }
            let mut request = Request::from_parts(request_parts, Body::from(bytes));
            request.extensions_mut().insert(context.clone());

            let response = next.run(request).await;
            if !context.execution_authorized() || response.status().is_server_error() {
                return Ok(response);
            }

            let (parts, body) = response.into_parts();
            let bytes = to_bytes(body, usize::MAX).await.map_err(server_error)?;
            let headers = replay_headers(&parts.headers);
            challenge
                .store_terminal_response(
                    i32::from(parts.status.as_u16()),
                    headers,
                    bytes.to_vec(),
                    conn,
                )
                .await?;
            Ok(Response::from_parts(parts, Body::from(bytes)))
        })
        .await;

    result.unwrap_or_else(IntoResponse::into_response)
}

fn replay_headers(headers: &HeaderMap) -> serde_json::Value {
    json!(
        headers
            .iter()
            .filter(|(name, _)| {
                matches!(
                    name.as_str(),
                    "content-type"
                        | "cache-control"
                        | "vary"
                        | "www-authenticate"
                        | "access-control-allow-origin"
                        | "strict-transport-security"
                        | "x-content-type-options"
                        | "x-frame-options"
                        | "x-xss-protection"
                )
            })
            .filter_map(|(name, value)| Some((name.as_str(), value.to_str().ok()?)))
            .collect::<Vec<_>>()
    )
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
