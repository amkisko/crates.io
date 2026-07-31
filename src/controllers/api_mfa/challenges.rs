use super::webauthn_util::{
    build_webauthn, parse_auth_response, passkeys_from_credentials, record_passkey_authentication,
};
use crate::api_mfa::{
    ApiMfaCallback, ApiMfaOperation, RECOMMENDED_POLL_INTERVAL_SECS,
    insert_challenge_or_reuse_pending, mfa_callback_secret_from_headers, mfa_port_from_headers,
    normalize_challenge_operation, public_mfa_urls, refresh_challenge_localhost_callback,
    step_up_required_error,
};
use crate::app::AppState;
use crate::auth::{AuthCheck, AuthHeader, Authentication};
use crate::middleware::real_ip::RealIp;
use crate::models::token::EndpointScope;
use crate::models::{
    ApiMfaChallenge, Crate, MAX_PENDING_CHALLENGES_PER_USER, NewApiMfaChallenge,
    NewApiMfaChallengeOperation, NewApiMfaGrant, NewApiMfaMutationDescriptor, WebauthnCredential,
};
use crate::rate_limiter::LimitedAction;
use crate::util::errors::{AppResult, bad_request, forbidden, not_found, server_error};
use crate::util::no_store;
use axum::Json;
use axum::extract::Path;
use axum::response::{IntoResponse, Response};
use axum_extra::TypedHeader;
use axum_extra::headers::CacheControl;
use base64::Engine;
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::{AsyncConnection, RunQueryDsl};
use http::request::Parts;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use webauthn_rs::prelude::*;

/// Request to create a manual API MFA challenge.
#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
pub struct CreateChallengeRequest {
    /// Dangerous operation label. Defaults to `manual`.
    ///
    /// Allowed: `publish`, `yank`, `unyank`, `change-owners`, `change-trustpub-only`,
    /// `change-trusted-publishing`, `delete-crate`, `manual`.
    pub operation: Option<String>,
    /// Optional crate name associated with the operation.
    #[serde(rename = "crate")]
    pub crate_name: Option<String>,
    /// HTTP method of the ordinary mutation.
    pub method: Option<String>,
    /// Absolute-path endpoint of the ordinary mutation.
    pub endpoint: Option<String>,
    /// Version involved in publish, yank, or unyank.
    pub version: Option<String>,
    /// Hex SHA-256 of the exact raw mutation request body.
    pub request_sha256: Option<String>,
    /// Length of the exact raw mutation request body.
    pub request_size: Option<i64>,
    /// Hex SHA-256 of the publish archive bytes.
    pub archive_sha256: Option<String>,
    /// Length of the publish archive bytes.
    pub archive_size: Option<i64>,
    /// `add` or `remove` for owner changes.
    pub direction: Option<String>,
    /// Complete ordered owner list for owner changes.
    pub owners: Option<Vec<String>>,
    /// Step-up protocol version. Version 1 is currently supported.
    pub protocol_version: Option<u64>,
    /// Optional localhost port (1024–65535) for proof delivery to the CLI.
    ///
    /// Requires a valid `Cargo-Step-Up-Callback-Secret` header. Polling remains
    /// available as a fallback when callback delivery fails.
    pub port: Option<i32>,
}

/// Instructions and timing information for a newly created API MFA challenge.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct CreateChallengeResponse {
    /// `pending` for a manual challenge or `acknowledged` when mutation may start.
    pub status: String,
    /// Opaque step-up challenge identifier.
    pub challenge_id: String,
    /// Complete human-readable instructions for satisfying the challenge.
    pub detail: Option<String>,
    /// URL the CLI should poll until `acknowledged` is true.
    pub poll_url: Option<String>,
    pub expires_at: DateTime<Utc>,
    /// Suggested seconds between CLI polls of `poll_url`.
    pub recommended_poll_interval_secs: Option<u64>,
}

/// Create an API MFA challenge for a CLI client (token auth).
///
/// Prefer letting dangerous endpoints auto-create challenges; this endpoint is for
/// explicit preflight handshakes.
#[utoipa::path(
    post,
    path = "/api/v1/auth/challenges",
    request_body = inline(CreateChallengeRequest),
    security(("api_token" = [])),
    tag = "users",
    extensions(("x-internal" = json!(true))),
    responses((status = 200, description = "Successful Response", body = inline(CreateChallengeResponse))),
)]
pub async fn create_api_mfa_challenge(
    app: AppState,
    req: Parts,
    Json(body): Json<CreateChallengeRequest>,
) -> AppResult<Response> {
    let mut conn = app.db_write().await?;
    let requested_operation = normalize_challenge_operation(body.operation.as_deref())?;
    let descriptor = if requested_operation == "manual" {
        None
    } else {
        let max_archive_size = if requested_operation == "publish" {
            let crate_name = required_descriptor_field(body.crate_name.as_deref(), "crate")?;
            Crate::by_name(crate_name)
                .select(Crate::as_select())
                .first(&mut conn)
                .await
                .optional()?
                .and_then(|krate| krate.max_upload_size())
                .unwrap_or(app.config.publish_limits.upload_size)
        } else {
            0
        };
        Some(validate_mutation_descriptor(
            &body,
            &requested_operation,
            max_archive_size,
        )?)
    };

    let auth_check =
        auth_check_for_preflight(&requested_operation, body.crate_name.as_deref(), &conn).await?;
    let auth = auth_check.check(&req, &mut conn).await?;

    let Some(token) = auth.api_token() else {
        return Err(forbidden(
            "API MFA challenges must be created with an API token",
        ));
    };

    let user = auth.user();
    if requested_operation != "manual"
        && !user.api_mfa_enabled
        && let Some(crate_name) = body.crate_name.as_deref()
        && crate::api_mfa::crate_requires_api_mfa(crate_name, &mut conn).await?
    {
        return Err(bad_request(
            "This crate requires API MFA because an owner enabled it. Sign in on the website, \
             enable API MFA under Settings → API MFA, register a passkey, then retry.",
        ));
    }
    if requested_operation == "manual" && !user.api_mfa_enabled {
        return Err(bad_request("API MFA is not enabled for this account"));
    }

    if user.api_mfa_enabled {
        let credentials = WebauthnCredential::for_user(user.id, &conn).await?;
        if credentials.is_empty() {
            return Err(bad_request("no passkeys registered for this account"));
        }
    }

    let header_port = mfa_port_from_headers(&req)?;
    if let (Some(body_port), Some(header_port)) = (body.port, header_port)
        && body_port != header_port
    {
        return Err(bad_request(
            "port and Cargo-Step-Up-Port must match when both are supplied",
        ));
    }
    let callback_port = header_port.or(body.port);
    if let Some(port) = callback_port
        && !(1024..=65535).contains(&port)
    {
        return Err(bad_request("port must be between 1024 and 65535"));
    }
    let callback_secret = mfa_callback_secret_from_headers(&req)?;
    match (callback_port, callback_secret.as_deref()) {
        (Some(_), None) => {
            return Err(bad_request(
                "Cargo-Step-Up-Callback-Secret is required when port is set",
            ));
        }
        (None, Some(_)) => {
            return Err(bad_request("Cargo-Step-Up-Callback-Secret requires port"));
        }
        _ => {}
    }

    let operation = descriptor
        .as_ref()
        .map(ValidatedMutationDescriptor::operation)
        .unwrap_or_else(|| ApiMfaOperation::manual(body.crate_name.clone()));

    let existing = if requested_operation == "manual" {
        ApiMfaChallenge::find_pending_for_operation(
            user.id,
            token.id,
            operation.kind,
            operation.crate_name.as_deref(),
            &operation.mutation_fingerprint,
            &conn,
        )
        .await?
    } else {
        ApiMfaChallenge::find_active_for_operation(
            user.id,
            token.id,
            operation.kind,
            operation.crate_name.as_deref(),
            &operation.mutation_fingerprint,
            &conn,
        )
        .await?
    };
    if let Some(existing) = existing {
        let existing = refresh_challenge_localhost_callback(
            existing,
            ApiMfaCallback {
                port: callback_port,
                secret: callback_secret.as_deref(),
            },
            &mut conn,
        )
        .await?;
        if requested_operation != "manual" {
            if existing.is_acknowledged() {
                return Ok((no_store(), Json(challenge_ready_response(&existing))).into_response());
            }
            return Err(step_up_required_error(
                &app.config.webauthn,
                &existing,
                &operation,
            ));
        }
        return Ok((
            no_store(),
            Json(challenge_created_response(&app.config.webauthn, &existing)),
        )
            .into_response());
    }

    app.rate_limiter
        .check_rate_limit(user.id, LimitedAction::ApiMfaChallengeCreate, &mut conn)
        .await?;

    ApiMfaChallenge::delete_expired_pending_for_operation(
        token.id,
        operation.kind,
        operation.crate_name.as_deref(),
        &operation.mutation_fingerprint,
        &conn,
    )
    .await?;

    let pending = ApiMfaChallenge::count_pending_for_user(user.id, &conn).await?;
    if pending >= MAX_PENDING_CHALLENGES_PER_USER {
        return Err(bad_request(format!(
            "too many pending API MFA challenges (max {MAX_PENDING_CHALLENGES_PER_USER}); \
             acknowledge or wait for existing ones to expire"
        )));
    }

    let callback = ApiMfaCallback {
        port: callback_port,
        secret: callback_secret.as_deref(),
    };
    let (challenge, created) = if let Some(descriptor) = descriptor {
        insert_preflight_or_reuse(
            user.id, token.id, &operation, descriptor, callback, &mut conn,
        )
        .await?
    } else {
        insert_challenge_or_reuse_pending(user.id, token.id, &operation, callback, &mut conn)
            .await?
    };

    if created {
        app.instance_metrics.api_mfa_challenges_created_total.inc();
    }

    if requested_operation != "manual"
        && (!app.config.api_mfa_enforcement_enabled || !user.api_mfa_enabled)
    {
        conn.transaction(async |conn| {
            challenge.mark_ready(conn).await?;
            NewApiMfaGrant::for_operation(
                user.id,
                token.id,
                operation.kind.to_owned(),
                operation.crate_name.clone(),
                operation.mutation_fingerprint.clone(),
            )
            .insert(conn)
            .await?;
            Ok::<_, diesel::result::Error>(())
        })
        .await?;
        return Ok((no_store(), Json(challenge_ready_response(&challenge))).into_response());
    }

    if requested_operation != "manual" {
        return Err(step_up_required_error(
            &app.config.webauthn,
            &challenge,
            &operation,
        ));
    }

    Ok((
        no_store(),
        Json(challenge_created_response(&app.config.webauthn, &challenge)),
    )
        .into_response())
}

fn challenge_created_response(
    webauthn: &crate::config::WebauthnConfig,
    challenge: &ApiMfaChallenge,
) -> CreateChallengeResponse {
    let (verification_url, poll_url) = public_mfa_urls(webauthn, &challenge.id);
    CreateChallengeResponse {
        status: "pending".into(),
        challenge_id: challenge.id.clone(),
        detail: Some(format!(
            "Additional authentication is required. Open this link to verify with your passkey:\n\n\
             {verification_url}\n\nAfter verification, retry the request."
        )),
        poll_url: Some(poll_url),
        expires_at: challenge.expires_at,
        recommended_poll_interval_secs: Some(RECOMMENDED_POLL_INTERVAL_SECS),
    }
}

fn challenge_ready_response(challenge: &ApiMfaChallenge) -> CreateChallengeResponse {
    CreateChallengeResponse {
        status: "acknowledged".into(),
        challenge_id: challenge.id.clone(),
        detail: None,
        poll_url: None,
        expires_at: challenge.expires_at,
        recommended_poll_interval_secs: None,
    }
}

#[derive(Debug)]
struct ValidatedMutationDescriptor {
    operation: &'static str,
    crate_name: String,
    summary: String,
    fingerprint: Vec<u8>,
    stored: NewApiMfaMutationDescriptor,
}

impl ValidatedMutationDescriptor {
    fn operation(&self) -> ApiMfaOperation {
        ApiMfaOperation {
            kind: self.operation,
            crate_name: Some(self.crate_name.clone()),
            mutation_fingerprint: self.fingerprint.clone(),
            summary: self.summary.clone(),
            facts: self
                .stored
                .descriptor_json
                .as_object()
                .map(|descriptor| {
                    let mut facts = serde_json::Map::new();
                    for name in [
                        "version",
                        "archive_sha256",
                        "archive_size",
                        "direction",
                        "owners",
                    ] {
                        if let Some(value) = descriptor.get(name) {
                            facts.insert(name.to_owned(), value.clone());
                        }
                    }
                    serde_json::Value::Object(facts)
                })
                .unwrap_or(serde_json::Value::Null),
        }
    }
}

fn validate_mutation_descriptor(
    body: &CreateChallengeRequest,
    operation: &str,
    max_archive_size: u32,
) -> AppResult<ValidatedMutationDescriptor> {
    if body.protocol_version != Some(1) {
        return Err(bad_request("protocol_version must be 1"));
    }
    let crate_name = required_descriptor_field(body.crate_name.as_deref(), "crate")?;
    crates_io_validation::validate_crate_name("crate", crate_name).map_err(bad_request)?;
    let method = required_descriptor_field(body.method.as_deref(), "method")?.to_uppercase();
    let endpoint = required_descriptor_field(body.endpoint.as_deref(), "endpoint")?;
    let request_sha256 = decode_sha256(
        required_descriptor_field(body.request_sha256.as_deref(), "request_sha256")?,
        "request_sha256",
    )?;
    let request_size = body
        .request_size
        .filter(|size| *size >= 0)
        .ok_or_else(|| bad_request("request_size must be a non-negative integer"))?;

    let (kind, summary) = match operation {
        "publish" => {
            let version = required_descriptor_field(body.version.as_deref(), "version")?;
            semver::Version::parse(version)
                .map_err(|_| bad_request("version is not valid semver"))?;
            if method != "PUT" || endpoint != "/api/v1/crates/new" {
                return Err(bad_request("publish must describe PUT /api/v1/crates/new"));
            }
            decode_sha256(
                required_descriptor_field(body.archive_sha256.as_deref(), "archive_sha256")?,
                "archive_sha256",
            )?;
            let _archive_size = body
                .archive_size
                .filter(|size| {
                    *size >= 0 && *size <= request_size && *size <= i64::from(max_archive_size)
                })
                .ok_or_else(|| {
                    bad_request(
                        "archive_size must be non-negative, within the registry upload limit, \
                         and no larger than request_size",
                    )
                })?;
            const MAX_METADATA_SIZE: i64 = 1024 * 1024;
            if request_size - _archive_size > MAX_METADATA_SIZE + 8 {
                return Err(bad_request(
                    "publish request overhead exceeds the metadata limit",
                ));
            }
            ("publish", format!("Publish {crate_name} {version}"))
        }
        "yank" | "unyank" => {
            let version = required_descriptor_field(body.version.as_deref(), "version")?;
            semver::Version::parse(version)
                .map_err(|_| bad_request("version is not valid semver"))?;
            let action = operation;
            let expected_method = if operation == "yank" { "DELETE" } else { "PUT" };
            let expected_endpoint = format!("/api/v1/crates/{crate_name}/{version}/{action}");
            if method != expected_method || endpoint != expected_endpoint {
                return Err(bad_request(format!(
                    "{operation} descriptor method or endpoint does not match its fields"
                )));
            }
            if request_size != 0 || request_sha256 != Sha256::digest([]).as_slice() {
                return Err(bad_request(format!(
                    "{operation} must describe an empty request body"
                )));
            }
            let verb = if operation == "yank" {
                "Yank"
            } else {
                "Unyank"
            };
            (
                if operation == "yank" {
                    "yank"
                } else {
                    "unyank"
                },
                format!("{verb} {crate_name} {version}"),
            )
        }
        "change-owners" => {
            if request_size > 64 * 1024 {
                return Err(bad_request("change-owners request body is too large"));
            }
            let direction = required_descriptor_field(body.direction.as_deref(), "direction")?;
            let expected_method = match direction {
                "add" => "PUT",
                "remove" => "DELETE",
                _ => return Err(bad_request("direction must be `add` or `remove`")),
            };
            let expected_endpoint = format!("/api/v1/crates/{crate_name}/owners");
            if method != expected_method || endpoint != expected_endpoint {
                return Err(bad_request(
                    "change-owners descriptor method or endpoint does not match its fields",
                ));
            }
            let owners = body
                .owners
                .as_ref()
                .ok_or_else(|| bad_request("owners is required for change-owners"))?;
            if owners.len() > 10 {
                return Err(bad_request("owners may contain at most 10 entries"));
            }
            let verb = if direction == "add" { "Add" } else { "Remove" };
            (
                "change-owners",
                format!("{verb} owners for {crate_name}: {}", owners.join(", ")),
            )
        }
        _ => {
            return Err(bad_request(
                "operation is not supported by mutation preflight",
            ));
        }
    };

    let mut descriptor = serde_json::Map::from_iter([
        ("protocol_version".to_owned(), serde_json::json!(1)),
        ("operation".to_owned(), serde_json::json!(kind)),
        ("method".to_owned(), serde_json::json!(method)),
        ("endpoint".to_owned(), serde_json::json!(endpoint)),
        ("crate".to_owned(), serde_json::json!(crate_name)),
        (
            "request_sha256".to_owned(),
            serde_json::json!(hex::encode(&request_sha256)),
        ),
        ("request_size".to_owned(), serde_json::json!(request_size)),
    ]);
    for (name, value) in [
        ("version", body.version.as_ref().map(|value| json!(value))),
        (
            "archive_sha256",
            body.archive_sha256
                .as_ref()
                .map(|value| json!(value.trim().to_ascii_lowercase())),
        ),
        ("archive_size", body.archive_size.map(|value| json!(value))),
        (
            "direction",
            body.direction.as_ref().map(|value| json!(value.trim())),
        ),
        ("owners", body.owners.as_ref().map(|value| json!(value))),
    ] {
        if let Some(value) = value {
            descriptor.insert(name.to_owned(), value);
        }
    }
    let descriptor_json = serde_json::Value::Object(descriptor);
    let fingerprint = Sha256::digest(serde_json::to_vec(&descriptor_json)?).to_vec();
    Ok(ValidatedMutationDescriptor {
        operation: kind,
        crate_name: crate_name.to_owned(),
        summary,
        fingerprint,
        stored: NewApiMfaMutationDescriptor {
            descriptor_json,
            request_method: method,
            request_endpoint: endpoint.to_owned(),
            request_sha256,
            request_size,
        },
    })
}

fn required_descriptor_field<'a>(value: Option<&'a str>, name: &str) -> AppResult<&'a str> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| bad_request(format!("{name} is required for mutation preflight")))
}

fn decode_sha256(value: &str, name: &str) -> AppResult<Vec<u8>> {
    let decoded =
        hex::decode(value).map_err(|_| bad_request(format!("{name} must be hex SHA-256")))?;
    if decoded.len() != 32 {
        return Err(bad_request(format!("{name} must be hex SHA-256")));
    }
    Ok(decoded)
}

async fn auth_check_for_preflight(
    operation: &str,
    crate_name: Option<&str>,
    mut conn: &diesel_async::AsyncPgConnection,
) -> AppResult<AuthCheck> {
    let mut check = AuthCheck::default();
    if let Some(crate_name) = crate_name {
        check = check.for_crate(crate_name);
    }
    check = match operation {
        "publish" => {
            let crate_name = crate_name.ok_or_else(|| bad_request("crate is required"))?;
            let exists = Crate::by_name(crate_name)
                .select(Crate::as_select())
                .first(&mut conn)
                .await
                .optional()?
                .is_some();
            check.with_endpoint_scope(if exists {
                EndpointScope::PublishUpdate
            } else {
                EndpointScope::PublishNew
            })
        }
        "yank" | "unyank" => check.with_endpoint_scope(EndpointScope::Yank),
        "change-owners" => check.with_endpoint_scope(EndpointScope::ChangeOwners),
        _ => check,
    };
    Ok(check)
}

async fn insert_preflight_or_reuse(
    user_id: i32,
    api_token_id: i32,
    operation: &ApiMfaOperation,
    descriptor: ValidatedMutationDescriptor,
    callback: ApiMfaCallback<'_>,
    conn: &mut diesel_async::AsyncPgConnection,
) -> AppResult<(ApiMfaChallenge, bool)> {
    use diesel::result::{DatabaseErrorKind, Error as DieselError};

    let challenge = NewApiMfaChallenge::new(
        user_id,
        Some(api_token_id),
        NewApiMfaChallengeOperation {
            operation: operation.kind.to_owned(),
            crate_name: operation.crate_name.clone(),
            mutation_fingerprint: operation.mutation_fingerprint.clone(),
            operation_summary: operation.summary.clone(),
            descriptor: Some(descriptor.stored),
        },
        callback.port,
        callback.secret,
    );
    match challenge.insert(conn).await {
        Ok(challenge) => Ok((challenge, true)),
        Err(DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, _)) => {
            let existing = ApiMfaChallenge::find_pending_for_operation(
                user_id,
                api_token_id,
                operation.kind,
                operation.crate_name.as_deref(),
                &operation.mutation_fingerprint,
                conn,
            )
            .await?
            .ok_or_else(|| server_error("preflight conflict without a reusable mutation record"))?;
            let existing = refresh_challenge_localhost_callback(existing, callback, conn).await?;
            Ok((existing, false))
        }
        Err(error) => Err(error.into()),
    }
}

/// Current state and operation details for an API MFA challenge.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct GetChallengeResponse {
    /// Opaque step-up challenge identifier.
    pub challenge_id: String,
    /// `pending` until passkey succeeds, then `acknowledged`.
    pub status: String,
    /// True once the browser passkey ceremony has acknowledged the operation.
    pub acknowledged: bool,
    /// Alias of `acknowledged` for older clients.
    pub verified: bool,
    pub operation: String,
    /// Server-generated description of the exact mutation being approved.
    pub operation_summary: String,
    pub crate_name: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub localhost_port: Option<i32>,
    /// Suggested seconds between CLI polls while status is `pending`.
    pub recommended_poll_interval_secs: u64,
}

/// Poll an API MFA challenge until the browser acknowledges it.
///
/// The opaque `challenge_id` is a capability URL: the verify page can load
/// metadata without a crates.io cookie. API token clients (CLI poll loops) are
/// rate-limited per user; unauthenticated browsers are rate-limited per IP.
/// Aside from rate-limit bucket updates this handler is read-only.
#[utoipa::path(
    get,
    path = "/api/v1/auth/challenges/{id}",
    params(("id" = String, Path, description = "Challenge ID")),
    tag = "users",
    extensions(("x-internal" = json!(true))),
    responses((status = 200, description = "Successful Response", body = inline(GetChallengeResponse))),
)]
pub async fn get_api_mfa_challenge(
    app: AppState,
    Path(id): Path<String>,
    req: Parts,
) -> AppResult<(TypedHeader<CacheControl>, Json<GetChallengeResponse>)> {
    // Rate-limit buckets need a write connection; challenge rows are only read.
    //
    // Unauthenticated polls are limited by the challenge *owner* id. Synthetic
    // negative IP ids cannot be stored in `publish_limit_buckets` (FK → users).
    let mut conn = app.db_write().await?;

    let has_auth_header = AuthHeader::optional_from_request_parts(&req)
        .await?
        .is_some();

    let Some(challenge) = ApiMfaChallenge::find_active(&id, &conn).await? else {
        return Err(not_found());
    };

    // Optional API token: CLI poll with binding + per-user rate limit.
    if has_auth_header {
        let auth = AuthCheck::default().check(&req, &mut conn).await?;
        authorize_challenge_read(&auth, &challenge)?;
        if auth.api_token().is_some() {
            app.rate_limiter
                .check_rate_limit(
                    auth.user_id(),
                    LimitedAction::ApiMfaChallengePoll,
                    &mut conn,
                )
                .await?;
            app.instance_metrics.api_mfa_challenge_polls_total.inc();
        }
    } else {
        let bucket_key = challenge_rate_limit_key(&challenge.id, &req)?;
        app.rate_limiter
            .check_key_rate_limit(&bucket_key, LimitedAction::ApiMfaChallengePoll, &mut conn)
            .await?;
        app.rate_limiter
            .check_rate_limit(
                challenge.user_id,
                LimitedAction::ApiMfaChallengeAggregate,
                &mut conn,
            )
            .await?;
    }

    let acknowledged = challenge.is_acknowledged();
    Ok((
        no_store(),
        Json(GetChallengeResponse {
            challenge_id: challenge.id,
            status: if acknowledged {
                "acknowledged".into()
            } else {
                "pending".into()
            },
            acknowledged,
            verified: acknowledged,
            operation: challenge.operation,
            operation_summary: challenge.operation_summary,
            crate_name: challenge.crate_name,
            expires_at: challenge.expires_at,
            localhost_port: challenge.localhost_port,
            recommended_poll_interval_secs: RECOMMENDED_POLL_INTERVAL_SECS,
        }),
    ))
}

fn authorize_challenge_read(auth: &Authentication, challenge: &ApiMfaChallenge) -> AppResult<()> {
    if challenge.user_id != auth.user_id() {
        return Err(not_found());
    }

    if let Some(token) = auth.api_token()
        && challenge.api_token_id != Some(token.id)
    {
        return Err(forbidden("this challenge belongs to a different API token"));
    }

    Ok(())
}

async fn rate_limit_challenge_ceremony(
    app: &AppState,
    challenge: &ApiMfaChallenge,
    req: &Parts,
    conn: &mut diesel_async::AsyncPgConnection,
) -> AppResult<()> {
    let bucket_key = challenge_rate_limit_key(&challenge.id, req)?;
    app.rate_limiter
        .check_key_rate_limit(&bucket_key, LimitedAction::ApiMfaChallengeCreate, conn)
        .await?;
    app.rate_limiter
        .check_rate_limit(
            challenge.user_id,
            LimitedAction::ApiMfaChallengeAggregate,
            conn,
        )
        .await?;
    Ok(())
}

fn challenge_rate_limit_key(challenge_id: &str, req: &Parts) -> AppResult<String> {
    let real_ip = req
        .extensions
        .get::<RealIp>()
        .ok_or_else(|| server_error("request is missing its resolved client IP"))?;
    let mut hasher = Sha256::new();
    hasher.update(challenge_id.as_bytes());
    hasher.update([0]);
    hasher.update(real_ip.to_string().as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

/// Browser options returned when starting challenge passkey verification.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct StartChallengeAuthResponse {
    pub public_key: serde_json::Value,
}

/// Start passkey authentication for a pending challenge.
///
/// Unauthenticated: possession of the opaque operation id is the capability.
/// Passkeys are loaded for the challenge owner (no crates.io cookie session).
#[utoipa::path(
    post,
    path = "/api/v1/auth/challenges/{id}/start",
    params(("id" = String, Path, description = "Challenge ID")),
    tag = "users",
    extensions(("x-internal" = json!(true))),
    responses((status = 200, description = "Successful Response", body = inline(StartChallengeAuthResponse))),
)]
pub async fn start_api_mfa_challenge(
    app: AppState,
    Path(id): Path<String>,
    req: Parts,
) -> AppResult<(TypedHeader<CacheControl>, Json<StartChallengeAuthResponse>)> {
    let mut conn = app.db_write().await?;

    let Some(challenge) = ApiMfaChallenge::find_active(&id, &conn).await? else {
        return Err(not_found());
    };
    if challenge.verified_at.is_some() {
        return Err(bad_request("this challenge is already acknowledged"));
    }

    rate_limit_challenge_ceremony(&app, &challenge, &req, &mut conn).await?;

    let credentials = WebauthnCredential::for_user(challenge.user_id, &conn).await?;
    if credentials.is_empty() {
        return Err(bad_request("no passkeys registered for this account"));
    }

    let webauthn = build_webauthn(&app.config.webauthn)?;
    let passkeys = passkeys_from_credentials(&credentials)?;
    let (rcr, auth_state) = webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|err| bad_request(format!("failed to start passkey authentication: {err}")))?;

    let state_json = serde_json::to_value(&auth_state)
        .map_err(|err| server_error(format!("failed to serialize auth state: {err}")))?;
    if !challenge.set_auth_state(state_json, &conn).await? {
        return Err(bad_request("this challenge is already acknowledged"));
    }

    let public_key = serde_json::to_value(rcr.public_key)
        .map_err(|err| server_error(format!("failed to serialize request options: {err}")))?;

    Ok((no_store(), Json(StartChallengeAuthResponse { public_key })))
}

/// Browser assertion submitted to finish challenge verification.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct FinishChallengeAuthRequest {
    pub credential: serde_json::Value,
}

/// Proof and fallback grant issued after successful challenge verification.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct FinishChallengeAuthResponse {
    /// One-time proof for the CLI to send as `Cargo-Step-Up-Proof`.
    pub otp: String,
    /// Optional loopback URL where the browser can deliver the proof.
    ///
    /// This URL excludes callback state. The browser adds its fragment-held
    /// callback secret locally, so the registry never reflects that secret.
    pub localhost_callback_url: Option<String>,
    /// Expiry of the exact token-and-operation-scoped polling fallback grant.
    pub grant_expires_at: DateTime<Utc>,
    pub challenge_id: String,
}

/// Finish challenge verification, issue OTP + grant.
///
/// Unauthenticated: passkey assertion for the challenge owner's credentials is
/// the only factor (no crates.io cookie). `cargo login` must already have
/// minted the API token that created this challenge.
#[utoipa::path(
    post,
    path = "/api/v1/auth/challenges/{id}/finish",
    params(("id" = String, Path, description = "Challenge ID")),
    request_body = inline(FinishChallengeAuthRequest),
    tag = "users",
    extensions(("x-internal" = json!(true))),
    responses((status = 200, description = "Successful Response", body = inline(FinishChallengeAuthResponse))),
)]
pub async fn finish_api_mfa_challenge(
    app: AppState,
    Path(id): Path<String>,
    req: Parts,
    Json(body): Json<FinishChallengeAuthRequest>,
) -> AppResult<(TypedHeader<CacheControl>, Json<FinishChallengeAuthResponse>)> {
    let mut conn = app.db_write().await?;

    let Some(challenge) = ApiMfaChallenge::find_active(&id, &conn).await? else {
        return Err(not_found());
    };
    if challenge.verified_at.is_some() {
        return Err(bad_request("this challenge is already acknowledged"));
    }

    rate_limit_challenge_ceremony(&app, &challenge, &req, &mut conn).await?;

    let callback_secret = mfa_callback_secret_from_headers(&req)?;
    if challenge.localhost_port.is_some()
        && callback_secret
            .as_deref()
            .is_none_or(|secret| !challenge.localhost_callback_secret_matches(secret))
    {
        return Err(forbidden("invalid localhost callback secret"));
    }

    let Some(state_json) = challenge.auth_state_json.clone() else {
        return Err(bad_request("passkey authentication has not been started"));
    };
    let auth_state: PasskeyAuthentication = serde_json::from_value(state_json)
        .map_err(|err| bad_request(format!("invalid authentication state: {err}")))?;

    let webauthn = build_webauthn(&app.config.webauthn)?;
    let auth_response = parse_auth_response(&body.credential)?;
    let auth_result = webauthn
        .finish_passkey_authentication(&auth_response, &auth_state)
        .map_err(|err| bad_request(format!("passkey authentication failed: {err}")))?;

    record_passkey_authentication(challenge.user_id, &auth_result, &mut conn).await?;

    let otp = ApiMfaChallenge::generate_otp();
    let hashed_otp = ApiMfaChallenge::hash_otp(&otp);
    let sealed_otp = challenge
        .localhost_port
        .map(|_| seal_callback_otp(&app.config.token_encryption, &otp))
        .transpose()?;
    let grant_token_id = challenge.api_token_id.ok_or_else(|| {
        bad_request("challenge is missing api_token_id; cannot issue a token-bound grant")
    })?;

    // Ack + scoped grant in one transaction so callback and poll are always
    // interchangeable completion channels for the exact token + operation.
    let grant_expires_at: Option<DateTime<Utc>> = conn
        .transaction(async |conn| {
            if !challenge
                .mark_verified(hashed_otp, sealed_otp, conn)
                .await?
            {
                return Ok::<_, diesel::result::Error>(None);
            }

            let grant = NewApiMfaGrant::for_operation(
                challenge.user_id,
                grant_token_id,
                challenge.operation.clone(),
                challenge.crate_name.clone(),
                challenge.mutation_fingerprint.clone(),
            )
            .insert(conn)
            .await?;
            Ok(Some(grant.expires_at))
        })
        .await?;

    let Some(grant_expires_at) = grant_expires_at else {
        return Err(bad_request("this challenge is already acknowledged"));
    };

    let localhost_callback_url = challenge
        .localhost_port
        .map(|port| format!("http://127.0.0.1:{port}/?code={otp}"));

    use crate::models::{NewUserSecurityEvent, SecurityEventType};
    NewUserSecurityEvent::new(
        challenge.user_id,
        SecurityEventType::ApiMfaChallengeVerified,
        challenge.api_token_id,
        None,
        serde_json::json!({
            "operation": challenge.operation,
            "crate_name": challenge.crate_name,
            "challenge_id": challenge.id,
        }),
    )
    .record_if(app.config.security_activity_enabled, &mut conn)
    .await;

    Ok((
        no_store(),
        Json(FinishChallengeAuthResponse {
            otp,
            localhost_callback_url,
            grant_expires_at,
            challenge_id: challenge.id,
        }),
    ))
}

/// Loopback callback details recovered for an acknowledged challenge.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct RecoverChallengeCallbackResponse {
    /// Loopback URL without callback state. The browser adds state locally.
    pub localhost_callback_url: String,
    pub challenge_id: String,
}

/// Recover a verified callback after a browser reload or transient delivery failure.
///
/// The callback secret lives only in the verification URL fragment and request
/// header. The server stores only its hash.
#[utoipa::path(
    post,
    path = "/api/v1/auth/challenges/{id}/recover",
    params(("id" = String, Path, description = "Challenge ID")),
    tag = "users",
    extensions(("x-internal" = json!(true))),
    responses((status = 200, description = "Successful Response", body = inline(RecoverChallengeCallbackResponse))),
)]
pub async fn recover_api_mfa_challenge_callback(
    app: AppState,
    Path(id): Path<String>,
    req: Parts,
) -> AppResult<(
    TypedHeader<CacheControl>,
    Json<RecoverChallengeCallbackResponse>,
)> {
    let mut conn = app.db_write().await?;
    let Some(challenge) = ApiMfaChallenge::find_active(&id, &conn).await? else {
        return Err(not_found());
    };

    rate_limit_challenge_ceremony(&app, &challenge, &req, &mut conn).await?;
    let Some(secret) = mfa_callback_secret_from_headers(&req)? else {
        return Err(not_found());
    };
    if !challenge.localhost_callback_secret_matches(&secret) {
        return Err(not_found());
    }
    if challenge.verified_at.is_none() {
        return Err(bad_request("this challenge has not been acknowledged"));
    }
    if challenge.otp_consumed_at.is_some() {
        return Err(bad_request("this challenge OTP has already been consumed"));
    }

    let port = challenge
        .localhost_port
        .ok_or_else(|| bad_request("this challenge has no localhost callback"))?;
    let sealed = challenge
        .sealed_otp
        .as_deref()
        .ok_or_else(|| server_error("verified callback challenge is missing its sealed OTP"))?;
    let otp = open_callback_otp(&app.config.token_encryption, sealed)?;

    Ok((
        no_store(),
        Json(RecoverChallengeCallbackResponse {
            localhost_callback_url: format!("http://127.0.0.1:{port}/?code={otp}"),
            challenge_id: challenge.id,
        }),
    ))
}

fn seal_callback_otp(
    encryption: &crates_io_encryption::TokenEncryption,
    otp: &str,
) -> AppResult<String> {
    let ciphertext = encryption
        .encrypt(otp)
        .map_err(|err| server_error(format!("failed to seal API MFA callback OTP: {err}")))?;
    Ok(base64::engine::general_purpose::STANDARD.encode(ciphertext))
}

fn open_callback_otp(
    encryption: &crates_io_encryption::TokenEncryption,
    sealed: &str,
) -> AppResult<String> {
    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(sealed)
        .map_err(|err| server_error(format!("corrupt API MFA callback OTP: {err}")))?;
    encryption
        .decrypt(&ciphertext)
        .map(|otp| otp.expose_secret().to_owned())
        .map_err(|err| server_error(format!("failed to open API MFA callback OTP: {err}")))
}
