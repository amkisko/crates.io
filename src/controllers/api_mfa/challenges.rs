use super::webauthn_util::{
    build_webauthn, parse_auth_response, passkeys_from_credentials, record_passkey_authentication,
};
use crate::api_mfa::{
    ApiMfaCallback, ApiMfaOperation, RECOMMENDED_POLL_INTERVAL_SECS,
    insert_challenge_or_reuse_pending, mfa_callback_secret_from_headers,
    normalize_challenge_operation, public_mfa_urls,
};
use crate::app::AppState;
use crate::auth::{AuthCheck, AuthHeader, Authentication};
use crate::middleware::real_ip::RealIp;
use crate::models::{
    ApiMfaChallenge, MAX_PENDING_CHALLENGES_PER_USER, NewApiMfaGrant, WebauthnCredential,
};
use crate::rate_limiter::LimitedAction;
use crate::util::errors::{AppResult, bad_request, forbidden, not_found, server_error};
use crate::util::no_store;
use axum::Json;
use axum::extract::Path;
use axum_extra::TypedHeader;
use axum_extra::headers::CacheControl;
use base64::Engine;
use chrono::{DateTime, Utc};
use diesel_async::AsyncConnection;
use http::request::Parts;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use webauthn_rs::prelude::*;

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateChallengeRequest {
    /// Dangerous operation label. Defaults to `manual`.
    ///
    /// Allowed: `publish`, `yank`, `unyank`, `change-owners`, `change-trustpub-only`,
    /// `change-trusted-publishing`, `delete-crate`, `manual`.
    pub operation: Option<String>,
    /// Optional crate name associated with the operation.
    pub crate_name: Option<String>,
    /// Optional localhost port (1024–65535) for RubyGems-style OTP delivery to the CLI.
    pub port: Option<i32>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct CreateChallengeResponse {
    /// Opaque operation / transaction identifier.
    pub operation_id: String,
    /// Browser URL where the user must complete passkey verification.
    pub verification_url: String,
    /// URL the CLI should poll until `acknowledged` is true.
    pub poll_url: String,
    pub expires_at: DateTime<Utc>,
    /// Suggested seconds between CLI polls of `poll_url`.
    pub recommended_poll_interval_secs: u64,
}

/// Create an API MFA challenge for a CLI client (token auth).
///
/// Prefer letting dangerous endpoints auto-create challenges; this endpoint is for
/// explicit preflight handshakes.
#[utoipa::path(
    post,
    path = "/api/v1/mfa/challenges",
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
) -> AppResult<(TypedHeader<CacheControl>, Json<CreateChallengeResponse>)> {
    let mut conn = app.db_write().await?;
    let auth = AuthCheck::default().check(&req, &mut conn).await?;

    let Some(token) = auth.api_token() else {
        return Err(forbidden(
            "API MFA challenges must be created with an API token",
        ));
    };

    let user = auth.user();
    if !user.api_mfa_enabled {
        return Err(bad_request("API MFA is not enabled for this account"));
    }

    let credentials = WebauthnCredential::for_user(user.id, &conn).await?;
    if credentials.is_empty() {
        return Err(bad_request("no passkeys registered for this account"));
    }

    if let Some(port) = body.port
        && !(1024..=65535).contains(&port)
    {
        return Err(bad_request("port must be between 1024 and 65535"));
    }

    let operation = normalize_challenge_operation(body.operation.as_deref())?;
    if operation != "manual" {
        return Err(bad_request(
            "operation preflight cannot authorize a mutation; perform the exact mutation and use \
             the challenge returned by its mfa_required response",
        ));
    }
    let operation = ApiMfaOperation::manual(body.crate_name);

    if let Some(existing) = ApiMfaChallenge::find_pending_for_operation(
        user.id,
        token.id,
        operation.kind,
        operation.crate_name.as_deref(),
        &operation.mutation_fingerprint,
        &conn,
    )
    .await?
    {
        return Ok((
            no_store(),
            Json(challenge_created_response(&app.config.webauthn, &existing)),
        ));
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

    let (challenge, created) = insert_challenge_or_reuse_pending(
        user.id,
        token.id,
        &operation,
        ApiMfaCallback {
            port: body.port,
            secret: None,
        },
        &mut conn,
    )
    .await?;

    if created {
        app.instance_metrics.api_mfa_challenges_created_total.inc();
    }

    Ok((
        no_store(),
        Json(challenge_created_response(&app.config.webauthn, &challenge)),
    ))
}

fn challenge_created_response(
    webauthn: &crate::config::WebauthnConfig,
    challenge: &ApiMfaChallenge,
) -> CreateChallengeResponse {
    let (verification_url, poll_url) = public_mfa_urls(webauthn, &challenge.id);
    CreateChallengeResponse {
        operation_id: challenge.id.clone(),
        verification_url,
        poll_url,
        expires_at: challenge.expires_at,
        recommended_poll_interval_secs: RECOMMENDED_POLL_INTERVAL_SECS,
    }
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct GetChallengeResponse {
    /// Opaque operation / transaction identifier.
    pub operation_id: String,
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
/// The opaque `operation_id` is a capability URL: the verify page can load
/// metadata without a crates.io cookie. API token clients (CLI poll loops) are
/// rate-limited per user; unauthenticated browsers are rate-limited per IP.
/// Aside from rate-limit bucket updates this handler is read-only.
#[utoipa::path(
    get,
    path = "/api/v1/mfa/challenges/{id}",
    params(("id" = String, Path, description = "Operation ID")),
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
    }

    let acknowledged = challenge.is_acknowledged();
    Ok((
        no_store(),
        Json(GetChallengeResponse {
            operation_id: challenge.id,
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
    challenge_id: &str,
    req: &Parts,
    conn: &mut diesel_async::AsyncPgConnection,
) -> AppResult<()> {
    let bucket_key = challenge_rate_limit_key(challenge_id, req)?;
    app.rate_limiter
        .check_key_rate_limit(&bucket_key, LimitedAction::ApiMfaChallengeCreate, conn)
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
    path = "/api/v1/mfa/challenges/{id}/start",
    params(("id" = String, Path, description = "Operation ID")),
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

    rate_limit_challenge_ceremony(&app, &challenge.id, &req, &mut conn).await?;

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

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct FinishChallengeAuthRequest {
    pub credential: serde_json::Value,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct FinishChallengeAuthResponse {
    /// One-time password for the CLI to send as `Crates-OTP`.
    pub otp: String,
    /// Optional URL the browser can hit to deliver the OTP to a local CLI listener.
    pub localhost_callback_url: Option<String>,
    /// Present when a scoped grant was issued (stock cargo retry without OTP).
    ///
    /// Omitted when `localhost_port` was set — the CLI is expected to use the OTP callback.
    pub grant_expires_at: Option<DateTime<Utc>>,
    pub operation_id: String,
}

/// Finish challenge verification, issue OTP + grant.
///
/// Unauthenticated: passkey assertion for the challenge owner's credentials is
/// the only factor (no crates.io cookie). `cargo login` must already have
/// minted the API token that created this challenge.
#[utoipa::path(
    post,
    path = "/api/v1/mfa/challenges/{id}/finish",
    params(("id" = String, Path, description = "Operation ID")),
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

    rate_limit_challenge_ceremony(&app, &challenge.id, &req, &mut conn).await?;

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
    let issue_grant = challenge.localhost_port.is_none();
    let callback_secret = mfa_callback_secret_from_headers(&req)?;
    if challenge.localhost_port.is_some()
        && callback_secret
            .as_deref()
            .is_none_or(|secret| !challenge.localhost_callback_secret_matches(secret))
    {
        return Err(forbidden("invalid localhost callback secret"));
    }
    let sealed_otp = challenge
        .localhost_port
        .map(|_| seal_callback_otp(&app.config.token_encryption, &otp))
        .transpose()?;
    let grant_token_id = if issue_grant {
        challenge.api_token_id.ok_or_else(|| {
            bad_request("challenge is missing api_token_id; cannot issue a token-bound grant")
        })?
    } else {
        // Unused when only OTP callback is issued.
        0
    };

    // Ack + scoped grant in one transaction so a grant insert failure cannot
    // leave a verified challenge without a retry path for stock cargo.
    let grant_expires_at: Option<Option<DateTime<Utc>>> = conn
        .transaction(async |conn| {
            if !challenge
                .mark_verified(hashed_otp, sealed_otp, conn)
                .await?
            {
                return Ok::<_, diesel::result::Error>(None);
            }

            if !issue_grant {
                return Ok(Some(None));
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
            Ok(Some(Some(grant.expires_at)))
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
            "operation_id": challenge.id,
        }),
    )
    .record(&mut conn)
    .await;

    Ok((
        no_store(),
        Json(FinishChallengeAuthResponse {
            otp,
            localhost_callback_url,
            grant_expires_at,
            operation_id: challenge.id,
        }),
    ))
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct RecoverChallengeCallbackResponse {
    /// URL for the browser to retry against the waiting loopback listener.
    pub localhost_callback_url: String,
    pub operation_id: String,
}

/// Recover a verified callback after a browser reload or transient delivery failure.
///
/// The callback secret lives only in the verification URL fragment and request
/// header. The server stores only its hash.
#[utoipa::path(
    post,
    path = "/api/v1/mfa/challenges/{id}/recover",
    params(("id" = String, Path, description = "Operation ID")),
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

    rate_limit_challenge_ceremony(&app, &challenge.id, &req, &mut conn).await?;
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
            operation_id: challenge.id,
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
