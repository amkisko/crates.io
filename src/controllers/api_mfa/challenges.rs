use super::webauthn_util::{build_webauthn, parse_auth_response, passkeys_from_credentials};
use crate::api_mfa::{RECOMMENDED_POLL_INTERVAL_SECS, public_mfa_urls};
use crate::app::AppState;
use crate::auth::{AuthCheck, AuthHeader, Authentication};
use crate::middleware::real_ip::RealIp;
use crate::models::{
    ApiMfaChallenge, MAX_PENDING_CHALLENGES_PER_USER, NewApiMfaChallenge, NewApiMfaGrant,
    WebauthnCredential,
};
use crate::rate_limiter::{LimitedAction, rate_limit_id_for_ip};
use crate::util::errors::{AppResult, bad_request, forbidden, not_found, server_error};
use crate::util::no_store;
use axum::Json;
use axum::extract::Path;
use axum_extra::TypedHeader;
use axum_extra::headers::CacheControl;
use chrono::{DateTime, Utc};
use http::request::Parts;
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::*;

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateChallengeRequest {
    /// Dangerous operation label (e.g. `publish`). Defaults to `manual`.
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
    path = "/api/v1/me/api_mfa/challenges",
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

    let operation = body
        .operation
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("manual");

    if let Some(existing) = ApiMfaChallenge::find_pending_for_operation(
        user.id,
        token.id,
        operation,
        body.crate_name.as_deref(),
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
        operation,
        body.crate_name.as_deref(),
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

    let challenge = NewApiMfaChallenge::new(
        user.id,
        Some(token.id),
        operation,
        body.crate_name,
        body.port,
    )
    .insert(&conn)
    .await?;

    app.instance_metrics.api_mfa_challenges_created_total.inc();

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
    path = "/api/v1/me/api_mfa/challenges/{id}",
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
    let mut conn = app.db_write().await?;

    let has_auth_header = AuthHeader::optional_from_request_parts(&req)
        .await?
        .is_some();

    if !has_auth_header {
        let ip = req
            .extensions
            .get::<RealIp>()
            .map(|ip| **ip)
            .unwrap_or_else(|| std::net::IpAddr::from([0, 0, 0, 0]));
        app.rate_limiter
            .check_rate_limit(
                rate_limit_id_for_ip(ip),
                LimitedAction::ApiMfaChallengePoll,
                &mut conn,
            )
            .await?;
    }

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
    req: &Parts,
    challenge_user_id: i32,
    conn: &mut diesel_async::AsyncPgConnection,
) -> AppResult<()> {
    let ip = req
        .extensions
        .get::<RealIp>()
        .map(|ip| **ip)
        .unwrap_or_else(|| std::net::IpAddr::from([0, 0, 0, 0]));
    // IP bucket: leaked capability URLs cannot thrash the write pool unbounded.
    app.rate_limiter
        .check_rate_limit(
            rate_limit_id_for_ip(ip),
            LimitedAction::ApiMfaChallengeCreate,
            conn,
        )
        .await?;
    // Per-owner bucket: protects the account that owns the challenge.
    app.rate_limiter
        .check_rate_limit(
            challenge_user_id,
            LimitedAction::ApiMfaChallengeCreate,
            conn,
        )
        .await?;
    Ok(())
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
    path = "/api/v1/me/api_mfa/challenges/{id}/start",
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

    rate_limit_challenge_ceremony(&app, &req, challenge.user_id, &mut conn).await?;

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
    path = "/api/v1/me/api_mfa/challenges/{id}/finish",
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

    rate_limit_challenge_ceremony(&app, &req, challenge.user_id, &mut conn).await?;

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

    let credentials = WebauthnCredential::for_user(challenge.user_id, &conn).await?;
    for credential in &credentials {
        if credential.credential_id.as_slice() == auth_result.cred_id().as_slice() {
            credential.touch(&conn).await?;
            break;
        }
    }

    let otp = ApiMfaChallenge::generate_otp();
    if !challenge
        .mark_verified(ApiMfaChallenge::hash_otp(&otp), &conn)
        .await?
    {
        return Err(bad_request("this challenge is already acknowledged"));
    }

    let localhost_callback_url = challenge
        .localhost_port
        .map(|port| format!("http://localhost:{port}/?code={otp}"));

    // Scoped grant for stock cargo retries. Skip when a localhost OTP callback was requested.
    // Only the atomic mark_verified winner reaches this insert.
    let grant_expires_at = if challenge.localhost_port.is_some() {
        None
    } else {
        let grant = NewApiMfaGrant::for_operation(
            challenge.user_id,
            challenge.operation.clone(),
            challenge.crate_name.clone(),
        )
        .insert(&conn)
        .await?;
        Some(grant.expires_at)
    };

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
