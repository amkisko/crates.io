//! Passkey ceremony for API MFA and mutation-authorization challenges.

use axum::Json;
use axum::extract::Path;
use axum_extra::TypedHeader;
use axum_extra::headers::CacheControl;
use http::request::Parts;
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::PasskeyAuthentication;

use crate::app::AppState;
use crate::models::{ApiMfaChallenge, WebauthnCredential};
use crate::util::errors::{AppResult, bad_request, not_found, server_error};
use crate::util::no_store;

use super::super::webauthn_util::{
    build_webauthn, parse_auth_response, passkeys_from_credentials, record_passkey_authentication,
};
use super::status::rate_limit_challenge_ceremony;

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
    if challenge.mutation_state.as_deref() == Some("denied") {
        return Err(bad_request("this mutation authorization was denied"));
    }
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

/// Result of successful challenge verification.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct FinishChallengeAuthResponse {
    /// Exact loopback URL registered by Cargo, used only as a wake-up signal.
    pub callback_url: Option<String>,
}

/// Finish verification and make the mutation authorization ready.
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
    if challenge.mutation_state.as_deref() == Some("denied") {
        return Err(bad_request("this mutation authorization was denied"));
    }
    if challenge.verified_at.is_some() {
        return Err(bad_request("this challenge is already acknowledged"));
    }

    rate_limit_challenge_ceremony(&app, &challenge, &req, &mut conn).await?;

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

    if !challenge.mark_verified(&conn).await? {
        return Err(bad_request("this challenge is already acknowledged"));
    }

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
            callback_url: challenge.callback_url,
        }),
    ))
}
