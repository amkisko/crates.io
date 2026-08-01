//! Recovery of legacy localhost callbacks after passkey verification.

use axum::Json;
use axum::extract::Path;
use axum_extra::TypedHeader;
use axum_extra::headers::CacheControl;
use base64::Engine;
use http::request::Parts;
use secrecy::ExposeSecret;
use serde::Serialize;

use crate::api_mfa::mfa_callback_secret_from_headers;
use crate::app::AppState;
use crate::models::ApiMfaChallenge;
use crate::util::errors::{AppResult, bad_request, not_found, server_error};
use crate::util::no_store;

use super::status::rate_limit_challenge_ceremony;

/// Loopback callback details recovered for an acknowledged challenge.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct RecoverChallengeCallbackResponse {
    /// Legacy loopback URL without callback state. The browser adds state locally.
    pub localhost_callback_url: String,
    pub challenge_id: String,
}

/// Recover a verified callback after a browser reload or transient delivery failure.
///
/// The legacy callback secret lives only in the verification URL fragment and
/// request header. The server stores only its hash.
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

pub(super) fn seal_callback_otp(
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
