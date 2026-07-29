//! Browser-assisted cargo CLI login (link → scopes → one-time poll).

pub mod approve;
pub mod poll;
pub mod start;

use crate::app::AppState;
use crate::models::{CliLoginSession, TouchPollOutcome};
use crate::rate_limiter::{LimitedAction, RateLimiter};
use crate::util::errors::{AppResult, TooManyRequests, custom, server_error};
use chrono::{TimeDelta, Utc};
use crates_io_encryption::TokenEncryption;
use diesel_async::AsyncPgConnection;
use http::StatusCode;
use secrecy::ExposeSecret;

/// Recommended CLI poll interval for login acknowledgment (seconds).
pub const RECOMMENDED_POLL_INTERVAL_SECS: u64 = 2;

/// Returns an error when `CLI_LOGIN_ENABLED` is false.
pub fn ensure_cli_login_enabled(app: &AppState) -> AppResult<()> {
    if app.config.cli_login_enabled {
        return Ok(());
    }
    Err(custom(
        StatusCode::SERVICE_UNAVAILABLE,
        "CLI link-login is temporarily unavailable",
    ))
}

/// Builds absolute login and poll URLs from the `WebAuthn` RP origin (public site origin).
pub fn public_cli_login_urls(
    webauthn: &crate::config::WebauthnConfig,
    session_id: &str,
) -> (String, String) {
    let base = webauthn.rp_origin.as_str().trim_end_matches('/');
    (
        format!("{base}/settings/tokens/cli/{session_id}"),
        format!("{base}/api/v1/cli_login/{session_id}"),
    )
}

/// Rate-limits CLI login creates by counting recent sessions for the client IP.
///
/// `publish_limit_buckets.user_id` references `users`, so unauthenticated IP traffic
/// cannot use the token-bucket helper; the sessions table is the rate-limit store.
/// Window length and burst come from `RATE_LIMITER_CLI_LOGIN_CREATE_*`.
pub async fn check_create_rate_limit(
    rate_limiter: &RateLimiter,
    client_ip: &str,
    conn: &mut AsyncPgConnection,
) -> AppResult<()> {
    let action = LimitedAction::CliLoginCreate;
    let config = rate_limiter.config_for_action(action);
    let window = TimeDelta::from_std(config.rate).unwrap_or_else(|_| TimeDelta::seconds(30));
    let since = Utc::now() - window;
    let count = CliLoginSession::count_created_since(client_ip, since, conn).await?;
    if count >= i64::from(config.burst) {
        return Err(Box::new(TooManyRequests {
            action,
            retry_after: Utc::now() + window,
        }));
    }
    Ok(())
}

/// Enforces the minimum poll interval and returns status without a second SELECT.
///
/// Interval comes from `RATE_LIMITER_CLI_LOGIN_POLL_RATE_SECONDS`.
pub async fn touch_poll_or_rate_limit(
    rate_limiter: &RateLimiter,
    session_id: &str,
    conn: &mut AsyncPgConnection,
) -> AppResult<TouchPollOutcome> {
    let action = LimitedAction::CliLoginPoll;
    let min_secs = rate_limiter.config_for_action(action).rate.as_secs() as i64;
    let outcome = CliLoginSession::touch_poll(session_id, min_secs, conn).await?;
    if matches!(outcome, TouchPollOutcome::RateLimited) {
        return Err(Box::new(TooManyRequests {
            action,
            retry_after: Utc::now() + TimeDelta::seconds(min_secs),
        }));
    }
    Ok(outcome)
}

/// Encrypts a plaintext API token for short-lived stash on the login session.
pub fn seal_redeem_token(encryption: &TokenEncryption, plaintext: &str) -> AppResult<String> {
    let ciphertext = encryption
        .encrypt(plaintext)
        .map_err(|err| server_error(format!("failed to seal CLI login token: {err}")))?;
    Ok(base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        ciphertext,
    ))
}

/// Decrypts a sealed redeem blob from the login session.
pub fn open_redeem_token(encryption: &TokenEncryption, sealed: &str) -> AppResult<String> {
    let ciphertext = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, sealed)
        .map_err(|err| server_error(format!("corrupt CLI login token blob: {err}")))?;
    let secret = encryption
        .decrypt(&ciphertext)
        .map_err(|err| server_error(format!("failed to open CLI login token: {err}")))?;
    Ok(secret.expose_secret().to_string())
}
