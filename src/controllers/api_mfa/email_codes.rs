//! Send email OTPs for API MFA bootstrap / recovery step-up.

use crate::app::AppState;
use crate::auth::AuthCheck;
use crate::email::EmailMessage;
use crate::models::{ApiMfaEmailOtp, DEFAULT_EMAIL_OTP_DURATION_SECS};
use crate::rate_limiter::LimitedAction;
use crate::util::errors::{AppResult, bad_request, server_error};
use crate::util::no_store;
use axum::Json;
use axum_extra::TypedHeader;
use axum_extra::headers::CacheControl;
use chrono::{TimeDelta, Utc};
use http::request::Parts;
use minijinja::context;
use serde::Serialize;
use tracing::warn;

/// Delivery details for a newly issued email OTP.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SendEmailOtpResponse {
    /// When the emailed code expires.
    pub expires_at: chrono::DateTime<Utc>,
    /// Masked destination address (e.g. `a***@example.com`).
    pub sent_to_hint: String,
}

/// Email a one-time code for API MFA enable/disable, passkey enrollment, or
/// changing away from a verified email address.
///
/// Requires a verified email address. The code is never returned in the response.
#[utoipa::path(
    post,
    path = "/api/v1/me/mfa/email_codes",
    security(("cookie" = [])),
    tag = "users",
    extensions(("x-internal" = json!(true))),
    responses((status = 200, description = "Successful Response", body = inline(SendEmailOtpResponse))),
)]
pub async fn send_api_mfa_email_code(
    app: AppState,
    req: Parts,
) -> AppResult<(TypedHeader<CacheControl>, Json<SendEmailOtpResponse>)> {
    let mut conn = app.db_write().await?;
    let auth = AuthCheck::only_cookie().check(&req, &mut conn).await?;
    let user = auth.user();

    let Some(email) = user.verified_email(&conn).await? else {
        return Err(bad_request(
            "a verified email address is required to receive an API MFA code; \
             visit Settings → Profile to set and verify your email",
        ));
    };

    app.rate_limiter
        .check_rate_limit(user.id, LimitedAction::ApiMfaEmailOtpSend, &mut conn)
        .await?;

    let expires_at = Utc::now() + TimeDelta::seconds(DEFAULT_EMAIL_OTP_DURATION_SECS);
    let (otp, expires_at) = ApiMfaEmailOtp::issue(user.id, expires_at, &conn).await?;

    let email_message = EmailMessage::from_template(
        "api_mfa_email_otp",
        context! {
            user_name => user.gh_login,
            domain => app.emails.domain,
            otp => otp,
            expires_minutes => DEFAULT_EMAIL_OTP_DURATION_SECS / 60,
        },
    )
    .map_err(|err| {
        warn!(error = %err, "Failed to render API MFA email OTP template: {err}");
        server_error("failed to send email code")
    })?;

    app.emails
        .send(&email, email_message)
        .await
        .map_err(|err| {
            warn!(
                user.id = user.id,
                error = %err,
                "Failed to send API MFA email OTP to user `{}`: {err}",
                user.id,
            );
            server_error("failed to send email code")
        })?;

    Ok((
        no_store(),
        Json(SendEmailOtpResponse {
            expires_at,
            sent_to_hint: mask_email(&email),
        }),
    ))
}

/// Masks an email for UI display (`a***@example.com`).
fn mask_email(email: &str) -> String {
    let Some((local, domain)) = email.split_once('@') else {
        return "***".to_string();
    };
    let first = local.chars().next().unwrap_or('*');
    format!("{first}***@{domain}")
}

/// Consumes `email_code` for `user_id`, returning a client error when invalid.
pub(crate) async fn require_email_code(
    user_id: i32,
    email_code: Option<&str>,
    conn: &mut diesel_async::AsyncPgConnection,
) -> AppResult<()> {
    let Some(otp) = email_code.map(str::trim).filter(|s| !s.is_empty()) else {
        return Err(bad_request(
            "email verification code required; request one with POST /api/v1/me/mfa/email_codes",
        ));
    };

    if !ApiMfaEmailOtp::consume(user_id, otp, conn).await? {
        return Err(bad_request(
            "invalid or expired email verification code; request a new one with POST /api/v1/me/mfa/email_codes",
        ));
    }

    Ok(())
}
