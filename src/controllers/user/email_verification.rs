use crate::app::AppState;
use crate::auth::AuthCheck;
use crate::controllers::helpers::OkResponse;
use crate::email::EmailMessage;
use crate::middleware::real_ip::RealIp;
use crate::models::{Email, NewUserSecurityEvent, SecurityEventType};
use crate::rate_limiter::LimitedAction;
use crate::util::errors::AppResult;
use crate::util::errors::{BoxedAppError, bad_request};
use axum::extract::Path;
use crates_io_database::schema::emails;
use diesel::dsl::sql;
use diesel::prelude::*;
use diesel_async::{AsyncConnection, RunQueryDsl};
use http::request::Parts;
use minijinja::context;
use secrecy::ExposeSecret;

/// Marks the email belonging to the given token as verified.
///
/// When a `pending_email` is staged, confirmation promotes it to the primary
/// address and clears the pending field. Otherwise the existing address is marked verified.
#[utoipa::path(
    put,
    path = "/api/v1/confirm/{email_token}",
    params(
        ("email_token" = String, Path, description = "Secret verification token sent to the user's email address"),
    ),
    tag = "users",
    responses((status = 200, description = "Successful Response", body = inline(OkResponse))),
)]
pub async fn confirm_user_email(
    state: AppState,
    Path(token): Path<String>,
    req: Parts,
) -> AppResult<OkResponse> {
    let mut conn = state.db_write().await?;

    let Some(confirmed) = Email::confirm_token(&token, &mut conn).await? else {
        return Err(bad_request("Email belonging to token not found."));
    };

    if confirmed.promoted_pending {
        let ip = req.extensions.get::<RealIp>().map(|ip| ip.to_string());
        NewUserSecurityEvent::new(
            confirmed.email.user_id,
            SecurityEventType::EmailChanged,
            None,
            ip,
            serde_json::json!({}),
        )
        .record_if(state.config.security_activity_enabled, &mut conn)
        .await;
    }

    Ok(OkResponse::new())
}

/// Regenerate and send an email verification token.
///
/// When a pending address is staged, the confirmation email is sent there.
/// Otherwise it is sent to the current (unverified) address.
#[utoipa::path(
    put,
    path = "/api/v1/users/{id}/resend",
    params(
        ("id" = i32, Path, description = "ID of the user"),
    ),
    security(
        ("api_token" = []),
        ("cookie" = []),
    ),
    tag = "users",
    responses((status = 200, description = "Successful Response", body = inline(OkResponse))),
)]
pub async fn resend_email_verification(
    state: AppState,
    Path(param_user_id): Path<i32>,
    req: Parts,
) -> AppResult<OkResponse> {
    let mut conn = state.db_write().await?;
    let auth = AuthCheck::default().check(&req, &mut conn).await?;

    // need to check if current user matches user to be updated
    if auth.user_id() != param_user_id {
        return Err(bad_request("current user does not match requested user"));
    }

    state
        .rate_limiter
        .check_rate_limit(auth.user_id(), LimitedAction::EmailUpdate, &mut conn)
        .await?;

    conn.transaction(async |conn| {
        let email: Email = diesel::update(Email::belonging_to(auth.user()))
            .set(emails::token.eq(sql("DEFAULT")))
            .returning(Email::as_returning())
            .get_result(conn)
            .await
            .optional()?
            .ok_or_else(|| bad_request("Email could not be found"))?;

        let destination = email
            .pending_email
            .as_deref()
            .unwrap_or(email.email.as_str());

        let email_message = EmailMessage::from_template(
            "user_confirm",
            context! {
                user_name => auth.user().gh_login,
                domain => state.emails.domain,
                token => email.token.expose_secret()
            },
        )
        .map_err(|_| bad_request("Failed to render email template"))?;

        state
            .emails
            .send(destination, email_message)
            .await
            .map_err(BoxedAppError::from)
    })
    .await?;

    Ok(OkResponse::new())
}
