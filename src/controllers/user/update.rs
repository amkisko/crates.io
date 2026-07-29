use crate::app::AppState;
use crate::auth::AuthCheck;
use crate::controllers::api_mfa::email_codes::require_email_code;
use crate::controllers::helpers::OkResponse;
use crate::email::EmailMessage;
use crate::models::{Email, NewEmail};
use crate::rate_limiter::LimitedAction;
use crate::schema::users;
use crate::util::errors::{AppResult, bad_request, server_error};
use axum::Json;
use axum::extract::Path;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use http::request::Parts;
use lettre::Address;
use minijinja::context;
use secrecy::ExposeSecret;
use serde::Deserialize;
use tracing::warn;

#[derive(Deserialize, utoipa::ToSchema)]
pub struct UserUpdate {
    #[schema(inline)]
    user: User,
    /// Email OTP from `POST /api/v1/me/mfa/email_codes`, required when staging a
    /// change away from a verified address (sent to the current verified inbox).
    #[serde(default)]
    pub email_code: Option<String>,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct User {
    email: Option<String>,
    publish_notifications: Option<bool>,
}

/// Update user settings.
///
/// This endpoint allows users to update their email address and publish notifications settings.
///
/// The `id` parameter needs to match the ID of the currently authenticated user.
///
/// Changing away from a verified email requires an email OTP sent to the current
/// verified address. The verified inbox stays in place until the new address is
/// confirmed via the link emailed to it (`pending_email`).
#[utoipa::path(
    put,
    path = "/api/v1/users/{user}",
    params(
        ("user" = i32, Path, description = "ID of the user"),
    ),
    request_body = inline(UserUpdate),
    security(
        ("api_token" = []),
        ("cookie" = []),
    ),
    tag = "users",
    responses((status = 200, description = "Successful Response", body = inline(OkResponse))),
)]
pub async fn update_user(
    state: AppState,
    Path(param_user_id): Path<i32>,
    req: Parts,
    Json(user_update): Json<UserUpdate>,
) -> AppResult<OkResponse> {
    let mut conn = state.db_write().await?;
    let auth = AuthCheck::default().check(&req, &mut conn).await?;

    let user = auth.user();

    // need to check if current user matches user to be updated
    if user.id != param_user_id {
        return Err(bad_request("current user does not match requested user"));
    }

    if let Some(publish_notifications) = &user_update.user.publish_notifications
        && user.publish_notifications != *publish_notifications
    {
        diesel::update(user)
            .set(users::publish_notifications.eq(*publish_notifications))
            .execute(&mut conn)
            .await?;

        if !publish_notifications {
            let email_address = user.verified_email(&conn).await?;

            if let Some(email_address) = email_address {
                let email = EmailMessage::from_template(
                    "unsubscribe_notifications",
                    context! {
                        user_name => user.gh_login,
                        domain => state.emails.domain
                    },
                );

                match email {
                    Ok(email) => {
                        if let Err(error) = state.emails.send(&email_address, email).await {
                            warn!(
                                "Failed to send publish notifications unsubscribe email to {email_address}: {error}"
                            );
                        }
                    }
                    Err(error) => warn!("Failed to render unsubscribe email template: {error}"),
                }
            }
        }
    }

    if let Some(user_email) = &user_update.user.email {
        let user_email = user_email.trim();

        if user_email.is_empty() {
            return Err(bad_request("empty email rejected"));
        }

        user_email
            .parse::<Address>()
            .map_err(|_| bad_request("invalid email address"))?;

        state
            .rate_limiter
            .check_rate_limit(user.id, LimitedAction::EmailUpdate, &mut conn)
            .await?;

        let current_verified = user.verified_email(&conn).await?;

        if let Some(current) = current_verified.as_deref() {
            if current.eq_ignore_ascii_case(user_email) {
                // Same verified address: clear any staged pending change.
                Email::clear_pending_email(user.id, &conn).await?;
            } else {
                // Keep verified inbox; stage replacement until confirm link is used.
                require_email_code(user.id, user_update.email_code.as_deref(), &mut conn).await?;
                let token = Email::stage_pending_email(user.id, user_email, &conn)
                    .await
                    .map_err(|_| server_error("Error in creating token"))?;

                let email = EmailMessage::from_template(
                    "user_confirm",
                    context! {
                        user_name => user.gh_login,
                        domain => state.emails.domain,
                        token => token.expose_secret()
                    },
                );

                match email {
                    Ok(email) => {
                        let _ = state.emails.send(user_email, email).await;
                    }
                    Err(error) => {
                        warn!("Failed to render user confirmation email template: {error}");
                    }
                };
            }
        } else {
            // No verified inbox yet: replace the unverified address in place.
            let new_email = NewEmail::builder()
                .user_id(user.id)
                .email(user_email)
                .build();

            let token = new_email
                .insert_or_update(&conn)
                .await
                .map_err(|_| server_error("Error in creating token"))?;

            // This swallows any errors that occur while attempting to send the email. Some users have
            // an invalid email set in their GitHub profile, and we should let them sign in even though
            // we're trying to silently use their invalid address during signup and can't send them an
            // email. They'll then have to provide a valid email address.
            let email = EmailMessage::from_template(
                "user_confirm",
                context! {
                    user_name => user.gh_login,
                    domain => state.emails.domain,
                    token => token.expose_secret()
                },
            );

            match email {
                Ok(email) => {
                    let _ = state.emails.send(user_email, email).await;
                }
                Err(error) => {
                    warn!("Failed to render user confirmation email template: {error}");
                }
            };
        }
    }

    Ok(OkResponse::new())
}
