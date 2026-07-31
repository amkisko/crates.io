//! Best-effort notification emails for API MFA settings changes.

use crate::app::AppState;
use crate::email::EmailMessage;
use crate::models::User;
use diesel_async::AsyncPgConnection;
use minijinja::context;
use tracing::error;

/// Sends a settings-change notice when the user has a verified email.
///
/// Failures are logged only; the primary API action already succeeded.
pub async fn notify_api_mfa_settings_changed(
    app: &AppState,
    user: &User,
    conn: &mut AsyncPgConnection,
    action: &'static str,
    detail: Option<&str>,
) {
    let Ok(Some(recipient)) = user.verified_email(conn).await else {
        return;
    };

    let action_label = match action {
        "enabled" => "enabled",
        "disabled" => "disabled",
        "passkey_registered" => "passkey registered",
        "passkey_deleted" => "passkey deleted",
        other => other,
    };

    let email = match EmailMessage::from_template(
        "api_mfa_settings_changed",
        context! {
            user_name => &user.gh_login,
            domain => app.emails.domain,
            action => action,
            action_label => action_label,
            detail => detail.unwrap_or(""),
        },
    ) {
        Ok(email) => email,
        Err(err) => {
            error!(
                api_mfa.action = action,
                error = %err,
                "Failed to render API MFA settings email ({action}): {err}",
            );
            return;
        }
    };

    if let Err(err) = app.emails.send(&recipient, email).await {
        error!(
            user.id = user.id,
            api_mfa.action = action,
            error = %err,
            "Failed to send API MFA settings email ({action}) to user `{}`: {err}",
            user.id,
        );
    }
}
