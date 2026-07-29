use super::{ensure_cli_login_enabled, open_redeem_token, touch_poll_or_rate_limit};
use crate::app::AppState;
use crate::models::{
    CliLoginSession, STATUS_CONSUMED, STATUS_EXPIRED, STATUS_PENDING, STATUS_READY,
    TouchPollOutcome,
};
use crate::util::errors::{AppResult, bad_request, not_found};
use crate::util::no_store;
use axum::Json;
use axum::extract::Path;
use axum_extra::TypedHeader;
use axum_extra::headers::CacheControl;
use chrono::Utc;
use serde::Serialize;

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct PollCliLoginResponse {
    pub status: String,
    /// Present exactly once when status transitions through `ready` on this poll.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

/// Poll a CLI login session until a token is available (unauthenticated).
///
/// Returns the plaintext token at most once (`ready` → `consumed`).
#[utoipa::path(
    get,
    path = "/api/v1/cli_login/{id}",
    params(("id" = String, Path, description = "CLI login session id")),
    tag = "api_tokens",
    responses((status = 200, description = "Successful Response", body = inline(PollCliLoginResponse))),
)]
pub async fn poll_cli_login(
    app: AppState,
    Path(id): Path<String>,
) -> AppResult<(TypedHeader<CacheControl>, Json<PollCliLoginResponse>)> {
    ensure_cli_login_enabled(&app)?;

    let mut conn = app.db_write().await?;
    let outcome = touch_poll_or_rate_limit(&id, &mut conn).await?;

    let TouchPollOutcome::Proceed { status, expires_at } = outcome else {
        return Err(not_found());
    };

    if expires_at <= Utc::now() {
        return Ok((
            no_store(),
            Json(PollCliLoginResponse {
                status: STATUS_EXPIRED.into(),
                token: None,
            }),
        ));
    }

    match status.as_str() {
        STATUS_PENDING => Ok((
            no_store(),
            Json(PollCliLoginResponse {
                status: STATUS_PENDING.into(),
                token: None,
            }),
        )),
        STATUS_READY => {
            let Some(sealed) = CliLoginSession::consume_token(&id, &mut conn).await? else {
                return Ok((
                    no_store(),
                    Json(PollCliLoginResponse {
                        status: STATUS_CONSUMED.into(),
                        token: None,
                    }),
                ));
            };

            let token = open_redeem_token(&app.config.token_encryption, &sealed)?;

            Ok((
                no_store(),
                Json(PollCliLoginResponse {
                    status: STATUS_READY.into(),
                    token: Some(token),
                }),
            ))
        }
        STATUS_CONSUMED => Ok((
            no_store(),
            Json(PollCliLoginResponse {
                status: STATUS_CONSUMED.into(),
                token: None,
            }),
        )),
        other => Err(bad_request(format!("unexpected CLI login status: {other}"))),
    }
}
