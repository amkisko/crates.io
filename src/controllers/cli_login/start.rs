use super::{
    RECOMMENDED_POLL_INTERVAL_SECS, check_create_rate_limit, ensure_cli_login_enabled,
    public_cli_login_urls,
};
use crate::app::AppState;
use crate::middleware::real_ip::RealIp;
use crate::models::{MAX_PENDING_CLI_LOGIN_PER_IP, NewCliLoginSession};
use crate::util::errors::{AppResult, bad_request};
use crate::util::no_store;
use axum::Json;
use axum_extra::TypedHeader;
use axum_extra::headers::CacheControl;
use chrono::{DateTime, Utc};
use http::request::Parts;
use serde::{Deserialize, Serialize};

/// Request to begin a browser-assisted CLI login ceremony.
#[derive(Debug, Default, Deserialize, utoipa::ToSchema)]
pub struct StartCliLoginRequest {
    /// Optional localhost port the browser may ping (token-free) after approve.
    pub localhost_port: Option<i32>,
}

/// Browser and polling details returned for a new CLI login ceremony.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct StartCliLoginResponse {
    pub login_id: String,
    pub login_url: String,
    pub poll_url: String,
    /// Short code printed by the CLI; must be typed on the approve page (not returned by meta).
    pub confirmation_code: String,
    /// Opaque secret returned only to the CLI; send as `Crates-Cli-Login-Secret` on poll.
    ///
    /// Not included in browser URLs or meta. Possession of `login_id` alone cannot redeem.
    pub poll_secret: String,
    pub expires_at: DateTime<Utc>,
    pub recommended_poll_interval_secs: u64,
}

/// Start a browser-assisted cargo login ceremony (unauthenticated).
#[utoipa::path(
    post,
    path = "/api/v1/cli_login",
    request_body = inline(StartCliLoginRequest),
    tag = "api_tokens",
    responses((status = 200, description = "Successful Response", body = inline(StartCliLoginResponse))),
)]
pub async fn start_cli_login(
    app: AppState,
    parts: Parts,
    Json(body): Json<StartCliLoginRequest>,
) -> AppResult<(TypedHeader<CacheControl>, Json<StartCliLoginResponse>)> {
    ensure_cli_login_enabled(&app)?;

    if let Some(port) = body.localhost_port
        && !(1024..=65535).contains(&port)
    {
        return Err(bad_request("localhost_port must be between 1024 and 65535"));
    }

    let client_ip = parts
        .extensions
        .get::<RealIp>()
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "unknown".into());

    let mut conn = app.db_write().await?;
    check_create_rate_limit(&app.rate_limiter, &client_ip, &mut conn).await?;

    let pending = crate::models::CliLoginSession::count_pending_for_ip(&client_ip, &conn).await?;
    if pending >= MAX_PENDING_CLI_LOGIN_PER_IP {
        return Err(bad_request(format!(
            "too many pending CLI login sessions (max {MAX_PENDING_CLI_LOGIN_PER_IP}); \
             complete or wait for existing ones to expire"
        )));
    }

    let (session, confirmation_code, poll_secret) =
        NewCliLoginSession::pending_with_secrets(body.localhost_port, Some(client_ip))
            .insert(&conn)
            .await?;

    let (login_url, poll_url) = public_cli_login_urls(&app.config.webauthn, &session.id);

    Ok((
        no_store(),
        Json(StartCliLoginResponse {
            login_id: session.id,
            login_url,
            poll_url,
            confirmation_code,
            poll_secret,
            expires_at: session.expires_at,
            recommended_poll_interval_secs: RECOMMENDED_POLL_INTERVAL_SECS,
        }),
    ))
}
