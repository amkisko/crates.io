use super::{ensure_cli_login_enabled, seal_redeem_token};
use crate::app::AppState;
use crate::auth::AuthCheck;
use crate::controllers::api_mfa::webauthn_util::complete_passkey_authentication;
use crate::controllers::token::mint_api_token_for_user;
use crate::models::{ApiToken, CliLoginSession, STATUS_PENDING, STATUS_READY};
use crate::schema::api_tokens;
use crate::util::errors::{AppResult, bad_request, not_found, server_error};
use crate::util::no_store;
use axum::Json;
use axum::extract::Path;
use axum_extra::TypedHeader;
use axum_extra::headers::CacheControl;
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use http::request::Parts;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct CliLoginMetaResponse {
    pub login_id: String,
    pub status: String,
    pub expires_at: DateTime<Utc>,
    pub localhost_port: Option<i32>,
    /// Client IP that started the ceremony (shown so users can spot phishing).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<String>,
    /// When true, approve must include a passkey assertion from `authorize/start`.
    pub api_mfa_required: bool,
}

/// Metadata for the browser approve page (cookie session required).
#[utoipa::path(
    get,
    path = "/api/v1/cli_login/{id}/meta",
    params(("id" = String, Path, description = "CLI login session id")),
    security(("cookie" = [])),
    tag = "api_tokens",
    extensions(("x-internal" = json!(true))),
    responses((status = 200, description = "Successful Response", body = inline(CliLoginMetaResponse))),
)]
pub async fn get_cli_login_meta(
    app: AppState,
    Path(id): Path<String>,
    req: Parts,
) -> AppResult<(TypedHeader<CacheControl>, Json<CliLoginMetaResponse>)> {
    ensure_cli_login_enabled(&app)?;

    let mut conn = app.db_write().await?;
    let auth = AuthCheck::only_cookie().check(&req, &mut conn).await?;
    let user = auth.user();

    let Some(session) = CliLoginSession::find_active(&id, &conn).await? else {
        return Err(not_found());
    };

    Ok((
        no_store(),
        Json(CliLoginMetaResponse {
            login_id: session.id,
            status: session.status,
            expires_at: session.expires_at,
            localhost_port: session.localhost_port,
            client_ip: session.client_ip,
            api_mfa_required: user.api_mfa_enabled,
        }),
    ))
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct ApproveCliLoginRequest {
    pub name: String,
    pub crate_scopes: Option<Vec<String>>,
    pub endpoint_scopes: Option<Vec<String>>,
    pub expired_at: Option<DateTime<Utc>>,
    /// Required when API MFA is enabled: assertion from `authorize/start`.
    pub credential: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ApproveCliLoginResponse {
    pub status: String,
    pub token_name: String,
    pub api_token_id: i32,
    /// Optional port the browser may ping (token-free) so a waiting CLI can wake.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub localhost_port: Option<i32>,
}

/// Approve a CLI login session: choose scopes and mint a token (cookie only).
///
/// The plaintext token is **not** returned here; the CLI retrieves it via poll.
#[utoipa::path(
    post,
    path = "/api/v1/cli_login/{id}/approve",
    params(("id" = String, Path, description = "CLI login session id")),
    request_body = inline(ApproveCliLoginRequest),
    security(("cookie" = [])),
    tag = "api_tokens",
    extensions(("x-internal" = json!(true))),
    responses((status = 200, description = "Successful Response", body = inline(ApproveCliLoginResponse))),
)]
pub async fn approve_cli_login(
    app: AppState,
    Path(id): Path<String>,
    req: Parts,
    Json(body): Json<ApproveCliLoginRequest>,
) -> AppResult<(TypedHeader<CacheControl>, Json<ApproveCliLoginResponse>)> {
    ensure_cli_login_enabled(&app)?;

    let name = body.name.trim();
    if name.is_empty() {
        return Err(bad_request("name must have a value"));
    }

    let mut conn = app.db_write().await?;
    let auth = AuthCheck::only_cookie().check(&req, &mut conn).await?;
    let user = auth.user();

    if let Some(disable_message) = &app.config.disable_token_creation {
        return Err(crate::util::errors::custom(
            http::StatusCode::SERVICE_UNAVAILABLE,
            disable_message.clone(),
        ));
    }

    let Some(session) = CliLoginSession::find_active(&id, &conn).await? else {
        return Err(not_found());
    };
    if session.status != STATUS_PENDING {
        return Err(bad_request("this CLI login session is no longer pending"));
    }

    if user.api_mfa_enabled {
        let Some(credential) = body.credential.as_ref() else {
            return Err(bad_request(
                "passkey verification required to approve CLI login while API MFA is enabled; \
                 complete authorize/start first and include the credential assertion",
            ));
        };
        complete_passkey_authentication(user.id, credential, &app.config.webauthn, &mut conn)
            .await?;
    }

    // Claim before mint so a losing concurrent approver never creates an orphan token.
    if !session.claim(user.id, &conn).await? {
        return Err(bad_request(
            "this CLI login session was already claimed by another approval",
        ));
    }

    let minted = match mint_api_token_for_user(
        &app,
        user,
        name,
        body.crate_scopes,
        body.endpoint_scopes,
        body.expired_at,
        &mut conn,
    )
    .await
    {
        Ok(minted) => minted,
        Err(err) => {
            // Best-effort unlock so the user can correct scopes and retry.
            let _ = session.release_claim(user.id, &conn).await;
            return Err(err);
        }
    };

    let sealed = match seal_redeem_token(&app.config.token_encryption, &minted.plaintext) {
        Ok(sealed) => sealed,
        Err(err) => {
            let _ = session.release_claim(user.id, &conn).await;
            return Err(err);
        }
    };
    let marked = session
        .mark_ready(user.id, minted.token.id, &sealed, &conn)
        .await?;
    if !marked {
        // Mint succeeded but the session was not ready; revoke so the token cannot linger.
        let _ = diesel::update(ApiToken::belonging_to(user).find(minted.token.id))
            .set(api_tokens::revoked.eq(true))
            .execute(&mut conn)
            .await;
        let _ = session.release_claim(user.id, &conn).await;
        return Err(server_error(
            "failed to attach minted token to CLI login session",
        ));
    }

    Ok((
        no_store(),
        Json(ApproveCliLoginResponse {
            status: STATUS_READY.into(),
            token_name: name.to_string(),
            api_token_id: minted.token.id,
            localhost_port: session.localhost_port,
        }),
    ))
}
