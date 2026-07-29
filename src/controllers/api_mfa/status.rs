use super::webauthn_util::complete_passkey_authentication;
use crate::app::AppState;
use crate::auth::AuthCheck;
use crate::models::{ApiMfaGrant, WebauthnCredential};
use crate::schema::users;
use crate::util::errors::{AppResult, bad_request};
use crate::util::no_store;
use axum::Json;
use axum_extra::TypedHeader;
use axum_extra::headers::CacheControl;
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use http::request::Parts;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ApiMfaStatusResponse {
    /// Whether API MFA is currently enforced for token-authenticated actions.
    pub enabled: bool,
    /// Registered passkeys.
    #[schema(inline)]
    pub credentials: Vec<EncodableWebauthnCredential>,
    /// Active grant expiry, if any.
    pub grant_expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct EncodableWebauthnCredential {
    pub id: i64,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

impl From<WebauthnCredential> for EncodableWebauthnCredential {
    fn from(value: WebauthnCredential) -> Self {
        Self {
            id: value.id,
            name: value.name,
            created_at: value.created_at,
            last_used_at: value.last_used_at,
        }
    }
}

/// Get API MFA status for the authenticated user.
#[utoipa::path(
    get,
    path = "/api/v1/me/api_mfa",
    security(("cookie" = [])),
    tag = "users",
    extensions(("x-internal" = json!(true))),
    responses((status = 200, description = "Successful Response", body = inline(ApiMfaStatusResponse))),
)]
pub async fn get_api_mfa_status(
    app: AppState,
    req: Parts,
) -> AppResult<(TypedHeader<CacheControl>, Json<ApiMfaStatusResponse>)> {
    let mut conn = app.db_read_prefer_primary().await?;
    let auth = AuthCheck::only_cookie().check(&req, &mut conn).await?;
    let user = auth.user();

    let credentials = WebauthnCredential::for_user(user.id, &conn).await?;
    let grant = ApiMfaGrant::active_for_user(user.id, &conn).await?;

    Ok((
        no_store(),
        Json(ApiMfaStatusResponse {
            enabled: user.api_mfa_enabled,
            credentials: credentials.into_iter().map(Into::into).collect(),
            grant_expires_at: grant.map(|g| g.expires_at),
        }),
    ))
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct ApiMfaUpdateRequest {
    /// Whether to enable API MFA enforcement.
    pub enabled: bool,
    /// Passkey assertion required when disabling API MFA.
    ///
    /// Obtain options from `POST /api/v1/me/api_mfa/authorize/start` first.
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub credential: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ApiMfaUpdateResponse {
    pub enabled: bool,
}

/// Enable or disable API MFA for the authenticated user.
///
/// Enabling requires at least one registered passkey.
/// Disabling requires a fresh passkey assertion (`credential`) so a stolen session
/// cookie alone cannot turn off enforcement.
#[utoipa::path(
    put,
    path = "/api/v1/me/api_mfa",
    request_body = inline(ApiMfaUpdateRequest),
    security(("cookie" = [])),
    tag = "users",
    extensions(("x-internal" = json!(true))),
    responses((status = 200, description = "Successful Response", body = inline(ApiMfaUpdateResponse))),
)]
pub async fn update_api_mfa_status(
    app: AppState,
    req: Parts,
    Json(body): Json<ApiMfaUpdateRequest>,
) -> AppResult<(TypedHeader<CacheControl>, Json<ApiMfaUpdateResponse>)> {
    let mut conn = app.db_write().await?;
    let auth = AuthCheck::only_cookie().check(&req, &mut conn).await?;
    let user = auth.user();

    if body.enabled {
        let credentials = WebauthnCredential::for_user(user.id, &conn).await?;
        if credentials.is_empty() {
            return Err(bad_request(
                "register at least one passkey before enabling API MFA",
            ));
        }
    } else if user.api_mfa_enabled {
        let Some(credential) = body.credential.as_ref() else {
            return Err(bad_request(
                "passkey verification required to disable API MFA; complete authorize/start first and include the credential assertion",
            ));
        };
        complete_passkey_authentication(user.id, credential, &app.config.webauthn, &mut conn)
            .await?;
        ApiMfaGrant::delete_all_for_user(user.id, &conn).await?;
    }

    diesel::update(users::table.find(user.id))
        .set(users::api_mfa_enabled.eq(body.enabled))
        .execute(&mut conn)
        .await?;

    Ok((
        no_store(),
        Json(ApiMfaUpdateResponse {
            enabled: body.enabled,
        }),
    ))
}
