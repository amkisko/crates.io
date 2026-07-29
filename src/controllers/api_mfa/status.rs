use super::email_codes::require_email_code;
use super::notify::notify_api_mfa_settings_changed;
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
    /// Whether the user has opted into API MFA.
    pub enabled: bool,
    /// Whether the server is currently applying MFA on dangerous mutates
    /// (`API_MFA_ENFORCEMENT_ENABLED`). Bootstrap / plant-prevention gates stay on
    /// even when this is false.
    pub enforcement_active: bool,
    /// Registered passkeys.
    #[schema(inline)]
    pub credentials: Vec<EncodableWebauthnCredential>,
    /// Active grant expiry, if any.
    pub grant_expires_at: Option<DateTime<Utc>>,
    /// Whether the user has a verified email (required to send email OTPs).
    pub has_verified_email: bool,
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
    path = "/api/v1/me/mfa",
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
    let has_verified_email = user.verified_email(&conn).await?.is_some();

    Ok((
        no_store(),
        Json(ApiMfaStatusResponse {
            enabled: user.api_mfa_enabled,
            enforcement_active: app.config.api_mfa_enforcement_enabled,
            credentials: credentials.into_iter().map(Into::into).collect(),
            grant_expires_at: grant.map(|g| g.expires_at),
            has_verified_email,
        }),
    ))
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct ApiMfaUpdateRequest {
    /// Whether to enable API MFA enforcement.
    pub enabled: bool,
    /// Passkey assertion: required when disabling if no `email_code` is provided.
    ///
    /// Obtain options from `POST /api/v1/me/mfa/authorize/start` first.
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub credential: Option<serde_json::Value>,
    /// Email OTP from `POST /api/v1/me/mfa/email_codes`.
    ///
    /// Required when enabling. When disabling, accepted as an alternative to `credential`
    /// (e.g. recovery when all passkeys were removed).
    #[serde(default)]
    pub email_code: Option<String>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ApiMfaUpdateResponse {
    pub enabled: bool,
}

/// Enable or disable API MFA for the authenticated user.
///
/// Enabling requires at least one registered passkey and a fresh email OTP so a
/// stolen session cookie alone cannot turn on enforcement after planting a passkey.
///
/// Disabling requires a fresh passkey assertion **or** email OTP. Enforcement may
/// remain enabled with zero passkeys (dangerous actions stay blocked until a
/// passkey is registered via email OTP recovery).
#[utoipa::path(
    put,
    path = "/api/v1/me/mfa",
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
        // Email OTP always required so session hijack + planted passkey cannot turn MFA on
        // even when `API_MFA_ENFORCEMENT_ENABLED=false` (dangerous-mutate bypass only).
        require_email_code(user.id, body.email_code.as_deref(), &mut conn).await?;
    } else if user.api_mfa_enabled {
        let has_passkey = body.credential.is_some();
        let has_email_code = body
            .email_code
            .as_deref()
            .is_some_and(|s| !s.trim().is_empty());

        match (has_passkey, has_email_code) {
            (true, _) => {
                complete_passkey_authentication(
                    user.id,
                    body.credential.as_ref().unwrap(),
                    &app.config.webauthn,
                    &mut conn,
                )
                .await?;
            }
            (false, true) => {
                require_email_code(user.id, body.email_code.as_deref(), &mut conn).await?;
            }
            (false, false) => {
                return Err(bad_request(
                    "passkey verification or email code required to disable API MFA; \
                     complete authorize/start and include the credential assertion, \
                     or request an email code with POST /api/v1/me/mfa/email_codes",
                ));
            }
        }
        ApiMfaGrant::delete_all_for_user(user.id, &conn).await?;
    }

    let previously_enabled = user.api_mfa_enabled;
    diesel::update(users::table.find(user.id))
        .set(users::api_mfa_enabled.eq(body.enabled))
        .execute(&mut conn)
        .await?;

    if body.enabled != previously_enabled {
        use crate::middleware::real_ip::RealIp;
        use crate::models::{NewUserSecurityEvent, SecurityEventType};

        let event = if body.enabled {
            SecurityEventType::ApiMfaEnabled
        } else {
            SecurityEventType::ApiMfaDisabled
        };
        NewUserSecurityEvent::new(
            user.id,
            event,
            None,
            req.extensions.get::<RealIp>().map(|ip| ip.to_string()),
            serde_json::json!({}),
        )
        .record(&mut conn)
        .await;

        notify_api_mfa_settings_changed(
            &app,
            user,
            &mut conn,
            if body.enabled { "enabled" } else { "disabled" },
            None,
        )
        .await;
    }

    Ok((
        no_store(),
        Json(ApiMfaUpdateResponse {
            enabled: body.enabled,
        }),
    ))
}
