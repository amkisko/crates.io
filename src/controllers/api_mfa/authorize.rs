use super::webauthn_util::{
    build_webauthn, complete_passkey_authentication, passkeys_from_credentials,
};
use crate::app::AppState;
use crate::auth::AuthCheck;
use crate::models::{
    KIND_AUTHENTICATION, NewApiMfaGrant, WebauthnCeremonyState, WebauthnCredential,
};
use crate::util::errors::{AppResult, bad_request, server_error};
use crate::util::no_store;
use axum::Json;
use axum_extra::TypedHeader;
use axum_extra::headers::CacheControl;
use chrono::{DateTime, Utc};
use http::request::Parts;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct StartAuthorizeResponse {
    /// `PublicKeyCredentialRequestOptions` for `navigator.credentials.get()`.
    pub public_key: serde_json::Value,
}

/// Start passkey authentication to create a short-lived API MFA grant.
///
/// Also used as the passkey step-up ceremony before disabling API MFA or registering
/// an additional passkey while MFA is enabled (see `PUT /api/v1/me/mfa` and
/// `POST /api/v1/me/mfa/passkeys/start`). Disabling may use email OTP instead.
#[utoipa::path(
    post,
    path = "/api/v1/me/mfa/authorize/start",
    security(("cookie" = [])),
    tag = "users",
    extensions(("x-internal" = json!(true))),
    responses((status = 200, description = "Successful Response", body = inline(StartAuthorizeResponse))),
)]
pub async fn start_api_mfa_authorize(
    app: AppState,
    req: Parts,
) -> AppResult<(TypedHeader<CacheControl>, Json<StartAuthorizeResponse>)> {
    let mut conn = app.db_write().await?;
    let auth = AuthCheck::only_cookie().check(&req, &mut conn).await?;
    let user = auth.user();

    let credentials = WebauthnCredential::for_user(user.id, &conn).await?;
    if credentials.is_empty() {
        return Err(bad_request(
            "register a passkey before authorizing API actions",
        ));
    }

    let webauthn = build_webauthn(&app.config.webauthn)?;
    let passkeys = passkeys_from_credentials(&credentials)?;
    let (rcr, auth_state) = webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|err| bad_request(format!("failed to start passkey authentication: {err}")))?;

    let state_json = serde_json::to_value(&auth_state)
        .map_err(|err| server_error(format!("failed to serialize auth state: {err}")))?;
    WebauthnCeremonyState::store(user.id, KIND_AUTHENTICATION, state_json, &conn).await?;

    let public_key = serde_json::to_value(rcr.public_key)
        .map_err(|err| server_error(format!("failed to serialize request options: {err}")))?;

    Ok((no_store(), Json(StartAuthorizeResponse { public_key })))
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct FinishAuthorizeRequest {
    /// Credential assertion response from the browser.
    pub credential: serde_json::Value,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct FinishAuthorizeResponse {
    /// When the newly issued grant expires.
    pub grant_expires_at: DateTime<Utc>,
}

/// Finish passkey authentication and issue a 15-minute wildcard API MFA grant.
#[utoipa::path(
    post,
    path = "/api/v1/me/mfa/authorize/finish",
    request_body = inline(FinishAuthorizeRequest),
    security(("cookie" = [])),
    tag = "users",
    extensions(("x-internal" = json!(true))),
    responses((status = 200, description = "Successful Response", body = inline(FinishAuthorizeResponse))),
)]
pub async fn finish_api_mfa_authorize(
    app: AppState,
    req: Parts,
    Json(body): Json<FinishAuthorizeRequest>,
) -> AppResult<(TypedHeader<CacheControl>, Json<FinishAuthorizeResponse>)> {
    let mut conn = app.db_write().await?;
    let auth = AuthCheck::only_cookie().check(&req, &mut conn).await?;
    let user = auth.user();

    complete_passkey_authentication(user.id, &body.credential, &app.config.webauthn, &mut conn)
        .await?;

    // Wildcard grant for stock cargo after an explicit settings-page authorize.
    let grant = NewApiMfaGrant::for_user(user.id).insert(&conn).await?;

    use crate::middleware::real_ip::RealIp;
    use crate::models::{NewUserSecurityEvent, SecurityEventType};
    NewUserSecurityEvent::new(
        user.id,
        SecurityEventType::ApiMfaAuthorized,
        None,
        req.extensions.get::<RealIp>().map(|ip| ip.to_string()),
        serde_json::json!({}),
    )
    .record(&mut conn)
    .await;

    Ok((
        no_store(),
        Json(FinishAuthorizeResponse {
            grant_expires_at: grant.expires_at,
        }),
    ))
}
