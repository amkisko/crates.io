use super::email_codes::require_email_code;
use super::notify::notify_api_mfa_settings_changed;
use super::status::EncodableWebauthnCredential;
use super::webauthn_util::{
    build_webauthn, complete_passkey_authentication, parse_register_response,
    passkeys_from_credentials, user_handle,
};
use crate::app::AppState;
use crate::auth::AuthCheck;
use crate::controllers::helpers::OkResponse;
use crate::middleware::real_ip::RealIp;
use crate::models::{
    KIND_REGISTRATION, MAX_PASSKEYS_PER_USER, NewUserSecurityEvent, NewWebauthnCredential,
    SecurityEventType, WebauthnCeremonyState, WebauthnCredential,
};
use crate::util::errors::{AppResult, bad_request, not_found, server_error};
use crate::util::no_store;
use axum::Json;
use axum::extract::Path;
use axum_extra::TypedHeader;
use axum_extra::headers::CacheControl;
use http::request::Parts;
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::*;

#[derive(Debug, Default, Deserialize, utoipa::ToSchema)]
pub struct StartRegistrationRequest {
    /// Required when API MFA is enabled and at least one passkey exists: assertion from
    /// `authorize/start` so a stolen session cookie alone cannot register another passkey.
    #[serde(default)]
    pub credential: Option<serde_json::Value>,
    /// Email OTP from `POST /api/v1/me/mfa/email_codes`.
    ///
    /// Required when the user has no passkeys (first enroll or recovery) or when API MFA
    /// is off (prevents a hijacked session from planting a passkey before enable).
    #[serde(default)]
    pub email_code: Option<String>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct StartRegistrationResponse {
    /// `PublicKeyCredentialCreationOptions` for `navigator.credentials.create()`.
    pub public_key: serde_json::Value,
}

/// Start passkey registration for the authenticated user.
///
/// Step-up:
/// - API MFA on with existing passkeys: fresh passkey assertion (`credential`)
/// - otherwise (first enroll, recovery with zero passkeys, or MFA off): email OTP
#[utoipa::path(
    post,
    path = "/api/v1/me/mfa/passkeys/start",
    request_body = inline(StartRegistrationRequest),
    security(("cookie" = [])),
    tag = "users",
    extensions(("x-internal" = json!(true))),
    responses((status = 200, description = "Successful Response", body = inline(StartRegistrationResponse))),
)]
pub async fn start_webauthn_registration(
    app: AppState,
    req: Parts,
    Json(body): Json<StartRegistrationRequest>,
) -> AppResult<(TypedHeader<CacheControl>, Json<StartRegistrationResponse>)> {
    let mut conn = app.db_write().await?;
    let auth = AuthCheck::only_cookie().check(&req, &mut conn).await?;
    let user = auth.user();

    let existing = WebauthnCredential::for_user(user.id, &conn).await?;
    if existing.len() as i64 >= MAX_PASSKEYS_PER_USER {
        return Err(bad_request(format!(
            "maximum passkeys per user is: {MAX_PASSKEYS_PER_USER}"
        )));
    }

    // With MFA on and at least one passkey, require that passkey so a hijacked
    // session cannot mint a second factor the attacker controls. With zero
    // passkeys (or MFA off), require email OTP for first enroll / recovery.
    if app.config.api_mfa_enforcement_enabled {
        if user.api_mfa_enabled && !existing.is_empty() {
            let Some(credential) = body.credential.as_ref() else {
                return Err(bad_request(
                    "passkey verification required to register another passkey while API MFA is enabled; \
                     complete authorize/start first and include the credential assertion",
                ));
            };
            complete_passkey_authentication(user.id, credential, &app.config.webauthn, &mut conn)
                .await?;
        } else {
            require_email_code(user.id, body.email_code.as_deref(), &mut conn).await?;
        }
    }

    let webauthn = build_webauthn(&app.config.webauthn)?;
    let exclude = passkeys_from_credentials(&existing)?;
    let exclude_credentials = if exclude.is_empty() {
        None
    } else {
        Some(exclude.iter().map(|pk| pk.cred_id().clone()).collect())
    };

    let (ccr, reg_state) = webauthn
        .start_passkey_registration(
            user_handle(user.id),
            &user.gh_login,
            user.name.as_deref().unwrap_or(&user.gh_login),
            exclude_credentials,
        )
        .map_err(|err| bad_request(format!("failed to start passkey registration: {err}")))?;

    let state_json = serde_json::to_value(&reg_state)
        .map_err(|err| server_error(format!("failed to serialize registration state: {err}")))?;
    WebauthnCeremonyState::store(user.id, KIND_REGISTRATION, state_json, &conn).await?;

    let public_key = serde_json::to_value(ccr.public_key)
        .map_err(|err| server_error(format!("failed to serialize creation options: {err}")))?;

    Ok((no_store(), Json(StartRegistrationResponse { public_key })))
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct FinishRegistrationRequest {
    /// Label for the new passkey.
    pub name: String,
    /// Credential creation response from the browser.
    pub credential: serde_json::Value,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct FinishRegistrationResponse {
    #[schema(inline)]
    pub credential: EncodableWebauthnCredential,
}

/// Finish passkey registration and store the credential.
#[utoipa::path(
    post,
    path = "/api/v1/me/mfa/passkeys/finish",
    request_body = inline(FinishRegistrationRequest),
    security(("cookie" = [])),
    tag = "users",
    extensions(("x-internal" = json!(true))),
    responses((status = 200, description = "Successful Response", body = inline(FinishRegistrationResponse))),
)]
pub async fn finish_webauthn_registration(
    app: AppState,
    req: Parts,
    Json(body): Json<FinishRegistrationRequest>,
) -> AppResult<(TypedHeader<CacheControl>, Json<FinishRegistrationResponse>)> {
    let name = body.name.trim();
    if name.is_empty() || name.len() > 64 {
        return Err(bad_request(
            "passkey name must be between 1 and 64 characters",
        ));
    }

    let mut conn = app.db_write().await?;
    let auth = AuthCheck::only_cookie().check(&req, &mut conn).await?;
    let user = auth.user();

    let existing = WebauthnCredential::for_user(user.id, &conn).await?;
    if existing.len() as i64 >= MAX_PASSKEYS_PER_USER {
        return Err(bad_request(format!(
            "maximum passkeys per user is: {MAX_PASSKEYS_PER_USER}"
        )));
    }

    let Some(state_json) = WebauthnCeremonyState::take(user.id, KIND_REGISTRATION, &conn).await?
    else {
        return Err(bad_request("no passkey registration in progress"));
    };
    let reg_state: PasskeyRegistration = serde_json::from_value(state_json)
        .map_err(|err| bad_request(format!("invalid registration state: {err}")))?;

    let webauthn = build_webauthn(&app.config.webauthn)?;
    let register_response = parse_register_response(&body.credential)?;
    let passkey = webauthn
        .finish_passkey_registration(&register_response, &reg_state)
        .map_err(|err| bad_request(format!("passkey registration failed: {err}")))?;

    let passkey_json = serde_json::to_value(&passkey)
        .map_err(|err| server_error(format!("failed to serialize passkey: {err}")))?;
    let credential_id = passkey.cred_id().to_vec();

    let credential = NewWebauthnCredential {
        user_id: user.id,
        credential_id: &credential_id,
        passkey_json,
        name,
    }
    .insert(&conn)
    .await
    .map_err(|err| {
        if err
            .to_string()
            .contains("webauthn_credentials_credential_id")
        {
            bad_request("this passkey is already registered")
        } else {
            server_error(format!("failed to store passkey: {err}"))
        }
    })?;

    NewUserSecurityEvent::new(
        user.id,
        SecurityEventType::PasskeyRegistered,
        None,
        req.extensions.get::<RealIp>().map(|ip| ip.to_string()),
        serde_json::json!({ "passkey_name": credential.name }),
    )
    .record(&mut conn)
    .await;

    notify_api_mfa_settings_changed(
        &app,
        user,
        &mut conn,
        "passkey_registered",
        Some(&credential.name),
    )
    .await;

    Ok((
        no_store(),
        Json(FinishRegistrationResponse {
            credential: credential.into(),
        }),
    ))
}

#[derive(Debug, Default, Deserialize, utoipa::ToSchema)]
pub struct DeleteCredentialRequest {
    /// Passkey assertion from `authorize/start` (preferred when a passkey remains).
    #[serde(default)]
    pub credential: Option<serde_json::Value>,
    /// Email OTP alternative when API MFA is enabled (e.g. deleting the last passkey).
    #[serde(default)]
    pub email_code: Option<String>,
}

/// Delete a registered passkey.
///
/// When API MFA is enabled, requires a passkey assertion or email OTP so a stolen
/// session cookie alone cannot strip backup keys. The last passkey may be deleted
/// while enforcement stays on; dangerous actions remain blocked until a passkey is
/// registered again (email OTP recovery) or MFA is disabled.
#[utoipa::path(
    delete,
    path = "/api/v1/me/mfa/passkeys/{id}",
    params(("id" = i64, Path, description = "Credential ID")),
    request_body = inline(DeleteCredentialRequest),
    security(("cookie" = [])),
    tag = "users",
    extensions(("x-internal" = json!(true))),
    responses((status = 200, description = "Successful Response", body = inline(OkResponse))),
)]
pub async fn delete_webauthn_credential(
    app: AppState,
    Path(id): Path<i64>,
    req: Parts,
    Json(body): Json<DeleteCredentialRequest>,
) -> AppResult<OkResponse> {
    let mut conn = app.db_write().await?;
    let auth = AuthCheck::only_cookie().check(&req, &mut conn).await?;
    let user = auth.user();

    let Some(target) = WebauthnCredential::find_for_user(id, user.id, &conn).await? else {
        return Err(not_found());
    };

    if app.config.api_mfa_enforcement_enabled && user.api_mfa_enabled {
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
                    "passkey verification or email code required to delete a passkey while API MFA is enabled; \
                     complete authorize/start and include the credential assertion, \
                     or request an email code with POST /api/v1/me/mfa/email_codes",
                ));
            }
        }
    }

    let deleted = WebauthnCredential::delete_for_user(id, user.id, &conn).await?;
    if deleted == 0 {
        return Err(not_found());
    }

    NewUserSecurityEvent::new(
        user.id,
        SecurityEventType::PasskeyDeleted,
        None,
        req.extensions.get::<RealIp>().map(|ip| ip.to_string()),
        serde_json::json!({ "passkey_name": target.name }),
    )
    .record(&mut conn)
    .await;

    notify_api_mfa_settings_changed(&app, user, &mut conn, "passkey_deleted", Some(&target.name))
        .await;

    Ok(OkResponse::new())
}
