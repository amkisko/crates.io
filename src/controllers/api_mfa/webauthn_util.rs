use crate::config::WebauthnConfig;
use crate::models::{KIND_AUTHENTICATION, WebauthnCeremonyState, WebauthnCredential};
use crate::util::errors::{AppResult, bad_request, server_error};
use diesel_async::AsyncPgConnection;
use webauthn_rs::prelude::*;

/// Builds a [`Webauthn`] instance from server config.
pub fn build_webauthn(config: &WebauthnConfig) -> AppResult<Webauthn> {
    WebauthnBuilder::new(&config.rp_id, &config.rp_origin)
        .map_err(|err| server_error(format!("invalid WebAuthn configuration: {err}")))?
        .rp_name(&config.rp_name)
        .build()
        .map_err(|err| server_error(format!("failed to build WebAuthn: {err}")))
}

/// Completes a passkey authentication ceremony started via authorize/start (or equivalent).
///
/// Takes server-side [`KIND_AUTHENTICATION`] state, verifies the assertion, and records
/// `last_used_at` plus any counter / backup-flag updates on the matching credential.
pub async fn complete_passkey_authentication(
    user_id: i32,
    credential_body: &serde_json::Value,
    config: &WebauthnConfig,
    conn: &mut AsyncPgConnection,
) -> AppResult<AuthenticationResult> {
    let Some(state_json) = WebauthnCeremonyState::take(user_id, KIND_AUTHENTICATION, conn).await?
    else {
        return Err(bad_request("no passkey authentication in progress"));
    };
    let auth_state: PasskeyAuthentication = serde_json::from_value(state_json)
        .map_err(|err| bad_request(format!("invalid authentication state: {err}")))?;

    let webauthn = build_webauthn(config)?;
    let auth_response = parse_auth_response(credential_body)?;
    let auth_result = webauthn
        .finish_passkey_authentication(&auth_response, &auth_state)
        .map_err(|err| bad_request(format!("passkey authentication failed: {err}")))?;

    record_passkey_authentication(user_id, &auth_result, conn).await?;

    Ok(auth_result)
}

/// Touches `last_used_at` and persists `Passkey` counter / backup updates when needed.
pub async fn record_passkey_authentication(
    user_id: i32,
    auth_result: &AuthenticationResult,
    conn: &mut AsyncPgConnection,
) -> AppResult<()> {
    let credentials = WebauthnCredential::for_user(user_id, conn).await?;
    for credential in &credentials {
        if credential.credential_id.as_slice() != auth_result.cred_id().as_slice() {
            continue;
        }

        credential.touch(conn).await?;

        if auth_result.needs_update() {
            let mut passkey: Passkey = serde_json::from_value(credential.passkey_json.clone())
                .map_err(|err| {
                    server_error(format!(
                        "corrupt passkey credential {}: {err}",
                        credential.id
                    ))
                })?;
            if passkey.update_credential(auth_result) == Some(true) {
                let passkey_json = serde_json::to_value(&passkey).map_err(|err| {
                    server_error(format!(
                        "failed to serialize updated passkey {}: {err}",
                        credential.id
                    ))
                })?;
                credential.update_passkey_json(passkey_json, conn).await?;
            }
        }

        return Ok(());
    }

    Ok(())
}

/// Deserializes stored passkeys for a user.
pub fn passkeys_from_credentials(credentials: &[WebauthnCredential]) -> AppResult<Vec<Passkey>> {
    credentials
        .iter()
        .map(|cred| {
            serde_json::from_value(cred.passkey_json.clone()).map_err(|err| {
                server_error(format!("corrupt passkey credential {}: {err}", cred.id))
            })
        })
        .collect()
}

/// Stable UUID derived from the crates.io user id for `WebAuthn` user handles.
pub fn user_handle(user_id: i32) -> Uuid {
    // Deterministic UUID so re-registrations keep a stable user handle.
    Uuid::new_v5(
        &Uuid::NAMESPACE_OID,
        format!("crates.io:user:{user_id}").as_bytes(),
    )
}

/// Parses a creation response from the browser.
pub fn parse_register_response(body: &serde_json::Value) -> AppResult<RegisterPublicKeyCredential> {
    serde_json::from_value(body.clone())
        .map_err(|err| bad_request(format!("invalid WebAuthn registration response: {err}")))
}

/// Parses an authentication response from the browser.
pub fn parse_auth_response(body: &serde_json::Value) -> AppResult<PublicKeyCredential> {
    serde_json::from_value(body.clone())
        .map_err(|err| bad_request(format!("invalid WebAuthn authentication response: {err}")))
}
