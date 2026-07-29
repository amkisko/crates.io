//! `SoftPasskey` coverage for MFA-gated CLI login approve.

use crate::util::{RequestHelper, TestApp};
use serde_json::{Value, json};
use url::Url;
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse};

const TEST_ORIGIN: &str = "http://localhost:8888";

#[tokio::test(flavor = "multi_thread")]
async fn approve_with_soft_passkey_when_mfa_enabled() {
    let (_, anon, user) = TestApp::full().with_user().await;
    let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));

    register_passkey(&user, &mut authenticator, "cli-login-passkey").await;
    let enabled = user
        .put::<Value>("/api/v1/me/api_mfa", json!({ "enabled": true }).to_string())
        .await;
    assert_eq!(enabled.status(), 200);

    let start = anon.post::<Value>("/api/v1/cli_login", "{}").await.good();
    let login_id = start["login_id"].as_str().unwrap().to_string();

    let assertion = authenticate(&user, &mut authenticator).await;
    let approve = user
        .post::<Value>(
            &format!("/api/v1/cli_login/{login_id}/approve"),
            json!({
                "name": "mfa-cli-ok",
                "endpoint_scopes": ["yank"],
                "credential": assertion,
            })
            .to_string(),
        )
        .await;
    assert_eq!(approve.status(), 200);
    assert_eq!(approve.json()["status"], "ready");
    assert!(approve.json().get("token").is_none());

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let ready = anon
        .get::<Value>(&format!("/api/v1/cli_login/{login_id}"))
        .await
        .good();
    assert_eq!(ready["status"], "ready");
    assert!(ready["token"].as_str().unwrap().starts_with("cio"));
}

async fn register_passkey(
    user: &crate::util::MockCookieUser,
    authenticator: &mut WebauthnAuthenticator<SoftPasskey>,
    name: &str,
) {
    let start = user
        .post::<Value>(
            "/api/v1/me/api_mfa/credentials/start",
            json!({}).to_string(),
        )
        .await
        .good();
    let ccr = CreationChallengeResponse {
        public_key: serde_json::from_value(start["public_key"].clone()).unwrap(),
    };
    let attestation = authenticator
        .do_registration(Url::parse(TEST_ORIGIN).unwrap(), ccr)
        .expect("soft passkey registration");
    let finish = user
        .post::<Value>(
            "/api/v1/me/api_mfa/credentials/finish",
            json!({
                "name": name,
                "credential": attestation,
            })
            .to_string(),
        )
        .await;
    assert_eq!(finish.status(), 200);
}

async fn authenticate(
    user: &crate::util::MockCookieUser,
    authenticator: &mut WebauthnAuthenticator<SoftPasskey>,
) -> Value {
    let start = user
        .post::<Value>("/api/v1/me/api_mfa/authorize/start", "")
        .await
        .good();
    let rcr = RequestChallengeResponse {
        public_key: serde_json::from_value(start["public_key"].clone()).unwrap(),
        mediation: None,
    };
    let assertion = authenticator
        .do_authentication(Url::parse(TEST_ORIGIN).unwrap(), rcr)
        .expect("soft passkey authentication");
    serde_json::to_value(assertion).unwrap()
}
