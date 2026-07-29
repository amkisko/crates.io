//! End-to-end `WebAuthn` ceremonies using `SoftPasskey` (software authenticator).

use crate::builders::PublishBuilder;
use crate::util::{MockCookieUser, RequestHelper, TestApp};
use crates_io::schema::users;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use serde_json::{Value, json};
use url::Url;
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse};

const TEST_ORIGIN: &str = "http://localhost:8888";

#[tokio::test(flavor = "multi_thread")]
async fn register_authorize_and_publish_with_soft_passkey() {
    let (app, _, user, token) = TestApp::full().with_token().await;
    let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));

    register_passkey(&user, &mut authenticator, "soft-passkey", None).await;

    let enabled = user
        .put::<Value>("/api/v1/me/api_mfa", json!({ "enabled": true }).to_string())
        .await;
    assert_eq!(enabled.status(), 200);
    assert_eq!(enabled.json()["enabled"], true);

    // Token publish is blocked until passkey grant.
    let blocked = token
        .publish_crate(PublishBuilder::new("foo_soft_passkey", "1.0.0"))
        .await;
    assert_eq!(blocked.status(), 403);
    assert_eq!(blocked.json()["errors"][0]["id"], "api_mfa_required");

    // Settings-page authorize issues a wildcard grant.
    let assertion = authenticate(&user, &mut authenticator).await;
    let grant = user
        .post::<Value>(
            "/api/v1/me/api_mfa/authorize/finish",
            json!({ "credential": assertion }).to_string(),
        )
        .await;
    assert_eq!(grant.status(), 200);
    assert!(grant.json()["grant_expires_at"].is_string());

    let published = token
        .publish_crate(PublishBuilder::new("foo_soft_passkey", "1.0.0"))
        .await;
    assert_eq!(published.status(), 200);

    // Drop the in-memory app handle so background workers shut down cleanly.
    drop(app);
}

#[tokio::test(flavor = "multi_thread")]
async fn challenge_ack_with_soft_passkey_allows_scoped_retry() {
    let (_app, anon, user, token) = TestApp::full().with_token().await;
    let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));

    register_passkey(&user, &mut authenticator, "soft-passkey", None).await;
    user.put::<Value>("/api/v1/me/api_mfa", json!({ "enabled": true }).to_string())
        .await
        .good();

    let blocked = token
        .publish_crate(PublishBuilder::new("foo_soft_challenge", "1.0.0"))
        .await;
    let operation_id = blocked.json()["errors"][0]["operation_id"]
        .as_str()
        .unwrap()
        .to_owned();

    // Verify page is cookie-less: capability URL + passkey (anonymous client).
    let meta = anon
        .get::<Value>(&format!("/api/v1/me/api_mfa/challenges/{operation_id}"))
        .await
        .good();
    assert_eq!(meta["status"], "pending");

    let start = anon
        .post::<Value>(
            &format!("/api/v1/me/api_mfa/challenges/{operation_id}/start"),
            "",
        )
        .await
        .good();
    let rcr = RequestChallengeResponse {
        public_key: serde_json::from_value(start["public_key"].clone()).unwrap(),
        mediation: None,
    };
    let assertion = authenticator
        .do_authentication(Url::parse(TEST_ORIGIN).unwrap(), rcr)
        .expect("soft passkey authentication");

    let finish = anon
        .post::<Value>(
            &format!("/api/v1/me/api_mfa/challenges/{operation_id}/finish"),
            json!({ "credential": assertion }).to_string(),
        )
        .await
        .good();
    assert!(finish["otp"].as_str().unwrap().len() >= 8);
    assert_eq!(finish["operation_id"], operation_id);

    let ready = token
        .get::<Value>(&format!("/api/v1/me/api_mfa/challenges/{operation_id}"))
        .await
        .good();
    assert_eq!(ready["status"], "acknowledged");

    let published = token
        .publish_crate(PublishBuilder::new("foo_soft_challenge", "1.0.0"))
        .await;
    assert_eq!(published.status(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn disable_api_mfa_requires_passkey() {
    let (_app, _, user) = TestApp::full().with_user().await;
    let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));

    register_passkey(&user, &mut authenticator, "soft-passkey", None).await;
    user.put::<Value>("/api/v1/me/api_mfa", json!({ "enabled": true }).to_string())
        .await
        .good();

    let denied = user
        .put::<Value>(
            "/api/v1/me/api_mfa",
            json!({ "enabled": false }).to_string(),
        )
        .await;
    assert_eq!(denied.status(), 400);
    assert!(
        denied.json()["errors"][0]["detail"]
            .as_str()
            .unwrap()
            .contains("passkey verification required")
    );

    let mut conn = user.app().db_conn().await;
    let still_enabled: bool = users::table
        .find(user.as_model().id)
        .select(users::api_mfa_enabled)
        .first(&mut conn)
        .await
        .unwrap();
    assert!(still_enabled);

    let assertion = authenticate(&user, &mut authenticator).await;
    let disabled = user
        .put::<Value>(
            "/api/v1/me/api_mfa",
            json!({ "enabled": false, "credential": assertion }).to_string(),
        )
        .await;
    assert_eq!(disabled.status(), 200);
    assert_eq!(disabled.json()["enabled"], false);
}

#[tokio::test(flavor = "multi_thread")]
async fn register_additional_passkey_requires_step_up_when_mfa_enabled() {
    let (_app, _, user) = TestApp::full().with_user().await;
    let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));

    register_passkey(&user, &mut authenticator, "first", None).await;
    user.put::<Value>("/api/v1/me/api_mfa", json!({ "enabled": true }).to_string())
        .await
        .good();

    let denied = user
        .post::<Value>("/api/v1/me/api_mfa/credentials/start", "{}")
        .await;
    assert_eq!(denied.status(), 400);
    assert!(
        denied.json()["errors"][0]["detail"]
            .as_str()
            .unwrap()
            .contains("passkey verification required")
    );

    let assertion = authenticate(&user, &mut authenticator).await;
    register_passkey(&user, &mut authenticator, "second", Some(assertion)).await;

    let status = user.get::<Value>("/api/v1/me/api_mfa").await.good();
    assert_eq!(status["credentials"].as_array().unwrap().len(), 2);
}

async fn register_passkey(
    user: &MockCookieUser,
    authenticator: &mut WebauthnAuthenticator<SoftPasskey>,
    name: &str,
    step_up: Option<Value>,
) {
    let start_body = match step_up {
        Some(credential) => json!({ "credential": credential }).to_string(),
        None => "{}".to_string(),
    };
    let start = user
        .post::<Value>("/api/v1/me/api_mfa/credentials/start", start_body)
        .await
        .good();
    let ccr = CreationChallengeResponse {
        public_key: serde_json::from_value(start["public_key"].clone()).unwrap(),
    };
    let registration = authenticator
        .do_registration(Url::parse(TEST_ORIGIN).unwrap(), ccr)
        .expect("soft passkey registration");

    let finish = user
        .post::<Value>(
            "/api/v1/me/api_mfa/credentials/finish",
            json!({
                "name": name,
                "credential": registration,
            })
            .to_string(),
        )
        .await;
    assert_eq!(
        finish.status(),
        200,
        "finish registration: {}",
        finish.text()
    );
    assert_eq!(finish.json()["credential"]["name"], name);
}

/// Starts authorize ceremony and returns a `SoftPasskey` assertion JSON value.
async fn authenticate(
    user: &MockCookieUser,
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
