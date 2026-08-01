//! End-to-end `WebAuthn` ceremonies using `SoftPasskey` (software authenticator).

use crate::builders::PublishBuilder;
use crate::util::{MockCookieUser, MockRequestExt, RequestHelper, TestApp};
use crates_io::schema::users;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use regex::regex;
use serde_json::{json, Value};
use url::Url;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse};

const TEST_ORIGIN: &str = "http://localhost:8888";

#[tokio::test(flavor = "multi_thread")]
async fn register_authorize_is_cookie_only_with_soft_passkey() {
    let (app, _, user, token) = TestApp::full().with_token().await;
    let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));

    register_passkey(&app, &user, &mut authenticator, "soft-passkey", None).await;
    let user = enable_api_mfa(&app, &user).await;
    assert!(
        app.emails()
            .await
            .iter()
            .any(|email| email.contains("API MFA was") && email.contains("enabled")),
        "expected enable notification email"
    );

    // Token publish is blocked until passkey grant.
    let blocked = token
        .publish_crate(PublishBuilder::new("foo_soft_passkey", "1.0.0"))
        .await;
    assert_eq!(blocked.status(), 403);
    assert!(blocked.text().contains("Cargo-Mutation-Id is required"));

    // Settings-page authorize issues a wildcard grant.
    let assertion = authenticate(&user, &mut authenticator).await;
    let grant = user
        .post::<Value>(
            "/api/v1/me/mfa/authorize/finish",
            json!({ "credential": assertion }).to_string(),
        )
        .await;
    assert_eq!(grant.status(), 200);
    assert!(grant.json()["grant_expires_at"].is_string());

    let published = token
        .publish_crate(PublishBuilder::new("foo_soft_passkey", "1.0.0"))
        .await;
    assert_eq!(
        published.status(),
        403,
        "cookie wildcard grant must not authorize an API token"
    );

    let published = user
        .publish_crate(PublishBuilder::new("foo_soft_passkey", "1.0.0"))
        .await;
    assert_eq!(published.status(), 200);

    // Drop the in-memory app handle so background workers shut down cleanly.
    drop(app);
}

#[tokio::test(flavor = "multi_thread")]
async fn mutation_preflight_verification_returns_wakeup_metadata() {
    use http::Method;

    let (app, anon, user, token) = TestApp::full().with_token().await;
    let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));

    register_passkey(&app, &user, &mut authenticator, "soft-passkey", None).await;
    let _user = enable_api_mfa(&app, &user).await;

    let body = PublishBuilder::new("foo_mutation_passkey", "1.0.0").body();
    let descriptor = super::publish_preflight_descriptor("foo_mutation_passkey", "1.0.0", &body);
    let pending = token
        .run::<Value>(
            token
                .request_builder(Method::POST, "/api/v1/auth/mutation-challenges")
                .with_body(descriptor.to_string().into()),
        )
        .await;
    assert_eq!(pending.status(), 202, "{}", pending.text());
    let challenge_id = pending.json()["mutation_id"].as_str().unwrap().to_owned();
    let poll_url = Url::parse(pending.json()["poll_url"].as_str().unwrap()).unwrap();

    let start = anon
        .post::<Value>(&format!("/api/v1/auth/challenges/{challenge_id}/start"), "")
        .await
        .good();
    let assertion = authenticator
        .do_authentication(
            Url::parse(TEST_ORIGIN).unwrap(),
            RequestChallengeResponse {
                public_key: serde_json::from_value(start["public_key"].clone()).unwrap(),
                mediation: None,
            },
        )
        .expect("soft passkey authentication");
    let finish = anon
        .post::<Value>(
            &format!("/api/v1/auth/challenges/{challenge_id}/finish"),
            json!({ "credential": assertion }).to_string(),
        )
        .await
        .good();
    assert_eq!(
        finish,
        json!({ "callback_url": null, "challenge_id": challenge_id })
    );

    let ready = anon.get::<Value>(poll_url.path()).await.good();
    assert_eq!(ready["status"], "ready");

    let mut request = token.request_builder(Method::PUT, "/api/v1/crates/new");
    request.header("Cargo-Mutation-Id", &challenge_id);
    request.header("Content-Type", "application/octet-stream");
    let body_len = body.len().to_string();
    request.header("Content-Length", &body_len);
    let published = token
        .run::<crates_io::views::GoodCrate>(request.with_body(body))
        .await;
    assert_eq!(published.status(), 200, "{}", published.text());
}

#[tokio::test(flavor = "multi_thread")]
async fn disable_api_mfa_requires_passkey_or_email_otp() {
    let (app, _, user) = TestApp::full().with_user().await;
    let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));

    register_passkey(&app, &user, &mut authenticator, "soft-passkey", None).await;
    let user = enable_api_mfa(&app, &user).await;

    let denied = user
        .put::<Value>("/api/v1/me/mfa", json!({ "enabled": false }).to_string())
        .await;
    assert_eq!(denied.status(), 400);
    assert!(denied.json()["errors"][0]["detail"]
        .as_str()
        .unwrap()
        .contains("passkey verification or email code required"));

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
            "/api/v1/me/mfa",
            json!({ "enabled": false, "credential": assertion }).to_string(),
        )
        .await;
    assert_eq!(disabled.status(), 200);
    assert_eq!(disabled.json()["enabled"], false);
}

#[tokio::test(flavor = "multi_thread")]
async fn disable_api_mfa_with_email_otp_after_last_passkey_removed() {
    let (app, _, user) = TestApp::full().with_user().await;
    let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));

    register_passkey(&app, &user, &mut authenticator, "soft-passkey", None).await;
    let user = enable_api_mfa(&app, &user).await;

    let status = user.get::<Value>("/api/v1/me/mfa").await.good();
    let cred_id = status["credentials"][0]["id"].as_i64().unwrap();
    let assertion = authenticate(&user, &mut authenticator).await;
    user.delete_with_body::<Value>(
        &format!("/api/v1/me/mfa/passkeys/{cred_id}"),
        json!({ "credential": assertion }).to_string(),
    )
    .await
    .good();

    let status = user.get::<Value>("/api/v1/me/mfa").await.good();
    assert!(status["enabled"].as_bool().unwrap());
    assert!(status["credentials"].as_array().unwrap().is_empty());

    let otp = request_email_code(&app, &user).await;
    let disabled = user
        .put::<Value>(
            "/api/v1/me/mfa",
            json!({ "enabled": false, "email_code": otp }).to_string(),
        )
        .await;
    assert_eq!(disabled.status(), 200);
    assert_eq!(disabled.json()["enabled"], false);
}

#[tokio::test(flavor = "multi_thread")]
async fn enable_api_mfa_requires_email_otp() {
    let (app, _, user) = TestApp::full().with_user().await;
    let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));

    register_passkey(&app, &user, &mut authenticator, "soft-passkey", None).await;

    let denied = user
        .put::<Value>("/api/v1/me/mfa", json!({ "enabled": true }).to_string())
        .await;
    assert_eq!(denied.status(), 400);
    assert!(denied.json()["errors"][0]["detail"]
        .as_str()
        .unwrap()
        .contains("email verification code required"));

    let _user = enable_api_mfa(&app, &user).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn register_first_passkey_requires_email_otp() {
    let (app, _, user) = TestApp::full().with_user().await;

    let denied = user
        .post::<Value>("/api/v1/me/mfa/passkeys/start", "{}")
        .await;
    assert_eq!(denied.status(), 400);
    assert!(denied.json()["errors"][0]["detail"]
        .as_str()
        .unwrap()
        .contains("email verification code required"));

    let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
    register_passkey(&app, &user, &mut authenticator, "first", None).await;

    let status = user.get::<Value>("/api/v1/me/mfa").await.good();
    assert_eq!(status["credentials"].as_array().unwrap().len(), 1);
    assert!(status["has_verified_email"].as_bool().unwrap());
    assert_eq!(status["enforcement_active"], true);
}

#[tokio::test(flavor = "multi_thread")]
async fn register_additional_passkey_requires_step_up_when_mfa_enabled() {
    let (app, _, user) = TestApp::full().with_user().await;
    let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));

    register_passkey(&app, &user, &mut authenticator, "first", None).await;
    let user = enable_api_mfa(&app, &user).await;

    let denied = user
        .post::<Value>("/api/v1/me/mfa/passkeys/start", "{}")
        .await;
    assert_eq!(denied.status(), 400);
    assert!(denied.json()["errors"][0]["detail"]
        .as_str()
        .unwrap()
        .contains("passkey verification required"));

    let assertion = authenticate(&user, &mut authenticator).await;
    register_passkey(&app, &user, &mut authenticator, "second", Some(assertion)).await;

    let status = user.get::<Value>("/api/v1/me/mfa").await.good();
    assert_eq!(status["credentials"].as_array().unwrap().len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn recovery_register_passkey_with_email_otp_when_none_remain() {
    let (app, _, user) = TestApp::full().with_user().await;
    let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));

    register_passkey(&app, &user, &mut authenticator, "first", None).await;
    let user = enable_api_mfa(&app, &user).await;

    let status = user.get::<Value>("/api/v1/me/mfa").await.good();
    let cred_id = status["credentials"][0]["id"].as_i64().unwrap();
    let assertion = authenticate(&user, &mut authenticator).await;
    user.delete_with_body::<Value>(
        &format!("/api/v1/me/mfa/passkeys/{cred_id}"),
        json!({ "credential": assertion }).to_string(),
    )
    .await
    .good();

    // Recovery enroll uses email OTP (no passkeys left for assertion).
    let mut recovery = WebauthnAuthenticator::new(SoftPasskey::new(true));
    register_passkey(&app, &user, &mut recovery, "recovered", None).await;

    let status = user.get::<Value>("/api/v1/me/mfa").await.good();
    assert!(status["enabled"].as_bool().unwrap());
    assert_eq!(status["credentials"].as_array().unwrap().len(), 1);
    assert_eq!(status["credentials"][0]["name"], "recovered");
}

#[tokio::test(flavor = "multi_thread")]
async fn delete_passkey_requires_step_up_when_mfa_enabled() {
    let (app, _, user) = TestApp::full().with_user().await;
    let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));

    register_passkey(&app, &user, &mut authenticator, "soft-passkey", None).await;
    let user = enable_api_mfa(&app, &user).await;

    let status = user.get::<Value>("/api/v1/me/mfa").await.good();
    let cred_id = status["credentials"][0]["id"].as_i64().unwrap();

    let denied = user
        .delete_with_body::<Value>(
            &format!("/api/v1/me/mfa/passkeys/{cred_id}"),
            "{}".to_string(),
        )
        .await;
    assert_eq!(denied.status(), 400);
    assert!(denied.json()["errors"][0]["detail"]
        .as_str()
        .unwrap()
        .contains("passkey verification or email code required"));

    let assertion = authenticate(&user, &mut authenticator).await;
    user.delete_with_body::<Value>(
        &format!("/api/v1/me/mfa/passkeys/{cred_id}"),
        json!({ "credential": assertion }).to_string(),
    )
    .await
    .good();

    let status = user.get::<Value>("/api/v1/me/mfa").await.good();
    assert!(status["credentials"].as_array().unwrap().is_empty());
    assert!(status["enabled"].as_bool().unwrap());
}

async fn enable_api_mfa(app: &TestApp, user: &MockCookieUser) -> MockCookieUser {
    let otp = request_email_code(app, user).await;
    let enabled = user
        .put::<Value>(
            "/api/v1/me/mfa",
            json!({ "enabled": true, "email_code": otp }).to_string(),
        )
        .await;
    assert_eq!(enabled.status(), 200, "enable API MFA: {}", enabled.text());
    assert_eq!(enabled.json()["enabled"], true);

    // Enabling MFA intentionally invalidates every existing cookie session.
    // Simulate the user signing in again before exercising post-enable flows.
    let conn = app.db_conn().await;
    let user = crates_io::models::User::find(&conn, user.as_model().id)
        .await
        .unwrap();
    MockCookieUser::new(app, user)
}

async fn request_email_code(app: &TestApp, user: &MockCookieUser) -> String {
    let before = app.emails().await.len();
    let sent = user
        .post::<Value>("/api/v1/me/mfa/email_codes", "")
        .await
        .good();
    assert!(sent["expires_at"].is_string());
    assert!(sent["sent_to_hint"].as_str().unwrap().contains('@'));

    let emails = app.emails().await;
    assert!(emails.len() > before);
    let latest = emails.last().unwrap();
    let decoded = quoted_printable::decode(latest, quoted_printable::ParseMode::Robust).unwrap();
    let body = String::from_utf8_lossy(&decoded);
    // Prefer HTML `<strong>CODE</strong>`; fall back to a bare 8-char line in the text part.
    regex!(r"<strong>([A-Za-z0-9]{8})</strong>")
        .captures(&body)
        .or_else(|| regex!(r"(?m)^([A-Za-z0-9]{8})\r?$").captures(&body))
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_owned())
        .unwrap_or_else(|| panic!("email OTP not found in: {body}"))
}

async fn register_passkey(
    app: &TestApp,
    user: &MockCookieUser,
    authenticator: &mut WebauthnAuthenticator<SoftPasskey>,
    name: &str,
    step_up: Option<Value>,
) {
    let start_body = match step_up {
        Some(credential) => json!({ "credential": credential }).to_string(),
        None => {
            let otp = request_email_code(app, user).await;
            json!({ "email_code": otp }).to_string()
        }
    };
    let start = user
        .post::<Value>("/api/v1/me/mfa/passkeys/start", start_body)
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
            "/api/v1/me/mfa/passkeys/finish",
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
        .post::<Value>("/api/v1/me/mfa/authorize/start", "")
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
