//! End-to-end `WebAuthn` ceremonies using `SoftPasskey` (software authenticator).

use crate::builders::PublishBuilder;
use crate::util::{MockCookieUser, MockRequestExt, RequestHelper, TestApp};
use crates_io::schema::users;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use regex::regex;
use serde_json::{Value, json};
use url::Url;
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
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
    assert_eq!(blocked.json()["errors"][0]["id"], "step_up_required");

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
async fn challenge_ack_with_soft_passkey_allows_scoped_retry() {
    let (app, anon, user, token) = TestApp::full().with_token().await;
    let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));

    register_passkey(&app, &user, &mut authenticator, "soft-passkey", None).await;
    let user = enable_api_mfa(&app, &user).await;

    let blocked = token
        .publish_crate(PublishBuilder::new("foo_soft_challenge", "1.0.0"))
        .await;
    let challenge_id = blocked.json()["errors"][0]["challenge_id"]
        .as_str()
        .unwrap()
        .to_owned();

    // Verify page is cookie-less: capability URL + passkey (anonymous client).
    let meta = anon
        .get::<Value>(&format!("/api/v1/auth/challenges/{challenge_id}"))
        .await
        .good();
    assert_eq!(meta["status"], "pending");

    let start = anon
        .post::<Value>(&format!("/api/v1/auth/challenges/{challenge_id}/start"), "")
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
            &format!("/api/v1/auth/challenges/{challenge_id}/finish"),
            json!({ "credential": assertion }).to_string(),
        )
        .await
        .good();
    assert!(finish["otp"].as_str().unwrap().len() >= 32);
    assert_eq!(finish["challenge_id"], challenge_id);
    assert!(
        finish["grant_expires_at"].is_string(),
        "poll/grant path should issue a scoped grant when no localhost port is set"
    );
    assert!(finish["localhost_callback_url"].is_null());

    let status = user.get::<Value>("/api/v1/me/mfa").await.good();
    assert!(
        status["grant_expires_at"].is_null(),
        "token-scoped grants must not be presented as browser authorization"
    );

    let ready = token
        .get::<Value>(&format!("/api/v1/auth/challenges/{challenge_id}"))
        .await
        .good();
    assert_eq!(ready["status"], "acknowledged");

    let published = token
        .publish_crate(PublishBuilder::new("foo_soft_challenge", "1.0.0"))
        .await;
    assert_eq!(published.status(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn localhost_port_finish_returns_callback_url_and_otp_retry() {
    use http::Method;

    let (app, anon, user, token) = TestApp::full().with_token().await;
    let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));

    register_passkey(&app, &user, &mut authenticator, "soft-passkey", None).await;
    let _user = enable_api_mfa(&app, &user).await;

    let body = PublishBuilder::new("foo_soft_localhost", "1.0.0").body();
    let callback_secret = "0123456789abcdef0123456789abcdef";

    let mut request = token.request_builder(Method::PUT, "/api/v1/crates/new");
    request.header("Cargo-Step-Up-Port", "34567");
    let missing_secret = token.run::<Value>(request.with_body(body.clone())).await;
    assert_eq!(missing_secret.status(), 400);

    let mut request = token.request_builder(Method::PUT, "/api/v1/crates/new");
    request.header("Cargo-Step-Up-Callback-Secret", callback_secret);
    let missing_port = token.run::<Value>(request.with_body(body.clone())).await;
    assert_eq!(missing_port.status(), 400);

    let mut request = token.request_builder(Method::PUT, "/api/v1/crates/new");
    request.header("Cargo-Step-Up-Port", "34567");
    request.header("Cargo-Step-Up-Callback-Secret", callback_secret);
    let blocked = token.run::<Value>(request.with_body(body.clone())).await;
    assert_eq!(blocked.status(), 403);
    blocked.assert_cache_control("no-store");
    let blocked_body = blocked.json();
    assert!(!blocked_body.to_string().contains(callback_secret));
    let challenge_id = blocked_body["errors"][0]["challenge_id"]
        .as_str()
        .unwrap()
        .to_owned();

    // A later retry can refresh the stored localhost port on the pending challenge.
    let mut request = token.request_builder(Method::PUT, "/api/v1/crates/new");
    request.header("Cargo-Step-Up-Port", "34568");
    request.header("Cargo-Step-Up-Callback-Secret", callback_secret);
    let blocked_again = token.run::<Value>(request.with_body(body.clone())).await;
    assert_eq!(blocked_again.status(), 403);
    assert_eq!(
        blocked_again.json()["errors"][0]["challenge_id"],
        challenge_id
    );

    // The token alone cannot downgrade callback mode to a polling grant.
    let downgrade = token
        .run::<Value>(
            token
                .request_builder(Method::PUT, "/api/v1/crates/new")
                .with_body(body.clone()),
        )
        .await;
    assert_eq!(downgrade.status(), 403);
    assert_eq!(downgrade.json()["errors"][0]["challenge_id"], challenge_id);

    // A different callback secret cannot replace the bound port.
    let mut request = token.request_builder(Method::PUT, "/api/v1/crates/new");
    request.header("Cargo-Step-Up-Port", "34569");
    request.header(
        "Cargo-Step-Up-Callback-Secret",
        "abcdef0123456789abcdef0123456789",
    );
    let wrong_secret = token.run::<Value>(request.with_body(body)).await;
    assert_eq!(wrong_secret.status(), 403);
    assert_eq!(
        wrong_secret.json()["errors"][0]["challenge_id"],
        challenge_id
    );

    let start = anon
        .post::<Value>(&format!("/api/v1/auth/challenges/{challenge_id}/start"), "")
        .await
        .good();
    let rcr = RequestChallengeResponse {
        public_key: serde_json::from_value(start["public_key"].clone()).unwrap(),
        mediation: None,
    };
    let assertion = authenticator
        .do_authentication(Url::parse(TEST_ORIGIN).unwrap(), rcr)
        .expect("soft passkey authentication");

    let mut finish_request = anon.request_builder(
        Method::POST,
        &format!("/api/v1/auth/challenges/{challenge_id}/finish"),
    );
    finish_request.header("Cargo-Step-Up-Callback-Secret", callback_secret);
    let finish = anon
        .run::<Value>(
            finish_request.with_body(json!({ "credential": assertion }).to_string().into()),
        )
        .await
        .good();
    let otp = finish["otp"].as_str().unwrap().to_owned();
    assert!(otp.len() >= 32);
    assert_eq!(
        finish["localhost_callback_url"],
        format!("http://127.0.0.1:34568/?code={otp}")
    );
    assert!(!finish.to_string().contains(callback_secret));
    assert!(
        finish["grant_expires_at"].is_string(),
        "callback challenges must retain the scoped polling fallback grant"
    );

    // A reload/lost finish response can recover the same OTP with the URL-fragment secret.
    let missing_secret = anon
        .post::<Value>(
            &format!("/api/v1/auth/challenges/{challenge_id}/recover"),
            "",
        )
        .await;
    assert_eq!(missing_secret.status(), 404);
    let mut recovery_request = anon.request_builder(
        Method::POST,
        &format!("/api/v1/auth/challenges/{challenge_id}/recover"),
    );
    recovery_request.header("Cargo-Step-Up-Callback-Secret", callback_secret);
    let recovered = anon.run::<Value>(recovery_request).await.good();
    assert_eq!(
        recovered["localhost_callback_url"],
        format!("http://127.0.0.1:34568/?code={otp}")
    );
    assert!(!recovered.to_string().contains(callback_secret));

    // Poll fallback: retry without OTP succeeds through the exact scoped grant.
    let published_with_grant = token
        .publish_crate(PublishBuilder::new("foo_soft_localhost", "1.0.0"))
        .await;
    assert_eq!(published_with_grant.status(), 200);
    token.app().run_pending_background_jobs().await;

    let mut consumed_recovery = anon.request_builder(
        Method::POST,
        &format!("/api/v1/auth/challenges/{challenge_id}/recover"),
    );
    consumed_recovery.header("Cargo-Step-Up-Callback-Secret", callback_secret);
    let consumed_recovery = anon.run::<Value>(consumed_recovery).await;
    assert_eq!(consumed_recovery.status(), 400);

    drop(app);
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
    assert!(
        denied.json()["errors"][0]["detail"]
            .as_str()
            .unwrap()
            .contains("passkey verification or email code required")
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
    assert!(
        denied.json()["errors"][0]["detail"]
            .as_str()
            .unwrap()
            .contains("email verification code required")
    );

    let _user = enable_api_mfa(&app, &user).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn register_first_passkey_requires_email_otp() {
    let (app, _, user) = TestApp::full().with_user().await;

    let denied = user
        .post::<Value>("/api/v1/me/mfa/passkeys/start", "{}")
        .await;
    assert_eq!(denied.status(), 400);
    assert!(
        denied.json()["errors"][0]["detail"]
            .as_str()
            .unwrap()
            .contains("email verification code required")
    );

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
    assert!(
        denied.json()["errors"][0]["detail"]
            .as_str()
            .unwrap()
            .contains("passkey verification required")
    );

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
    assert!(
        denied.json()["errors"][0]["detail"]
            .as_str()
            .unwrap()
            .contains("passkey verification or email code required")
    );

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

#[tokio::test(flavor = "multi_thread")]
async fn deleting_passkey_revokes_in_flight_operation_ceremony() {
    let (app, anon, user, token) = TestApp::full().with_token().await;
    let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));

    register_passkey(&app, &user, &mut authenticator, "soft-passkey", None).await;
    let user = enable_api_mfa(&app, &user).await;

    let blocked = token
        .publish_crate(PublishBuilder::new("foo_revoked_ceremony", "1.0.0"))
        .await;
    let challenge_id = blocked.json()["errors"][0]["challenge_id"]
        .as_str()
        .unwrap()
        .to_owned();
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

    let status = user.get::<Value>("/api/v1/me/mfa").await.good();
    let credential_id = status["credentials"][0]["id"].as_i64().unwrap();
    let email_code = request_email_code(&app, &user).await;
    user.delete_with_body::<Value>(
        &format!("/api/v1/me/mfa/passkeys/{credential_id}"),
        json!({ "email_code": email_code }).to_string(),
    )
    .await
    .good();

    let finish = anon
        .post::<Value>(
            &format!("/api/v1/auth/challenges/{challenge_id}/finish"),
            json!({ "credential": assertion }).to_string(),
        )
        .await;
    assert_eq!(finish.status(), 400);
    assert!(
        finish.json()["errors"][0]["detail"]
            .as_str()
            .unwrap()
            .contains("has not been started")
    );
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
