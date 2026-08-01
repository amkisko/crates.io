//! `SoftPasskey` coverage for MFA-gated CLI login approve.

use crate::util::{MockCookieUser, MockRequestExt, RequestHelper, TestApp};
use regex::regex;
use serde_json::{Value, json};
use url::Url;
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse};

const TEST_ORIGIN: &str = "http://localhost:8888";

#[tokio::test(flavor = "multi_thread")]
async fn approve_with_soft_passkey_when_mfa_enabled() {
    let (app, anon, user) = TestApp::full().with_user().await;
    let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));

    register_passkey(&app, &user, &mut authenticator, "cli-login-passkey").await;
    let otp = request_email_code(&app, &user).await;
    let enabled = user
        .put::<Value>(
            "/api/v1/me/mfa",
            json!({ "enabled": true, "email_code": otp }).to_string(),
        )
        .await;
    assert_eq!(enabled.status(), 200);

    // Enabling MFA rotates the session generation. A real browser stores the
    // refreshed cookie returned above; reload the model so this request helper
    // signs subsequent requests with the same new generation.
    let conn = app.db_conn().await;
    let user = MockCookieUser::new(
        &app,
        crates_io::models::User::find(&conn, user.as_model().id)
            .await
            .unwrap(),
    );

    let start = anon.post::<Value>("/api/v1/cli_login", "{}").await.good();
    let login_id = start["login_id"].as_str().unwrap().to_string();
    let confirmation_code = start["confirmation_code"].as_str().unwrap();

    let assertion = authenticate(&user, &mut authenticator).await;
    let approve = user
        .post::<Value>(
            &format!("/api/v1/cli_login/{login_id}/approve"),
            json!({
                "name": "mfa-cli-ok",
                "endpoint_scopes": ["yank"],
                "confirmation_code": confirmation_code,
                "credential": assertion,
            })
            .to_string(),
        )
        .await;
    assert_eq!(approve.status(), 200, "response: {:#?}", approve.json());
    assert_eq!(approve.json()["status"], "ready");
    assert!(approve.json().get("token").is_none());

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let poll_secret = start["poll_secret"].as_str().unwrap();
    let mut request =
        anon.request_builder(http::Method::GET, &format!("/api/v1/cli_login/{login_id}"));
    request.header("Crates-Cli-Login-Secret", poll_secret);
    let ready = anon.run::<Value>(request).await.good();
    assert_eq!(ready["status"], "ready");
    assert!(ready["token"].as_str().unwrap().starts_with("cio"));
}

async fn request_email_code(app: &TestApp, user: &MockCookieUser) -> String {
    let before = app.emails().await.len();
    user.post::<Value>("/api/v1/me/mfa/email_codes", "")
        .await
        .good();
    let emails = app.emails().await;
    assert!(emails.len() > before);
    let latest = emails.last().unwrap();
    let decoded = quoted_printable::decode(latest, quoted_printable::ParseMode::Robust).unwrap();
    let body = String::from_utf8_lossy(&decoded);
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
) {
    let otp = request_email_code(app, user).await;
    let start = user
        .post::<Value>(
            "/api/v1/me/mfa/passkeys/start",
            json!({ "email_code": otp }).to_string(),
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
            "/api/v1/me/mfa/passkeys/finish",
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
