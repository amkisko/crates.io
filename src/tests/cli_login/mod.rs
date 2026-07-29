//! Integration tests for browser-assisted CLI link-login.

mod webauthn;

use crate::util::{MockRequestExt, RequestHelper, TestApp};
use crates_io::models::ApiToken;
use crates_io::models::token::{CrateScope, EndpointScope};
use crates_io::schema::{api_tokens, cli_login_sessions};
use crates_io::util::token::HashedToken;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use http::Method;
use insta::assert_snapshot;
use serde_json::{Value, json};

/// Polls with the starter `poll_secret` header (required for redeem).
async fn poll_with_secret(
    client: &impl RequestHelper,
    login_id: &str,
    poll_secret: &str,
) -> crate::util::Response<Value> {
    let mut request = client.request_builder(Method::GET, &format!("/api/v1/cli_login/{login_id}"));
    request.header("Crates-Cli-Login-Secret", poll_secret);
    client.run(request).await
}

#[tokio::test(flavor = "multi_thread")]
async fn start_approve_poll_delivers_token_once() {
    let (app, anon, user) = TestApp::full().with_user().await;

    let start = anon
        .post::<Value>("/api/v1/cli_login", r#"{"localhost_port":null}"#)
        .await
        .good();
    let login_id = start["login_id"].as_str().unwrap().to_string();
    let confirmation_code = start["confirmation_code"].as_str().unwrap().to_string();
    let poll_secret = start["poll_secret"].as_str().unwrap().to_string();
    assert!(login_id.starts_with("login_"));
    assert!(
        start["login_url"]
            .as_str()
            .unwrap()
            .contains(&format!("/settings/tokens/cli/{login_id}"))
    );
    assert_eq!(start["recommended_poll_interval_secs"], 2);
    assert!(
        confirmation_code.len() >= 8,
        "confirmation code should be human-typed length"
    );
    assert!(
        poll_secret.len() >= 32,
        "poll secret should be high-entropy for the CLI starter"
    );
    // Meta must not echo the confirmation code or poll secret.
    let meta = user
        .get::<Value>(&format!("/api/v1/cli_login/{login_id}/meta"))
        .await
        .good();
    assert!(meta.get("confirmation_code").is_none());
    assert!(meta.get("poll_secret").is_none());

    let pending = poll_with_secret(&anon, &login_id, &poll_secret)
        .await
        .good();
    assert_eq!(pending["status"], "pending");
    assert!(pending.get("token").is_none());

    assert_eq!(meta["status"], "pending");
    assert_eq!(meta["mfa_required"], false);

    // Wait out the per-session poll pacing before approve+redeem.
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let approve = user
        .post::<Value>(
            &format!("/api/v1/cli_login/{login_id}/approve"),
            json!({
                "name": "cli-link",
                "endpoint_scopes": ["publish-update", "publish-new"],
                "crate_scopes": ["foo*"],
                "expired_at": null,
                "confirmation_code": confirmation_code,
            })
            .to_string(),
        )
        .await
        .good();
    assert_eq!(approve["status"], "ready");
    assert_eq!(approve["token_name"], "cli-link");
    assert!(approve.get("token").is_none());
    assert!(approve.get("localhost_callback_url").is_none());
    assert!(meta["client_ip"].as_str().is_some());

    // Stash must be sealed ciphertext, not the raw API token prefix.
    {
        let mut conn = app.db_conn().await;
        let sealed: Option<String> = cli_login_sessions::table
            .find(&login_id)
            .select(cli_login_sessions::sealed_token)
            .first(&mut conn)
            .await
            .unwrap();
        let sealed = sealed.expect("sealed redeem blob");
        assert!(!sealed.starts_with("cio"));
    }

    let ready = poll_with_secret(&anon, &login_id, &poll_secret)
        .await
        .good();
    assert_eq!(ready["status"], "ready");
    let token = ready["token"].as_str().unwrap().to_string();
    assert!(token.starts_with("cio"));

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let second = poll_with_secret(&anon, &login_id, &poll_secret)
        .await
        .good();
    assert_eq!(second["status"], "consumed");
    assert!(second.get("token").is_none());

    let mut conn = app.db_conn().await;
    let (name, endpoint_scopes, crate_scopes): (
        String,
        Option<Vec<EndpointScope>>,
        Option<Vec<CrateScope>>,
    ) = api_tokens::table
        .filter(api_tokens::id.eq(approve["api_token_id"].as_i64().unwrap() as i32))
        .select((
            api_tokens::name,
            api_tokens::endpoint_scopes,
            api_tokens::crate_scopes,
        ))
        .first(&mut conn)
        .await
        .unwrap();
    assert_eq!(name, "cli-link");
    assert_eq!(
        endpoint_scopes,
        Some(vec![
            EndpointScope::PublishUpdate,
            EndpointScope::PublishNew
        ])
    );
    assert_eq!(
        crate_scopes,
        Some(vec![CrateScope::try_from("foo*").unwrap()])
    );

    let plaintext: Option<String> = cli_login_sessions::table
        .find(&login_id)
        .select(cli_login_sessions::sealed_token)
        .first(&mut conn)
        .await
        .unwrap();
    assert!(plaintext.is_none());

    let hashed = HashedToken::parse(&token).expect("token format");
    let looked_up = ApiToken::find_by_api_token(&mut conn, &hashed)
        .await
        .expect("redeemed token must authenticate");
    assert_eq!(
        looked_up.id,
        approve["api_token_id"].as_i64().unwrap() as i32
    );
    assert_eq!(looked_up.user_id, user.as_model().id);
}

#[tokio::test(flavor = "multi_thread")]
async fn poll_without_secret_is_rejected() {
    let (_, anon, _) = TestApp::full().with_user().await;
    let start = anon.post::<Value>("/api/v1/cli_login", "{}").await.good();
    let login_id = start["login_id"].as_str().unwrap();

    let response = anon
        .get::<Value>(&format!("/api/v1/cli_login/{login_id}"))
        .await;
    assert_snapshot!(response.status(), @"400 Bad Request");
    assert!(
        response.json()["errors"][0]["detail"]
            .as_str()
            .unwrap()
            .contains("Crates-Cli-Login-Secret")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn poll_with_wrong_secret_is_forbidden() {
    let (_, anon, _) = TestApp::full().with_user().await;
    let start = anon.post::<Value>("/api/v1/cli_login", "{}").await.good();
    let login_id = start["login_id"].as_str().unwrap();

    let response = poll_with_secret(&anon, login_id, "definitely-not-the-secret").await;
    assert_snapshot!(response.status(), @"403 Forbidden");
    assert!(
        response.json()["errors"][0]["detail"]
            .as_str()
            .unwrap()
            .contains("invalid CLI login poll secret")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_confirmation_code_is_rejected() {
    let (_, anon, user) = TestApp::full().with_user().await;
    let start = anon.post::<Value>("/api/v1/cli_login", "{}").await.good();
    let login_id = start["login_id"].as_str().unwrap();

    let response = user
        .post::<Value>(
            &format!("/api/v1/cli_login/{login_id}/approve"),
            json!({
                "name": "wrong-code",
                "endpoint_scopes": ["yank"],
                "confirmation_code": "AAAA-BBBB",
            })
            .to_string(),
        )
        .await;
    assert_snapshot!(response.status(), @"400 Bad Request");
    assert!(
        response.json()["errors"][0]["detail"]
            .as_str()
            .unwrap()
            .contains("confirmation code")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_approve_only_mints_one_token() {
    let (app, anon, user_a) = TestApp::full().with_user().await;
    let user_b = app.db_new_user("other-approver").await;

    let start = anon.post::<Value>("/api/v1/cli_login", "{}").await.good();
    let login_id = start["login_id"].as_str().unwrap().to_string();
    let confirmation_code = start["confirmation_code"].as_str().unwrap();

    let body = json!({
        "name": "race-cli",
        "endpoint_scopes": ["yank"],
        "confirmation_code": confirmation_code,
    })
    .to_string();

    let path = format!("/api/v1/cli_login/{login_id}/approve");
    let (a, b) = tokio::join!(
        user_a.post::<Value>(&path, body.clone()),
        user_b.post::<Value>(&path, body),
    );

    let statuses = [a.status().as_u16(), b.status().as_u16()];
    assert!(
        statuses.contains(&200) && statuses.contains(&400),
        "expected one success and one claim failure, got {statuses:?}"
    );

    let mut conn = app.db_conn().await;
    let count: i64 = api_tokens::table
        .filter(api_tokens::name.eq("race-cli"))
        .count()
        .get_result(&mut conn)
        .await
        .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn approve_without_cookie_is_forbidden() {
    let (_, anon, _user) = TestApp::full().with_user().await;
    let start = anon.post::<Value>("/api/v1/cli_login", "{}").await.good();
    let login_id = start["login_id"].as_str().unwrap();
    let confirmation_code = start["confirmation_code"].as_str().unwrap();

    let response = anon
        .post::<Value>(
            &format!("/api/v1/cli_login/{login_id}/approve"),
            json!({
                "name": "nope",
                "endpoint_scopes": ["yank"],
                "confirmation_code": confirmation_code,
            })
            .to_string(),
        )
        .await;
    assert_snapshot!(response.status(), @"403 Forbidden");
}

#[tokio::test(flavor = "multi_thread")]
async fn mfa_enabled_approve_requires_credential() {
    use crates_io::models::NewWebauthnCredential;

    let (app, anon, user) = TestApp::full().with_user().await;
    let mut conn = app.db_conn().await;
    let user_id = user.as_model().id;

    diesel::update(crates_io::schema::users::table.find(user_id))
        .set(crates_io::schema::users::api_mfa_enabled.eq(true))
        .execute(&mut conn)
        .await
        .unwrap();

    // Zero passkeys: recovery path requires email OTP (not a dead-end).
    let start = anon.post::<Value>("/api/v1/cli_login", "{}").await.good();
    let login_id = start["login_id"].as_str().unwrap();
    let confirmation_code = start["confirmation_code"].as_str().unwrap();

    let meta = user
        .get::<Value>(&format!("/api/v1/cli_login/{login_id}/meta"))
        .await
        .good();
    assert_eq!(meta["mfa_required"], true);
    assert_eq!(meta["mfa_email_otp_allowed"], true);

    let response = user
        .post::<Value>(
            &format!("/api/v1/cli_login/{login_id}/approve"),
            json!({
                "name": "mfa-cli",
                "endpoint_scopes": ["yank"],
                "confirmation_code": confirmation_code,
            })
            .to_string(),
        )
        .await;
    assert_snapshot!(response.status(), @"400 Bad Request");
    assert!(
        response.json()["errors"][0]["detail"]
            .as_str()
            .unwrap()
            .contains("email verification code required")
    );

    // With a passkey registered, approve requires a passkey assertion.
    NewWebauthnCredential {
        user_id,
        credential_id: b"dummy-cli-login-passkey",
        passkey_json: json!({ "dummy": true }),
        name: "test-passkey",
    }
    .insert(&conn)
    .await
    .unwrap();

    let start = anon.post::<Value>("/api/v1/cli_login", "{}").await.good();
    let login_id = start["login_id"].as_str().unwrap();
    let confirmation_code = start["confirmation_code"].as_str().unwrap();

    let meta = user
        .get::<Value>(&format!("/api/v1/cli_login/{login_id}/meta"))
        .await
        .good();
    assert_eq!(meta["mfa_required"], true);
    assert_eq!(meta["mfa_email_otp_allowed"], false);

    let response = user
        .post::<Value>(
            &format!("/api/v1/cli_login/{login_id}/approve"),
            json!({
                "name": "mfa-cli-passkey",
                "endpoint_scopes": ["yank"],
                "confirmation_code": confirmation_code,
            })
            .to_string(),
        )
        .await;
    assert_snapshot!(response.status(), @"400 Bad Request");
    assert!(
        response.json()["errors"][0]["detail"]
            .as_str()
            .unwrap()
            .contains("passkey verification required")
    );
}
