mod webauthn;

use crate::builders::PublishBuilder;
use crate::util::{MockRequestExt, RequestHelper, TestApp};
use crates_io::models::{
    ApiMfaChallenge, MAX_PENDING_CHALLENGES_PER_USER, NewApiMfaChallenge, NewApiMfaGrant,
};
use crates_io::schema::{api_mfa_challenges, users};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use http::Method;
use insta::assert_snapshot;
use serde_json::{Value, json};

#[tokio::test(flavor = "multi_thread")]
async fn publish_returns_operation_challenge_link() {
    let (app, _, user, token) = TestApp::full().with_token().await;
    let mut conn = app.db_conn().await;

    diesel::update(users::table.find(user.as_model().id))
        .set(users::api_mfa_enabled.eq(true))
        .execute(&mut conn)
        .await
        .unwrap();

    // Pretend the user already registered a passkey so the handshake can start.
    insert_dummy_passkey(user.as_model().id, &mut conn).await;

    let crate_to_publish = PublishBuilder::new("foo_api_mfa", "1.0.0");
    let response = token.publish_crate(crate_to_publish).await;
    assert_snapshot!(response.status(), @"403 Forbidden");

    let body: Value = response.json();
    let error = &body["errors"][0];
    assert_eq!(error["id"], "mfa_required");
    assert_eq!(error["operation"], "publish");
    assert_eq!(error["crate"], "foo_api_mfa");

    let operation_id = error["operation_id"].as_str().unwrap();
    assert!(operation_id.starts_with("mfa_"));
    assert!(
        error["verification_url"]
            .as_str()
            .unwrap()
            .contains(&format!("/mfa/verify/{operation_id}"))
    );
    assert!(
        error["poll_url"]
            .as_str()
            .unwrap()
            .contains(&format!("/api/v1/mfa/challenges/{operation_id}"))
    );
    assert!(
        error["detail"]
            .as_str()
            .unwrap()
            .contains("API MFA required")
    );

    // Idempotent: retrying the same operation reuses the challenge.
    let response2 = token
        .publish_crate(PublishBuilder::new("foo_api_mfa", "1.0.0"))
        .await;
    let body2: Value = response2.json();
    assert_eq!(body2["errors"][0]["operation_id"], operation_id);

    let count: i64 = api_mfa_challenges::table
        .filter(api_mfa_challenges::user_id.eq(user.as_model().id))
        .count()
        .get_result(&mut conn)
        .await
        .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn cli_can_poll_until_acknowledged_then_publish() {
    let (app, _, user, token) = TestApp::full().with_token().await;
    let mut conn = app.db_conn().await;

    diesel::update(users::table.find(user.as_model().id))
        .set(users::api_mfa_enabled.eq(true))
        .execute(&mut conn)
        .await
        .unwrap();
    insert_dummy_passkey(user.as_model().id, &mut conn).await;

    let response = token
        .publish_crate(PublishBuilder::new("foo_api_mfa_poll", "1.0.0"))
        .await;
    let body: Value = response.json();
    let operation_id = body["errors"][0]["operation_id"].as_str().unwrap();

    let pending = token
        .get::<Value>(&format!("/api/v1/mfa/challenges/{operation_id}"))
        .await;
    assert_snapshot!(pending.status(), @"200 OK");
    let pending_body = pending.json();
    assert_eq!(pending_body["status"], "pending");
    assert_eq!(pending_body["acknowledged"], false);

    // Simulate browser acknowledgment with a scoped grant for this operation/crate.
    let challenge = ApiMfaChallenge::find_active(operation_id, &conn)
        .await
        .unwrap()
        .unwrap();
    challenge
        .mark_verified(ApiMfaChallenge::hash_otp("ACKNOWLD"), &conn)
        .await
        .unwrap();
    NewApiMfaGrant::for_operation(
        user.as_model().id,
        "publish",
        Some("foo_api_mfa_poll".into()),
    )
    .insert(&conn)
    .await
    .unwrap();

    let ready = token
        .get::<Value>(&format!("/api/v1/mfa/challenges/{operation_id}"))
        .await
        .good();
    assert_eq!(ready["status"], "acknowledged");
    assert_eq!(ready["acknowledged"], true);

    let published = token
        .publish_crate(PublishBuilder::new("foo_api_mfa_poll", "1.0.0"))
        .await;
    assert_snapshot!(published.status(), @"200 OK");
}

#[tokio::test(flavor = "multi_thread")]
async fn scoped_grant_does_not_cover_other_crate() {
    let (app, _, user, token) = TestApp::full().with_token().await;
    let mut conn = app.db_conn().await;

    diesel::update(users::table.find(user.as_model().id))
        .set(users::api_mfa_enabled.eq(true))
        .execute(&mut conn)
        .await
        .unwrap();
    insert_dummy_passkey(user.as_model().id, &mut conn).await;

    NewApiMfaGrant::for_operation(user.as_model().id, "publish", Some("other_crate".into()))
        .insert(&conn)
        .await
        .unwrap();

    let response = token
        .publish_crate(PublishBuilder::new("foo_api_mfa_scope", "1.0.0"))
        .await;
    assert_snapshot!(response.status(), @"403 Forbidden");
    assert_eq!(response.json()["errors"][0]["id"], "mfa_required");
}

#[tokio::test(flavor = "multi_thread")]
async fn publish_allowed_with_active_grant() {
    let (app, _, user, token) = TestApp::full().with_token().await;
    let mut conn = app.db_conn().await;

    diesel::update(users::table.find(user.as_model().id))
        .set(users::api_mfa_enabled.eq(true))
        .execute(&mut conn)
        .await
        .unwrap();

    // Wildcard grant from settings-page "Authorize for 15 minutes".
    NewApiMfaGrant::for_user(user.as_model().id)
        .insert(&conn)
        .await
        .unwrap();

    let crate_to_publish = PublishBuilder::new("foo_api_mfa_grant", "1.0.0");
    let response = token.publish_crate(crate_to_publish).await;
    assert_snapshot!(response.status(), @"200 OK");
}

#[tokio::test(flavor = "multi_thread")]
async fn publish_allowed_with_otp_header() {
    let (app, _, user, token) = TestApp::full().with_token().await;
    let mut conn = app.db_conn().await;

    diesel::update(users::table.find(user.as_model().id))
        .set(users::api_mfa_enabled.eq(true))
        .execute(&mut conn)
        .await
        .unwrap();

    let otp = ApiMfaChallenge::generate_otp();
    let challenge = NewApiMfaChallenge::new(
        user.as_model().id,
        Some(token.as_model().id),
        "publish",
        Some("foo_api_mfa_otp".into()),
        None,
    )
    .insert(&conn)
    .await
    .unwrap();
    challenge
        .mark_verified(ApiMfaChallenge::hash_otp(&otp), &conn)
        .await
        .unwrap();

    let body = PublishBuilder::new("foo_api_mfa_otp", "1.0.0").body();
    let mut request = token.request_builder(Method::PUT, "/api/v1/crates/new");
    request.header("Crates-OTP", &otp);
    let request = request.with_body(body);
    let response = token.run::<crates_io::views::GoodCrate>(request).await;
    token.app().run_pending_background_jobs().await;

    assert_snapshot!(response.status(), @"200 OK");
}

#[tokio::test(flavor = "multi_thread")]
async fn otp_for_other_crate_is_rejected() {
    let (app, _, user, token) = TestApp::full().with_token().await;
    let mut conn = app.db_conn().await;

    diesel::update(users::table.find(user.as_model().id))
        .set(users::api_mfa_enabled.eq(true))
        .execute(&mut conn)
        .await
        .unwrap();
    insert_dummy_passkey(user.as_model().id, &mut conn).await;

    let otp = ApiMfaChallenge::generate_otp();
    let challenge = NewApiMfaChallenge::new(
        user.as_model().id,
        Some(token.as_model().id),
        "publish",
        Some("other_crate".into()),
        None,
    )
    .insert(&conn)
    .await
    .unwrap();
    challenge
        .mark_verified(ApiMfaChallenge::hash_otp(&otp), &conn)
        .await
        .unwrap();

    let body = PublishBuilder::new("foo_api_mfa_otp_wrong", "1.0.0").body();
    let mut request = token.request_builder(Method::PUT, "/api/v1/crates/new");
    request.header("Crates-OTP", &otp);
    let request = request.with_body(body);
    let response = token.run::<Value>(request).await;

    assert_snapshot!(response.status(), @"403 Forbidden");
    assert_eq!(response.json()["errors"][0]["id"], "mfa_required");
}

#[tokio::test(flavor = "multi_thread")]
async fn pending_challenge_cap_is_enforced() {
    let (app, _, user, token) = TestApp::full().with_token().await;
    let mut conn = app.db_conn().await;

    diesel::update(users::table.find(user.as_model().id))
        .set(users::api_mfa_enabled.eq(true))
        .execute(&mut conn)
        .await
        .unwrap();
    insert_dummy_passkey(user.as_model().id, &mut conn).await;

    for i in 0..MAX_PENDING_CHALLENGES_PER_USER {
        NewApiMfaChallenge::new(
            user.as_model().id,
            Some(token.as_model().id),
            "publish",
            Some(format!("pending_cap_{i}")),
            None,
        )
        .insert(&conn)
        .await
        .unwrap();
    }

    let response = token
        .publish_crate(PublishBuilder::new("pending_cap_overflow", "1.0.0"))
        .await;
    assert_snapshot!(response.status(), @"400 Bad Request");
    assert!(
        response.json()["errors"][0]["detail"]
            .as_str()
            .unwrap()
            .contains("too many pending API MFA challenges")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn challenge_create_rejects_unknown_operation() {
    let (app, _, user, token) = TestApp::full().with_token().await;
    let mut conn = app.db_conn().await;

    diesel::update(users::table.find(user.as_model().id))
        .set(users::api_mfa_enabled.eq(true))
        .execute(&mut conn)
        .await
        .unwrap();
    insert_dummy_passkey(user.as_model().id, &mut conn).await;

    let response = token
        .post::<Value>(
            "/api/v1/mfa/challenges",
            json!({ "operation": "harmless-check", "crate_name": "foo" }).to_string(),
        )
        .await;
    assert_snapshot!(response.status(), @"400 Bad Request");
    assert!(
        response.json()["errors"][0]["detail"]
            .as_str()
            .unwrap()
            .contains("invalid operation")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn challenge_create_is_rate_limited() {
    use crates_io::rate_limiter::LimitedAction;
    use std::time::Duration;

    let (app, _, user, token) = TestApp::full()
        .with_rate_limit(
            LimitedAction::ApiMfaChallengeCreate,
            Duration::from_secs(60),
            1,
        )
        .with_token()
        .await;
    let mut conn = app.db_conn().await;

    diesel::update(users::table.find(user.as_model().id))
        .set(users::api_mfa_enabled.eq(true))
        .execute(&mut conn)
        .await
        .unwrap();
    insert_dummy_passkey(user.as_model().id, &mut conn).await;

    let first = token
        .publish_crate(PublishBuilder::new("foo_mfa_rl_a", "1.0.0"))
        .await;
    assert_eq!(first.status(), 403);
    assert_eq!(first.json()["errors"][0]["id"], "mfa_required");
    assert_eq!(
        first.json()["errors"][0]["recommended_poll_interval_secs"],
        2
    );

    // Different crate forces a new challenge insert → rate limit.
    let second = token
        .publish_crate(PublishBuilder::new("foo_mfa_rl_b", "1.0.0"))
        .await;
    second.assert_rate_limited(LimitedAction::ApiMfaChallengeCreate);
}

#[tokio::test(flavor = "multi_thread")]
async fn cookie_auth_requires_authorize_grant() {
    let (app, _, user) = TestApp::full().with_user().await;
    let mut conn = app.db_conn().await;

    diesel::update(users::table.find(user.as_model().id))
        .set(users::api_mfa_enabled.eq(true))
        .execute(&mut conn)
        .await
        .unwrap();
    insert_dummy_passkey(user.as_model().id, &mut conn).await;

    let blocked = user
        .publish_crate(PublishBuilder::new("foo_api_mfa_cookie", "1.0.0"))
        .await;
    assert_snapshot!(blocked.status(), @"400 Bad Request");
    assert!(
        blocked.json()["errors"][0]["detail"]
            .as_str()
            .unwrap()
            .contains("Authorize for 15 minutes")
    );

    NewApiMfaGrant::for_user(user.as_model().id)
        .insert(&conn)
        .await
        .unwrap();

    let published = user
        .publish_crate(PublishBuilder::new("foo_api_mfa_cookie", "1.0.0"))
        .await;
    assert_snapshot!(published.status(), @"200 OK");
}

#[tokio::test(flavor = "multi_thread")]
async fn kill_switch_skips_mutate_enforcement_but_keeps_bootstrap_otp() {
    let (app, _, user, token) = TestApp::full()
        .with_config(|config| {
            config.api_mfa_enforcement_enabled = false;
        })
        .with_token()
        .await;
    let mut conn = app.db_conn().await;

    diesel::update(users::table.find(user.as_model().id))
        .set(users::api_mfa_enabled.eq(true))
        .execute(&mut conn)
        .await
        .unwrap();
    insert_dummy_passkey(user.as_model().id, &mut conn).await;

    let status = user.get::<Value>("/api/v1/me/mfa").await.good();
    assert_eq!(status["enabled"], true);
    assert_eq!(status["enforcement_active"], false);

    // Dangerous mutates skip MFA while the kill switch is off.
    let published = token
        .publish_crate(PublishBuilder::new("foo_api_mfa_kill_switch", "1.0.0"))
        .await;
    assert_snapshot!(published.status(), @"200 OK");

    // Enabling still requires email OTP (plant-prevention stays on).
    diesel::update(users::table.find(user.as_model().id))
        .set(users::api_mfa_enabled.eq(false))
        .execute(&mut conn)
        .await
        .unwrap();
    let enable_without_otp = user
        .put::<()>(
            "/api/v1/me/mfa",
            json!({ "enabled": true }).to_string(),
        )
        .await;
    assert_snapshot!(enable_without_otp.status(), @"400 Bad Request");
    assert!(
        enable_without_otp
            .text()
            .contains("email verification code required"),
        "{}",
        enable_without_otp.text()
    );
}

async fn insert_dummy_passkey(user_id: i32, conn: &mut diesel_async::AsyncPgConnection) {
    use crates_io::models::NewWebauthnCredential;
    use serde_json::json;

    // Minimal JSON placeholder; WebAuthn ceremony tests are separate. Presence is enough
    // for ensure_api_mfa to open a handshake instead of asking the user to register.
    NewWebauthnCredential {
        user_id,
        credential_id: b"dummy-credential-id",
        passkey_json: json!({ "dummy": true }),
        name: "test-passkey",
    }
    .insert(conn)
    .await
    .unwrap();
}
