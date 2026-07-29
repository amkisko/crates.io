mod webauthn;

use crate::builders::PublishBuilder;
use crate::util::{MockRequestExt, RequestHelper, TestApp};
use crates_io::models::{
    ApiMfaChallenge, MAX_PENDING_CHALLENGES_PER_USER, NewApiMfaChallenge, NewApiMfaGrant,
};
use crates_io::schema::{api_mfa_challenges, api_tokens, users};
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
    assert_eq!(
        error["detail"],
        format!(
            "API MFA required. Open this link to verify with your passkey:\n\n\
             http://127.0.0.1:8888/mfa/verify/{operation_id}\n\n\
             After verification, retry the request."
        )
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
        .mark_verified(ApiMfaChallenge::hash_otp("ACKNOWLD"), None, &conn)
        .await
        .unwrap();
    NewApiMfaGrant::for_operation(
        user.as_model().id,
        token.as_model().id,
        "publish",
        Some("foo_api_mfa_poll".into()),
        challenge.mutation_fingerprint.clone(),
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
async fn approval_is_bound_to_exact_publish_tarball() {
    let (app, _, user, token) = TestApp::full().with_token().await;
    let mut conn = app.db_conn().await;

    diesel::update(users::table.find(user.as_model().id))
        .set(users::api_mfa_enabled.eq(true))
        .execute(&mut conn)
        .await
        .unwrap();
    insert_dummy_passkey(user.as_model().id, &mut conn).await;

    let approved_body = PublishBuilder::new("foo_api_mfa_exact", "1.0.0")
        .add_file("approved.txt", "approved")
        .body();
    let initial = token
        .run::<Value>(
            token
                .request_builder(Method::PUT, "/api/v1/crates/new")
                .with_body(approved_body.clone()),
        )
        .await;
    assert_eq!(initial.status(), 403);
    let operation_id = initial.json()["errors"][0]["operation_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let challenge = ApiMfaChallenge::find_active(&operation_id, &conn)
        .await
        .unwrap()
        .unwrap();

    NewApiMfaGrant::for_operation(
        user.as_model().id,
        token.as_model().id,
        challenge.operation.clone(),
        challenge.crate_name.clone(),
        challenge.mutation_fingerprint,
    )
    .insert(&conn)
    .await
    .unwrap();

    let substituted = token
        .publish_crate(
            PublishBuilder::new("foo_api_mfa_exact", "1.0.0")
                .add_file("substituted.txt", "different bytes"),
        )
        .await;
    assert_snapshot!(substituted.status(), @"403 Forbidden");
    assert_ne!(
        substituted.json()["errors"][0]["operation_id"],
        operation_id
    );

    let approved = token
        .run::<crates_io::views::GoodCrate>(
            token
                .request_builder(Method::PUT, "/api/v1/crates/new")
                .with_body(approved_body),
        )
        .await;
    token.app().run_pending_background_jobs().await;
    assert_snapshot!(approved.status(), @"200 OK");
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

    NewApiMfaGrant::for_operation(
        user.as_model().id,
        token.as_model().id,
        "publish",
        Some("other_crate".into()),
        vec![0; 32],
    )
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
async fn cookie_wildcard_grant_does_not_authorize_api_token() {
    let (app, _, user, token) = TestApp::full().with_token().await;
    let mut conn = app.db_conn().await;

    diesel::update(users::table.find(user.as_model().id))
        .set(users::api_mfa_enabled.eq(true))
        .execute(&mut conn)
        .await
        .unwrap();
    insert_dummy_passkey(user.as_model().id, &mut conn).await;

    // Wildcard grant from settings-page "Authorize for 15 minutes".
    NewApiMfaGrant::for_user(user.as_model().id)
        .insert(&conn)
        .await
        .unwrap();

    let crate_to_publish = PublishBuilder::new("foo_api_mfa_grant", "1.0.0");
    let response = token.publish_crate(crate_to_publish).await;
    assert_snapshot!(response.status(), @"403 Forbidden");
    assert_eq!(response.json()["errors"][0]["id"], "mfa_required");
}

#[tokio::test(flavor = "multi_thread")]
async fn publish_allowed_with_otp_header() {
    let (app, _, user, token) = TestApp::full().with_token().await;
    let mut conn = app.db_conn().await;
    let other_token = user.db_new_token("other-token").await;

    diesel::update(users::table.find(user.as_model().id))
        .set(users::api_mfa_enabled.eq(true))
        .execute(&mut conn)
        .await
        .unwrap();
    insert_dummy_passkey(user.as_model().id, &mut conn).await;

    let body = PublishBuilder::new("foo_api_mfa_otp", "1.0.0").body();
    let initial = token
        .run::<Value>(
            token
                .request_builder(Method::PUT, "/api/v1/crates/new")
                .with_body(body.clone()),
        )
        .await;
    let operation_id = initial.json()["errors"][0]["operation_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let challenge = ApiMfaChallenge::find_active(&operation_id, &conn)
        .await
        .unwrap()
        .unwrap();
    let otp = ApiMfaChallenge::generate_otp();
    challenge
        .mark_verified(ApiMfaChallenge::hash_otp(&otp), None, &conn)
        .await
        .unwrap();

    let mut wrong_request = other_token.request_builder(Method::PUT, "/api/v1/crates/new");
    wrong_request.header("Crates-OTP", &otp);
    let wrong_token = other_token
        .run::<Value>(wrong_request.with_body(body.clone()))
        .await;
    assert_snapshot!(wrong_token.status(), @"403 Forbidden");

    let mut request = token.request_builder(Method::PUT, "/api/v1/crates/new");
    request.header("Crates-OTP", &otp);
    let request = request.with_body(body);
    let response = token.run::<crates_io::views::GoodCrate>(request).await;
    token.app().run_pending_background_jobs().await;

    assert_snapshot!(response.status(), @"200 OK");
}

#[tokio::test(flavor = "multi_thread")]
async fn otp_from_revoked_token_challenge_is_rejected() {
    let (app, _, user, token) = TestApp::full().with_token().await;
    let mut conn = app.db_conn().await;
    let revoked_token = user.db_new_token("revoked-token").await;

    diesel::update(users::table.find(user.as_model().id))
        .set(users::api_mfa_enabled.eq(true))
        .execute(&mut conn)
        .await
        .unwrap();
    insert_dummy_passkey(user.as_model().id, &mut conn).await;

    let body = PublishBuilder::new("foo_api_mfa_revoked_otp", "1.0.0").body();
    let initial = revoked_token
        .run::<Value>(
            revoked_token
                .request_builder(Method::PUT, "/api/v1/crates/new")
                .with_body(body.clone()),
        )
        .await;
    let operation_id = initial.json()["errors"][0]["operation_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let challenge = ApiMfaChallenge::find_active(&operation_id, &conn)
        .await
        .unwrap()
        .unwrap();
    let otp = ApiMfaChallenge::generate_otp();
    challenge
        .mark_verified(ApiMfaChallenge::hash_otp(&otp), None, &conn)
        .await
        .unwrap();

    diesel::delete(api_tokens::table.find(revoked_token.as_model().id))
        .execute(&mut conn)
        .await
        .unwrap();
    let challenge = ApiMfaChallenge::find_active(&challenge.id, &conn)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        challenge.api_token_id, None,
        "deleting the originating token must clear the challenge foreign key"
    );

    let mut request = token.request_builder(Method::PUT, "/api/v1/crates/new");
    request.header("Crates-OTP", &otp);
    let response = token.run::<Value>(request.with_body(body)).await;

    assert_snapshot!(response.status(), @"403 Forbidden");
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
        crates_io_database::models::NewApiMfaChallengeOperation {
            operation: "publish".into(),
            crate_name: Some("other_crate".into()),
            mutation_fingerprint: vec![0; 32],
            operation_summary: "Publish other_crate".into(),
        },
        None,
        None,
    )
    .insert(&conn)
    .await
    .unwrap();
    challenge
        .mark_verified(ApiMfaChallenge::hash_otp(&otp), None, &conn)
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
            crates_io_database::models::NewApiMfaChallengeOperation {
                operation: "publish".into(),
                crate_name: Some(format!("pending_cap_{i}")),
                mutation_fingerprint: vec![i as u8; 32],
                operation_summary: format!("Publish pending_cap_{i}"),
            },
            None,
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
        .put::<()>("/api/v1/me/mfa", json!({ "enabled": true }).to_string())
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

#[tokio::test(flavor = "multi_thread")]
async fn challenge_grant_does_not_cover_other_token() {
    let (app, _, user, token) = TestApp::full().with_token().await;
    let mut conn = app.db_conn().await;
    let other_token = user.db_new_token("other-token").await;

    diesel::update(users::table.find(user.as_model().id))
        .set(users::api_mfa_enabled.eq(true))
        .execute(&mut conn)
        .await
        .unwrap();
    insert_dummy_passkey(user.as_model().id, &mut conn).await;

    NewApiMfaGrant::for_operation(
        user.as_model().id,
        token.as_model().id,
        "publish",
        Some("foo_mfa_token_bind".into()),
        vec![0; 32],
    )
    .insert(&conn)
    .await
    .unwrap();

    // Bound to `token`; a second token of the same user cannot ride it.
    let blocked = other_token
        .publish_crate(PublishBuilder::new("foo_mfa_token_bind", "1.0.0"))
        .await;
    assert_snapshot!(blocked.status(), @"403 Forbidden");
    assert_eq!(blocked.json()["errors"][0]["id"], "mfa_required");

    // A cookie wildcard grant must not become an API-token bypass.
    NewApiMfaGrant::for_user(user.as_model().id)
        .insert(&conn)
        .await
        .unwrap();
    let still_blocked = other_token
        .publish_crate(PublishBuilder::new("foo_mfa_token_bind", "1.0.0"))
        .await;
    assert_snapshot!(still_blocked.status(), @"403 Forbidden");
}

#[tokio::test(flavor = "multi_thread")]
async fn crate_with_mfa_owner_requires_coowner_mfa() {
    use crate::builders::CrateBuilder;
    use crates_io::models::CrateOwner;

    let (app, _, mfa_owner, _) = TestApp::full().with_token().await;
    let mut conn = app.db_conn().await;
    let coowner = app.db_new_user("coowner_no_mfa").await;
    let coowner_token = coowner.db_new_token("coowner-token").await;

    diesel::update(users::table.find(mfa_owner.as_model().id))
        .set(users::api_mfa_enabled.eq(true))
        .execute(&mut conn)
        .await
        .unwrap();
    insert_dummy_passkey(mfa_owner.as_model().id, &mut conn).await;

    let krate = CrateBuilder::new("foo_mfa_inherit", mfa_owner.as_model().id)
        .expect_build(&mut conn)
        .await;
    CrateOwner::builder()
        .crate_id(krate.id)
        .user_id(coowner.as_model().id)
        .created_by(mfa_owner.as_model().id)
        .build()
        .insert(&conn)
        .await
        .unwrap();

    let blocked = coowner_token
        .publish_crate(PublishBuilder::new("foo_mfa_inherit", "1.0.1"))
        .await;
    assert_snapshot!(blocked.status(), @"400 Bad Request");
    assert!(
        blocked.json()["errors"][0]["detail"]
            .as_str()
            .unwrap()
            .contains("requires API MFA because an owner enabled it"),
        "{}",
        blocked.text()
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
