mod webauthn;

use crate::builders::PublishBuilder;
use crate::util::{MockRequestExt, RequestHelper, TestApp};
use crates_io::models::{ApiMfaChallenge, NewApiMfaGrant};
use crates_io::schema::{api_mfa_challenges, users};
use diesel::prelude::*;
use diesel_async::{AsyncConnection, RunQueryDsl};
use http::Method;
use insta::assert_snapshot;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[tokio::test(flavor = "multi_thread")]
async fn publish_preflight_binds_and_replays_one_mutation() {
    let (app, anon, user, token) = TestApp::full().with_token().await;
    let mut conn = app.db_conn().await;
    diesel::update(users::table.find(user.as_model().id))
        .set(users::api_mfa_enabled.eq(true))
        .execute(&mut conn)
        .await
        .unwrap();
    insert_dummy_passkey(user.as_model().id, &mut conn).await;

    let body = PublishBuilder::new("preflight_replay", "1.0.0")
        .add_file("preflight_replay-1.0.0/large.txt", "payload")
        .body();
    let mut descriptor = publish_preflight_descriptor("preflight_replay", "1.0.0", &body);
    let callback_url = "http://127.0.0.1:34567/cargo/registry-authorization?state=0123456789abcdef0123456789abcdef";
    descriptor["callback"] = json!({ "url": callback_url });
    descriptor["requested_extensions"] = json!(["idempotent-final", "loopback-callback"]);
    let initial = token
        .run::<Value>(
            token
                .request_builder(Method::POST, "/api/v1/auth/mutation-challenges")
                .with_body(descriptor.to_string().into()),
        )
        .await;
    assert_eq!(initial.status(), 202);
    initial.assert_cache_control("no-store");
    assert_eq!(
        initial.json()["active_extensions"],
        json!(["idempotent-final", "loopback-callback"])
    );
    assert!(initial.json().get("receive_lease_secs").is_none());
    let challenge_id = initial.json()["mutation_id"].as_str().unwrap().to_owned();
    let challenge = ApiMfaChallenge::find_active(&challenge_id, &conn)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(challenge.request_size, Some(body.len() as i64));
    assert!(challenge.idempotent_final);
    assert_eq!(challenge.mutation_state.as_deref(), Some("pending"));
    assert_eq!(challenge.callback_url.as_deref(), Some(callback_url));
    assert_eq!(
        challenge.request_sha256,
        Some(Sha256::digest(&body).to_vec())
    );
    let browser_status = anon
        .get::<Value>(&format!("/api/v1/auth/challenges/{challenge_id}"))
        .await
        .good();
    assert_eq!(
        browser_status["archive_sha256"],
        descriptor["archive_sha256"]
    );

    challenge.mark_verified(&conn).await.unwrap();
    let ready_response = token
        .run::<Value>(
            token
                .request_builder(Method::POST, "/api/v1/auth/mutation-challenges")
                .with_body(descriptor.to_string().into()),
        )
        .await;
    assert_eq!(ready_response.status(), 200, "{}", ready_response.text());
    assert_eq!(ready_response.json()["receive_lease_secs"], 30 * 60);
    assert!(ready_response.json().get("detail").is_none());
    assert!(ready_response.json().get("poll_url").is_none());
    assert!(ready_response.json().get("challenge_expires_in").is_none());
    assert!(
        ready_response
            .json()
            .get("recommended_poll_interval_secs")
            .is_none()
    );
    let ready = ApiMfaChallenge::find(&challenge_id, &conn)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ready.mutation_state.as_deref(), Some("ready"));
    ready.begin_receiving(&conn).await.unwrap().unwrap();
    let rolled_back = conn
        .transaction::<(), diesel::result::Error, _>(async |conn| {
            assert!(ready.begin_execution(conn).await?);
            Err(diesel::result::Error::RollbackTransaction)
        })
        .await;
    assert!(rolled_back.is_err());
    let after_rollback = ApiMfaChallenge::find(&challenge_id, &conn)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after_rollback.mutation_state.as_deref(), Some("receiving"));
    let body_len = body.len().to_string();
    let mut direct_request = token.request_builder(Method::PUT, "/api/v1/crates/new");
    direct_request.header("Content-Type", "application/octet-stream");
    direct_request.header("Content-Length", &body_len);
    let direct = token
        .run::<Value>(direct_request.with_body(body.clone()))
        .await;
    assert_ne!(
        direct.status(),
        200,
        "mutation record authorized a direct request"
    );

    let mut first_request = token.request_builder(Method::PUT, "/api/v1/crates/new");
    first_request.header("Cargo-Mutation-Id", &challenge_id);
    first_request.header("Content-Type", "application/octet-stream");
    first_request.header("Content-Length", &body_len);
    let mut concurrent_request = token.request_builder(Method::PUT, "/api/v1/crates/new");
    concurrent_request.header("Cargo-Mutation-Id", &challenge_id);
    concurrent_request.header("Content-Type", "application/octet-stream");
    concurrent_request.header("Content-Length", &body_len);
    let (first, concurrent) = tokio::join!(
        token.run::<crates_io::views::GoodCrate>(first_request.with_body(body.clone())),
        token.run::<crates_io::views::GoodCrate>(concurrent_request.with_body(body.clone())),
    );
    let statuses = [first.status(), concurrent.status()];
    assert!(statuses.contains(&http::StatusCode::OK), "{statuses:?}");
    assert!(
        statuses
            .iter()
            .all(|status| matches!(*status, http::StatusCode::OK | http::StatusCode::TOO_EARLY)),
        "{statuses:?}"
    );

    let mut replay = token.request_builder(Method::PUT, "/api/v1/crates/new");
    replay.header("Cargo-Mutation-Id", &challenge_id);
    replay.header("Content-Type", "application/octet-stream");
    replay.header("Content-Length", &body_len);
    let replay = token
        .run::<crates_io::views::GoodCrate>(replay.with_body(body))
        .await;
    assert_eq!(replay.status(), 200, "{}", replay.text());

    let stored = ApiMfaChallenge::find_active(&challenge_id, &conn)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.response_status, Some(200));
    assert!(stored.completed_at.is_some());
    assert_eq!(stored.mutation_state.as_deref(), Some("terminal"));
}

#[tokio::test(flavor = "multi_thread")]
async fn browser_can_deny_a_pending_mutation_authorization() {
    let (app, anon, user, token) = TestApp::full().with_token().await;
    let mut conn = app.db_conn().await;
    diesel::update(users::table.find(user.as_model().id))
        .set(users::api_mfa_enabled.eq(true))
        .execute(&mut conn)
        .await
        .unwrap();
    insert_dummy_passkey(user.as_model().id, &mut conn).await;

    let body = PublishBuilder::new("preflight_denied", "1.0.0").body();
    let descriptor = publish_preflight_descriptor("preflight_denied", "1.0.0", &body);
    let initial = token
        .run::<Value>(
            token
                .request_builder(Method::POST, "/api/v1/auth/mutation-challenges")
                .with_body(descriptor.to_string().into()),
        )
        .await;
    assert_eq!(initial.status(), 202, "{}", initial.text());
    let mutation_id = initial.json()["mutation_id"].as_str().unwrap().to_owned();
    let poll_url = initial.json()["poll_url"].as_str().unwrap().to_owned();

    let denied = token
        .post::<Value>(&format!("/api/v1/auth/challenges/{mutation_id}/deny"), "")
        .await;
    assert_eq!(denied.status(), 200, "{}", denied.text());
    assert_eq!(denied.json()["status"], "denied");

    let poll_path = url::Url::parse(&poll_url).unwrap().path().to_owned();
    let poll = anon.get::<Value>(&poll_path).await;
    poll.assert_cache_control("no-store");
    assert_eq!(poll.json()["status"], "denied");

    let retry = token
        .run::<Value>(
            token
                .request_builder(Method::POST, "/api/v1/auth/mutation-challenges")
                .with_body(descriptor.to_string().into()),
        )
        .await;
    assert_eq!(retry.status(), 200, "{}", retry.text());
    assert_eq!(retry.json()["status"], "denied");

    let mut mutation = token.request_builder(Method::PUT, "/api/v1/crates/new");
    mutation.header("Cargo-Mutation-Id", &mutation_id);
    mutation.header("Content-Type", "application/octet-stream");
    mutation.header("Content-Length", &body.len().to_string());
    let mutation = token.run::<Value>(mutation.with_body(body)).await;
    assert_eq!(mutation.status(), 400, "{}", mutation.text());
    assert!(mutation.text().contains("was denied"));
}

#[tokio::test(flavor = "multi_thread")]
async fn noninteractive_preflight_creates_no_pending_record() {
    let (app, _, user, token) = TestApp::full().with_token().await;
    let mut conn = app.db_conn().await;
    diesel::update(users::table.find(user.as_model().id))
        .set(users::api_mfa_enabled.eq(true))
        .execute(&mut conn)
        .await
        .unwrap();
    insert_dummy_passkey(user.as_model().id, &mut conn).await;

    let body = PublishBuilder::new("preflight_noninteractive", "1.0.0").body();
    let mut descriptor = publish_preflight_descriptor("preflight_noninteractive", "1.0.0", &body);
    descriptor["allow_pending"] = json!(false);

    let response = token
        .run::<Value>(
            token
                .request_builder(Method::POST, "/api/v1/auth/mutation-challenges")
                .with_body(descriptor.to_string().into()),
        )
        .await;
    assert_eq!(response.status(), 403, "{}", response.text());
    assert_eq!(response.json()["status"], "interaction_required");
    assert!(response.json()["mutation_id"].is_null());
    assert!(response.json()["poll_url"].is_null());

    let count: i64 = api_mfa_challenges::table
        .filter(api_mfa_challenges::user_id.eq(user.as_model().id))
        .count()
        .get_result(&mut conn)
        .await
        .unwrap();
    assert_eq!(count, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn mutation_id_rejects_a_different_raw_publish_body() {
    let (_app, _, user, token) = TestApp::full().with_token().await;
    let other_token = user.db_new_token("other-mutation-token").await;
    let body = PublishBuilder::new("preflight_mismatch", "1.0.0").body();
    let descriptor = publish_preflight_descriptor("preflight_mismatch", "1.0.0", &body);
    let ready = token
        .run::<Value>(
            token
                .request_builder(Method::POST, "/api/v1/auth/mutation-challenges")
                .with_body(descriptor.to_string().into()),
        )
        .await;
    assert_eq!(ready.status(), 200, "{}", ready.text());
    let challenge_id = ready.json()["mutation_id"].as_str().unwrap().to_owned();

    let body_len = body.len().to_string();
    let mut stolen_id = other_token.request_builder(Method::PUT, "/api/v1/crates/new");
    stolen_id.header("Cargo-Mutation-Id", &challenge_id);
    stolen_id.header("Content-Type", "application/octet-stream");
    stolen_id.header("Content-Length", &body_len);
    let stolen_id = other_token
        .run::<Value>(stolen_id.with_body(body.clone()))
        .await;
    assert_eq!(stolen_id.status(), 400, "{}", stolen_id.text());
    assert!(stolen_id.text().contains("different credential"));

    let different = PublishBuilder::new("preflight_mismatch", "1.0.0")
        .add_file("preflight_mismatch-1.0.0/different.txt", "different")
        .body();
    let mut request = token.request_builder(Method::PUT, "/api/v1/crates/new");
    request.header("Cargo-Mutation-Id", &challenge_id);
    request.header("Content-Type", "application/octet-stream");
    request.header("Content-Length", &different.len().to_string());
    let rejected = token.run::<Value>(request.with_body(different)).await;
    assert_eq!(rejected.status(), 400, "{}", rejected.text());
    assert!(
        rejected
            .text()
            .contains("Content-Length does not match its preflight descriptor"),
        "{}",
        rejected.text()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn mutation_id_rejects_content_encoding_without_claiming() {
    let (app, _, _user, token) = TestApp::full().with_token().await;
    let body = PublishBuilder::new("preflight_content_encoding", "1.0.0").body();
    let descriptor = publish_preflight_descriptor("preflight_content_encoding", "1.0.0", &body);
    let ready = token
        .run::<Value>(
            token
                .request_builder(Method::POST, "/api/v1/auth/mutation-challenges")
                .with_body(descriptor.to_string().into()),
        )
        .await;
    assert_eq!(ready.status(), 200, "{}", ready.text());
    let mutation_id = ready.json()["mutation_id"].as_str().unwrap().to_owned();
    let body_len = body.len().to_string();

    let mut encoded = token.request_builder(Method::PUT, "/api/v1/crates/new");
    encoded.header("Cargo-Mutation-Id", &mutation_id);
    encoded.header("Content-Type", "application/octet-stream");
    encoded.header("Content-Encoding", "gzip");
    encoded.header("Content-Length", &body_len);
    let rejected = token.run::<Value>(encoded.with_body(body.clone())).await;
    assert_eq!(rejected.status(), 400, "{}", rejected.text());
    assert!(
        rejected.text().contains("does not permit Content-Encoding"),
        "{}",
        rejected.text()
    );

    let conn = app.db_conn().await;
    let stored = ApiMfaChallenge::find(&mutation_id, &conn)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.mutation_state.as_deref(), Some("ready"));
    assert!(stored.receive_expires_at.is_none());
    drop(conn);

    let mut request = token.request_builder(Method::PUT, "/api/v1/crates/new");
    request.header("Cargo-Mutation-Id", &mutation_id);
    request.header("Content-Type", "application/octet-stream");
    request.header("Content-Length", &body_len);
    let published = token
        .run::<crates_io::views::GoodCrate>(request.with_body(body))
        .await;
    assert_eq!(published.status(), 200, "{}", published.text());
}

#[tokio::test(flavor = "multi_thread")]
async fn mutation_id_rejects_method_or_target_without_claiming() {
    let (app, _, _user, token) = TestApp::full().with_token().await;
    let body = PublishBuilder::new("preflight_claim_order", "1.0.0").body();
    let descriptor = publish_preflight_descriptor("preflight_claim_order", "1.0.0", &body);
    let ready = token
        .run::<Value>(
            token
                .request_builder(Method::POST, "/api/v1/auth/mutation-challenges")
                .with_body(descriptor.to_string().into()),
        )
        .await;
    assert_eq!(ready.status(), 200, "{}", ready.text());
    let mutation_id = ready.json()["mutation_id"].as_str().unwrap().to_owned();
    let body_len = body.len().to_string();

    for (method, target) in [
        (Method::POST, "/api/v1/crates/new"),
        (
            Method::PUT,
            "/api/v1/crates/preflight_claim_order/1.0.0/unyank",
        ),
    ] {
        let mut request = token.request_builder(method, target);
        request.header("Cargo-Mutation-Id", &mutation_id);
        request.header("Content-Type", "application/octet-stream");
        request.header("Content-Length", &body_len);
        let rejected = token.run::<Value>(request.with_body(body.clone())).await;
        assert_eq!(rejected.status(), 400, "{}", rejected.text());
        assert!(
            rejected
                .text()
                .contains("method or request target does not match"),
            "{}",
            rejected.text()
        );

        let conn = app.db_conn().await;
        let stored = ApiMfaChallenge::find(&mutation_id, &conn)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.mutation_state.as_deref(), Some("ready"));
        assert!(stored.receive_expires_at.is_none());
    }

    let mut request = token.request_builder(Method::PUT, "/api/v1/crates/new");
    request.header("Cargo-Mutation-Id", &mutation_id);
    request.header("Content-Type", "application/octet-stream");
    request.header("Content-Length", &body_len);
    let published = token
        .run::<crates_io::views::GoodCrate>(request.with_body(body))
        .await;
    assert_eq!(published.status(), 200, "{}", published.text());
}

fn publish_preflight_descriptor(name: &str, version: &str, body: &[u8]) -> Value {
    let metadata_size = u32::from_le_bytes(body[..4].try_into().unwrap()) as usize;
    let archive_size_offset = 4 + metadata_size;
    let archive_size = u32::from_le_bytes(
        body[archive_size_offset..archive_size_offset + 4]
            .try_into()
            .unwrap(),
    ) as usize;
    let archive = &body[archive_size_offset + 4..];
    assert_eq!(archive.len(), archive_size);
    json!({
        "protocol_version": 1,
        "preflight_id": "pf_0123456789abcdefghijklmnopqr",
        "allow_pending": true,
        "requested_extensions": ["idempotent-final"],
        "operation": "publish",
        "method": "PUT",
        "request_target": "/api/v1/crates/new",
        "content_type": "application/octet-stream",
        "crate": name,
        "version": version,
        "request_sha256": hex::encode(Sha256::digest(body)),
        "request_size": body.len(),
        "archive_sha256": hex::encode(Sha256::digest(archive)),
        "archive_size": archive.len(),
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn core_preflight_derives_final_endpoint_facts() {
    let (app, _, _user, token) = TestApp::full().with_token().await;
    let body = PublishBuilder::new("preflight_derived", "1.0.0").body();
    let mut descriptor = publish_preflight_descriptor("preflight_derived", "1.0.0", &body);
    let descriptor = descriptor.as_object_mut().unwrap();
    descriptor.remove("method");
    descriptor.remove("request_target");
    descriptor.remove("content_type");
    descriptor.insert("requested_extensions".into(), json!(["future-extension"]));
    descriptor.insert("future_extension_hint".into(), json!("ignored"));

    let ready = token
        .run::<Value>(
            token
                .request_builder(Method::POST, "/api/v1/auth/mutation-challenges")
                .with_body(serde_json::to_vec(descriptor).unwrap().into()),
        )
        .await;
    assert_eq!(ready.status(), 200, "{}", ready.text());
    assert_eq!(ready.json()["status"], "ready");
    assert_eq!(ready.json()["active_extensions"], json!([]));
    let mutation_id = ready.json()["mutation_id"].as_str().unwrap().to_owned();
    let descriptor_body = serde_json::to_vec(descriptor).unwrap();

    let body_len = body.len().to_string();
    let mut request = token.request_builder(Method::PUT, "/api/v1/crates/new");
    request.header("Cargo-Mutation-Id", &mutation_id);
    request.header("Content-Type", "application/octet-stream");
    request.header("Content-Length", &body_len);
    let response = token
        .run::<crates_io::views::GoodCrate>(request.with_body(body))
        .await;
    assert_eq!(response.status(), 200, "{}", response.text());

    let conn = app.db_conn().await;
    let stored = ApiMfaChallenge::find(&mutation_id, &conn)
        .await
        .unwrap()
        .unwrap();
    assert!(!stored.idempotent_final);
    assert_eq!(stored.mutation_state.as_deref(), Some("consumed"));
    assert!(stored.response_body.is_none());
    assert!(stored.completed_at.is_none());

    let poll_token = stored.poll_token.as_deref().unwrap();
    let poll = token
        .get::<Value>(&format!(
            "/api/v1/auth/mutation-challenges/poll/{poll_token}"
        ))
        .await;
    poll.assert_cache_control("no-store");
    assert_eq!(poll.status(), 404, "{}", poll.text());

    let retry = token
        .run::<Value>(
            token
                .request_builder(Method::POST, "/api/v1/auth/mutation-challenges")
                .with_body(descriptor_body.into()),
        )
        .await;
    assert_eq!(retry.status(), 409, "{}", retry.text());
}

#[tokio::test(flavor = "multi_thread")]
async fn inactive_extension_fields_are_rejected_even_when_null() {
    let (_, _, _user, token) = TestApp::full().with_token().await;
    let body = PublishBuilder::new("preflight_inactive_fields", "1.0.0").body();
    let mut descriptor = publish_preflight_descriptor("preflight_inactive_fields", "1.0.0", &body);
    let descriptor = descriptor.as_object_mut().unwrap();
    descriptor.remove("method");
    descriptor.remove("request_target");
    descriptor.remove("content_type");
    descriptor.insert("requested_extensions".into(), json!(["future-extension"]));

    for field in ["method", "request_target", "content_type"] {
        let mut request = descriptor.clone();
        request.insert(field.into(), Value::Null);
        let response = token
            .run::<Value>(
                token
                    .request_builder(Method::POST, "/api/v1/auth/mutation-challenges")
                    .with_body(serde_json::to_vec(&request).unwrap().into()),
            )
            .await;
        assert_eq!(response.status(), 400, "{field}: {}", response.text());
        assert!(response.text().contains("require idempotent-final"));
    }

    let mut request = descriptor.clone();
    request.insert("callback".into(), Value::Null);
    let response = token
        .run::<Value>(
            token
                .request_builder(Method::POST, "/api/v1/auth/mutation-challenges")
                .with_body(serde_json::to_vec(&request).unwrap().into()),
        )
        .await;
    assert_eq!(response.status(), 400, "{}", response.text());
    assert!(
        response
            .text()
            .contains("requires the active `loopback-callback` extension")
    );

    let mut descriptor =
        publish_preflight_descriptor("preflight_inactive_fields", "1.0.0", &body);
    for content_type in [None, Some(Value::Null)] {
        let descriptor = descriptor.as_object_mut().unwrap();
        descriptor.remove("content_type");
        if let Some(content_type) = content_type {
            descriptor.insert("content_type".into(), content_type);
        }
        let response = token
            .run::<Value>(
                token
                    .request_builder(Method::POST, "/api/v1/auth/mutation-challenges")
                    .with_body(serde_json::to_vec(descriptor).unwrap().into()),
            )
            .await;
        assert_eq!(response.status(), 400, "{}", response.text());
        assert!(
            response
                .text()
                .contains("requires publish content_type")
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn yank_and_owner_finals_use_mutation_authorization() {
    let (app, _, user, token) = TestApp::full().with_token().await;
    let published = token
        .publish_crate(PublishBuilder::new("protocol_mutations", "1.0.0"))
        .await;
    assert_eq!(published.status(), 200, "{}", published.text());
    app.run_pending_background_jobs().await;

    let mut conn = app.db_conn().await;
    diesel::update(users::table.find(user.as_model().id))
        .set(users::api_mfa_enabled.eq(true))
        .execute(&mut conn)
        .await
        .unwrap();
    insert_dummy_passkey(user.as_model().id, &mut conn).await;

    let yank_descriptor = json!({
        "protocol_version": 1,
        "preflight_id": "pf_yank_0123456789abcdefghijkl",
        "allow_pending": true,
        "requested_extensions": ["idempotent-final"],
        "operation": "yank",
        "method": "DELETE",
        "request_target": "/api/v1/crates/protocol_mutations/1.0.0/yank",
        "content_type": null,
        "crate": "protocol_mutations",
        "version": "1.0.0",
        "request_sha256": hex::encode(Sha256::digest([])),
        "request_size": 0,
    });
    let yank_pending = token
        .run::<Value>(
            token
                .request_builder(Method::POST, "/api/v1/auth/mutation-challenges")
                .with_body(yank_descriptor.to_string().into()),
        )
        .await;
    assert_eq!(yank_pending.status(), 202, "{}", yank_pending.text());
    let yank_id = yank_pending.json()["mutation_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let yank_challenge = ApiMfaChallenge::find(&yank_id, &conn)
        .await
        .unwrap()
        .unwrap();
    yank_challenge.mark_verified(&conn).await.unwrap();

    let mut yank = token.request_builder(
        Method::DELETE,
        "/api/v1/crates/protocol_mutations/1.0.0/yank",
    );
    yank.header("Cargo-Mutation-Id", &yank_id);
    yank.header("Content-Length", "0");
    let yanked = token.run::<Value>(yank.with_body(Vec::new().into())).await;
    assert_eq!(yanked.status(), 200, "{}", yanked.text());

    let invitee = app.db_new_user("protocol_invitee").await;
    let owner_body = json!({ "users": [invitee.as_model().gh_login] })
        .to_string()
        .into_bytes();
    let owner_descriptor = json!({
        "protocol_version": 1,
        "preflight_id": "pf_owner_0123456789abcdefghijklm",
        "allow_pending": true,
        "requested_extensions": ["idempotent-final"],
        "operation": "owners",
        "method": "PUT",
        "request_target": "/api/v1/crates/protocol_mutations/owners",
        "content_type": "application/json",
        "crate": "protocol_mutations",
        "direction": "add",
        "owners": [invitee.as_model().gh_login],
        "request_sha256": hex::encode(Sha256::digest(&owner_body)),
        "request_size": owner_body.len(),
    });
    let owner_pending = token
        .run::<Value>(
            token
                .request_builder(Method::POST, "/api/v1/auth/mutation-challenges")
                .with_body(owner_descriptor.to_string().into()),
        )
        .await;
    assert_eq!(owner_pending.status(), 202, "{}", owner_pending.text());
    let owner_id = owner_pending.json()["mutation_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let owner_challenge = ApiMfaChallenge::find(&owner_id, &conn)
        .await
        .unwrap()
        .unwrap();
    owner_challenge.mark_verified(&conn).await.unwrap();

    let owner_body_len = owner_body.len().to_string();
    let mut add_owner =
        token.request_builder(Method::PUT, "/api/v1/crates/protocol_mutations/owners");
    add_owner.header("Cargo-Mutation-Id", &owner_id);
    add_owner.header("Content-Type", "application/json");
    add_owner.header("Content-Length", &owner_body_len);
    let added = token
        .run::<Value>(add_owner.with_body(owner_body.into()))
        .await;
    assert_eq!(added.status(), 200, "{}", added.text());
}

#[tokio::test(flavor = "multi_thread")]
async fn protected_publish_requires_mutation_id() {
    let (app, _, user, token) = TestApp::full().with_token().await;
    let mut conn = app.db_conn().await;

    diesel::update(users::table.find(user.as_model().id))
        .set(users::api_mfa_enabled.eq(true))
        .execute(&mut conn)
        .await
        .unwrap();

    insert_dummy_passkey(user.as_model().id, &mut conn).await;

    let crate_to_publish = PublishBuilder::new("foo_api_mfa", "1.0.0");
    let response = token.publish_crate(crate_to_publish).await;
    assert_snapshot!(response.status(), @"403 Forbidden");
    let body: Value = response.json();
    let error = &body["errors"][0];
    assert!(
        error["detail"]
            .as_str()
            .unwrap()
            .contains("Cargo-Mutation-Id is required")
    );

    let count: i64 = api_mfa_challenges::table
        .filter(api_mfa_challenges::user_id.eq(user.as_model().id))
        .count()
        .get_result(&mut conn)
        .await
        .unwrap();
    assert_eq!(count, 0, "a direct final request must not mint a challenge");
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
    assert!(response.text().contains("Cargo-Mutation-Id is required"));
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
    // for mutation authorization instead of asking the user to register.
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
