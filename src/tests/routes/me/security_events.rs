use crate::util::insta::{self, assert_json_snapshot};
use crate::util::{RequestHelper, TestApp};
use claims::assert_ok;
use crates_io::models::{
    NewUserSecurityEvent, SecurityEventType, UserSecurityEvent, token::NewApiToken,
};
use crates_io::schema::user_security_events;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use insta::assert_snapshot;
use serde_json::json;

#[tokio::test(flavor = "multi_thread")]
async fn list_logged_out() {
    let (_, anon) = TestApp::init().empty().await;
    let response = anon.get::<()>("/api/v1/me/security_events").await;
    assert_snapshot!(response.status(), @"403 Forbidden");
}

#[tokio::test(flavor = "multi_thread")]
async fn list_with_api_token_is_forbidden() {
    let (_, _, _, token) = TestApp::init().with_token().await;
    let response = token.get::<()>("/api/v1/me/security_events").await;
    assert_snapshot!(response.status(), @"403 Forbidden");
}

#[tokio::test(flavor = "multi_thread")]
async fn list_empty() {
    let (_, _, user) = TestApp::init().with_user().await;
    let response = user.get::<()>("/api/v1/me/security_events").await;
    assert_snapshot!(response.status(), @"200 OK");
    assert_snapshot!(
        response.text(),
        @r#"{"security_events":[],"meta":{"total":0}}"#
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn create_token_records_security_event() {
    let (app, _, user) = TestApp::init().with_user().await;
    let mut conn = app.db_conn().await;

    let body: &[u8] = br#"{ "api_token": { "name": "audit-me" } }"#;
    let response = user.put::<()>("/api/v1/me/tokens", body).await;
    assert_snapshot!(response.status(), @"200 OK");

    let events: Vec<UserSecurityEvent> = assert_ok!(
        UserSecurityEvent::query()
            .filter(user_security_events::user_id.eq(user.as_model().id))
            .order(user_security_events::id.desc())
            .load(&mut conn)
            .await
    );
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, SecurityEventType::TokenCreated);
    assert_eq!(events[0].metadata["token_name"], "audit-me");

    let response = user.get::<()>("/api/v1/me/security_events").await;
    assert_snapshot!(response.status(), @"200 OK");
    assert_json_snapshot!(response.json(), {
        ".security_events[].id" => insta::any_id_redaction(),
        ".security_events[].api_token_id" => insta::any_id_redaction(),
        ".security_events[].created_at" => "[datetime]",
    });
}

#[tokio::test(flavor = "multi_thread")]
async fn token_used_records_at_most_once_per_day() {
    let (app, _, user, token) = TestApp::init().with_token().await;
    let mut conn = app.db_conn().await;

    // `/api/v1/me` is cookie-only; hit a token-authenticated route instead.
    token.search("following=1").await;
    token.search("following=1").await;

    let count: i64 = assert_ok!(
        user_security_events::table
            .filter(user_security_events::user_id.eq(user.as_model().id))
            .filter(user_security_events::event_type.eq(SecurityEventType::TokenUsed))
            .count()
            .get_result(&mut conn)
            .await
    );
    assert_eq!(count, 1);

    // token_used must never store IP
    let event: UserSecurityEvent = assert_ok!(
        UserSecurityEvent::query()
            .filter(user_security_events::user_id.eq(user.as_model().id))
            .filter(user_security_events::event_type.eq(SecurityEventType::TokenUsed))
            .first(&mut conn)
            .await
    );
    assert!(event.ip.is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn list_paginates_with_seek() {
    let (app, _, user) = TestApp::init().with_user().await;
    let mut conn = app.db_conn().await;
    let user_id = user.as_model().id;

    for _ in 0..3 {
        NewUserSecurityEvent::new(
            user_id,
            SecurityEventType::SessionLogin,
            None,
            None,
            json!({}),
        )
        .insert(&mut conn)
        .await
        .unwrap();
    }

    let response = user
        .get::<()>("/api/v1/me/security_events?per_page=2")
        .await;
    assert_snapshot!(response.status(), @"200 OK");
    let json = response.json();
    assert_eq!(json["security_events"].as_array().unwrap().len(), 2);
    assert_eq!(json["meta"]["total"], 3);
    assert!(json["meta"]["next_page"].as_str().is_some());

    let next = json["meta"]["next_page"].as_str().unwrap();
    let response = user
        .get::<()>(&format!("/api/v1/me/security_events{next}"))
        .await;
    assert_snapshot!(response.status(), @"200 OK");
    let json = response.json();
    assert_eq!(json["security_events"].as_array().unwrap().len(), 1);
    assert!(json["meta"]["next_page"].is_null());
}

#[tokio::test(flavor = "multi_thread")]
async fn revoke_records_security_event() {
    let (app, _, user) = TestApp::init().with_user().await;
    let mut conn = app.db_conn().await;
    let id = user.as_model().id;

    let token = assert_ok!(
        NewApiToken::builder()
            .name("to-revoke")
            .user_id(id)
            .build()
            .insert(&conn)
            .await
    );

    let response = user
        .delete::<()>(&format!("/api/v1/me/tokens/{}", token.id))
        .await;
    assert_snapshot!(response.status(), @"200 OK");

    let events: Vec<UserSecurityEvent> = assert_ok!(
        UserSecurityEvent::query()
            .filter(user_security_events::user_id.eq(id))
            .filter(user_security_events::event_type.eq(SecurityEventType::TokenRevoked))
            .load(&mut conn)
            .await
    );
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].metadata["token_name"], "to-revoke");
}

#[tokio::test(flavor = "multi_thread")]
async fn metadata_is_allowlisted_and_ip_truncated() {
    let (app, _, user) = TestApp::init().with_user().await;
    let mut conn = app.db_conn().await;
    let user_id = user.as_model().id;

    NewUserSecurityEvent::new(
        user_id,
        SecurityEventType::CliLoginApproved,
        None,
        Some("203.0.113.45".into()),
        json!({
            "token_name": "cli",
            "user_agent": "should-drop",
            "email": "a@b.c",
        }),
    )
    .insert(&mut conn)
    .await
    .unwrap();

    let event: UserSecurityEvent = assert_ok!(
        UserSecurityEvent::query()
            .filter(user_security_events::user_id.eq(user_id))
            .first(&mut conn)
            .await
    );
    assert_eq!(event.ip.as_deref(), Some("203.0.113.0/24"));
    assert_eq!(event.metadata, json!({ "token_name": "cli" }));
}
