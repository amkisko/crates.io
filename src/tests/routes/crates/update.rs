use crate::builders::CrateBuilder;
use crate::util::{RequestHelper, TestApp};
use crates_io::models::token::{CrateScope, EndpointScope};
use insta::{assert_json_snapshot, assert_snapshot};

#[tokio::test(flavor = "multi_thread")]
async fn test_enable_trustpub_only() {
    let (app, _, user) = TestApp::full().with_user().await;
    let mut conn = app.db_conn().await;

    // Create a crate
    let owner_id = user.as_model().id;
    CrateBuilder::new("foo", owner_id)
        .expect_build(&mut conn)
        .await;

    let url = "/api/v1/crates/foo";

    // Try to set trustpub_only to false when it's already false (no change)
    let body = serde_json::json!({ "crate": { "trustpub_only": false } });
    let response = user.patch::<()>(url, body.to_string()).await;
    assert_snapshot!(response.status(), @"200 OK");
    let json = response.json();
    assert_json_snapshot!(json["crate"]["trustpub_only"], @"false");
    assert_json_snapshot!(json, {
        ".crate.created_at" => "[datetime]",
        ".crate.updated_at" => "[datetime]",
    });

    // Now enable trustpub_only
    let body = serde_json::json!({ "crate": { "trustpub_only": true } });
    let response = user.patch::<()>(url, body.to_string()).await;
    assert_snapshot!(response.status(), @"200 OK");
    let json = response.json();
    assert_json_snapshot!(json["crate"]["trustpub_only"], @"true");
    assert_json_snapshot!(json, {
        ".crate.created_at" => "[datetime]",
        ".crate.updated_at" => "[datetime]",
    });

    // Verify the flag was set
    let response = user.get::<()>(url).await;
    assert_snapshot!(response.status(), @"200 OK");
    let json = response.json();
    assert_json_snapshot!(json["crate"]["trustpub_only"], @"true");
    assert_json_snapshot!(json, {
        ".crate.created_at" => "[datetime]",
        ".crate.updated_at" => "[datetime]",
        ".versions[].created_at" => "[datetime]",
        ".versions[].updated_at" => "[datetime]",
        ".versions[].published_by.created_at" => "[datetime]",
    });

    assert_snapshot!(app.emails_snapshot().await);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_disable_trustpub_only() {
    let (app, _, user) = TestApp::full().with_user().await;
    let mut conn = app.db_conn().await;

    // Create a crate with trustpub_only enabled
    let owner_id = user.as_model().id;
    CrateBuilder::new("foo", owner_id)
        .trustpub_only(true)
        .expect_build(&mut conn)
        .await;

    let url = "/api/v1/crates/foo";

    // Try to set trustpub_only to true when it's already true (no change)
    let body = serde_json::json!({ "crate": { "trustpub_only": true } });
    let response = user.patch::<()>(url, body.to_string()).await;
    assert_snapshot!(response.status(), @"200 OK");
    let json = response.json();
    assert_json_snapshot!(json["crate"]["trustpub_only"], @"true");
    assert_json_snapshot!(json, {
        ".crate.created_at" => "[datetime]",
        ".crate.updated_at" => "[datetime]",
    });

    // Now disable trustpub_only
    let body = serde_json::json!({ "crate": { "trustpub_only": false } });
    let response = user.patch::<()>(url, body.to_string()).await;
    assert_snapshot!(response.status(), @"200 OK");
    let json = response.json();
    assert_json_snapshot!(json["crate"]["trustpub_only"], @"false");
    assert_json_snapshot!(json, {
        ".crate.created_at" => "[datetime]",
        ".crate.updated_at" => "[datetime]",
    });

    // Verify the flag was unset
    let response = user.get::<()>(url).await;
    assert_snapshot!(response.status(), @"200 OK");
    let json = response.json();
    assert_json_snapshot!(json["crate"]["trustpub_only"], @"false");
    assert_json_snapshot!(json, {
        ".crate.created_at" => "[datetime]",
        ".crate.updated_at" => "[datetime]",
        ".versions[].created_at" => "[datetime]",
        ".versions[].updated_at" => "[datetime]",
        ".versions[].published_by.created_at" => "[datetime]",
    });

    assert_snapshot!(app.emails_snapshot().await);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_update_trustpub_only_requires_authentication() {
    let (app, anon, user) = TestApp::full().with_user().await;
    let mut conn = app.db_conn().await;

    // Create a crate
    let owner_id = user.as_model().id;
    CrateBuilder::new("foo", owner_id)
        .expect_build(&mut conn)
        .await;

    // Try to update as an unauthenticated user
    let url = "/api/v1/crates/foo";
    let body = serde_json::json!({ "crate": { "trustpub_only": true } });
    let response = anon.patch::<()>(url, body.to_string()).await;
    assert_snapshot!(response.status(), @"403 Forbidden");

    assert_eq!(app.emails().await.len(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_update_trustpub_only_requires_ownership() {
    let (app, _, user) = TestApp::full().with_user().await;
    let mut conn = app.db_conn().await;

    // Create a crate with one user
    let owner_id = user.as_model().id;
    CrateBuilder::new("foo", owner_id)
        .expect_build(&mut conn)
        .await;

    // Create a different user
    let another_user = app.db_new_user("another").await;

    // Try to update with a different user
    let url = "/api/v1/crates/foo";
    let body = serde_json::json!({ "crate": { "trustpub_only": true } });
    let response = another_user.patch::<()>(url, body.to_string()).await;
    assert_snapshot!(response.status(), @"403 Forbidden");

    assert_eq!(app.emails().await.len(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_update_nonexistent_crate() {
    let (app, _, user) = TestApp::full().with_user().await;

    let url = "/api/v1/crates/nonexistent";
    let body = serde_json::json!({ "crate": { "trustpub_only": true } });
    let response = user.patch::<()>(url, body.to_string()).await;
    assert_snapshot!(response.status(), @"404 Not Found");

    assert_eq!(app.emails().await.len(), 0);
}

mod auth {
    use super::*;

    const CRATE_NAME: &str = "foo";

    async fn prepare() -> (TestApp, crate::util::MockCookieUser) {
        let (app, _, user) = TestApp::full().with_user().await;
        let mut conn = app.db_conn().await;

        // Create a crate
        let owner_id = user.as_model().id;
        CrateBuilder::new(CRATE_NAME, owner_id)
            .expect_build(&mut conn)
            .await;

        (app, user)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn token_user_with_legacy_token() {
        let (app, user) = prepare().await;
        let token = user.db_new_token("test-token").await;

        let url = format!("/api/v1/crates/{}", CRATE_NAME);
        let body = serde_json::json!({ "crate": { "trustpub_only": true } });
        let response = token.patch::<()>(&url, body.to_string()).await;
        assert_snapshot!(response.status(), @"403 Forbidden");
        assert_snapshot!(response.text(), @r#"{"errors":[{"detail":"This endpoint cannot be used with legacy API tokens. Use a scoped API token instead."}]}"#);

        assert_eq!(app.emails().await.len(), 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn token_user_with_correct_endpoint_scope() {
        let (app, user) = prepare().await;
        let token = user
            .db_new_scoped_token(
                "test-token",
                None,
                Some(vec![EndpointScope::TrustedPublishing]),
                None,
            )
            .await;

        let url = format!("/api/v1/crates/{}", CRATE_NAME);
        let body = serde_json::json!({ "crate": { "trustpub_only": true } });
        let response = token.patch::<()>(&url, body.to_string()).await;
        assert_snapshot!(response.status(), @"200 OK");

        assert!(!app.emails().await.is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn token_user_with_incorrect_endpoint_scope() {
        let (app, user) = prepare().await;
        let token = user
            .db_new_scoped_token(
                "test-token",
                None,
                Some(vec![EndpointScope::PublishUpdate]),
                None,
            )
            .await;

        let url = format!("/api/v1/crates/{}", CRATE_NAME);
        let body = serde_json::json!({ "crate": { "trustpub_only": true } });
        let response = token.patch::<()>(&url, body.to_string()).await;
        assert_snapshot!(response.status(), @"403 Forbidden");
        assert_snapshot!(response.text(), @r#"{"errors":[{"detail":"this token does not have the required permissions to perform this action"}]}"#);

        assert_eq!(app.emails().await.len(), 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn token_user_with_only_crate_scope() {
        let (app, user) = prepare().await;
        let token = user
            .db_new_scoped_token(
                "test-token",
                Some(vec![CrateScope::try_from(CRATE_NAME).unwrap()]),
                None,
                None,
            )
            .await;

        let url = format!("/api/v1/crates/{}", CRATE_NAME);
        let body = serde_json::json!({ "crate": { "trustpub_only": true } });
        let response = token.patch::<()>(&url, body.to_string()).await;
        assert_snapshot!(response.status(), @"403 Forbidden");
        assert_snapshot!(response.text(), @r#"{"errors":[{"detail":"This endpoint cannot be used with legacy API tokens. Use a scoped API token instead."}]}"#);

        assert_eq!(app.emails().await.len(), 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn token_user_with_incorrect_crate_scope() {
        let (app, user) = prepare().await;
        let token = user
            .db_new_scoped_token(
                "test-token",
                Some(vec![CrateScope::try_from("bar").unwrap()]),
                Some(vec![EndpointScope::TrustedPublishing]),
                None,
            )
            .await;

        let url = format!("/api/v1/crates/{}", CRATE_NAME);
        let body = serde_json::json!({ "crate": { "trustpub_only": true } });
        let response = token.patch::<()>(&url, body.to_string()).await;
        assert_snapshot!(response.status(), @"403 Forbidden");
        assert_snapshot!(response.text(), @r#"{"errors":[{"detail":"this token does not have the required permissions to perform this action"}]}"#);

        assert_eq!(app.emails().await.len(), 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn token_user_with_both_scopes() {
        let (app, user) = prepare().await;
        let token = user
            .db_new_scoped_token(
                "test-token",
                Some(vec![CrateScope::try_from(CRATE_NAME).unwrap()]),
                Some(vec![EndpointScope::TrustedPublishing]),
                None,
            )
            .await;

        let url = format!("/api/v1/crates/{}", CRATE_NAME);
        let body = serde_json::json!({ "crate": { "trustpub_only": true } });
        let response = token.patch::<()>(&url, body.to_string()).await;
        assert_snapshot!(response.status(), @"200 OK");

        assert!(!app.emails().await.is_empty());
    }
}

/// Cookie session with API MFA enabled cannot toggle `trustpub_only` without a grant (#13367).
#[tokio::test(flavor = "multi_thread")]
async fn trustpub_only_change_requires_api_mfa_grant() {
    use crates_io::models::{NewApiMfaGrant, NewWebauthnCredential};
    use crates_io::schema::users;
    use diesel::prelude::*;
    use diesel_async::RunQueryDsl;
    use serde_json::json;

    let (app, _, user) = TestApp::full().with_user().await;
    let mut conn = app.db_conn().await;

    let owner_id = user.as_model().id;
    CrateBuilder::new("foo_mfa_trustpub", owner_id)
        .trustpub_only(true)
        .expect_build(&mut conn)
        .await;

    diesel::update(users::table.find(owner_id))
        .set(users::api_mfa_enabled.eq(true))
        .execute(&mut conn)
        .await
        .unwrap();
    NewWebauthnCredential {
        user_id: owner_id,
        credential_id: b"dummy-credential-id",
        passkey_json: json!({ "dummy": true }),
        name: "test-passkey",
    }
    .insert(&mut conn)
    .await
    .unwrap();

    let url = "/api/v1/crates/foo_mfa_trustpub";
    let body = serde_json::json!({ "crate": { "trustpub_only": false } });
    let blocked = user.patch::<()>(url, body.to_string()).await;
    assert_snapshot!(blocked.status(), @"400 Bad Request");
    assert!(
        blocked.json()["errors"][0]["detail"]
            .as_str()
            .unwrap()
            .contains("Authorize for 15 minutes")
    );

    NewApiMfaGrant::for_user(owner_id)
        .insert(&conn)
        .await
        .unwrap();

    let allowed = user.patch::<()>(url, body.to_string()).await;
    assert_snapshot!(allowed.status(), @"200 OK");
    assert_eq!(allowed.json()["crate"]["trustpub_only"], false);
}
