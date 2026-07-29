use crate::util::{MockCookieUser, RequestHelper, Response, TestApp};
use http::StatusCode;
use insta::assert_snapshot;
use regex::regex;
use serde_json::{Value, json};

mod publish_notifications;

pub trait MockEmailHelper: RequestHelper {
    // TODO: I don't like the name of this method or `update_email` on the `MockCookieUser` impl;
    // this is starting to look like a builder might help?
    // I want to explore alternative abstractions in any case.
    async fn update_email_more_control(&self, user_id: i32, email: Option<&str>) -> Response<()> {
        let body = json!({"user": { "email": email }});
        let url = format!("/api/v1/users/{user_id}");
        self.put(&url, body.to_string()).await
    }

    async fn update_email_with_code(
        &self,
        user_id: i32,
        email: Option<&str>,
        email_code: Option<&str>,
    ) -> Response<()> {
        let body = json!({
            "user": { "email": email },
            "email_code": email_code,
        });
        let url = format!("/api/v1/users/{user_id}");
        self.put(&url, body.to_string()).await
    }
}

impl MockEmailHelper for crate::util::MockCookieUser {}
impl MockEmailHelper for crate::util::MockAnonymousUser {}

impl crate::util::MockCookieUser {
    /// Stages or replaces email. When the current address is verified, sends an OTP first.
    pub async fn update_email(&self, email: &str) {
        let model = self.as_model();
        let me = self.show_me().await;
        let response = if me.user.email_verified {
            let otp = request_email_code_for_user(self).await;
            self.update_email_with_code(model.id, Some(email), Some(&otp))
                .await
        } else {
            self.update_email_more_control(model.id, Some(email)).await
        };
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.json(), json!({ "ok": true }));
    }
}

async fn request_email_code_for_user(user: &MockCookieUser) -> String {
    let before = user.app().emails().await.len();
    let sent = user
        .post::<Value>("/api/v1/me/mfa/email_codes", "")
        .await
        .good();
    assert!(sent["expires_at"].is_string());
    assert!(sent["sent_to_hint"].as_str().unwrap().contains('@'));

    let emails = user.app().emails().await;
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

/// Given a crates.io user, check to make sure that the user
/// cannot add to the database an empty string or null as
/// their email. If an attempt is made, `update_user.rs` will
/// return an error indicating that an empty email cannot be
/// added.
///
/// This is checked on the frontend already, but I'd like to
/// make sure that a user cannot get around that and delete
/// their email by adding an empty string.
#[tokio::test(flavor = "multi_thread")]
async fn test_empty_email_not_added() {
    let (_app, _anon, user) = TestApp::init().with_user().await;
    let model = user.as_model();

    let response = user.update_email_more_control(model.id, Some("")).await;
    assert_snapshot!(response.status(), @"400 Bad Request");
    assert_snapshot!(response.text(), @r#"{"errors":[{"detail":"empty email rejected"}]}"#);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_ignore_empty() {
    let (_app, _anon, user) = TestApp::init().with_user().await;
    let model = user.as_model();

    let url = format!("/api/v1/users/{}", model.id);
    let payload = json!({"user": {}});
    let response = user.put::<()>(&url, payload.to_string()).await;
    assert_snapshot!(response.status(), @"200 OK");
    assert_snapshot!(response.text(), @r#"{"ok":true}"#);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_ignore_nulls() {
    let (_app, _anon, user) = TestApp::init().with_user().await;
    let model = user.as_model();

    let url = format!("/api/v1/users/{}", model.id);
    let payload = json!({"user": { "email": null }});
    let response = user.put::<()>(&url, payload.to_string()).await;
    assert_snapshot!(response.status(), @"200 OK");
    assert_snapshot!(response.text(), @r#"{"ok":true}"#);
}

/// Check to make sure that neither other signed in users nor anonymous users can edit another
/// user's email address.
///
/// If an attempt is made, the endpoint will return an error indicating that the current user
/// does not match the requested user.
#[tokio::test(flavor = "multi_thread")]
async fn test_other_users_cannot_change_my_email() {
    let (app, anon, user) = TestApp::init().with_user().await;
    let another_user = app.db_new_user("not_me").await;
    let another_user_model = another_user.as_model();

    let response = user
        .update_email_more_control(
            another_user_model.id,
            Some("pineapple@pineapples.pineapple"),
        )
        .await;
    assert_snapshot!(response.status(), @"400 Bad Request");
    assert_snapshot!(response.text(), @r#"{"errors":[{"detail":"current user does not match requested user"}]}"#);

    let response = anon
        .update_email_more_control(
            another_user_model.id,
            Some("pineapple@pineapples.pineapple"),
        )
        .await;
    assert_snapshot!(response.status(), @"403 Forbidden");
    assert_snapshot!(response.text(), @r#"{"errors":[{"detail":"this action requires authentication"}]}"#);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_invalid_email_address() {
    let (_app, _, user) = TestApp::init().with_user().await;
    let model = user.as_model();

    let response = user.update_email_more_control(model.id, Some("foo")).await;
    assert_snapshot!(response.status(), @"400 Bad Request");
    assert_snapshot!(response.text(), @r#"{"errors":[{"detail":"invalid email address"}]}"#);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_invalid_json() {
    let (_app, _anon, user) = TestApp::init().with_user().await;
    let model = user.as_model();

    let url = format!("/api/v1/users/{}", model.id);
    let response = user.put::<()>(&url, r#"{ "user": foo }"#).await;
    assert_snapshot!(response.status(), @"400 Bad Request");
    assert_snapshot!(response.text(), @r#"{"errors":[{"detail":"Failed to parse the request body as JSON: user: expected ident at line 1 column 12"}]}"#);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_verified_email_change_requires_otp() {
    let (_app, _, user) = TestApp::init().with_user().await;
    let model = user.as_model();

    let response = user
        .update_email_more_control(model.id, Some("new@example.com"))
        .await;
    assert_snapshot!(response.status(), @"400 Bad Request");
    assert_snapshot!(
        response.text(),
        @r#"{"errors":[{"detail":"email verification code required; request one with POST /api/v1/me/mfa/email_codes"}]}"#
    );

    user.update_email("new@example.com").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_verified_email_stays_until_pending_confirmed() {
    use crates_io::schema::emails;
    use diesel::prelude::*;
    use diesel_async::RunQueryDsl;

    let (app, _, user) = TestApp::init().with_user().await;
    let model = user.as_model();
    let mut conn = app.db_conn().await;

    let old_email: String = emails::table
        .filter(emails::user_id.eq(model.id))
        .select(emails::email)
        .first(&mut conn)
        .await
        .unwrap();

    user.update_email("pending@example.com").await;

    let me = user.show_me().await;
    assert_eq!(me.user.email.as_deref(), Some(old_email.as_str()));
    assert!(me.user.email_verified);
    assert_eq!(
        me.user.email_pending.as_deref(),
        Some("pending@example.com")
    );

    let token: String = emails::table
        .filter(emails::user_id.eq(model.id))
        .select(emails::token)
        .first(&mut conn)
        .await
        .unwrap();

    user.confirm_email(&token).await;

    let me = user.show_me().await;
    assert_eq!(me.user.email.as_deref(), Some("pending@example.com"));
    assert!(me.user.email_verified);
    assert_eq!(me.user.email_pending, None);
}
