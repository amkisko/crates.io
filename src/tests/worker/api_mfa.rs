use crate::util::TestApp;
use chrono::{TimeDelta, Utc};
use crates_io::schema::{
    api_mfa_challenges, api_mfa_grants, cli_login_sessions, users, webauthn_ceremony_states,
};
use crates_io::worker::jobs::api_mfa::PurgeExpiredApiMfa;
use crates_io_worker::BackgroundJob;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use serde_json::json;

#[tokio::test(flavor = "multi_thread")]
async fn purge_expired_api_mfa_rows() -> anyhow::Result<()> {
    let (app, _, user) = TestApp::full().with_user().await;
    let mut conn = app.db_conn().await;
    let user_id = user.as_model().id;

    diesel::insert_into(api_mfa_challenges::table)
        .values((
            api_mfa_challenges::id.eq("stp_keep_recent"),
            api_mfa_challenges::user_id.eq(user_id),
            api_mfa_challenges::operation.eq("publish"),
            api_mfa_challenges::mutation_fingerprint.eq(vec![1; 32]),
            api_mfa_challenges::operation_summary.eq("Publish keep"),
            api_mfa_challenges::expires_at.eq(Utc::now() + TimeDelta::minutes(5)),
            api_mfa_challenges::auth_state_json.eq(Some(json!({ "state": true }))),
        ))
        .execute(&mut conn)
        .await?;

    diesel::insert_into(api_mfa_challenges::table)
        .values((
            api_mfa_challenges::id.eq("stp_clear_auth_state"),
            api_mfa_challenges::user_id.eq(user_id),
            api_mfa_challenges::operation.eq("publish"),
            api_mfa_challenges::mutation_fingerprint.eq(vec![2; 32]),
            api_mfa_challenges::operation_summary.eq("Publish clear"),
            api_mfa_challenges::expires_at.eq(Utc::now() - TimeDelta::hours(1)),
            api_mfa_challenges::auth_state_json.eq(Some(json!({ "state": true }))),
        ))
        .execute(&mut conn)
        .await?;

    diesel::insert_into(api_mfa_challenges::table)
        .values((
            api_mfa_challenges::id.eq("stp_delete_old"),
            api_mfa_challenges::user_id.eq(user_id),
            api_mfa_challenges::operation.eq("publish"),
            api_mfa_challenges::mutation_fingerprint.eq(vec![3; 32]),
            api_mfa_challenges::operation_summary.eq("Publish old"),
            api_mfa_challenges::expires_at.eq(Utc::now() - TimeDelta::days(2)),
        ))
        .execute(&mut conn)
        .await?;

    diesel::insert_into(api_mfa_grants::table)
        .values((
            api_mfa_grants::user_id.eq(user_id),
            api_mfa_grants::expires_at.eq(Utc::now() - TimeDelta::minutes(1)),
        ))
        .execute(&mut conn)
        .await?;

    diesel::insert_into(api_mfa_grants::table)
        .values((
            api_mfa_grants::user_id.eq(user_id),
            api_mfa_grants::expires_at.eq(Utc::now() + TimeDelta::minutes(15)),
        ))
        .execute(&mut conn)
        .await?;

    diesel::insert_into(webauthn_ceremony_states::table)
        .values((
            webauthn_ceremony_states::user_id.eq(user_id),
            webauthn_ceremony_states::kind.eq("authentication"),
            webauthn_ceremony_states::state_json.eq(json!({ "x": 1 })),
            webauthn_ceremony_states::expires_at.eq(Utc::now() - TimeDelta::minutes(1)),
        ))
        .execute(&mut conn)
        .await?;

    diesel::insert_into(cli_login_sessions::table)
        .values((
            cli_login_sessions::id.eq("login_expired"),
            cli_login_sessions::status.eq("ready"),
            cli_login_sessions::confirmation_code_hash.eq(vec![0u8; 32]),
            cli_login_sessions::poll_secret_hash.eq(vec![1u8; 32]),
            cli_login_sessions::sealed_token.eq(Some("cio_should_be_purged")),
            cli_login_sessions::expires_at.eq(Utc::now() - TimeDelta::minutes(1)),
        ))
        .execute(&mut conn)
        .await?;

    diesel::insert_into(cli_login_sessions::table)
        .values((
            cli_login_sessions::id.eq("login_keep"),
            cli_login_sessions::status.eq("pending"),
            cli_login_sessions::confirmation_code_hash.eq(vec![0u8; 32]),
            cli_login_sessions::poll_secret_hash.eq(vec![1u8; 32]),
            cli_login_sessions::expires_at.eq(Utc::now() + TimeDelta::minutes(5)),
        ))
        .execute(&mut conn)
        .await?;

    PurgeExpiredApiMfa.enqueue(&conn).await?;
    app.run_pending_background_jobs().await;

    let challenge_ids: Vec<String> = api_mfa_challenges::table
        .select(api_mfa_challenges::id)
        .order(api_mfa_challenges::id.asc())
        .load(&mut conn)
        .await?;
    assert_eq!(
        challenge_ids,
        vec![
            "stp_clear_auth_state".to_string(),
            "stp_keep_recent".to_string()
        ]
    );

    let auth_state: Option<serde_json::Value> = api_mfa_challenges::table
        .find("stp_clear_auth_state")
        .select(api_mfa_challenges::auth_state_json)
        .first(&mut conn)
        .await?;
    assert!(auth_state.is_none());

    let grant_count: i64 = api_mfa_grants::table
        .filter(api_mfa_grants::user_id.eq(user_id))
        .count()
        .get_result(&mut conn)
        .await?;
    assert_eq!(grant_count, 1);

    let ceremony_count: i64 = webauthn_ceremony_states::table
        .filter(webauthn_ceremony_states::user_id.eq(user_id))
        .count()
        .get_result(&mut conn)
        .await?;
    assert_eq!(ceremony_count, 0);

    let cli_ids: Vec<String> = cli_login_sessions::table
        .select(cli_login_sessions::id)
        .order(cli_login_sessions::id.asc())
        .load(&mut conn)
        .await?;
    assert_eq!(cli_ids, vec!["login_keep".to_string()]);

    // Keep the users row referenced so FK cleanup is tidy when the schema drops.
    let _: bool = users::table
        .find(user_id)
        .select(users::api_mfa_enabled)
        .first(&mut conn)
        .await?;

    Ok(())
}
