use crate::util::TestApp;
use chrono::{TimeDelta, Utc};
use crates_io::models::{NewUserSecurityEvent, SecurityEventType};
use crates_io::schema::user_security_events;
use crates_io::worker::jobs::security_events::PurgeExpiredSecurityEvents;
use crates_io_worker::BackgroundJob;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use serde_json::json;

#[tokio::test(flavor = "multi_thread")]
async fn purge_old_security_events() -> anyhow::Result<()> {
    let (app, _, user) = TestApp::full().with_user().await;
    let mut conn = app.db_conn().await;
    let user_id = user.as_model().id;

    let keep = NewUserSecurityEvent::new(
        user_id,
        SecurityEventType::SessionLogin,
        None,
        None,
        json!({}),
    )
    .insert(&mut conn)
    .await?
    .unwrap();

    let old_id = NewUserSecurityEvent::new(
        user_id,
        SecurityEventType::TokenCreated,
        None,
        None,
        json!({}),
    )
    .insert(&mut conn)
    .await?
    .unwrap()
    .id;

    diesel::update(user_security_events::table.find(old_id))
        .set(user_security_events::created_at.eq(Utc::now() - TimeDelta::days(91)))
        .execute(&mut conn)
        .await?;

    PurgeExpiredSecurityEvents.enqueue(&conn).await?;
    app.run_pending_background_jobs().await;

    let remaining: Vec<i64> = user_security_events::table
        .select(user_security_events::id)
        .filter(user_security_events::user_id.eq(user_id))
        .load(&mut conn)
        .await?;

    assert_eq!(remaining, vec![keep.id]);
    Ok(())
}
