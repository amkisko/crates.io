use crate::models::UserSecurityEvent;
use crate::worker::Environment;
use chrono::{TimeDelta, Utc};
use crates_io_worker::BackgroundJob;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::info;

/// How long security activity events are retained before purge.
pub const SECURITY_EVENT_RETENTION_DAYS: i64 = 90;

/// Deletes `user_security_events` older than [`SECURITY_EVENT_RETENTION_DAYS`].
///
/// Enqueue daily in production (e.g. `crates-admin enqueue-job security_events_cleanup`).
#[derive(Deserialize, Serialize)]
pub struct PurgeExpiredSecurityEvents;

impl BackgroundJob for PurgeExpiredSecurityEvents {
    const JOB_NAME: &'static str = "security_events::purge_expired";
    const DEDUPLICATED: bool = true;

    type Context = Arc<Environment>;

    async fn run(&self, ctx: Self::Context) -> anyhow::Result<()> {
        let mut conn = ctx.deadpool.get().await?;
        let cutoff = Utc::now() - TimeDelta::days(SECURITY_EVENT_RETENTION_DAYS);
        let deleted = UserSecurityEvent::delete_older_than(cutoff, &mut conn).await?;
        info!(deleted, %cutoff, "Purged expired user security events");
        Ok(())
    }
}
