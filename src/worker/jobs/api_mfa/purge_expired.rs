use crate::models::{ApiMfaEmailOtp, CliLoginSession};
use crate::schema::{
    api_mfa_challenges, api_mfa_grants, api_mfa_rate_limit_buckets, webauthn_ceremony_states,
};
use crate::worker::Environment;
use chrono::{TimeDelta, Utc};
use crates_io_worker::BackgroundJob;
use diesel::dsl::now;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::info;

/// Deletes expired API MFA and CLI login ceremony rows so tables do not grow without bound.
///
/// Enqueue at least every 15 minutes in production (e.g. Heroku Scheduler /
/// `crates-admin enqueue-job api_mfa_cleanup`) so `cli_login_sessions`
/// and MFA ceremony tables stay bounded. Watch
/// `cratesio_service_cli_login_sessions{status=…}` for growth between runs.
///
/// Retention:
/// - Pending challenges: kept for 24 hours after `expires_at`
/// - Terminal mutations: kept for 24 hours after `completed_at` for response replay
/// - Grants: deleted once expired
/// - Ceremony states: deleted once expired
/// - Email OTPs: deleted once expired or consumed
/// - CLI login sessions: deleted once expired or consumed (ciphertext cleared first)
/// - Inactive API MFA rate-limit buckets: kept for 24 hours after their last refill
///
/// Also clears `auth_state_json` on expired challenges immediately so JSONB TOAST
/// does not linger until the 24h challenge purge.
#[derive(Deserialize, Serialize)]
pub struct PurgeExpiredApiMfa;

impl BackgroundJob for PurgeExpiredApiMfa {
    const JOB_NAME: &'static str = "api_mfa::purge_expired";
    const DEDUPLICATED: bool = true;

    type Context = Arc<Environment>;

    async fn run(&self, ctx: Self::Context) -> anyhow::Result<()> {
        let mut conn = ctx.deadpool.get().await?;

        let auth_states_cleared = diesel::update(
            api_mfa_challenges::table
                .filter(api_mfa_challenges::expires_at.lt(now))
                .filter(api_mfa_challenges::auth_state_json.is_not_null()),
        )
        .set(api_mfa_challenges::auth_state_json.eq(None::<serde_json::Value>))
        .execute(&mut conn)
        .await?;

        let challenge_cutoff = Utc::now() - TimeDelta::days(1);
        let challenges_deleted = diesel::delete(
            api_mfa_challenges::table.filter(
                api_mfa_challenges::completed_at
                    .is_null()
                    .and(api_mfa_challenges::expires_at.lt(challenge_cutoff))
                    .or(api_mfa_challenges::completed_at.lt(challenge_cutoff)),
            ),
        )
        .execute(&mut conn)
        .await?;

        let grants_deleted =
            diesel::delete(api_mfa_grants::table.filter(api_mfa_grants::expires_at.lt(now)))
                .execute(&mut conn)
                .await?;

        let ceremonies_deleted = diesel::delete(
            webauthn_ceremony_states::table.filter(webauthn_ceremony_states::expires_at.lt(now)),
        )
        .execute(&mut conn)
        .await?;

        let email_otps_deleted = ApiMfaEmailOtp::purge_expired(&conn).await?;

        let cli_login_deleted = CliLoginSession::purge_expired(&conn).await?;

        let bucket_cutoff = Utc::now() - TimeDelta::days(1);
        let rate_limit_buckets_deleted = diesel::delete(
            api_mfa_rate_limit_buckets::table
                .filter(api_mfa_rate_limit_buckets::last_refill.lt(bucket_cutoff)),
        )
        .execute(&mut conn)
        .await?;

        info!(
            auth_states_cleared,
            challenges_deleted,
            grants_deleted,
            ceremonies_deleted,
            email_otps_deleted,
            cli_login_deleted,
            rate_limit_buckets_deleted,
            "Purged expired API MFA and CLI login rows"
        );

        Ok(())
    }
}
