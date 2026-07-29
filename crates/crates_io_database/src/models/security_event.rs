//! Durable user security activity events (logins, tokens, API MFA).
//!
//! Privacy constraints (GDPR / CCPA):
//! - 90-day retention (`security_events::purge_expired`)
//! - `ON DELETE CASCADE` from `users` for account erasure
//! - Metadata allowlist only (no UA, geo, emails, free-form dumps)
//! - IPs truncated at write (/24 IPv4, /56 IPv6); `token_used` never stores IP
//! - Owner-only API access; not for analytics

use crate::models::{ApiToken, User};
use crate::pg_enum;
use crate::schema::user_security_events;
use bon::Builder;
use chrono::{DateTime, NaiveDate, Utc};
use diesel::prelude::*;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::{Map, Value as JsonValue};
use std::net::IpAddr;
use tracing::warn;

/// Allowed `metadata` keys. Unknown keys are dropped at write time.
pub const METADATA_ALLOWLIST: &[&str] = &[
    "token_name",
    "crate_name",
    "operation",
    "passkey_name",
    "operation_id",
];

pg_enum! {
    /// Event kinds stored in `user_security_events.event_type`.
    pub enum SecurityEventType {
        SessionLogin = 0,
        CliLoginApproved = 1,
        TokenCreated = 2,
        TokenRevoked = 3,
        TokenRevokedGithub = 4,
        TokenUsed = 5,
        ApiMfaEnabled = 6,
        ApiMfaDisabled = 7,
        PasskeyRegistered = 8,
        PasskeyDeleted = 9,
        ApiMfaAuthorized = 10,
        ApiMfaChallengeVerified = 11,
        EmailChanged = 12,
        SessionLogoutAll = 13,
    }
}

impl From<SecurityEventType> for &'static str {
    fn from(event: SecurityEventType) -> Self {
        match event {
            SecurityEventType::SessionLogin => "session_login",
            SecurityEventType::CliLoginApproved => "cli_login_approved",
            SecurityEventType::TokenCreated => "token_created",
            SecurityEventType::TokenRevoked => "token_revoked",
            SecurityEventType::TokenRevokedGithub => "token_revoked_github",
            SecurityEventType::TokenUsed => "token_used",
            SecurityEventType::ApiMfaEnabled => "api_mfa_enabled",
            SecurityEventType::ApiMfaDisabled => "api_mfa_disabled",
            SecurityEventType::PasskeyRegistered => "passkey_registered",
            SecurityEventType::PasskeyDeleted => "passkey_deleted",
            SecurityEventType::ApiMfaAuthorized => "api_mfa_authorized",
            SecurityEventType::ApiMfaChallengeVerified => "api_mfa_challenge_verified",
            SecurityEventType::EmailChanged => "email_changed",
            SecurityEventType::SessionLogoutAll => "session_logout_all",
        }
    }
}

impl From<SecurityEventType> for String {
    fn from(event: SecurityEventType) -> Self {
        let string: &'static str = event.into();
        string.into()
    }
}

/// A row in `user_security_events`.
#[derive(Debug, Clone, HasQuery, Identifiable, Associations)]
#[diesel(
    table_name = user_security_events,
    belongs_to(User, foreign_key = user_id),
    belongs_to(ApiToken, foreign_key = api_token_id),
)]
pub struct UserSecurityEvent {
    pub id: i64,
    pub user_id: i32,
    pub api_token_id: Option<i32>,
    pub event_type: SecurityEventType,
    pub ip: Option<String>,
    pub metadata: JsonValue,
    pub event_day: Option<NaiveDate>,
    pub created_at: DateTime<Utc>,
}

/// Insert payload for a new security activity event.
#[derive(Debug, Insertable, Builder)]
#[diesel(table_name = user_security_events, check_for_backend(diesel::pg::Pg))]
pub struct NewUserSecurityEvent {
    pub user_id: i32,
    pub api_token_id: Option<i32>,
    pub event_type: SecurityEventType,
    pub ip: Option<String>,
    #[builder(default = serde_json::json!({}))]
    pub metadata: JsonValue,
    pub event_day: Option<NaiveDate>,
}

impl NewUserSecurityEvent {
    /// Build a non-token-use event (no `event_day`).
    ///
    /// `ip` is truncated (/24 IPv4, /56 IPv6). `metadata` is filtered to [`METADATA_ALLOWLIST`].
    pub fn new(
        user_id: i32,
        event_type: SecurityEventType,
        api_token_id: Option<i32>,
        ip: Option<String>,
        metadata: JsonValue,
    ) -> Self {
        Self {
            user_id,
            api_token_id,
            event_type,
            ip: ip.and_then(|s| truncate_ip_for_storage(&s)),
            metadata: filter_metadata(metadata),
            event_day: None,
        }
    }

    /// Build a `token_used` event for the current UTC day (unique per token/day).
    ///
    /// Never stores IP (usage volume must not become a location history).
    pub fn token_used(user_id: i32, api_token_id: i32, metadata: JsonValue) -> Self {
        Self {
            user_id,
            api_token_id: Some(api_token_id),
            event_type: SecurityEventType::TokenUsed,
            ip: None,
            metadata: filter_metadata(metadata),
            event_day: Some(Utc::now().date_naive()),
        }
    }

    /// Insert the event. Returns `Ok(None)` when a `token_used` conflict is ignored.
    pub async fn insert(
        &self,
        conn: &mut AsyncPgConnection,
    ) -> QueryResult<Option<UserSecurityEvent>> {
        if self.event_type == SecurityEventType::TokenUsed {
            diesel::insert_into(user_security_events::table)
                .values(self)
                .on_conflict((
                    user_security_events::api_token_id,
                    user_security_events::event_day,
                ))
                .do_nothing()
                .returning(UserSecurityEvent::as_returning())
                .get_result(conn)
                .await
                .optional()
        } else {
            diesel::insert_into(user_security_events::table)
                .values(self)
                .returning(UserSecurityEvent::as_returning())
                .get_result(conn)
                .await
                .map(Some)
        }
    }

    /// Best-effort insert: log failures and never fail the parent request.
    ///
    /// Does not include IP or metadata in the log line (LOGGING.md).
    pub async fn record(&self, conn: &mut AsyncPgConnection) {
        if let Err(err) = self.insert(conn).await {
            warn!(
                user_id = self.user_id,
                event_type = ?self.event_type,
                "failed to record security event: {err}"
            );
        }
    }
}

impl UserSecurityEvent {
    /// List events for a user newest-first, optionally after a seek `id`.
    pub async fn for_user(
        user_id: i32,
        after_id: Option<i64>,
        limit: i64,
        conn: &mut AsyncPgConnection,
    ) -> QueryResult<Vec<Self>> {
        let mut query = UserSecurityEvent::query()
            .filter(user_security_events::user_id.eq(user_id))
            .order(user_security_events::id.desc())
            .limit(limit)
            .into_boxed();

        if let Some(after_id) = after_id {
            query = query.filter(user_security_events::id.lt(after_id));
        }

        query.load(conn).await
    }

    /// Count events for a user (for list `meta.total`).
    pub async fn count_for_user(user_id: i32, conn: &mut AsyncPgConnection) -> QueryResult<i64> {
        user_security_events::table
            .filter(user_security_events::user_id.eq(user_id))
            .count()
            .get_result(conn)
            .await
    }

    /// Delete events older than `cutoff` (retention purge).
    pub async fn delete_older_than(
        cutoff: DateTime<Utc>,
        conn: &mut AsyncPgConnection,
    ) -> QueryResult<usize> {
        diesel::delete(
            user_security_events::table.filter(user_security_events::created_at.lt(cutoff)),
        )
        .execute(conn)
        .await
    }
}

/// Keep only allowlisted metadata keys with string values (plus null `crate_name`).
fn filter_metadata(metadata: JsonValue) -> JsonValue {
    let JsonValue::Object(map) = metadata else {
        return JsonValue::Object(Map::new());
    };

    let filtered = map
        .into_iter()
        .filter(|(key, value)| {
            METADATA_ALLOWLIST.contains(&key.as_str()) && (value.is_string() || value.is_null())
        })
        .collect::<Map<_, _>>();

    JsonValue::Object(filtered)
}

/// Truncate an IP for durable storage: IPv4 `/24`, IPv6 `/56`.
///
/// Unparseable values are dropped rather than stored raw.
pub fn truncate_ip_for_storage(ip: &str) -> Option<String> {
    let parsed: IpAddr = ip.parse().ok()?;
    match parsed {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            Some(format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2]))
        }
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            // /56 keeps the first 56 bits (3.5 hextets): seg0, seg1, seg2, and high byte of seg3.
            let seg3 = segments[3] & 0xff00;
            Some(format!(
                "{:x}:{:x}:{:x}:{:x}::/56",
                segments[0], segments[1], segments[2], seg3
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn filter_metadata_drops_unknown_keys() {
        let filtered = filter_metadata(json!({
            "token_name": "ci",
            "user_agent": "evil",
            "operation": "publish",
            "email": "a@b.c",
            "crate_name": null,
        }));
        assert_eq!(
            filtered,
            json!({
                "token_name": "ci",
                "operation": "publish",
                "crate_name": null,
            })
        );
    }

    #[test]
    fn truncate_ipv4() {
        assert_eq!(
            truncate_ip_for_storage("203.0.113.45").as_deref(),
            Some("203.0.113.0/24")
        );
    }

    #[test]
    fn truncate_ipv6() {
        let truncated = truncate_ip_for_storage("2001:db8:abcd:1234:5678::1").unwrap();
        assert!(truncated.ends_with("::/56"));
        assert!(truncated.starts_with("2001:db8:abcd:"));
    }

    #[test]
    fn truncate_rejects_garbage() {
        assert_eq!(truncate_ip_for_storage("not-an-ip"), None);
        assert_eq!(truncate_ip_for_storage("unknown"), None);
    }
}
