use chrono::{DateTime, Utc};
use diesel::dsl::now;
use diesel::prelude::*;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::Value as JsonValue;

use crate::schema::webauthn_ceremony_states;

/// Default lifetime of an in-progress `WebAuthn` ceremony.
pub const DEFAULT_CEREMONY_DURATION_SECS: i64 = 5 * 60;

/// Ceremony kind for passkey registration.
pub const KIND_REGISTRATION: &str = "registration";

/// Ceremony kind for passkey authentication (manual authorize).
pub const KIND_AUTHENTICATION: &str = "authentication";

/// Server-side `WebAuthn` ceremony state (not stored in session cookies).
#[derive(Clone, Debug, Queryable, Selectable, Identifiable)]
#[diesel(table_name = webauthn_ceremony_states, check_for_backend(diesel::pg::Pg))]
pub struct WebauthnCeremonyState {
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub id: i64,
    pub kind: String,
    pub state_json: JsonValue,
    pub user_id: i32,
}

impl WebauthnCeremonyState {
    /// Replaces any existing ceremony of `kind` for `user_id` with `state_json`.
    pub async fn store(
        user_id: i32,
        kind: &str,
        state_json: JsonValue,
        mut conn: &AsyncPgConnection,
    ) -> QueryResult<()> {
        diesel::delete(
            webauthn_ceremony_states::table
                .filter(webauthn_ceremony_states::user_id.eq(user_id))
                .filter(webauthn_ceremony_states::kind.eq(kind)),
        )
        .execute(&mut conn)
        .await?;

        diesel::insert_into(webauthn_ceremony_states::table)
            .values((
                webauthn_ceremony_states::user_id.eq(user_id),
                webauthn_ceremony_states::kind.eq(kind),
                webauthn_ceremony_states::state_json.eq(state_json),
                webauthn_ceremony_states::expires_at
                    .eq(Utc::now() + chrono::Duration::seconds(DEFAULT_CEREMONY_DURATION_SECS)),
            ))
            .execute(&mut conn)
            .await?;

        Ok(())
    }

    /// Atomically takes (and deletes) a non-expired ceremony of `kind` for `user_id`.
    pub async fn take(
        user_id: i32,
        kind: &str,
        mut conn: &AsyncPgConnection,
    ) -> QueryResult<Option<JsonValue>> {
        diesel::delete(
            webauthn_ceremony_states::table
                .filter(webauthn_ceremony_states::user_id.eq(user_id))
                .filter(webauthn_ceremony_states::kind.eq(kind))
                .filter(webauthn_ceremony_states::expires_at.gt(now)),
        )
        .returning(webauthn_ceremony_states::state_json)
        .get_result(&mut conn)
        .await
        .optional()
    }

    /// Deletes every in-progress ceremony for `user_id`.
    ///
    /// Credential revocation uses this to ensure serialized ceremony state
    /// cannot outlive the credential set it was created from.
    pub async fn delete_all_for_user(
        user_id: i32,
        mut conn: &AsyncPgConnection,
    ) -> QueryResult<usize> {
        diesel::delete(
            webauthn_ceremony_states::table.filter(webauthn_ceremony_states::user_id.eq(user_id)),
        )
        .execute(&mut conn)
        .await
    }
}
