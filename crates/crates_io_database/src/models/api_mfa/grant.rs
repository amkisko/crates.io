use chrono::{DateTime, Utc};
use diesel::dsl::now;
use diesel::prelude::*;
use diesel_async::{AsyncPgConnection, RunQueryDsl};

use crate::schema::api_mfa_grants;

/// Default lifetime of a browser-session API MFA grant.
pub const DEFAULT_GRANT_DURATION_SECS: i64 = 15 * 60;

/// A short-lived browser-session authorization after passkey verification.
#[derive(Clone, Debug, Queryable, Selectable, Identifiable)]
#[diesel(table_name = api_mfa_grants, check_for_backend(diesel::pg::Pg))]
pub struct ApiMfaGrant {
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub id: i64,
    pub user_id: i32,
}

/// Insertable browser-session authorization.
#[derive(Debug, Insertable)]
#[diesel(table_name = api_mfa_grants, check_for_backend(diesel::pg::Pg))]
pub struct NewApiMfaGrant {
    pub user_id: i32,
    pub expires_at: DateTime<Utc>,
}

impl ApiMfaGrant {
    /// Returns the latest non-expired browser-session grant for `user_id`.
    pub async fn active_browser_for_user(
        user_id: i32,
        mut conn: &AsyncPgConnection,
    ) -> QueryResult<Option<Self>> {
        api_mfa_grants::table
            .filter(api_mfa_grants::user_id.eq(user_id))
            .filter(api_mfa_grants::expires_at.gt(now))
            .order(api_mfa_grants::expires_at.desc())
            .select(Self::as_select())
            .first(&mut conn)
            .await
            .optional()
    }

    /// Deletes all grants for `user_id` (used when disabling API MFA).
    pub async fn delete_all_for_user(
        user_id: i32,
        mut conn: &AsyncPgConnection,
    ) -> QueryResult<usize> {
        diesel::delete(api_mfa_grants::table.filter(api_mfa_grants::user_id.eq(user_id)))
            .execute(&mut conn)
            .await
    }
}

impl NewApiMfaGrant {
    /// Creates a browser-session grant covering protected product actions for 15 minutes.
    pub fn for_user(user_id: i32) -> Self {
        Self {
            user_id,
            expires_at: Utc::now() + chrono::Duration::seconds(DEFAULT_GRANT_DURATION_SECS),
        }
    }

    /// Inserts the grant and returns the created row.
    pub async fn insert(&self, mut conn: &AsyncPgConnection) -> QueryResult<ApiMfaGrant> {
        diesel::insert_into(api_mfa_grants::table)
            .values(self)
            .returning(ApiMfaGrant::as_returning())
            .get_result(&mut conn)
            .await
    }
}
