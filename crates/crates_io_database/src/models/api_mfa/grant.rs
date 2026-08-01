use chrono::{DateTime, Utc};
use diesel::dsl::now;
use diesel::prelude::*;
use diesel_async::{AsyncPgConnection, RunQueryDsl};

use crate::schema::api_mfa_grants;

/// Default lifetime of an API MFA grant after passkey verification.
pub const DEFAULT_GRANT_DURATION_SECS: i64 = 15 * 60;
/// Maximum lifetime of an exact mutation-authorization grant.
pub const MUTATION_GRANT_DURATION_SECS: i64 = 5 * 60;

/// A short-lived grant allowing API token actions after passkey verification.
#[derive(Clone, Debug, Queryable, Selectable, Identifiable)]
#[diesel(table_name = api_mfa_grants, check_for_backend(diesel::pg::Pg))]
pub struct ApiMfaGrant {
    pub api_token_id: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub crate_name: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub id: i64,
    pub mutation_fingerprint: Option<Vec<u8>>,
    pub operation: Option<String>,
    pub user_id: i32,
}

/// Insertable row for a new API MFA grant.
#[derive(Debug, Insertable)]
#[diesel(table_name = api_mfa_grants, check_for_backend(diesel::pg::Pg))]
pub struct NewApiMfaGrant {
    pub user_id: i32,
    pub api_token_id: Option<i32>,
    pub operation: Option<String>,
    pub crate_name: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub mutation_fingerprint: Option<Vec<u8>>,
}

impl ApiMfaGrant {
    /// Returns whether there is a non-expired grant covering this auth + operation.
    ///
    /// - A grant with `operation = NULL` is a cookie-only wildcard (manual authorize).
    /// - Otherwise the grant must match the operation, crate, and mutation fingerprint.
    /// - `api_token_id = NULL` grants never cover API-token requests.
    /// - Token-bound grants match only when `api_token_id` equals the request token.
    /// - Cookie requests (`api_token_id = None`) accept only `api_token_id IS NULL` grants.
    pub async fn has_active(
        user_id: i32,
        api_token_id: Option<i32>,
        operation: &str,
        crate_name: Option<&str>,
        mutation_fingerprint: &[u8],
        mut conn: &AsyncPgConnection,
    ) -> QueryResult<bool> {
        match api_token_id {
            Some(token_id) => {
                diesel::select(diesel::dsl::exists(
                    api_mfa_grants::table
                        .filter(api_mfa_grants::user_id.eq(user_id))
                        .filter(api_mfa_grants::expires_at.gt(now))
                        .filter(api_mfa_grants::api_token_id.eq(token_id))
                        .filter(api_mfa_grants::operation.eq(operation))
                        .filter(api_mfa_grants::crate_name.is_not_distinct_from(crate_name))
                        .filter(api_mfa_grants::mutation_fingerprint.eq(mutation_fingerprint)),
                ))
                .get_result(&mut conn)
                .await
            }
            None => {
                diesel::select(diesel::dsl::exists(
                    api_mfa_grants::table
                        .filter(api_mfa_grants::user_id.eq(user_id))
                        .filter(api_mfa_grants::expires_at.gt(now))
                        .filter(
                            api_mfa_grants::operation
                                .is_null()
                                .and(api_mfa_grants::mutation_fingerprint.is_null())
                                .or(api_mfa_grants::operation
                                    .eq(operation)
                                    .and(
                                        api_mfa_grants::crate_name.is_not_distinct_from(crate_name),
                                    )
                                    .and(
                                        api_mfa_grants::mutation_fingerprint
                                            .eq(mutation_fingerprint),
                                    )),
                        )
                        .filter(api_mfa_grants::api_token_id.is_null()),
                ))
                .get_result(&mut conn)
                .await
            }
        }
    }

    /// Returns the latest non-expired browser wildcard grant for `user_id`, if any.
    ///
    /// Token-bound and operation-scoped grants must not be presented as browser
    /// authorization because they cannot authorize cookie-authenticated requests.
    pub async fn active_browser_for_user(
        user_id: i32,
        mut conn: &AsyncPgConnection,
    ) -> QueryResult<Option<Self>> {
        api_mfa_grants::table
            .filter(api_mfa_grants::user_id.eq(user_id))
            .filter(api_mfa_grants::expires_at.gt(now))
            .filter(api_mfa_grants::api_token_id.is_null())
            .filter(api_mfa_grants::operation.is_null())
            .filter(api_mfa_grants::mutation_fingerprint.is_null())
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
    /// Creates a cookie-only wildcard grant covering any operation for 15 minutes.
    ///
    /// `api_token_id` is `NULL`; API-token requests require exact token-bound grants.
    pub fn for_user(user_id: i32) -> Self {
        Self {
            user_id,
            api_token_id: None,
            operation: None,
            crate_name: None,
            mutation_fingerprint: None,
            expires_at: Utc::now() + chrono::Duration::seconds(DEFAULT_GRANT_DURATION_SECS),
        }
    }

    /// Creates a grant scoped to a single dangerous operation, crate, and API token.
    pub fn for_operation(
        user_id: i32,
        api_token_id: i32,
        operation: impl Into<String>,
        crate_name: Option<String>,
        mutation_fingerprint: Vec<u8>,
    ) -> Self {
        Self {
            user_id,
            api_token_id: Some(api_token_id),
            operation: Some(operation.into()),
            crate_name,
            mutation_fingerprint: Some(mutation_fingerprint),
            expires_at: Utc::now() + chrono::Duration::seconds(MUTATION_GRANT_DURATION_SECS),
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
