use chrono::{DateTime, Utc};
use diesel::dsl::now;
use diesel::prelude::*;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use rand::distr::{Alphanumeric, SampleString};
use serde_json::Value as JsonValue;

use crate::schema::api_mfa_challenges;

/// Default lifetime of a pending mutation-authorization record.
pub const DEFAULT_CHALLENGE_DURATION_SECS: i64 = 5 * 60;
/// Time allowed to finish or retry a claimed mutation request body.
pub const MUTATION_RECEIVE_LEASE_SECS: i64 = 30 * 60;
/// Minimum time a committed idempotent response remains replayable.
pub const MUTATION_TERMINAL_RETENTION_SECS: i64 = 24 * 60 * 60;

/// Maximum non-expired pending challenges a user may hold at once.
pub const MAX_PENDING_CHALLENGES_PER_USER: i64 = 10;

const MUTATION_ID_PREFIX: &str = "mut_";
const POLL_TOKEN_PREFIX: &str = "poll_";
const CHALLENGE_ID_LENGTH: usize = 32;

/// A pending or acknowledged API MFA operation challenge for CLI clients.
#[derive(Clone, Debug, Queryable, Selectable, Identifiable)]
#[diesel(table_name = api_mfa_challenges, check_for_backend(diesel::pg::Pg))]
pub struct ApiMfaChallenge {
    pub allow_pending: Option<bool>,
    pub api_token_id: Option<i32>,
    pub auth_state_json: Option<JsonValue>,
    pub callback_url: Option<String>,
    pub crate_name: Option<String>,
    pub descriptor_json: Option<JsonValue>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub id: String,
    pub idempotent_final: bool,
    pub mutation_fingerprint: Vec<u8>,
    pub mutation_state: Option<String>,
    pub operation: String,
    pub operation_summary: String,
    pub poll_token: Option<String>,
    pub preflight_id: Option<String>,
    pub receive_expires_at: Option<DateTime<Utc>>,
    pub request_endpoint: Option<String>,
    pub request_method: Option<String>,
    pub request_sha256: Option<Vec<u8>>,
    pub request_size: Option<i64>,
    pub response_body: Option<Vec<u8>>,
    pub response_headers: Option<JsonValue>,
    pub response_status: Option<i32>,
    pub completed_at: Option<DateTime<Utc>>,
    pub user_id: i32,
    pub verified_at: Option<DateTime<Utc>>,
}

/// Minimal mutation state loaded by the unauthenticated poll endpoint.
#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = api_mfa_challenges, check_for_backend(diesel::pg::Pg))]
pub struct MutationPollStatus {
    pub id: String,
    pub mutation_state: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub verified_at: Option<DateTime<Utc>>,
    pub receive_expires_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub idempotent_final: bool,
}

/// Insertable row for a new API MFA challenge.
#[derive(Debug, Insertable)]
#[diesel(table_name = api_mfa_challenges, check_for_backend(diesel::pg::Pg))]
pub struct NewApiMfaChallenge {
    pub id: String,
    pub idempotent_final: bool,
    pub user_id: i32,
    pub api_token_id: Option<i32>,
    pub allow_pending: Option<bool>,
    pub callback_url: Option<String>,
    pub operation: String,
    pub crate_name: Option<String>,
    pub mutation_fingerprint: Vec<u8>,
    pub mutation_state: Option<String>,
    pub operation_summary: String,
    pub descriptor_json: Option<JsonValue>,
    pub request_method: Option<String>,
    pub request_endpoint: Option<String>,
    pub request_sha256: Option<Vec<u8>>,
    pub request_size: Option<i64>,
    pub poll_token: Option<String>,
    pub preflight_id: Option<String>,
    pub expires_at: DateTime<Utc>,
}

/// Exact mutation details bound to a new API MFA challenge.
#[derive(Debug)]
pub struct NewApiMfaChallengeOperation {
    pub operation: String,
    pub crate_name: Option<String>,
    pub mutation_fingerprint: Vec<u8>,
    pub operation_summary: String,
    pub descriptor: Option<NewApiMfaMutationDescriptor>,
}

/// Validated raw-request binding retained for an idempotent mutation.
#[derive(Debug)]
pub struct NewApiMfaMutationDescriptor {
    /// Canonical validated descriptor used for parsed-field comparisons.
    pub descriptor_json: JsonValue,
    /// Uppercase HTTP method of the final mutation.
    pub request_method: String,
    /// Absolute-path endpoint of the final mutation.
    pub request_endpoint: String,
    /// SHA-256 of the exact raw final request body.
    pub request_sha256: Vec<u8>,
    /// Length of the exact raw final request body.
    pub request_size: i64,
}

impl ApiMfaChallenge {
    /// Generates a mutation record identifier distinct from its polling capability.
    pub fn generate_mutation_id() -> String {
        format!(
            "{MUTATION_ID_PREFIX}{}",
            Alphanumeric.sample_string(&mut rand::rng(), CHALLENGE_ID_LENGTH)
        )
    }

    /// Generates a short-lived read-only polling capability.
    pub fn generate_poll_token() -> String {
        format!(
            "{POLL_TOKEN_PREFIX}{}",
            Alphanumeric.sample_string(&mut rand::rng(), CHALLENGE_ID_LENGTH)
        )
    }

    /// Whether passkey verification has acknowledged this operation.
    pub fn is_acknowledged(&self) -> bool {
        self.verified_at.is_some()
    }

    /// Marks a preflight ready when policy does not require additional authentication.
    pub async fn mark_ready(&self, mut conn: &AsyncPgConnection) -> QueryResult<Self> {
        diesel::update(
            api_mfa_challenges::table
                .find(&self.id)
                .filter(api_mfa_challenges::verified_at.is_null())
                .filter(
                    api_mfa_challenges::mutation_state
                        .is_null()
                        .or(api_mfa_challenges::mutation_state.eq("pending")),
                ),
        )
        .set((
            api_mfa_challenges::verified_at.eq(Utc::now()),
            api_mfa_challenges::expires_at
                .eq(Utc::now() + chrono::Duration::seconds(DEFAULT_CHALLENGE_DURATION_SECS)),
            api_mfa_challenges::mutation_state.eq("ready"),
        ))
        .returning(Self::as_returning())
        .get_result(&mut conn)
        .await
    }

    /// Stores the normal terminal response for later idempotent replay.
    pub async fn store_terminal_response(
        &self,
        status: i32,
        headers: JsonValue,
        body: Vec<u8>,
        mut conn: &AsyncPgConnection,
    ) -> QueryResult<bool> {
        let updated = diesel::update(
            api_mfa_challenges::table
                .find(&self.id)
                .filter(api_mfa_challenges::completed_at.is_null())
                .filter(api_mfa_challenges::mutation_state.eq("executing")),
        )
        .set((
            api_mfa_challenges::response_status.eq(status),
            api_mfa_challenges::response_headers.eq(headers),
            api_mfa_challenges::response_body.eq(body),
            api_mfa_challenges::completed_at.eq(Utc::now()),
            api_mfa_challenges::mutation_state.eq("terminal"),
        ))
        .execute(&mut conn)
        .await?;
        Ok(updated > 0)
    }

    /// Claims a ready record and starts its bounded receive lease.
    pub async fn begin_receiving(
        &self,
        mut conn: &AsyncPgConnection,
    ) -> QueryResult<Option<DateTime<Utc>>> {
        let receive_expires_at =
            Utc::now() + chrono::Duration::seconds(MUTATION_RECEIVE_LEASE_SECS);
        let updated = diesel::update(
            api_mfa_challenges::table
                .find(&self.id)
                .filter(api_mfa_challenges::mutation_state.eq("ready"))
                .filter(api_mfa_challenges::expires_at.gt(now)),
        )
        .set((
            api_mfa_challenges::mutation_state.eq("receiving"),
            api_mfa_challenges::receive_expires_at.eq(receive_expires_at),
        ))
        .execute(&mut conn)
        .await?;
        Ok((updated > 0).then_some(receive_expires_at))
    }

    /// Expires a receive lease without making the mutation executable.
    pub async fn expire_receiving(&self, mut conn: &AsyncPgConnection) -> QueryResult<bool> {
        let updated = diesel::update(
            api_mfa_challenges::table
                .find(&self.id)
                .filter(api_mfa_challenges::mutation_state.eq("receiving"))
                .filter(api_mfa_challenges::receive_expires_at.le(now)),
        )
        .set(api_mfa_challenges::mutation_state.eq("expired"))
        .execute(&mut conn)
        .await?;
        Ok(updated > 0)
    }

    /// Marks a completely received and matching request as executing.
    pub async fn begin_execution(&self, mut conn: &AsyncPgConnection) -> QueryResult<bool> {
        let updated = diesel::update(
            api_mfa_challenges::table
                .find(&self.id)
                .filter(api_mfa_challenges::mutation_state.eq("receiving"))
                .filter(api_mfa_challenges::receive_expires_at.gt(now)),
        )
        .set(api_mfa_challenges::mutation_state.eq("executing"))
        .execute(&mut conn)
        .await?;
        Ok(updated > 0)
    }

    /// Atomically and durably consumes a core grant before its single final request.
    pub async fn begin_core_execution(&self, mut conn: &AsyncPgConnection) -> QueryResult<bool> {
        let updated = diesel::update(
            api_mfa_challenges::table
                .find(&self.id)
                .filter(api_mfa_challenges::idempotent_final.eq(false))
                .filter(api_mfa_challenges::mutation_state.eq("ready"))
                .filter(api_mfa_challenges::expires_at.gt(now)),
        )
        .set((
            api_mfa_challenges::mutation_state.eq("consumed"),
            api_mfa_challenges::expires_at.eq(Utc::now()),
        ))
        .execute(&mut conn)
        .await?;
        Ok(updated > 0)
    }

    /// Denies a pending mutation authorization.
    pub async fn deny(&self, mut conn: &AsyncPgConnection) -> QueryResult<bool> {
        let updated = diesel::update(
            api_mfa_challenges::table
                .find(&self.id)
                .filter(api_mfa_challenges::mutation_state.eq("pending")),
        )
        .set((
            api_mfa_challenges::mutation_state.eq("denied"),
            api_mfa_challenges::expires_at
                .eq(Utc::now() + chrono::Duration::seconds(DEFAULT_CHALLENGE_DURATION_SECS)),
            api_mfa_challenges::auth_state_json.eq(None::<JsonValue>),
        ))
        .execute(&mut conn)
        .await?;
        Ok(updated > 0)
    }

    /// Loads a non-expired challenge by operation id.
    pub async fn find_active(id: &str, mut conn: &AsyncPgConnection) -> QueryResult<Option<Self>> {
        api_mfa_challenges::table
            .find(id)
            .filter(api_mfa_challenges::expires_at.gt(now))
            .select(Self::as_select())
            .first(&mut conn)
            .await
            .optional()
    }

    /// Loads a challenge by operation id, including one that expired during execution.
    pub async fn find(id: &str, mut conn: &AsyncPgConnection) -> QueryResult<Option<Self>> {
        api_mfa_challenges::table
            .find(id)
            .select(Self::as_select())
            .first(&mut conn)
            .await
            .optional()
    }

    /// Loads the mutation record for an idempotent preflight retry.
    pub async fn find_by_preflight_id(
        api_token_id: i32,
        preflight_id: &str,
        mut conn: &AsyncPgConnection,
    ) -> QueryResult<Option<Self>> {
        api_mfa_challenges::table
            .filter(api_mfa_challenges::api_token_id.eq(api_token_id))
            .filter(api_mfa_challenges::preflight_id.eq(preflight_id))
            .select(Self::as_select())
            .first(&mut conn)
            .await
            .optional()
    }

    /// Loads a mutation record through its read-only polling capability.
    pub async fn find_by_poll_token(
        poll_token: &str,
        mut conn: &AsyncPgConnection,
    ) -> QueryResult<Option<MutationPollStatus>> {
        api_mfa_challenges::table
            .filter(api_mfa_challenges::poll_token.eq(poll_token))
            .select(MutationPollStatus::as_select())
            .first(&mut conn)
            .await
            .optional()
    }

    /// Counts non-expired pending challenges for `user_id`.
    pub async fn count_pending_for_user(
        user_id: i32,
        mut conn: &AsyncPgConnection,
    ) -> QueryResult<i64> {
        api_mfa_challenges::table
            .filter(api_mfa_challenges::user_id.eq(user_id))
            .filter(api_mfa_challenges::verified_at.is_null())
            .filter(
                api_mfa_challenges::mutation_state
                    .is_null()
                    .or(api_mfa_challenges::mutation_state.eq("pending")),
            )
            .filter(api_mfa_challenges::expires_at.gt(now))
            .count()
            .get_result(&mut conn)
            .await
    }

    /// Stores `WebAuthn` authentication state for an in-progress ceremony.
    ///
    /// No-op (returns `false`) if the challenge is already acknowledged.
    pub async fn set_auth_state(
        &self,
        auth_state: JsonValue,
        mut conn: &AsyncPgConnection,
    ) -> QueryResult<bool> {
        let updated = diesel::update(
            api_mfa_challenges::table
                .find(&self.id)
                .filter(api_mfa_challenges::verified_at.is_null())
                .filter(
                    api_mfa_challenges::mutation_state
                        .is_null()
                        .or(api_mfa_challenges::mutation_state.eq("pending")),
                ),
        )
        .set(api_mfa_challenges::auth_state_json.eq(auth_state))
        .execute(&mut conn)
        .await?;
        Ok(updated > 0)
    }

    /// Clears in-progress `WebAuthn` state from every pending challenge for a user.
    ///
    /// Passkey deletion and MFA disablement use this to revoke ceremonies that
    /// were created from an older credential set.
    pub async fn clear_auth_state_for_user(
        user_id: i32,
        mut conn: &AsyncPgConnection,
    ) -> QueryResult<usize> {
        diesel::update(
            api_mfa_challenges::table
                .filter(api_mfa_challenges::user_id.eq(user_id))
                .filter(api_mfa_challenges::verified_at.is_null())
                .filter(api_mfa_challenges::auth_state_json.is_not_null()),
        )
        .set(api_mfa_challenges::auth_state_json.eq(None::<JsonValue>))
        .execute(&mut conn)
        .await
    }

    /// Atomically marks a mutation authorization ready after verification.
    pub async fn mark_verified(&self, mut conn: &AsyncPgConnection) -> QueryResult<bool> {
        let updated = diesel::update(
            api_mfa_challenges::table
                .find(&self.id)
                .filter(api_mfa_challenges::verified_at.is_null())
                .filter(api_mfa_challenges::mutation_state.eq("pending")),
        )
        .set((
            api_mfa_challenges::verified_at.eq(Utc::now()),
            api_mfa_challenges::expires_at
                .eq(Utc::now() + chrono::Duration::seconds(DEFAULT_CHALLENGE_DURATION_SECS)),
            api_mfa_challenges::auth_state_json.eq(None::<JsonValue>),
            api_mfa_challenges::mutation_state.eq("ready"),
        ))
        .execute(&mut conn)
        .await?;
        Ok(updated > 0)
    }
}

impl NewApiMfaChallenge {
    /// Creates a version 1 mutation-authorization record.
    pub fn for_preflight(
        user_id: i32,
        api_token_id: i32,
        operation: NewApiMfaChallengeOperation,
        preflight_id: String,
        allow_pending: bool,
        callback_url: Option<String>,
        idempotent_final: bool,
    ) -> Self {
        let descriptor = operation
            .descriptor
            .expect("mutation preflight requires a validated descriptor");
        Self {
            id: ApiMfaChallenge::generate_mutation_id(),
            idempotent_final,
            user_id,
            api_token_id: Some(api_token_id),
            allow_pending: Some(allow_pending),
            callback_url,
            operation: operation.operation,
            crate_name: operation.crate_name,
            mutation_fingerprint: operation.mutation_fingerprint,
            mutation_state: Some("pending".into()),
            operation_summary: operation.operation_summary,
            descriptor_json: Some(descriptor.descriptor_json),
            request_method: Some(descriptor.request_method),
            request_endpoint: Some(descriptor.request_endpoint),
            request_sha256: Some(descriptor.request_sha256),
            request_size: Some(descriptor.request_size),
            poll_token: Some(ApiMfaChallenge::generate_poll_token()),
            preflight_id: Some(preflight_id),
            expires_at: Utc::now() + chrono::Duration::seconds(DEFAULT_CHALLENGE_DURATION_SECS),
        }
    }

    /// Inserts the challenge and returns the created row.
    pub async fn insert(&self, mut conn: &AsyncPgConnection) -> QueryResult<ApiMfaChallenge> {
        diesel::insert_into(api_mfa_challenges::table)
            .values(self)
            .returning(ApiMfaChallenge::as_returning())
            .get_result(&mut conn)
            .await
    }
}
