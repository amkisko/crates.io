use chrono::{DateTime, Utc};
use diesel::dsl::now;
use diesel::prelude::*;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use rand::distr::{Alphanumeric, SampleString};
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};

use crate::schema::api_mfa_challenges;

/// Default lifetime of an API MFA challenge / operation handshake.
pub const DEFAULT_CHALLENGE_DURATION_SECS: i64 = 5 * 60;
/// Time allowed to finish or retry a claimed mutation request body.
pub const MUTATION_RECEIVE_LEASE_SECS: i64 = 30 * 60;

/// Maximum non-expired pending challenges a user may hold at once.
pub const MAX_PENDING_CHALLENGES_PER_USER: i64 = 10;

const CHALLENGE_ID_PREFIX: &str = "stp_";
const MUTATION_ID_PREFIX: &str = "mut_";
const POLL_TOKEN_PREFIX: &str = "poll_";
const CHALLENGE_ID_LENGTH: usize = 32;
const OTP_LENGTH: usize = 32;

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
    pub hashed_otp: Option<Vec<u8>>,
    pub id: String,
    pub localhost_callback_secret_hash: Option<Vec<u8>>,
    pub localhost_port: Option<i32>,
    pub mutation_fingerprint: Vec<u8>,
    pub mutation_state: Option<String>,
    pub operation: String,
    pub operation_summary: String,
    pub otp_consumed_at: Option<DateTime<Utc>>,
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
    pub sealed_otp: Option<String>,
    pub completed_at: Option<DateTime<Utc>>,
    pub user_id: i32,
    pub verified_at: Option<DateTime<Utc>>,
}

/// Insertable row for a new API MFA challenge.
#[derive(Debug, Insertable)]
#[diesel(table_name = api_mfa_challenges, check_for_backend(diesel::pg::Pg))]
pub struct NewApiMfaChallenge {
    pub id: String,
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
    pub localhost_callback_secret_hash: Option<Vec<u8>>,
    pub localhost_port: Option<i32>,
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
    /// Generates a new opaque step-up challenge identifier.
    pub fn generate_id() -> String {
        format!(
            "{CHALLENGE_ID_PREFIX}{}",
            Alphanumeric.sample_string(&mut rand::rng(), CHALLENGE_ID_LENGTH)
        )
    }

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

    /// Generates a plaintext one-time password for CLI use.
    pub fn generate_otp() -> String {
        Alphanumeric.sample_string(&mut rand::rng(), OTP_LENGTH)
    }

    /// Hashes a plaintext OTP for storage / comparison.
    pub fn hash_otp(otp: &str) -> Vec<u8> {
        Sha256::digest(otp.as_bytes()).as_slice().to_vec()
    }

    /// Hashes a client-held localhost callback secret for storage and comparison.
    pub fn hash_localhost_callback_secret(secret: &str) -> Vec<u8> {
        Sha256::digest(secret.as_bytes()).as_slice().to_vec()
    }

    /// Whether a client-held callback secret authorizes callback changes or OTP recovery.
    pub fn localhost_callback_secret_matches(&self, secret: &str) -> bool {
        self.localhost_callback_secret_hash.as_deref()
            == Some(Self::hash_localhost_callback_secret(secret).as_slice())
    }

    /// Whether passkey verification has acknowledged this operation.
    pub fn is_acknowledged(&self) -> bool {
        self.verified_at.is_some()
    }

    /// Marks a preflight ready when policy does not require additional authentication.
    pub async fn mark_ready(&self, mut conn: &AsyncPgConnection) -> QueryResult<bool> {
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
        .set((
            api_mfa_challenges::verified_at.eq(Utc::now()),
            api_mfa_challenges::expires_at
                .eq(Utc::now() + chrono::Duration::seconds(DEFAULT_CHALLENGE_DURATION_SECS)),
            api_mfa_challenges::mutation_state.eq("ready"),
        ))
        .execute(&mut conn)
        .await?;
        Ok(updated > 0)
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
    ) -> QueryResult<Option<Self>> {
        api_mfa_challenges::table
            .filter(api_mfa_challenges::poll_token.eq(poll_token))
            .select(Self::as_select())
            .first(&mut conn)
            .await
            .optional()
    }

    /// Finds a reusable pending challenge for the same token + operation (idempotent handshake).
    pub async fn find_pending_for_operation(
        user_id: i32,
        api_token_id: i32,
        operation: &str,
        crate_name: Option<&str>,
        mutation_fingerprint: &[u8],
        mut conn: &AsyncPgConnection,
    ) -> QueryResult<Option<Self>> {
        let mut query = api_mfa_challenges::table
            .filter(api_mfa_challenges::user_id.eq(user_id))
            .filter(api_mfa_challenges::api_token_id.eq(api_token_id))
            .filter(api_mfa_challenges::operation.eq(operation))
            .filter(api_mfa_challenges::mutation_fingerprint.eq(mutation_fingerprint))
            .filter(api_mfa_challenges::verified_at.is_null())
            .filter(api_mfa_challenges::expires_at.gt(now))
            .into_boxed();

        query = match crate_name {
            Some(name) => query.filter(api_mfa_challenges::crate_name.eq(name)),
            None => query.filter(api_mfa_challenges::crate_name.is_null()),
        };

        query
            .order(api_mfa_challenges::created_at.desc())
            .select(Self::as_select())
            .first(&mut conn)
            .await
            .optional()
    }

    /// Finds an unexpired mutation record, including acknowledged/completed records.
    pub async fn find_active_for_operation(
        user_id: i32,
        api_token_id: i32,
        operation: &str,
        crate_name: Option<&str>,
        mutation_fingerprint: &[u8],
        mut conn: &AsyncPgConnection,
    ) -> QueryResult<Option<Self>> {
        let mut query = api_mfa_challenges::table
            .filter(api_mfa_challenges::user_id.eq(user_id))
            .filter(api_mfa_challenges::api_token_id.eq(api_token_id))
            .filter(api_mfa_challenges::operation.eq(operation))
            .filter(api_mfa_challenges::mutation_fingerprint.eq(mutation_fingerprint))
            .filter(api_mfa_challenges::expires_at.gt(now))
            .into_boxed();
        query = match crate_name {
            Some(name) => query.filter(api_mfa_challenges::crate_name.eq(name)),
            None => query.filter(api_mfa_challenges::crate_name.is_null()),
        };
        query
            .order(api_mfa_challenges::created_at.desc())
            .select(Self::as_select())
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

    /// Deletes expired pending challenges for a token + operation key so a unique index slot frees.
    pub async fn delete_expired_pending_for_operation(
        api_token_id: i32,
        operation: &str,
        crate_name: Option<&str>,
        mutation_fingerprint: &[u8],
        mut conn: &AsyncPgConnection,
    ) -> QueryResult<usize> {
        let base = api_mfa_challenges::table
            .filter(api_mfa_challenges::api_token_id.eq(api_token_id))
            .filter(api_mfa_challenges::operation.eq(operation))
            .filter(api_mfa_challenges::mutation_fingerprint.eq(mutation_fingerprint))
            .filter(api_mfa_challenges::verified_at.is_null())
            .filter(api_mfa_challenges::expires_at.le(now));

        match crate_name {
            Some(name) => {
                diesel::delete(base.filter(api_mfa_challenges::crate_name.eq(name)))
                    .execute(&mut conn)
                    .await
            }
            None => {
                diesel::delete(base.filter(api_mfa_challenges::crate_name.is_null()))
                    .execute(&mut conn)
                    .await
            }
        }
    }

    /// Updates the localhost OTP callback binding on a pending challenge.
    ///
    /// Authorization to replace an existing port is checked by the caller using
    /// the stored callback-secret hash.
    pub async fn update_localhost_callback(
        &self,
        localhost_port: i32,
        localhost_callback_secret_hash: Option<Vec<u8>>,
        mut conn: &AsyncPgConnection,
    ) -> QueryResult<Self> {
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
            api_mfa_challenges::localhost_port.eq(localhost_port),
            api_mfa_challenges::localhost_callback_secret_hash.eq(localhost_callback_secret_hash),
        ))
        .returning(Self::as_returning())
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

    /// Atomically acknowledges the challenge and stores the hashed OTP.
    ///
    /// Returns `true` only for the first successful acknowledgment (`verified_at` was null).
    pub async fn mark_verified(
        &self,
        hashed_otp: Vec<u8>,
        sealed_otp: Option<String>,
        mut conn: &AsyncPgConnection,
    ) -> QueryResult<bool> {
        let base = diesel::update(
            api_mfa_challenges::table
                .find(&self.id)
                .filter(api_mfa_challenges::verified_at.is_null())
                .filter(
                    api_mfa_challenges::mutation_state
                        .is_null()
                        .or(api_mfa_challenges::mutation_state.eq("pending")),
                ),
        );
        let updated = if self.mutation_state.is_some() {
            base.set((
                api_mfa_challenges::hashed_otp.eq(hashed_otp),
                api_mfa_challenges::sealed_otp.eq(sealed_otp),
                api_mfa_challenges::verified_at.eq(Utc::now()),
                api_mfa_challenges::expires_at
                    .eq(Utc::now() + chrono::Duration::seconds(DEFAULT_CHALLENGE_DURATION_SECS)),
                api_mfa_challenges::auth_state_json.eq(None::<JsonValue>),
                api_mfa_challenges::mutation_state.eq("ready"),
            ))
            .execute(&mut conn)
            .await?
        } else {
            base.set((
                api_mfa_challenges::hashed_otp.eq(hashed_otp),
                api_mfa_challenges::sealed_otp.eq(sealed_otp),
                api_mfa_challenges::verified_at.eq(Utc::now()),
                api_mfa_challenges::expires_at
                    .eq(Utc::now() + chrono::Duration::seconds(DEFAULT_CHALLENGE_DURATION_SECS)),
                api_mfa_challenges::auth_state_json.eq(None::<JsonValue>),
            ))
            .execute(&mut conn)
            .await?
        };
        Ok(updated > 0)
    }

    /// Consumes a matching unused OTP for the given operation and crate.
    pub async fn consume_otp(
        user_id: i32,
        api_token_id: i32,
        otp: &str,
        operation: &str,
        crate_name: Option<&str>,
        mutation_fingerprint: &[u8],
        mut conn: &AsyncPgConnection,
    ) -> QueryResult<bool> {
        let hashed = Self::hash_otp(otp);
        let base = api_mfa_challenges::table
            .filter(api_mfa_challenges::user_id.eq(user_id))
            .filter(api_mfa_challenges::api_token_id.eq(api_token_id))
            .filter(api_mfa_challenges::operation.eq(operation))
            .filter(api_mfa_challenges::mutation_fingerprint.eq(mutation_fingerprint))
            .filter(api_mfa_challenges::hashed_otp.eq(hashed))
            .filter(api_mfa_challenges::otp_consumed_at.is_null())
            .filter(api_mfa_challenges::verified_at.is_not_null())
            .filter(api_mfa_challenges::expires_at.gt(now));

        let updated = match crate_name {
            Some(name) => {
                diesel::update(base.filter(api_mfa_challenges::crate_name.eq(name)))
                    .set(api_mfa_challenges::otp_consumed_at.eq(Utc::now()))
                    .execute(&mut conn)
                    .await?
            }
            None => {
                diesel::update(base.filter(api_mfa_challenges::crate_name.is_null()))
                    .set(api_mfa_challenges::otp_consumed_at.eq(Utc::now()))
                    .execute(&mut conn)
                    .await?
            }
        };

        Ok(updated > 0)
    }

    /// Marks callback delivery complete when the client used the scoped poll grant.
    ///
    /// Hybrid challenges can finish through either channel. Once the original
    /// mutation succeeds through polling, callback recovery must stop returning
    /// an OTP to a listener that Cargo has already closed.
    pub async fn mark_callback_completed_by_grant(
        user_id: i32,
        api_token_id: i32,
        operation: &str,
        crate_name: Option<&str>,
        mutation_fingerprint: &[u8],
        mut conn: &AsyncPgConnection,
    ) -> QueryResult<usize> {
        let base = api_mfa_challenges::table
            .filter(api_mfa_challenges::user_id.eq(user_id))
            .filter(api_mfa_challenges::api_token_id.eq(api_token_id))
            .filter(api_mfa_challenges::operation.eq(operation))
            .filter(api_mfa_challenges::mutation_fingerprint.eq(mutation_fingerprint))
            .filter(api_mfa_challenges::localhost_port.is_not_null())
            .filter(api_mfa_challenges::verified_at.is_not_null())
            .filter(api_mfa_challenges::otp_consumed_at.is_null())
            .filter(api_mfa_challenges::expires_at.gt(now));

        match crate_name {
            Some(name) => {
                diesel::update(base.filter(api_mfa_challenges::crate_name.eq(name)))
                    .set(api_mfa_challenges::otp_consumed_at.eq(Utc::now()))
                    .execute(&mut conn)
                    .await
            }
            None => {
                diesel::update(base.filter(api_mfa_challenges::crate_name.is_null()))
                    .set(api_mfa_challenges::otp_consumed_at.eq(Utc::now()))
                    .execute(&mut conn)
                    .await
            }
        }
    }
}

impl NewApiMfaChallenge {
    /// Creates a new operation challenge for `user_id`.
    pub fn new(
        user_id: i32,
        api_token_id: Option<i32>,
        operation: NewApiMfaChallengeOperation,
        localhost_port: Option<i32>,
        localhost_callback_secret: Option<&str>,
    ) -> Self {
        let descriptor = operation.descriptor;
        Self {
            id: ApiMfaChallenge::generate_id(),
            user_id,
            api_token_id,
            allow_pending: None,
            callback_url: None,
            operation: operation.operation,
            crate_name: operation.crate_name,
            mutation_fingerprint: operation.mutation_fingerprint,
            mutation_state: None,
            operation_summary: operation.operation_summary,
            descriptor_json: descriptor
                .as_ref()
                .map(|value| value.descriptor_json.clone()),
            request_method: descriptor
                .as_ref()
                .map(|value| value.request_method.clone()),
            request_endpoint: descriptor
                .as_ref()
                .map(|value| value.request_endpoint.clone()),
            request_sha256: descriptor
                .as_ref()
                .map(|value| value.request_sha256.clone()),
            request_size: descriptor.map(|value| value.request_size),
            localhost_callback_secret_hash: localhost_callback_secret
                .map(ApiMfaChallenge::hash_localhost_callback_secret),
            localhost_port,
            poll_token: None,
            preflight_id: None,
            expires_at: Utc::now() + chrono::Duration::seconds(DEFAULT_CHALLENGE_DURATION_SECS),
        }
    }

    /// Creates a version 1 mutation-authorization record.
    pub fn for_preflight(
        user_id: i32,
        api_token_id: i32,
        operation: NewApiMfaChallengeOperation,
        preflight_id: String,
        allow_pending: bool,
        callback_url: Option<String>,
    ) -> Self {
        let mut challenge = Self::new(user_id, Some(api_token_id), operation, None, None);
        challenge.id = ApiMfaChallenge::generate_mutation_id();
        challenge.allow_pending = Some(allow_pending);
        challenge.callback_url = callback_url;
        challenge.poll_token = Some(ApiMfaChallenge::generate_poll_token());
        challenge.preflight_id = Some(preflight_id);
        challenge.mutation_state = Some("pending".into());
        challenge
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
