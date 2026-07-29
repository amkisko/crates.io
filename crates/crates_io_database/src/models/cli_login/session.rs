use chrono::{DateTime, TimeDelta, Utc};
use diesel::dsl::now;
use diesel::prelude::*;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use rand::RngExt;
use rand::distr::{Alphanumeric, SampleString};
use sha2::{Digest, Sha256};

use crate::schema::cli_login_sessions;

/// Default lifetime of a CLI login ceremony.
pub const DEFAULT_SESSION_DURATION_SECS: i64 = 10 * 60;

/// Maximum non-expired pending sessions that may share a client IP.
pub const MAX_PENDING_CLI_LOGIN_PER_IP: i64 = 10;

pub const STATUS_PENDING: &str = "pending";
pub const STATUS_READY: &str = "ready";
pub const STATUS_CONSUMED: &str = "consumed";
pub const STATUS_EXPIRED: &str = "expired";

const SESSION_ID_PREFIX: &str = "login_";
const SESSION_ID_LENGTH: usize = 32;
/// Ambiguous-looking characters omitted (`0`/`O`, `1`/`I`/`L`).
const CONFIRMATION_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const CONFIRMATION_CODE_LENGTH: usize = 8;

/// Result of an atomic poll pace check (`UPDATE … RETURNING`).
#[derive(Debug, Clone)]
pub enum TouchPollOutcome {
    /// Interval elapsed; handler may serve this status without another SELECT.
    Proceed {
        status: String,
        expires_at: DateTime<Utc>,
    },
    /// Session exists but was polled too recently.
    RateLimited,
    /// No row for this id.
    NotFound,
}

/// A pending or completed CLI link-login ceremony.
#[derive(Clone, Debug, Queryable, Selectable, Identifiable)]
#[diesel(table_name = cli_login_sessions, check_for_backend(diesel::pg::Pg))]
pub struct CliLoginSession {
    pub api_token_id: Option<i32>,
    pub client_ip: Option<String>,
    pub confirmation_code_hash: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub id: String,
    pub last_polled_at: Option<DateTime<Utc>>,
    pub localhost_port: Option<i32>,
    pub plaintext_token: Option<String>,
    pub status: String,
    pub user_id: Option<i32>,
}

/// Insertable row for a new CLI login session.
#[derive(Debug, Insertable)]
#[diesel(table_name = cli_login_sessions, check_for_backend(diesel::pg::Pg))]
pub struct NewCliLoginSession {
    pub id: String,
    pub localhost_port: Option<i32>,
    pub client_ip: Option<String>,
    pub confirmation_code_hash: Vec<u8>,
    pub expires_at: DateTime<Utc>,
}

/// Plaintext confirmation code plus insertable session (code shown once to the CLI).
pub struct NewCliLoginSessionWithCode {
    pub session: NewCliLoginSession,
    /// Display form (`XXXX-XXXX`); returned only from `POST /cli_login`.
    pub confirmation_code: String,
}

impl NewCliLoginSession {
    /// Builds a new pending session with opaque id and confirmation code.
    pub fn new(
        localhost_port: Option<i32>,
        client_ip: Option<String>,
    ) -> NewCliLoginSessionWithCode {
        let confirmation_code = CliLoginSession::generate_confirmation_code();
        NewCliLoginSessionWithCode {
            session: Self {
                id: CliLoginSession::generate_id(),
                localhost_port,
                client_ip,
                confirmation_code_hash: CliLoginSession::hash_confirmation_code(&confirmation_code),
                expires_at: Utc::now() + TimeDelta::seconds(DEFAULT_SESSION_DURATION_SECS),
            },
            confirmation_code,
        }
    }

    /// Inserts the session and returns the loaded row.
    pub async fn insert(self, mut conn: &AsyncPgConnection) -> QueryResult<CliLoginSession> {
        diesel::insert_into(cli_login_sessions::table)
            .values(self)
            .returning(CliLoginSession::as_returning())
            .get_result(&mut conn)
            .await
    }
}

impl NewCliLoginSessionWithCode {
    /// Inserts the session and returns the loaded row (plaintext code stays on `self`).
    pub async fn insert(self, conn: &AsyncPgConnection) -> QueryResult<(CliLoginSession, String)> {
        let session = self.session.insert(conn).await?;
        Ok((session, self.confirmation_code))
    }
}

impl CliLoginSession {
    /// Generates a new opaque login session identifier.
    pub fn generate_id() -> String {
        format!(
            "{SESSION_ID_PREFIX}{}",
            Alphanumeric.sample_string(&mut rand::rng(), SESSION_ID_LENGTH)
        )
    }

    /// Generates a human-typed confirmation code (`XXXX-XXXX`).
    pub fn generate_confirmation_code() -> String {
        let mut rng = rand::rng();
        let chars: String = (0..CONFIRMATION_CODE_LENGTH)
            .map(|_| {
                let idx = rng.random_range(0..CONFIRMATION_ALPHABET.len());
                CONFIRMATION_ALPHABET[idx] as char
            })
            .collect();
        format!("{}-{}", &chars[..4], &chars[4..])
    }

    /// Strips separators and uppercases for comparison.
    pub fn normalize_confirmation_code(code: &str) -> String {
        code.chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect::<String>()
            .to_ascii_uppercase()
    }

    /// Hashes a confirmation code for storage.
    pub fn hash_confirmation_code(code: &str) -> Vec<u8> {
        Sha256::digest(Self::normalize_confirmation_code(code).as_bytes()).to_vec()
    }

    /// Whether `code` matches this session's stored hash.
    pub fn confirmation_code_matches(&self, code: &str) -> bool {
        self.confirmation_code_hash == Self::hash_confirmation_code(code)
    }

    /// Loads a session by id (including expired rows, for poll status reporting).
    pub async fn find(id: &str, mut conn: &AsyncPgConnection) -> QueryResult<Option<Self>> {
        cli_login_sessions::table
            .find(id)
            .select(Self::as_select())
            .first(&mut conn)
            .await
            .optional()
    }

    /// Loads a non-expired session by id.
    pub async fn find_active(id: &str, mut conn: &AsyncPgConnection) -> QueryResult<Option<Self>> {
        cli_login_sessions::table
            .find(id)
            .filter(cli_login_sessions::expires_at.gt(now))
            .select(Self::as_select())
            .first(&mut conn)
            .await
            .optional()
    }

    /// Counts pending non-expired sessions for a client IP.
    pub async fn count_pending_for_ip(
        client_ip: &str,
        mut conn: &AsyncPgConnection,
    ) -> QueryResult<i64> {
        cli_login_sessions::table
            .filter(cli_login_sessions::client_ip.eq(client_ip))
            .filter(cli_login_sessions::status.eq(STATUS_PENDING))
            .filter(cli_login_sessions::expires_at.gt(now))
            .count()
            .get_result(&mut conn)
            .await
    }

    /// Counts sessions created by a client IP within the given lookback window.
    pub async fn count_created_since(
        client_ip: &str,
        since: DateTime<Utc>,
        mut conn: &AsyncPgConnection,
    ) -> QueryResult<i64> {
        cli_login_sessions::table
            .filter(cli_login_sessions::client_ip.eq(client_ip))
            .filter(cli_login_sessions::created_at.ge(since))
            .count()
            .get_result(&mut conn)
            .await
    }

    /// Claims a pending session for `user_id` before minting a token.
    ///
    /// Returns `true` if this caller won the claim (so minting is safe).
    pub async fn claim(&self, user_id: i32, mut conn: &AsyncPgConnection) -> QueryResult<bool> {
        let updated = diesel::update(cli_login_sessions::table.find(&self.id))
            .filter(cli_login_sessions::status.eq(STATUS_PENDING))
            .filter(cli_login_sessions::expires_at.gt(now))
            .filter(cli_login_sessions::user_id.is_null())
            .set(cli_login_sessions::user_id.eq(user_id))
            .execute(&mut conn)
            .await?;
        Ok(updated == 1)
    }

    /// Releases a claim after a failed mint so another approve can retry.
    pub async fn release_claim(
        &self,
        user_id: i32,
        mut conn: &AsyncPgConnection,
    ) -> QueryResult<()> {
        diesel::update(cli_login_sessions::table.find(&self.id))
            .filter(cli_login_sessions::status.eq(STATUS_PENDING))
            .filter(cli_login_sessions::user_id.eq(user_id))
            .set(cli_login_sessions::user_id.eq(None::<i32>))
            .execute(&mut conn)
            .await?;
        Ok(())
    }

    /// Marks a claimed pending session ready (stores ciphertext for one redeem).
    ///
    /// Returns `true` if the claimed pending session was updated.
    pub async fn mark_ready(
        &self,
        user_id: i32,
        api_token_id: i32,
        plaintext_token: &str,
        mut conn: &AsyncPgConnection,
    ) -> QueryResult<bool> {
        let updated = diesel::update(cli_login_sessions::table.find(&self.id))
            .filter(cli_login_sessions::status.eq(STATUS_PENDING))
            .filter(cli_login_sessions::expires_at.gt(now))
            .filter(cli_login_sessions::user_id.eq(user_id))
            .set((
                cli_login_sessions::api_token_id.eq(api_token_id),
                cli_login_sessions::plaintext_token.eq(plaintext_token),
                cli_login_sessions::status.eq(STATUS_READY),
            ))
            .execute(&mut conn)
            .await?;
        Ok(updated == 1)
    }

    /// Atomically records a poll if the minimum interval has elapsed.
    ///
    /// On success, returns `status` and `expires_at` via `RETURNING` so the
    /// handler can skip a second full-row SELECT (and avoid loading the sealed
    /// redeem blob on pending polls).
    pub async fn touch_poll(
        id: &str,
        min_interval_secs: i64,
        mut conn: &AsyncPgConnection,
    ) -> QueryResult<TouchPollOutcome> {
        let now_ts = Utc::now();
        let cutoff = now_ts - TimeDelta::seconds(min_interval_secs);

        let touched: Option<(String, DateTime<Utc>)> = diesel::update(cli_login_sessions::table)
            .filter(cli_login_sessions::id.eq(id))
            .filter(
                cli_login_sessions::last_polled_at
                    .is_null()
                    .or(cli_login_sessions::last_polled_at.lt(cutoff)),
            )
            .set(cli_login_sessions::last_polled_at.eq(now_ts))
            .returning((cli_login_sessions::status, cli_login_sessions::expires_at))
            .get_result(&mut conn)
            .await
            .optional()?;

        if let Some((status, expires_at)) = touched {
            return Ok(TouchPollOutcome::Proceed { status, expires_at });
        }

        // UPDATE matched 0 rows: missing id → NotFound; else rate-limited.
        let exists = diesel::select(diesel::dsl::exists(cli_login_sessions::table.find(id)))
            .get_result::<bool>(&mut conn)
            .await?;

        Ok(if exists {
            TouchPollOutcome::RateLimited
        } else {
            TouchPollOutcome::NotFound
        })
    }

    /// Atomically consumes a ready session and returns the stored redeem blob once.
    pub async fn consume_token(
        id: &str,
        conn: &mut AsyncPgConnection,
    ) -> QueryResult<Option<String>> {
        use diesel_async::AsyncConnection;

        conn.transaction(async |conn| {
            let token: Option<String> = cli_login_sessions::table
                .find(id)
                .filter(cli_login_sessions::status.eq(STATUS_READY))
                .filter(cli_login_sessions::expires_at.gt(now))
                .select(cli_login_sessions::plaintext_token)
                .for_update()
                .first::<Option<String>>(conn)
                .await
                .optional()?
                .flatten();

            if token.is_some() {
                diesel::update(cli_login_sessions::table.find(id))
                    .set((
                        cli_login_sessions::status.eq(STATUS_CONSUMED),
                        cli_login_sessions::plaintext_token.eq(None::<String>),
                    ))
                    .execute(conn)
                    .await?;
            }

            Ok(token)
        })
        .await
    }

    /// Deletes expired and consumed sessions; clears leftover plaintext first.
    pub async fn purge_expired(mut conn: &AsyncPgConnection) -> QueryResult<usize> {
        diesel::update(
            cli_login_sessions::table
                .filter(
                    cli_login_sessions::expires_at
                        .lt(now)
                        .or(cli_login_sessions::status.eq(STATUS_CONSUMED)),
                )
                .filter(cli_login_sessions::plaintext_token.is_not_null()),
        )
        .set(cli_login_sessions::plaintext_token.eq(None::<String>))
        .execute(&mut conn)
        .await?;

        diesel::delete(
            cli_login_sessions::table.filter(
                cli_login_sessions::expires_at
                    .lt(now)
                    .or(cli_login_sessions::status.eq(STATUS_CONSUMED)),
            ),
        )
        .execute(&mut conn)
        .await
    }

    /// Whether this session has passed its ceremony TTL.
    pub fn is_expired(&self) -> bool {
        self.expires_at <= Utc::now()
    }
}
