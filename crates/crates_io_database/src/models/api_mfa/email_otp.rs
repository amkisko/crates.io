use chrono::{DateTime, Utc};
use diesel::dsl::now;
use diesel::prelude::*;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use rand::RngExt as _;
use sha2::{Digest, Sha256};

use crate::schema::api_mfa_email_otps;

/// Lifetime of an emailed API MFA step-up OTP.
pub const DEFAULT_EMAIL_OTP_DURATION_SECS: i64 = 10 * 60;

const OTP_LENGTH: usize = 8;

/// A short-lived email OTP used for API MFA enable/disable and passkey enrollment.
#[derive(Clone, Debug, Queryable, Selectable, Identifiable)]
#[diesel(table_name = api_mfa_email_otps, check_for_backend(diesel::pg::Pg))]
pub struct ApiMfaEmailOtp {
    pub consumed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub hashed_otp: Vec<u8>,
    pub id: i64,
    pub user_id: i32,
}

impl ApiMfaEmailOtp {
    /// Generates a plaintext one-time password for email delivery.
    pub fn generate_otp() -> String {
        let mut rng = rand::rng();
        (0..OTP_LENGTH)
            .map(|_| char::from(b'0' + rng.random_range(0..10)))
            .collect()
    }

    /// Hashes a plaintext OTP for storage / comparison.
    pub fn hash_otp(otp: &str) -> Vec<u8> {
        Sha256::digest(otp.as_bytes()).as_slice().to_vec()
    }

    /// Replaces any unused OTP for `user_id` with a new hashed code.
    ///
    /// Returns the plaintext OTP (caller must email it) and expiry.
    pub async fn issue(
        user_id: i32,
        expires_at: DateTime<Utc>,
        mut conn: &AsyncPgConnection,
    ) -> QueryResult<(String, DateTime<Utc>)> {
        diesel::delete(
            api_mfa_email_otps::table
                .filter(api_mfa_email_otps::user_id.eq(user_id))
                .filter(api_mfa_email_otps::consumed_at.is_null()),
        )
        .execute(&mut conn)
        .await?;

        let plaintext = Self::generate_otp();
        diesel::insert_into(api_mfa_email_otps::table)
            .values((
                api_mfa_email_otps::user_id.eq(user_id),
                api_mfa_email_otps::hashed_otp.eq(Self::hash_otp(&plaintext)),
                api_mfa_email_otps::expires_at.eq(expires_at),
            ))
            .execute(&mut conn)
            .await?;

        Ok((plaintext, expires_at))
    }

    /// Consumes a matching unused non-expired OTP for `user_id`.
    ///
    /// Returns `true` when the OTP was valid and marked consumed.
    pub async fn consume(
        user_id: i32,
        otp: &str,
        mut conn: &AsyncPgConnection,
    ) -> QueryResult<bool> {
        let hashed = Self::hash_otp(otp.trim());
        let updated = diesel::update(
            api_mfa_email_otps::table
                .filter(api_mfa_email_otps::user_id.eq(user_id))
                .filter(api_mfa_email_otps::hashed_otp.eq(hashed))
                .filter(api_mfa_email_otps::consumed_at.is_null())
                .filter(api_mfa_email_otps::expires_at.gt(now)),
        )
        .set(api_mfa_email_otps::consumed_at.eq(now))
        .execute(&mut conn)
        .await?;

        Ok(updated > 0)
    }

    /// Deletes expired and consumed rows so the table does not grow without bound.
    pub async fn purge_expired(mut conn: &AsyncPgConnection) -> QueryResult<usize> {
        diesel::delete(
            api_mfa_email_otps::table.filter(
                api_mfa_email_otps::expires_at
                    .lt(now)
                    .or(api_mfa_email_otps::consumed_at.is_not_null()),
            ),
        )
        .execute(&mut conn)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_otp_is_fixed_length_and_numeric() {
        let otp = ApiMfaEmailOtp::generate_otp();

        assert_eq!(otp.len(), OTP_LENGTH);
        assert!(otp.bytes().all(|byte| byte.is_ascii_digit()));
    }
}
