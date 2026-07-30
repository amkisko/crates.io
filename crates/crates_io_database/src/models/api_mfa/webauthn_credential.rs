use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::Value as JsonValue;

use crate::schema::webauthn_credentials;

/// Maximum number of passkeys a user may register.
pub const MAX_PASSKEYS_PER_USER: i64 = 10;

/// A registered passkey used for API MFA step-up verification.
#[derive(Clone, Debug, Queryable, Selectable, Identifiable, Associations)]
#[diesel(
    table_name = webauthn_credentials,
    check_for_backend(diesel::pg::Pg),
    belongs_to(crate::models::User),
)]
pub struct WebauthnCredential {
    pub created_at: DateTime<Utc>,
    pub credential_id: Vec<u8>,
    pub id: i64,
    pub last_used_at: Option<DateTime<Utc>>,
    pub name: String,
    pub passkey_json: JsonValue,
    pub user_id: i32,
}

/// Insertable row for a newly registered passkey.
#[derive(Debug, Insertable)]
#[diesel(table_name = webauthn_credentials, check_for_backend(diesel::pg::Pg))]
pub struct NewWebauthnCredential<'a> {
    pub user_id: i32,
    pub credential_id: &'a [u8],
    pub passkey_json: JsonValue,
    pub name: &'a str,
}

impl WebauthnCredential {
    /// Lists passkeys registered for `user_id`.
    pub async fn for_user(user_id: i32, mut conn: &AsyncPgConnection) -> QueryResult<Vec<Self>> {
        webauthn_credentials::table
            .filter(webauthn_credentials::user_id.eq(user_id))
            .order(webauthn_credentials::created_at.asc())
            .select(Self::as_select())
            .load(&mut conn)
            .await
    }

    /// Finds a credential by primary key belonging to `user_id`.
    pub async fn find_for_user(
        id: i64,
        user_id: i32,
        mut conn: &AsyncPgConnection,
    ) -> QueryResult<Option<Self>> {
        webauthn_credentials::table
            .find(id)
            .filter(webauthn_credentials::user_id.eq(user_id))
            .select(Self::as_select())
            .first(&mut conn)
            .await
            .optional()
    }

    /// Finds a credential id belonging to `user_id`.
    pub async fn find_by_credential_id_for_user(
        credential_id: &[u8],
        user_id: i32,
        mut conn: &AsyncPgConnection,
    ) -> QueryResult<Option<Self>> {
        webauthn_credentials::table
            .filter(webauthn_credentials::credential_id.eq(credential_id))
            .filter(webauthn_credentials::user_id.eq(user_id))
            .select(Self::as_select())
            .first(&mut conn)
            .await
            .optional()
    }

    /// Deletes a credential belonging to `user_id`.
    pub async fn delete_for_user(
        id: i64,
        user_id: i32,
        mut conn: &AsyncPgConnection,
    ) -> QueryResult<usize> {
        diesel::delete(
            webauthn_credentials::table
                .find(id)
                .filter(webauthn_credentials::user_id.eq(user_id)),
        )
        .execute(&mut conn)
        .await
    }

    /// Updates `last_used_at` after a successful authentication.
    pub async fn touch(&self, mut conn: &AsyncPgConnection) -> QueryResult<()> {
        diesel::update(webauthn_credentials::table.find(self.id))
            .set(webauthn_credentials::last_used_at.eq(Utc::now()))
            .execute(&mut conn)
            .await?;
        Ok(())
    }

    /// Persists updated `Passkey` JSON (counter / backup flags) after authentication.
    pub async fn update_passkey_json(
        &self,
        passkey_json: JsonValue,
        mut conn: &AsyncPgConnection,
    ) -> QueryResult<()> {
        diesel::update(webauthn_credentials::table.find(self.id))
            .set(webauthn_credentials::passkey_json.eq(passkey_json))
            .execute(&mut conn)
            .await?;
        Ok(())
    }
}

impl NewWebauthnCredential<'_> {
    /// Inserts the credential and returns the created row.
    pub async fn insert(&self, mut conn: &AsyncPgConnection) -> QueryResult<WebauthnCredential> {
        diesel::insert_into(webauthn_credentials::table)
            .values(self)
            .returning(WebauthnCredential::as_returning())
            .get_result(&mut conn)
            .await
    }
}
