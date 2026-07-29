use bon::Builder;
use diesel::dsl::sql;
use diesel::prelude::*;
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use secrecy::SecretString;

use crate::models::User;
use crate::schema::emails;

#[derive(Debug, HasQuery, Identifiable, Associations)]
#[diesel(belongs_to(User))]
pub struct Email {
    pub id: i32,
    pub user_id: i32,
    pub email: String,
    /// Unverified replacement; current `email` stays verified until confirm.
    pub pending_email: Option<String>,
    pub verified: bool,
    #[diesel(deserialize_as = String, serialize_as = String)]
    pub token: SecretString,
}

/// Result of an atomic email confirmation.
pub struct ConfirmedEmail {
    /// Updated email row.
    pub email: Email,
    /// Whether a staged replacement address was promoted.
    pub promoted_pending: bool,
}

#[derive(Debug, Insertable, AsChangeset, Builder)]
#[diesel(table_name = emails, check_for_backend(diesel::pg::Pg))]
pub struct NewEmail<'a> {
    pub user_id: i32,
    pub email: &'a str,
    #[builder(default = false)]
    pub verified: bool,
}

impl NewEmail<'_> {
    pub async fn insert(&self, mut conn: &AsyncPgConnection) -> QueryResult<()> {
        diesel::insert_into(emails::table)
            .values(self)
            .execute(&mut conn)
            .await?;

        Ok(())
    }

    /// Inserts the email into the database and returns the confirmation token,
    /// or does nothing if it already exists and returns `None`.
    pub async fn insert_if_missing(
        &self,
        mut conn: &AsyncPgConnection,
    ) -> QueryResult<Option<SecretString>> {
        diesel::insert_into(emails::table)
            .values(self)
            .on_conflict_do_nothing()
            .returning(emails::token)
            .get_result::<String>(&mut conn)
            .await
            .map(Into::into)
            .optional()
    }

    pub async fn insert_or_update(
        &self,
        mut conn: &AsyncPgConnection,
    ) -> QueryResult<SecretString> {
        diesel::insert_into(emails::table)
            .values(self)
            .on_conflict(emails::user_id)
            .do_update()
            .set((
                emails::email.eq(self.email),
                emails::verified.eq(self.verified),
                // Replacing an unverified address clears any leftover pending change.
                emails::pending_email.eq(None::<String>),
                emails::token.eq(sql("DEFAULT")),
            ))
            .returning(emails::token)
            .get_result::<String>(&mut conn)
            .await
            .map(Into::into)
    }
}

impl Email {
    /// Stages `pending` as the next address while keeping the verified inbox.
    ///
    /// Regenerates the confirmation token used by `/api/v1/confirm/{token}`.
    pub async fn stage_pending_email(
        user_id: i32,
        pending: &str,
        mut conn: &AsyncPgConnection,
    ) -> QueryResult<SecretString> {
        diesel::update(emails::table.filter(emails::user_id.eq(user_id)))
            .set((
                emails::pending_email.eq(pending),
                emails::token.eq(sql("DEFAULT")),
            ))
            .returning(emails::token)
            .get_result::<String>(&mut conn)
            .await
            .map(Into::into)
    }

    /// Clears a staged pending address without changing the verified inbox.
    pub async fn clear_pending_email(
        user_id: i32,
        mut conn: &AsyncPgConnection,
    ) -> QueryResult<usize> {
        diesel::update(emails::table.filter(emails::user_id.eq(user_id)))
            .set(emails::pending_email.eq(None::<String>))
            .execute(&mut conn)
            .await
    }

    /// Confirms a token: promotes `pending_email` when set, otherwise marks `email` verified.
    pub async fn confirm_token(
        token: &str,
        conn: &mut AsyncPgConnection,
    ) -> QueryResult<Option<ConfirmedEmail>> {
        conn.transaction(async |conn| {
            let Some(row) = emails::table
                .filter(emails::token.eq(token))
                .for_update()
                .select(Self::as_select())
                .first::<Self>(conn)
                .await
                .optional()?
            else {
                return Ok(None);
            };

            let promoted_pending = row.pending_email.is_some();
            let updated = if let Some(pending) = row.pending_email.as_deref() {
                diesel::update(emails::table.find(row.id).filter(emails::token.eq(token)))
                    .set((
                        emails::email.eq(pending),
                        emails::pending_email.eq(None::<String>),
                        emails::verified.eq(true),
                        emails::token.eq(sql("DEFAULT")),
                    ))
                    .returning(Self::as_returning())
                    .get_result(conn)
                    .await?
            } else {
                diesel::update(emails::table.find(row.id).filter(emails::token.eq(token)))
                    .set(emails::verified.eq(true))
                    .returning(Self::as_returning())
                    .get_result(conn)
                    .await?
            };

            Ok(Some(ConfirmedEmail {
                email: updated,
                promoted_pending,
            }))
        })
        .await
    }
}
