use crate::email::EmailMessage;
use crate::models::{CrateOwnerInvitation, User};
use crate::schema::crates;
use crate::worker::Environment;
use anyhow::Context;
use crates_io_worker::BackgroundJob;
use diesel::OptionalExtension;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use minijinja::context;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::info;

/// Transactional outbox job for an owner-invitation email.
#[derive(Deserialize, Serialize)]
pub struct SendOwnerInviteEmail {
    mutation_id: String,
    invited_user_id: i32,
    crate_id: i32,
}

impl SendOwnerInviteEmail {
    /// Creates an owner-invitation email job bound to one mutation.
    pub fn new(mutation_id: String, invited_user_id: i32, crate_id: i32) -> Self {
        Self {
            mutation_id,
            invited_user_id,
            crate_id,
        }
    }
}

impl BackgroundJob for SendOwnerInviteEmail {
    const JOB_NAME: &'static str = "send_owner_invite_email";
    const DEDUPLICATED: bool = true;

    type Context = Arc<Environment>;

    async fn run(&self, ctx: Self::Context) -> anyhow::Result<()> {
        let mut conn = ctx.deadpool.get().await?;
        let Some(invitation) =
            CrateOwnerInvitation::find_by_id(self.invited_user_id, self.crate_id, &conn)
                .await
                .optional()?
        else {
            info!(
                mutation_id = self.mutation_id,
                "Skipping obsolete owner invite email"
            );
            return Ok(());
        };
        let invitee = User::find(&conn, invitation.invited_user_id).await?;
        let Some(recipient) = invitee.verified_email(&conn).await? else {
            info!(
                mutation_id = self.mutation_id,
                "Skipping owner invite email without a verified recipient"
            );
            return Ok(());
        };
        let inviter = User::find(&conn, invitation.invited_by_user_id).await?;
        let crate_name = crates::table
            .find(invitation.crate_id)
            .select(crates::name)
            .first::<String>(&mut conn)
            .await?;
        let message = EmailMessage::from_template(
            "owner_invite",
            context! {
                inviter => inviter.gh_login,
                domain => ctx.emails.domain,
                crate_name => crate_name,
                token => invitation.token.expose_secret(),
            },
        )
        .context("Failed to render owner invite email")?;

        ctx.emails
            .send(&recipient, message)
            .await
            .context("Failed to send owner invite email")?;
        info!(
            mutation_id = self.mutation_id,
            "Sent transactional owner invite email"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn outbox_payload_contains_only_stable_ids() {
        let job = SendOwnerInviteEmail::new("mut_123".into(), 7, 11);
        assert_eq!(
            serde_json::to_value(job).unwrap(),
            json!({
                "mutation_id": "mut_123",
                "invited_user_id": 7,
                "crate_id": 11,
            })
        );
    }
}
