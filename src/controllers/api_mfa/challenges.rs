pub mod ceremony;
mod mutation_descriptor;
pub mod mutation_poll;
pub mod mutation_preflight;
mod mutation_response;
pub mod status;
mod types;

pub use types::{
    MutationAuthorizationRequest, MutationAuthorizationResponse, MutationCallbackRequest,
};

use mutation_descriptor::validate_mutation_descriptor;
use mutation_preflight::{
    auth_check_for_preflight, insert_preflight_or_reuse, interaction_required_response,
    validate_preflight_fields, validate_preflight_retry,
};
use mutation_response::{
    challenge_created_response, challenge_denied_response, challenge_expired_response,
    challenge_ready_response, grant_expires_in,
};

use crate::app::AppState;
use crate::models::{ApiMfaChallenge, Crate, MAX_PENDING_CHALLENGES_PER_USER, WebauthnCredential};
use crate::rate_limiter::LimitedAction;
use crate::util::errors::{AppResult, bad_request, custom, forbidden};
use crate::util::no_store;
use axum::Json;
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use http::{StatusCode, request::Parts};

/// Implements the version 1 mutation-authorization preflight endpoint.
async fn create_mutation_authorization_inner(
    app: AppState,
    req: Parts,
    Json(body): Json<MutationAuthorizationRequest>,
) -> AppResult<Response> {
    let mut conn = app.db_write().await?;
    let requested_operation = body.operation.trim();
    if !matches!(
        requested_operation,
        "publish" | "yank" | "unyank" | "owners"
    ) {
        return Err(bad_request(
            "mutation preflight operation must be publish, yank, unyank, or owners",
        ));
    }
    let protocol = validate_preflight_fields(
        &body.preflight_id,
        body.allow_pending,
        &body.requested_extensions,
        body.callback.as_ref(),
        body.callback.is_present(),
    )?;
    let max_archive_size = if requested_operation == "publish" {
        let crate_name = body.crate_name.trim();
        Crate::by_name(crate_name)
            .select(Crate::as_select())
            .first(&mut conn)
            .await
            .optional()?
            .and_then(|krate| krate.max_upload_size())
            .unwrap_or(app.config.publish_limits.upload_size)
    } else {
        0
    };
    let descriptor = validate_mutation_descriptor(
        &body,
        requested_operation,
        max_archive_size,
        protocol.idempotent_final(),
    )?;

    let auth_check =
        auth_check_for_preflight(requested_operation, Some(body.crate_name.trim()), &conn).await?;
    let auth = auth_check.check(&req, &mut conn).await?;

    let Some(token) = auth.api_token() else {
        return Err(forbidden(
            "API MFA challenges must be created with an API token",
        ));
    };

    let user = auth.user();
    if !user.api_mfa_enabled
        && crate::api_mfa::crate_requires_api_mfa(body.crate_name.trim(), &mut conn).await?
    {
        return Err(bad_request(
            "This crate requires API MFA because an owner enabled it. Sign in on the website, \
             enable API MFA under Settings → API MFA, register a passkey, then retry.",
        ));
    }
    if user.api_mfa_enabled {
        let credentials = WebauthnCredential::for_user(user.id, &conn).await?;
        if credentials.is_empty() {
            return Err(bad_request("no passkeys registered for this account"));
        }
    }

    let operation = descriptor.operation();

    let existing =
        ApiMfaChallenge::find_by_preflight_id(token.id, &protocol.preflight_id, &conn).await?;
    if let Some(existing) = existing {
        validate_preflight_retry(&existing, &protocol, &descriptor)?;
        if existing.mutation_state.as_deref() == Some("consumed") {
            return Err(custom(
                StatusCode::CONFLICT,
                "mutation authorization was already consumed",
            ));
        }
        if existing.mutation_state.as_deref() == Some("denied") && existing.expires_at > Utc::now()
        {
            return Ok((no_store(), Json(challenge_denied_response(&existing))).into_response());
        }
        if existing.is_acknowledged() {
            if grant_expires_in(&existing).is_none() {
                return Ok(
                    (no_store(), Json(challenge_expired_response(&existing))).into_response()
                );
            }
            return Ok((no_store(), Json(challenge_ready_response(&existing))).into_response());
        }
        if existing.expires_at <= Utc::now() {
            return Ok((no_store(), Json(challenge_expired_response(&existing))).into_response());
        }
        return Ok((
            StatusCode::ACCEPTED,
            no_store(),
            Json(challenge_created_response(&app.config.webauthn, &existing)),
        )
            .into_response());
    }

    app.rate_limiter
        .check_rate_limit(user.id, LimitedAction::ApiMfaChallengeCreate, &mut conn)
        .await?;

    let requires_pending = app.config.api_mfa_enforcement_enabled && user.api_mfa_enabled;
    if !protocol.allow_pending && requires_pending {
        return Ok(interaction_required_response());
    }

    let pending = ApiMfaChallenge::count_pending_for_user(user.id, &conn).await?;
    if pending >= MAX_PENDING_CHALLENGES_PER_USER {
        return Err(bad_request(format!(
            "too many pending API MFA challenges (max {MAX_PENDING_CHALLENGES_PER_USER}); \
             acknowledge or wait for existing ones to expire"
        )));
    }

    let (challenge, created) = insert_preflight_or_reuse(
        user.id, token.id, &operation, descriptor, protocol, &mut conn,
    )
    .await?;

    if created {
        app.instance_metrics.api_mfa_challenges_created_total.inc();
    }

    if !requires_pending {
        let challenge = challenge.mark_ready(&conn).await?;
        return Ok((no_store(), Json(challenge_ready_response(&challenge))).into_response());
    }

    Ok((
        StatusCode::ACCEPTED,
        no_store(),
        Json(challenge_created_response(&app.config.webauthn, &challenge)),
    )
        .into_response())
}

#[cfg(test)]
mod tests;
