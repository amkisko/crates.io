pub mod ceremony;
mod mutation_descriptor;
pub mod mutation_poll;
pub mod mutation_preflight;
mod mutation_response;
pub mod recovery;
pub mod status;
mod types;

pub use types::{CreateChallengeRequest, CreateChallengeResponse, MutationCallbackRequest};

use mutation_descriptor::{
    ValidatedMutationDescriptor, required_descriptor_field, validate_mutation_descriptor,
};
use mutation_preflight::{
    ValidatedPreflight, auth_check_for_preflight, insert_preflight_or_reuse,
    interaction_required_response, validate_preflight_fields, validate_preflight_retry,
};
use mutation_response::{
    challenge_created_response, challenge_denied_response, challenge_expired_response,
    challenge_ready_response, grant_expires_in,
};

use crate::api_mfa::{
    ApiMfaCallback, ApiMfaOperation, insert_challenge_or_reuse_pending,
    mfa_callback_secret_from_headers, mfa_port_from_headers, normalize_challenge_operation,
    refresh_challenge_localhost_callback,
};
use crate::app::AppState;
use crate::models::{ApiMfaChallenge, Crate, MAX_PENDING_CHALLENGES_PER_USER, WebauthnCredential};
use crate::rate_limiter::LimitedAction;
use crate::util::errors::{AppResult, bad_request, forbidden};
use crate::util::no_store;
use axum::Json;
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use http::{StatusCode, request::Parts};

/// Preflight an exact CLI mutation and create or reuse its API MFA challenge.
///
/// Create a manual API MFA challenge or support the legacy reactive flow.
#[utoipa::path(
    post,
    path = "/api/v1/auth/challenges",
    request_body = inline(CreateChallengeRequest),
    security(("api_token" = [])),
    tag = "users",
    extensions(("x-internal" = json!(true))),
    responses((status = 200, description = "Successful Response", body = inline(CreateChallengeResponse))),
)]
pub async fn create_api_mfa_challenge(
    app: AppState,
    req: Parts,
    Json(body): Json<CreateChallengeRequest>,
) -> AppResult<Response> {
    let mut conn = app.db_write().await?;
    let requested_operation = normalize_challenge_operation(body.operation.as_deref())?;
    let protocol = if requested_operation == "manual" {
        None
    } else {
        Some(validate_preflight_fields(
            body.preflight_id.as_deref(),
            body.allow_pending,
            body.requested_extensions.as_deref(),
            body.callback.as_ref(),
        )?)
    };
    let descriptor = if requested_operation == "manual" {
        None
    } else {
        let max_archive_size = if requested_operation == "publish" {
            let crate_name = required_descriptor_field(body.crate_name.as_deref(), "crate")?;
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
        Some(validate_mutation_descriptor(
            &body,
            &requested_operation,
            max_archive_size,
            protocol
                .as_ref()
                .is_some_and(ValidatedPreflight::idempotent_final),
        )?)
    };

    let auth_check =
        auth_check_for_preflight(&requested_operation, body.crate_name.as_deref(), &conn).await?;
    let auth = auth_check.check(&req, &mut conn).await?;

    let Some(token) = auth.api_token() else {
        return Err(forbidden(
            "API MFA challenges must be created with an API token",
        ));
    };

    let user = auth.user();
    if requested_operation != "manual"
        && !user.api_mfa_enabled
        && let Some(crate_name) = body.crate_name.as_deref()
        && crate::api_mfa::crate_requires_api_mfa(crate_name, &mut conn).await?
    {
        return Err(bad_request(
            "This crate requires API MFA because an owner enabled it. Sign in on the website, \
             enable API MFA under Settings → API MFA, register a passkey, then retry.",
        ));
    }
    if requested_operation == "manual" && !user.api_mfa_enabled {
        return Err(bad_request("API MFA is not enabled for this account"));
    }

    if user.api_mfa_enabled {
        let credentials = WebauthnCredential::for_user(user.id, &conn).await?;
        if credentials.is_empty() {
            return Err(bad_request("no passkeys registered for this account"));
        }
    }

    let header_port = mfa_port_from_headers(&req)?;
    if let (Some(body_port), Some(header_port)) = (body.port, header_port)
        && body_port != header_port
    {
        return Err(bad_request(
            "port and Cargo-Step-Up-Port must match when both are supplied",
        ));
    }
    let callback_port = header_port.or(body.port);
    if let Some(port) = callback_port
        && !(1024..=65535).contains(&port)
    {
        return Err(bad_request("port must be between 1024 and 65535"));
    }
    let callback_secret = mfa_callback_secret_from_headers(&req)?;
    match (callback_port, callback_secret.as_deref()) {
        (Some(_), None) => {
            return Err(bad_request(
                "Cargo-Step-Up-Callback-Secret is required when port is set",
            ));
        }
        (None, Some(_)) => {
            return Err(bad_request("Cargo-Step-Up-Callback-Secret requires port"));
        }
        _ => {}
    }
    if protocol.is_some() && (callback_port.is_some() || callback_secret.is_some()) {
        return Err(bad_request(
            "mutation preflight uses the callback object, not Cargo-Step-Up headers",
        ));
    }

    let operation = descriptor
        .as_ref()
        .map(ValidatedMutationDescriptor::operation)
        .unwrap_or_else(|| ApiMfaOperation::manual(body.crate_name.clone()));

    let existing = if let Some(protocol) = &protocol {
        ApiMfaChallenge::find_by_preflight_id(token.id, &protocol.preflight_id, &conn).await?
    } else {
        ApiMfaChallenge::find_pending_for_operation(
            user.id,
            token.id,
            operation.kind,
            operation.crate_name.as_deref(),
            &operation.mutation_fingerprint,
            &conn,
        )
        .await?
    };
    if let Some(existing) = existing {
        if let (Some(protocol), Some(descriptor)) = (&protocol, &descriptor) {
            validate_preflight_retry(&existing, protocol, descriptor)?;
            if existing.mutation_state.as_deref() == Some("denied")
                && existing.expires_at > Utc::now()
            {
                return Ok((no_store(), Json(challenge_denied_response(&existing))).into_response());
            }
            if existing.is_acknowledged() {
                if existing.completed_at.is_none() && grant_expires_in(&existing).is_none() {
                    return Ok(
                        (no_store(), Json(challenge_expired_response(&existing))).into_response()
                    );
                }
                return Ok((no_store(), Json(challenge_ready_response(&existing))).into_response());
            }
            if existing.expires_at <= Utc::now() {
                return Ok(
                    (no_store(), Json(challenge_expired_response(&existing))).into_response()
                );
            }
            return Ok((
                StatusCode::ACCEPTED,
                no_store(),
                Json(challenge_created_response(&app.config.webauthn, &existing)),
            )
                .into_response());
        }
        let existing = refresh_challenge_localhost_callback(
            existing,
            ApiMfaCallback {
                port: callback_port,
                secret: callback_secret.as_deref(),
            },
            &mut conn,
        )
        .await?;
        return Ok((
            no_store(),
            Json(challenge_created_response(&app.config.webauthn, &existing)),
        )
            .into_response());
    }

    app.rate_limiter
        .check_rate_limit(user.id, LimitedAction::ApiMfaChallengeCreate, &mut conn)
        .await?;

    if protocol.is_none() {
        ApiMfaChallenge::delete_expired_pending_for_operation(
            token.id,
            operation.kind,
            operation.crate_name.as_deref(),
            &operation.mutation_fingerprint,
            &conn,
        )
        .await?;
    }

    let requires_pending = requested_operation != "manual"
        && app.config.api_mfa_enforcement_enabled
        && user.api_mfa_enabled;
    if protocol
        .as_ref()
        .is_some_and(|protocol| !protocol.allow_pending && requires_pending)
    {
        return Ok(interaction_required_response());
    }

    let pending = ApiMfaChallenge::count_pending_for_user(user.id, &conn).await?;
    if pending >= MAX_PENDING_CHALLENGES_PER_USER {
        return Err(bad_request(format!(
            "too many pending API MFA challenges (max {MAX_PENDING_CHALLENGES_PER_USER}); \
             acknowledge or wait for existing ones to expire"
        )));
    }

    let callback = ApiMfaCallback {
        port: callback_port,
        secret: callback_secret.as_deref(),
    };
    let (challenge, created) = if let (Some(descriptor), Some(protocol)) = (descriptor, protocol) {
        insert_preflight_or_reuse(
            user.id, token.id, &operation, descriptor, protocol, &mut conn,
        )
        .await?
    } else {
        insert_challenge_or_reuse_pending(user.id, token.id, &operation, callback, &mut conn)
            .await?
    };

    if created {
        app.instance_metrics.api_mfa_challenges_created_total.inc();
    }

    if requested_operation != "manual" && !requires_pending {
        challenge.mark_ready(&conn).await?;
        return Ok((no_store(), Json(challenge_ready_response(&challenge))).into_response());
    }

    if requested_operation != "manual" {
        return Ok((
            StatusCode::ACCEPTED,
            no_store(),
            Json(challenge_created_response(&app.config.webauthn, &challenge)),
        )
            .into_response());
    }

    Ok((
        no_store(),
        Json(challenge_created_response(&app.config.webauthn, &challenge)),
    )
        .into_response())
}

#[cfg(test)]
mod tests;
