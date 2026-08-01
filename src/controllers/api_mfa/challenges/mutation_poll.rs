//! Polling through the mutation authorization's independent capability.

use axum::Json;
use axum::extract::Path;
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use http::request::Parts;
use serde::Serialize;

use crate::api_mfa::RECOMMENDED_POLL_INTERVAL_SECS;
use crate::app::AppState;
use crate::models::ApiMfaChallenge;
use crate::rate_limiter::LimitedAction;
use crate::util::errors::{AppResult, not_found};
use crate::util::no_store;

use super::mutation_response::{grant_expires_in_for_state, receive_lease_secs_for_state};
use super::status::challenge_rate_limit_key;

/// Read-only mutation-authorization status returned through a poll token.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct PollMutationAuthorizationResponse {
    /// One of `pending`, `ready`, `denied`, or `expired`.
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge_expires_in: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_expires_in: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receive_lease_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recommended_poll_interval_secs: Option<u64>,
}

/// Poll mutation authorization through its independent read-only capability.
#[utoipa::path(
    get,
    path = "/api/v1/auth/mutation-challenges/poll/{token}",
    params(("token" = String, Path, description = "Poll capability")),
    tag = "users",
    extensions(("x-internal" = json!(true))),
    responses((status = 200, description = "Mutation authorization status", body = inline(PollMutationAuthorizationResponse))),
)]
pub async fn poll_mutation_authorization(
    app: AppState,
    Path(token): Path<String>,
    req: Parts,
) -> Response {
    match poll_mutation_authorization_inner(app, token, req).await {
        Ok(response) => (no_store(), response).into_response(),
        Err(error) => (no_store(), error).into_response(),
    }
}

async fn poll_mutation_authorization_inner(
    app: AppState,
    token: String,
    req: Parts,
) -> AppResult<Json<PollMutationAuthorizationResponse>> {
    let mut conn = app.db_write().await?;
    let Some(challenge) = ApiMfaChallenge::find_by_poll_token(&token, &conn).await? else {
        return Err(not_found());
    };
    let bucket_key = challenge_rate_limit_key(&challenge.id, &req)?;
    app.rate_limiter
        .check_key_rate_limit(&bucket_key, LimitedAction::ApiMfaChallengePoll, &mut conn)
        .await?;
    app.instance_metrics.api_mfa_challenge_polls_total.inc();

    // A core grant is single-use. Its poll capability disappears once the
    // final request has atomically consumed the grant.
    if challenge.mutation_state.as_deref() == Some("consumed") {
        return Err(not_found());
    }

    let now = Utc::now();
    let response =
        if challenge.mutation_state.as_deref() == Some("denied") && challenge.expires_at > now {
            PollMutationAuthorizationResponse {
                status: "denied".into(),
                detail: Some("The registry authorization request was denied.".into()),
                challenge_expires_in: None,
                grant_expires_in: None,
                receive_lease_secs: None,
                recommended_poll_interval_secs: None,
            }
        } else if challenge.verified_at.is_some() {
            if let Some(grant_expires_in) = grant_expires_in_for_state(
                challenge.mutation_state.as_deref(),
                challenge.receive_expires_at,
                challenge.verified_at,
                challenge.completed_at,
            ) {
                PollMutationAuthorizationResponse {
                    status: "ready".into(),
                    detail: None,
                    challenge_expires_in: None,
                    grant_expires_in: Some(grant_expires_in),
                    receive_lease_secs: receive_lease_secs_for_state(
                        challenge.idempotent_final,
                        challenge.mutation_state.as_deref(),
                        challenge.receive_expires_at,
                        challenge.completed_at,
                    ),
                    recommended_poll_interval_secs: None,
                }
            } else {
                PollMutationAuthorizationResponse {
                    status: "expired".into(),
                    detail: None,
                    challenge_expires_in: None,
                    grant_expires_in: None,
                    receive_lease_secs: None,
                    recommended_poll_interval_secs: None,
                }
            }
        } else if challenge.expires_at <= now {
            PollMutationAuthorizationResponse {
                status: "expired".into(),
                detail: None,
                challenge_expires_in: None,
                grant_expires_in: None,
                receive_lease_secs: None,
                recommended_poll_interval_secs: None,
            }
        } else {
            PollMutationAuthorizationResponse {
                status: "pending".into(),
                detail: None,
                challenge_expires_in: Some(
                    (challenge.expires_at - now).num_seconds().clamp(1, 300) as u64,
                ),
                grant_expires_in: None,
                receive_lease_secs: None,
                recommended_poll_interval_secs: Some(RECOMMENDED_POLL_INTERVAL_SECS),
            }
        };
    Ok(Json(response))
}
