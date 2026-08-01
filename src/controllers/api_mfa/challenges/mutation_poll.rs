//! Polling through the mutation authorization's independent capability.

use axum::Json;
use axum::extract::Path;
use axum_extra::TypedHeader;
use axum_extra::headers::CacheControl;
use chrono::Utc;
use http::request::Parts;
use serde::Serialize;

use crate::api_mfa::RECOMMENDED_POLL_INTERVAL_SECS;
use crate::app::AppState;
use crate::models::{ApiMfaChallenge, MUTATION_RECEIVE_LEASE_SECS};
use crate::rate_limiter::LimitedAction;
use crate::util::errors::{AppResult, not_found};
use crate::util::no_store;

use super::mutation_response::grant_expires_in_for_state;
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
) -> AppResult<(
    TypedHeader<CacheControl>,
    Json<PollMutationAuthorizationResponse>,
)> {
    let mut conn = app.db_write().await?;
    let Some(challenge) = ApiMfaChallenge::find_by_poll_token(&token, &conn).await? else {
        return Err(not_found());
    };
    let bucket_key = challenge_rate_limit_key(&challenge.id, &req)?;
    app.rate_limiter
        .check_key_rate_limit(&bucket_key, LimitedAction::ApiMfaChallengePoll, &mut conn)
        .await?;
    app.instance_metrics.api_mfa_challenge_polls_total.inc();

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
        } else if challenge.completed_at.is_some() {
            PollMutationAuthorizationResponse {
                status: "ready".into(),
                detail: None,
                challenge_expires_in: None,
                grant_expires_in: Some(300),
                receive_lease_secs: challenge
                    .idempotent_final
                    .then_some(MUTATION_RECEIVE_LEASE_SECS as u64),
                recommended_poll_interval_secs: None,
            }
        } else if challenge.verified_at.is_some() {
            if let Some(grant_expires_in) = grant_expires_in_for_state(
                challenge.mutation_state.as_deref(),
                challenge.receive_expires_at,
                challenge.verified_at,
            ) {
                PollMutationAuthorizationResponse {
                    status: "ready".into(),
                    detail: None,
                    challenge_expires_in: None,
                    grant_expires_in: Some(grant_expires_in),
                    receive_lease_secs: challenge
                        .idempotent_final
                        .then_some(MUTATION_RECEIVE_LEASE_SECS as u64),
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
    Ok((no_store(), Json(response)))
}
