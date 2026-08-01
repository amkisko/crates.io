//! Verification-page status, denial, and ceremony rate limiting.

use axum::Json;
use axum::extract::Path;
use axum_extra::TypedHeader;
use axum_extra::headers::CacheControl;
use chrono::{DateTime, Utc};
use http::request::Parts;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::api_mfa::RECOMMENDED_POLL_INTERVAL_SECS;
use crate::app::AppState;
use crate::middleware::real_ip::RealIp;
use crate::models::ApiMfaChallenge;
use crate::rate_limiter::LimitedAction;
use crate::util::errors::{AppResult, bad_request, not_found, server_error};
use crate::util::no_store;

use super::MutationAuthorizationResponse;
use super::mutation_response::challenge_denied_response;

/// Current state and operation details for an API MFA challenge.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct GetChallengeResponse {
    /// Opaque API MFA challenge identifier.
    pub challenge_id: String,
    /// `pending`, `ready`, or `denied`.
    pub status: String,
    /// True once the browser passkey ceremony has acknowledged the operation.
    pub acknowledged: bool,
    pub operation: String,
    /// Server-generated description of the exact mutation being approved.
    pub operation_summary: String,
    pub crate_name: Option<String>,
    /// Hex SHA-256 of the publish archive, when this is a publish authorization.
    pub archive_sha256: Option<String>,
    pub expires_at: DateTime<Utc>,
    /// Suggested seconds between CLI polls while status is `pending`.
    pub recommended_poll_interval_secs: u64,
}

/// Poll an API MFA challenge until the browser acknowledges it.
///
/// The opaque `challenge_id` is a capability URL: the verify page can load
/// metadata without a crates.io cookie. Requests are rate-limited by capability,
/// IP, and challenge owner. Aside from rate-limit bucket updates this handler is
/// read-only.
#[utoipa::path(
    get,
    path = "/api/v1/auth/challenges/{id}",
    params(("id" = String, Path, description = "Challenge ID")),
    tag = "users",
    extensions(("x-internal" = json!(true))),
    responses((status = 200, description = "Successful Response", body = inline(GetChallengeResponse))),
)]
pub async fn get_api_mfa_challenge(
    app: AppState,
    Path(id): Path<String>,
    req: Parts,
) -> AppResult<(TypedHeader<CacheControl>, Json<GetChallengeResponse>)> {
    // Rate-limit buckets need a write connection; challenge rows are only read.
    //
    // Unauthenticated polls are limited by the challenge *owner* id. Synthetic
    // negative IP ids cannot be stored in `publish_limit_buckets` (FK → users).
    let mut conn = app.db_write().await?;

    let Some(challenge) = ApiMfaChallenge::find_active(&id, &conn).await? else {
        return Err(not_found());
    };

    let bucket_key = challenge_rate_limit_key(&challenge.id, &req)?;
    app.rate_limiter
        .check_key_rate_limit(&bucket_key, LimitedAction::ApiMfaChallengePoll, &mut conn)
        .await?;
    app.rate_limiter
        .check_rate_limit(
            challenge.user_id,
            LimitedAction::ApiMfaChallengeAggregate,
            &mut conn,
        )
        .await?;

    let acknowledged = challenge.is_acknowledged();
    let status = if challenge.mutation_state.as_deref() == Some("denied") {
        "denied"
    } else if acknowledged {
        "ready"
    } else {
        "pending"
    };
    let archive_sha256 = challenge
        .descriptor_json
        .as_ref()
        .and_then(|descriptor| descriptor.get("archive_sha256"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    Ok((
        no_store(),
        Json(GetChallengeResponse {
            challenge_id: challenge.id,
            status: status.into(),
            acknowledged,
            operation: challenge.operation,
            operation_summary: challenge.operation_summary,
            crate_name: challenge.crate_name,
            archive_sha256,
            expires_at: challenge.expires_at,
            recommended_poll_interval_secs: RECOMMENDED_POLL_INTERVAL_SECS,
        }),
    ))
}

/// Deny a pending mutation authorization from its verification page.
#[utoipa::path(
    post,
    path = "/api/v1/auth/challenges/{id}/deny",
    params(("id" = String, Path, description = "Challenge ID")),
    tag = "users",
    extensions(("x-internal" = json!(true))),
    responses((status = 200, description = "Mutation authorization denied", body = inline(MutationAuthorizationResponse))),
)]
pub async fn deny_api_mfa_challenge(
    app: AppState,
    Path(id): Path<String>,
    req: Parts,
) -> AppResult<(
    TypedHeader<CacheControl>,
    Json<MutationAuthorizationResponse>,
)> {
    let mut conn = app.db_write().await?;
    let Some(challenge) = ApiMfaChallenge::find_active(&id, &conn).await? else {
        return Err(not_found());
    };
    if challenge.mutation_state.is_none() {
        return Err(bad_request("only mutation authorizations can be denied"));
    }

    rate_limit_challenge_ceremony(&app, &challenge, &req, &mut conn).await?;
    if challenge.mutation_state.as_deref() != Some("denied") && !challenge.deny(&conn).await? {
        return Err(bad_request(
            "this mutation authorization is no longer pending",
        ));
    }

    let challenge = ApiMfaChallenge::find(&id, &conn)
        .await?
        .ok_or_else(not_found)?;
    Ok((no_store(), Json(challenge_denied_response(&challenge))))
}

pub(super) async fn rate_limit_challenge_ceremony(
    app: &AppState,
    challenge: &ApiMfaChallenge,
    req: &Parts,
    conn: &mut diesel_async::AsyncPgConnection,
) -> AppResult<()> {
    let bucket_key = challenge_rate_limit_key(&challenge.id, req)?;
    app.rate_limiter
        .check_key_rate_limit(&bucket_key, LimitedAction::ApiMfaChallengeCreate, conn)
        .await?;
    app.rate_limiter
        .check_rate_limit(
            challenge.user_id,
            LimitedAction::ApiMfaChallengeAggregate,
            conn,
        )
        .await?;
    Ok(())
}

pub(super) fn challenge_rate_limit_key(challenge_id: &str, req: &Parts) -> AppResult<String> {
    let real_ip = req
        .extensions
        .get::<RealIp>()
        .ok_or_else(|| server_error("request is missing its resolved client IP"))?;
    let mut hasher = Sha256::new();
    hasher.update(challenge_id.as_bytes());
    hasher.update([0]);
    hasher.update(real_ip.to_string().as_bytes());
    Ok(hex::encode(hasher.finalize()))
}
