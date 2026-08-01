//! Mutation-authorization protocol responses.

use chrono::{DateTime, Utc};

use crate::api_mfa::RECOMMENDED_POLL_INTERVAL_SECS;
use crate::models::{ApiMfaChallenge, MUTATION_RECEIVE_LEASE_SECS};

use super::CreateChallengeResponse;
use super::mutation_preflight::{IDEMPOTENT_FINAL_EXTENSION, LOOPBACK_CALLBACK_EXTENSION};

pub(super) fn challenge_created_response(
    webauthn: &crate::config::WebauthnConfig,
    challenge: &ApiMfaChallenge,
) -> CreateChallengeResponse {
    let (verification_page_url, poll_url) = mutation_authorization_urls(webauthn, challenge);
    let challenge_expires_in = (challenge.expires_at - Utc::now())
        .num_seconds()
        .clamp(1, 300) as u64;
    CreateChallengeResponse {
        status: "pending".into(),
        challenge_id: challenge.id.clone(),
        detail: Some(format!(
            "Additional authentication is required. Open this link to verify with your passkey:\n\n\
             {verification_page_url}\n\nAfter verification, retry the request."
        )),
        poll_url: Some(poll_url),
        protocol_version: Some(1),
        active_extensions: Some(active_extensions(challenge)),
        mutation_id: Some(challenge.id.clone()),
        operation: Some(challenge.operation.clone()),
        crate_name: challenge.crate_name.clone(),
        operation_summary: Some(challenge.operation_summary.clone()),
        challenge_expires_in: Some(challenge_expires_in),
        grant_expires_in: None,
        receive_lease_secs: None,
        expires_at: challenge.expires_at,
        recommended_poll_interval_secs: Some(RECOMMENDED_POLL_INTERVAL_SECS),
    }
}

pub(super) fn challenge_ready_response(challenge: &ApiMfaChallenge) -> CreateChallengeResponse {
    CreateChallengeResponse {
        status: "ready".into(),
        challenge_id: challenge.id.clone(),
        protocol_version: Some(1),
        active_extensions: Some(active_extensions(challenge)),
        mutation_id: Some(challenge.id.clone()),
        detail: None,
        poll_url: None,
        operation: None,
        crate_name: None,
        operation_summary: None,
        challenge_expires_in: None,
        grant_expires_in: Some(grant_expires_in(challenge).unwrap_or(300)),
        receive_lease_secs: challenge
            .idempotent_final
            .then_some(MUTATION_RECEIVE_LEASE_SECS as u64),
        expires_at: challenge.expires_at,
        recommended_poll_interval_secs: None,
    }
}

pub(super) fn grant_expires_in(challenge: &ApiMfaChallenge) -> Option<u64> {
    grant_expires_in_for_state(
        challenge.mutation_state.as_deref(),
        challenge.receive_expires_at,
        challenge.verified_at,
    )
}

pub(super) fn grant_expires_in_for_state(
    mutation_state: Option<&str>,
    receive_expires_at: Option<DateTime<Utc>>,
    verified_at: Option<DateTime<Utc>>,
) -> Option<u64> {
    if mutation_state == Some("terminal") {
        return Some(300);
    }
    if mutation_state == Some("executing") {
        return Some(1);
    }
    let deadline = if mutation_state == Some("receiving") {
        receive_expires_at?
    } else {
        verified_at? + chrono::TimeDelta::seconds(300)
    };
    let remaining = (deadline - Utc::now()).num_seconds();
    (remaining > 0).then_some(remaining.min(300) as u64)
}

pub(super) fn challenge_expired_response(challenge: &ApiMfaChallenge) -> CreateChallengeResponse {
    CreateChallengeResponse {
        status: "expired".into(),
        challenge_id: challenge.id.clone(),
        protocol_version: Some(1),
        active_extensions: Some(active_extensions(challenge)),
        mutation_id: Some(challenge.id.clone()),
        detail: Some("The registry authorization request expired.".into()),
        poll_url: None,
        operation: None,
        crate_name: None,
        operation_summary: None,
        challenge_expires_in: None,
        grant_expires_in: None,
        receive_lease_secs: None,
        expires_at: challenge.expires_at,
        recommended_poll_interval_secs: None,
    }
}

pub(super) fn challenge_denied_response(challenge: &ApiMfaChallenge) -> CreateChallengeResponse {
    CreateChallengeResponse {
        status: "denied".into(),
        challenge_id: challenge.id.clone(),
        protocol_version: Some(1),
        active_extensions: Some(active_extensions(challenge)),
        mutation_id: Some(challenge.id.clone()),
        detail: Some("The registry authorization request was denied.".into()),
        poll_url: None,
        operation: None,
        crate_name: None,
        operation_summary: None,
        challenge_expires_in: None,
        grant_expires_in: None,
        receive_lease_secs: None,
        expires_at: challenge.expires_at,
        recommended_poll_interval_secs: None,
    }
}

fn active_extensions(challenge: &ApiMfaChallenge) -> Vec<String> {
    let mut extensions = Vec::with_capacity(2);
    if challenge.idempotent_final {
        extensions.push(IDEMPOTENT_FINAL_EXTENSION.to_owned());
    }
    if challenge.callback_url.is_some() {
        extensions.push(LOOPBACK_CALLBACK_EXTENSION.to_owned());
    }
    extensions
}

fn mutation_authorization_urls(
    webauthn: &crate::config::WebauthnConfig,
    challenge: &ApiMfaChallenge,
) -> (String, String) {
    let verification_base = webauthn.rp_origin.as_str().trim_end_matches('/');
    let api_base = webauthn.api_origin.as_str().trim_end_matches('/');
    let poll_token = challenge
        .poll_token
        .as_deref()
        .expect("preflight mutation must have a poll token");
    (
        format!("{verification_base}/verify/{}", challenge.id),
        format!("{api_base}/api/v1/auth/mutation-challenges/poll/{poll_token}"),
    )
}
