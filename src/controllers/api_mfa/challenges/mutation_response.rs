//! Mutation-authorization protocol responses.

use chrono::{DateTime, Utc};

use crate::api_mfa::RECOMMENDED_POLL_INTERVAL_SECS;
use crate::models::{
    ApiMfaChallenge, MUTATION_RECEIVE_LEASE_SECS, MUTATION_TERMINAL_RETENTION_SECS,
};

use super::MutationAuthorizationResponse;
use super::mutation_preflight::{IDEMPOTENT_FINAL_EXTENSION, LOOPBACK_CALLBACK_EXTENSION};

pub(super) fn challenge_created_response(
    webauthn: &crate::config::WebauthnConfig,
    challenge: &ApiMfaChallenge,
) -> MutationAuthorizationResponse {
    let (verification_page_url, poll_url) = mutation_authorization_urls(webauthn, challenge);
    let challenge_expires_in = (challenge.expires_at - Utc::now())
        .num_seconds()
        .clamp(1, 300) as u64;
    MutationAuthorizationResponse {
        status: "pending".into(),
        detail: Some(format!(
            "Additional authentication is required. Open this link to verify with your passkey:\n\n\
             {verification_page_url}\n\nCargo will continue after authorization."
        )),
        poll_url: Some(poll_url),
        protocol_version: 1,
        active_extensions: active_extensions(challenge),
        mutation_id: challenge.id.clone(),
        challenge_expires_in: Some(challenge_expires_in),
        grant_expires_in: None,
        receive_lease_secs: None,
        recommended_poll_interval_secs: Some(RECOMMENDED_POLL_INTERVAL_SECS),
    }
}

pub(super) fn challenge_ready_response(
    challenge: &ApiMfaChallenge,
) -> MutationAuthorizationResponse {
    MutationAuthorizationResponse {
        status: "ready".into(),
        protocol_version: 1,
        active_extensions: active_extensions(challenge),
        mutation_id: challenge.id.clone(),
        detail: None,
        poll_url: None,
        challenge_expires_in: None,
        grant_expires_in: Some(
            grant_expires_in(challenge).expect("ready response requires a live grant"),
        ),
        receive_lease_secs: receive_lease_secs(challenge),
        recommended_poll_interval_secs: None,
    }
}

pub(super) fn grant_expires_in(challenge: &ApiMfaChallenge) -> Option<u64> {
    grant_expires_in_for_state(
        challenge.mutation_state.as_deref(),
        challenge.receive_expires_at,
        challenge.verified_at,
        challenge.completed_at,
    )
}

pub(super) fn grant_expires_in_for_state(
    mutation_state: Option<&str>,
    receive_expires_at: Option<DateTime<Utc>>,
    verified_at: Option<DateTime<Utc>>,
    completed_at: Option<DateTime<Utc>>,
) -> Option<u64> {
    let deadline = match mutation_state {
        Some("ready") => verified_at? + chrono::TimeDelta::seconds(300),
        Some("receiving") => receive_expires_at?,
        Some("executing") => return Some(1),
        Some("terminal") => {
            completed_at? + chrono::TimeDelta::seconds(MUTATION_TERMINAL_RETENTION_SECS)
        }
        Some("pending" | "denied" | "expired" | "consumed") | None | Some(_) => return None,
    };
    let remaining = (deadline - Utc::now()).num_seconds();
    (remaining > 0).then_some(remaining.min(300) as u64)
}

pub(super) fn receive_lease_secs(challenge: &ApiMfaChallenge) -> Option<u64> {
    receive_lease_secs_for_state(
        challenge.idempotent_final,
        challenge.mutation_state.as_deref(),
        challenge.receive_expires_at,
        challenge.completed_at,
    )
}

pub(super) fn receive_lease_secs_for_state(
    idempotent_final: bool,
    mutation_state: Option<&str>,
    receive_expires_at: Option<DateTime<Utc>>,
    completed_at: Option<DateTime<Utc>>,
) -> Option<u64> {
    if !idempotent_final {
        return None;
    }
    let now = Utc::now();
    let remaining = match mutation_state {
        Some("ready") => return Some(MUTATION_RECEIVE_LEASE_SECS as u64),
        Some("receiving") => (receive_expires_at? - now).num_seconds(),
        Some("executing") => 1,
        Some("terminal") => {
            let deadline =
                completed_at? + chrono::TimeDelta::seconds(MUTATION_TERMINAL_RETENTION_SECS);
            (deadline - now).num_seconds()
        }
        _ => return None,
    };
    (remaining > 0).then_some(remaining.min(3_600) as u64)
}

pub(super) fn challenge_expired_response(
    challenge: &ApiMfaChallenge,
) -> MutationAuthorizationResponse {
    MutationAuthorizationResponse {
        status: "expired".into(),
        protocol_version: 1,
        active_extensions: active_extensions(challenge),
        mutation_id: challenge.id.clone(),
        detail: Some("The registry authorization request expired.".into()),
        poll_url: None,
        challenge_expires_in: None,
        grant_expires_in: None,
        receive_lease_secs: None,
        recommended_poll_interval_secs: None,
    }
}

pub(super) fn challenge_denied_response(
    challenge: &ApiMfaChallenge,
) -> MutationAuthorizationResponse {
    MutationAuthorizationResponse {
        status: "denied".into(),
        protocol_version: 1,
        active_extensions: active_extensions(challenge),
        mutation_id: challenge.id.clone(),
        detail: Some("The registry authorization request was denied.".into()),
        poll_url: None,
        challenge_expires_in: None,
        grant_expires_in: None,
        receive_lease_secs: None,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_ready_states_never_expose_a_grant_window() {
        let verified_at = Some(Utc::now());
        for state in ["pending", "denied", "expired", "consumed", "invalid"] {
            assert_eq!(
                grant_expires_in_for_state(Some(state), None, verified_at, None),
                None,
                "state {state} exposed a grant window"
            );
        }
    }

    #[test]
    fn receiving_and_terminal_windows_count_down() {
        let now = Utc::now();
        let receiving = grant_expires_in_for_state(
            Some("receiving"),
            Some(now + chrono::TimeDelta::seconds(20)),
            Some(now),
            None,
        )
        .unwrap();
        assert!((19..=20).contains(&receiving));

        let terminal = grant_expires_in_for_state(
            Some("terminal"),
            None,
            Some(now),
            Some(now - chrono::TimeDelta::seconds(MUTATION_TERMINAL_RETENTION_SECS - 20)),
        )
        .unwrap();
        assert!((19..=20).contains(&terminal));
    }
}
