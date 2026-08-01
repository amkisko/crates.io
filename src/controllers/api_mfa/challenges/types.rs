//! API MFA and mutation-authorization challenge wire types.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Request to create a manual API MFA challenge.
#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
pub struct CreateChallengeRequest {
    /// Dangerous operation label. Defaults to `manual`.
    ///
    /// Allowed: `publish`, `yank`, `unyank`, `owners`, `change-trustpub-only`,
    /// `change-trusted-publishing`, `delete-crate`, `manual`.
    pub operation: Option<String>,
    /// Optional crate name associated with the operation.
    #[serde(rename = "crate")]
    pub crate_name: Option<String>,
    /// HTTP method of the ordinary mutation.
    pub method: Option<String>,
    /// Origin-form target of the ordinary mutation.
    pub request_target: Option<String>,
    /// Normalized media type of the ordinary mutation, or null when bodyless.
    pub content_type: Option<String>,
    /// Version involved in publish, yank, or unyank.
    pub version: Option<String>,
    /// Hex SHA-256 of the exact raw mutation request body.
    pub request_sha256: Option<String>,
    /// Length of the exact raw mutation request body.
    pub request_size: Option<i64>,
    /// Hex SHA-256 of the publish archive bytes.
    pub archive_sha256: Option<String>,
    /// Length of the publish archive bytes.
    pub archive_size: Option<i64>,
    /// `add` or `remove` for owner changes.
    pub direction: Option<String>,
    /// Complete ordered owner list for owner changes.
    pub owners: Option<Vec<String>>,
    /// Mutation-authorization protocol version. Version 1 is supported.
    pub protocol_version: Option<u64>,
    /// Cargo-generated logical invocation identifier.
    pub preflight_id: Option<String>,
    /// Whether the registry may create a pending authorization record.
    pub allow_pending: Option<bool>,
    /// Protocol extensions Cargo can use for this invocation.
    pub requested_extensions: Option<Vec<String>>,
    /// Optional exact loopback callback URL carrying wake-up state.
    pub callback: Option<MutationCallbackRequest>,
    /// Optional localhost port (1024–65535) for proof delivery to the CLI.
    ///
    /// Requires a valid `Cargo-Step-Up-Callback-Secret` header. Polling remains
    /// available as a fallback when callback delivery fails.
    pub port: Option<i32>,
}

/// Loopback delivery metadata for a mutation preflight.
#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
pub struct MutationCallbackRequest {
    /// Exact loopback URL with one random `state` query parameter.
    pub url: String,
}

/// Instructions and timing information for a newly created API MFA challenge.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct CreateChallengeResponse {
    /// Mutation protocol state, or the legacy manual challenge state.
    pub status: String,
    /// Opaque authorization challenge identifier.
    pub challenge_id: String,
    /// Selected mutation-authorization protocol version.
    pub protocol_version: Option<u64>,
    /// Extensions activated and bound to this mutation record.
    pub active_extensions: Option<Vec<String>>,
    /// Mutation record identifier sent on the final request.
    pub mutation_id: Option<String>,
    /// Complete human-readable instructions for satisfying the challenge.
    pub detail: Option<String>,
    /// URL the CLI should poll until `acknowledged` is true.
    pub poll_url: Option<String>,
    /// Server-generated operation label.
    pub operation: Option<String>,
    /// Crate associated with the operation.
    #[serde(rename = "crate")]
    pub crate_name: Option<String>,
    /// Server-generated summary of the exact mutation.
    pub operation_summary: Option<String>,
    /// Conservative remaining pending lifetime in seconds.
    pub challenge_expires_in: Option<u64>,
    /// Conservative remaining ready-grant lifetime in seconds.
    pub grant_expires_in: Option<u64>,
    /// Remaining receive lease when `idempotent-final` is active.
    pub receive_lease_secs: Option<u64>,
    pub expires_at: DateTime<Utc>,
    /// Suggested seconds between CLI polls of `poll_url`.
    pub recommended_poll_interval_secs: Option<u64>,
}
