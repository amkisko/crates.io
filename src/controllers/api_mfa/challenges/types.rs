//! API MFA and mutation-authorization challenge wire types.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// An optional JSON field that preserves the distinction between absent and `null`.
#[derive(Debug)]
pub struct OptionalField<T> {
    present: bool,
    value: Option<T>,
}

impl<T> OptionalField<T> {
    /// Returns whether the field occurred in the input object.
    pub fn is_present(&self) -> bool {
        self.present
    }

    /// Returns whether the field was absent from the input object.
    pub fn is_absent(&self) -> bool {
        !self.present
    }

    /// Borrows the non-null field value.
    pub fn as_ref(&self) -> Option<&T> {
        self.value.as_ref()
    }

    /// Borrows a string-like non-null field value.
    pub fn as_deref(&self) -> Option<&T::Target>
    where
        T: std::ops::Deref,
    {
        self.value.as_deref()
    }

    /// Returns whether the field value is null or absent.
    pub fn is_none(&self) -> bool {
        self.value.is_none()
    }

    /// Returns whether the field contains a non-null value.
    pub fn is_some(&self) -> bool {
        self.value.is_some()
    }
}

impl<T> Default for OptionalField<T> {
    fn default() -> Self {
        Self {
            present: false,
            value: None,
        }
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for OptionalField<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Option::<T>::deserialize(deserializer).map(|value| Self {
            present: true,
            value,
        })
    }
}

impl<T: Serialize> Serialize for OptionalField<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.value.serialize(serializer)
    }
}

/// Version 1 mutation-authorization preflight request.
#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
pub struct MutationAuthorizationRequest {
    /// Cargo mutation operation: `publish`, `yank`, `unyank`, or `owners`.
    pub operation: String,
    /// Crate name associated with the operation.
    #[serde(rename = "crate")]
    pub crate_name: String,
    /// HTTP method of the ordinary mutation.
    #[serde(default, skip_serializing_if = "OptionalField::is_absent")]
    #[schema(value_type = Option<String>)]
    pub method: OptionalField<String>,
    /// Origin-form target of the ordinary mutation.
    #[serde(default, skip_serializing_if = "OptionalField::is_absent")]
    #[schema(value_type = Option<String>)]
    pub request_target: OptionalField<String>,
    /// Normalized media type of the ordinary mutation, or null when bodyless.
    #[serde(default, skip_serializing_if = "OptionalField::is_absent")]
    #[schema(value_type = Option<String>)]
    pub content_type: OptionalField<String>,
    /// Version involved in publish, yank, or unyank.
    pub version: Option<String>,
    /// Hex SHA-256 of the exact raw mutation request body.
    pub request_sha256: String,
    /// Length of the exact raw mutation request body.
    pub request_size: i64,
    /// Hex SHA-256 of the publish archive bytes.
    pub archive_sha256: Option<String>,
    /// Length of the publish archive bytes.
    pub archive_size: Option<i64>,
    /// `add` or `remove` for owner changes.
    pub direction: Option<String>,
    /// Complete ordered owner list for owner changes.
    pub owners: Option<Vec<String>>,
    /// Mutation-authorization protocol version. Version 1 is supported.
    pub protocol_version: u64,
    /// Cargo-generated logical invocation identifier.
    pub preflight_id: String,
    /// Whether the registry may create a pending authorization record.
    pub allow_pending: bool,
    /// Protocol extensions Cargo can use for this invocation.
    pub requested_extensions: Vec<String>,
    /// Optional exact loopback callback URL carrying wake-up state.
    #[serde(default, skip_serializing_if = "OptionalField::is_absent")]
    #[schema(value_type = Option<MutationCallbackRequest>)]
    pub callback: OptionalField<MutationCallbackRequest>,
}

/// Loopback delivery metadata for a mutation preflight.
#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
pub struct MutationCallbackRequest {
    /// Exact loopback URL with one random `state` query parameter.
    pub url: String,
}

/// Version 1 mutation-authorization preflight response.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct MutationAuthorizationResponse {
    /// Mutation protocol state.
    pub status: String,
    /// Selected mutation-authorization protocol version.
    pub protocol_version: u64,
    /// Extensions activated and bound to this mutation record.
    pub active_extensions: Vec<String>,
    /// Mutation record identifier sent on the final request.
    pub mutation_id: String,
    /// Complete human-readable instructions for satisfying the challenge.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// URL the CLI should poll until authorization reaches a terminal or ready state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub poll_url: Option<String>,
    /// Conservative remaining pending lifetime in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge_expires_in: Option<u64>,
    /// Conservative remaining ready-grant lifetime in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_expires_in: Option<u64>,
    /// Remaining receive lease when `idempotent-final` is active.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receive_lease_secs: Option<u64>,
    /// Suggested seconds between CLI polls of `poll_url`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recommended_poll_interval_secs: Option<u64>,
}
