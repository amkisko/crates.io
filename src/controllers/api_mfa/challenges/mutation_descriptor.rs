//! Validation and canonicalization of exact mutation descriptors.

use serde_json::json;
use sha2::{Digest, Sha256};

use crate::api_mfa::ApiMfaOperation;
use crate::models::NewApiMfaMutationDescriptor;
use crate::util::errors::{AppResult, bad_request};

use super::CreateChallengeRequest;

#[derive(Debug)]
pub(super) struct ValidatedMutationDescriptor {
    operation: &'static str,
    crate_name: String,
    summary: String,
    fingerprint: Vec<u8>,
    pub(super) stored: NewApiMfaMutationDescriptor,
    pub(super) idempotent_final: bool,
}

impl ValidatedMutationDescriptor {
    pub(super) fn operation(&self) -> ApiMfaOperation {
        ApiMfaOperation {
            kind: self.operation,
            crate_name: Some(self.crate_name.clone()),
            mutation_fingerprint: self.fingerprint.clone(),
            summary: self.summary.clone(),
            facts: self
                .stored
                .descriptor_json
                .as_object()
                .map(|descriptor| {
                    let mut facts = serde_json::Map::new();
                    for name in [
                        "version",
                        "archive_sha256",
                        "archive_size",
                        "direction",
                        "owners",
                    ] {
                        if let Some(value) = descriptor.get(name) {
                            facts.insert(name.to_owned(), value.clone());
                        }
                    }
                    serde_json::Value::Object(facts)
                })
                .unwrap_or(serde_json::Value::Null),
        }
    }
}

pub(super) fn validate_mutation_descriptor(
    body: &CreateChallengeRequest,
    operation: &str,
    max_archive_size: u32,
    idempotent_final: bool,
) -> AppResult<ValidatedMutationDescriptor> {
    if body.protocol_version != Some(1) {
        return Err(bad_request("protocol_version must be 1"));
    }
    let crate_name = required_descriptor_field(body.crate_name.as_deref(), "crate")?;
    if idempotent_final && (body.method.is_none() || body.request_target.is_none()) {
        return Err(bad_request(
            "active idempotent-final requires both method and request_target",
        ));
    }
    if !idempotent_final
        && (body.method.is_some() || body.request_target.is_some() || body.content_type.is_some())
    {
        return Err(bad_request(
            "method, request_target, and content_type require idempotent-final",
        ));
    }
    crates_io_validation::validate_crate_name("crate", crate_name).map_err(bad_request)?;
    let request_sha256 = decode_sha256(
        required_descriptor_field(body.request_sha256.as_deref(), "request_sha256")?,
        "request_sha256",
    )?;
    let request_size = body
        .request_size
        .filter(|size| *size >= 0)
        .ok_or_else(|| bad_request("request_size must be a non-negative integer"))?;

    let (kind, summary, method, request_target, content_type) = match operation {
        "publish" => {
            let version = required_descriptor_field(body.version.as_deref(), "version")?;
            semver::Version::parse(version)
                .map_err(|_| bad_request("version is not valid semver"))?;
            validate_derived_method(body.method.as_deref(), "PUT")?;
            validate_derived_field(
                body.request_target.as_deref(),
                "/api/v1/crates/new",
                "request_target",
            )?;
            validate_derived_field(
                body.content_type.as_deref(),
                "application/octet-stream",
                "content_type",
            )?;
            decode_sha256(
                required_descriptor_field(body.archive_sha256.as_deref(), "archive_sha256")?,
                "archive_sha256",
            )?;
            let _archive_size = body
                .archive_size
                .filter(|size| {
                    *size >= 0 && *size <= request_size && *size <= i64::from(max_archive_size)
                })
                .ok_or_else(|| {
                    bad_request(
                        "archive_size must be non-negative, within the registry upload limit, \
                         and no larger than request_size",
                    )
                })?;
            const MAX_METADATA_SIZE: i64 = 1024 * 1024;
            if request_size - _archive_size > MAX_METADATA_SIZE + 8 {
                return Err(bad_request(
                    "publish request overhead exceeds the metadata limit",
                ));
            }
            (
                "publish",
                format!("Publish {crate_name} {version}"),
                "PUT".to_owned(),
                "/api/v1/crates/new".to_owned(),
                Some("application/octet-stream"),
            )
        }
        "yank" | "unyank" => {
            let version = required_descriptor_field(body.version.as_deref(), "version")?;
            semver::Version::parse(version)
                .map_err(|_| bad_request("version is not valid semver"))?;
            let (kind, verb) = match operation {
                "yank" => ("yank", "Yank"),
                _ => ("unyank", "Unyank"),
            };
            let expected_method = if operation == "yank" { "DELETE" } else { "PUT" };
            let expected_endpoint = format!("/api/v1/crates/{crate_name}/{version}/{operation}");
            validate_derived_method(body.method.as_deref(), expected_method)?;
            validate_derived_field(
                body.request_target.as_deref(),
                &expected_endpoint,
                "request_target",
            )?;
            if body.content_type.is_some() {
                return Err(bad_request(format!(
                    "{operation} content_type must be null"
                )));
            }
            if request_size != 0 || request_sha256 != Sha256::digest([]).as_slice() {
                return Err(bad_request(format!(
                    "{operation} must describe an empty request body"
                )));
            }
            (
                kind,
                format!("{verb} {crate_name} {version}"),
                expected_method.to_owned(),
                expected_endpoint,
                None,
            )
        }
        "owners" => {
            if request_size > 64 * 1024 {
                return Err(bad_request("owner-change request body is too large"));
            }
            let direction = required_descriptor_field(body.direction.as_deref(), "direction")?;
            let expected_method = match direction {
                "add" => "PUT",
                "remove" => "DELETE",
                _ => return Err(bad_request("direction must be `add` or `remove`")),
            };
            let expected_endpoint = format!("/api/v1/crates/{crate_name}/owners");
            validate_derived_method(body.method.as_deref(), expected_method)?;
            validate_derived_field(
                body.request_target.as_deref(),
                &expected_endpoint,
                "request_target",
            )?;
            validate_derived_field(
                body.content_type.as_deref(),
                "application/json",
                "content_type",
            )?;
            let owners = body
                .owners
                .as_ref()
                .ok_or_else(|| bad_request("owners is required for an owner change"))?;
            if owners.len() > 10 {
                return Err(bad_request("owners may contain at most 10 entries"));
            }
            let verb = if direction == "add" { "Add" } else { "Remove" };
            (
                "owners",
                format!("{verb} owners for {crate_name}: {}", owners.join(", ")),
                expected_method.to_owned(),
                expected_endpoint,
                Some("application/json"),
            )
        }
        _ => {
            return Err(bad_request(
                "operation is not supported by mutation preflight",
            ));
        }
    };

    let mut descriptor = serde_json::Map::from_iter([
        ("protocol_version".to_owned(), serde_json::json!(1)),
        ("operation".to_owned(), serde_json::json!(kind)),
        ("method".to_owned(), serde_json::json!(&method)),
        (
            "request_target".to_owned(),
            serde_json::json!(&request_target),
        ),
        ("content_type".to_owned(), serde_json::json!(content_type)),
        ("crate".to_owned(), serde_json::json!(crate_name)),
        (
            "request_sha256".to_owned(),
            serde_json::json!(hex::encode(&request_sha256)),
        ),
        ("request_size".to_owned(), serde_json::json!(request_size)),
    ]);
    for (name, value) in [
        ("version", body.version.as_ref().map(|value| json!(value))),
        (
            "archive_sha256",
            body.archive_sha256
                .as_ref()
                .map(|value| json!(value.trim().to_ascii_lowercase())),
        ),
        ("archive_size", body.archive_size.map(|value| json!(value))),
        (
            "direction",
            body.direction.as_ref().map(|value| json!(value.trim())),
        ),
        ("owners", body.owners.as_ref().map(|value| json!(value))),
    ] {
        if let Some(value) = value {
            descriptor.insert(name.to_owned(), value);
        }
    }
    let descriptor_json = serde_json::Value::Object(descriptor);
    let fingerprint = Sha256::digest(serde_json::to_vec(&descriptor_json)?).to_vec();
    Ok(ValidatedMutationDescriptor {
        operation: kind,
        crate_name: crate_name.to_owned(),
        summary,
        fingerprint,
        stored: NewApiMfaMutationDescriptor {
            descriptor_json,
            request_method: method,
            request_endpoint: request_target,
            request_sha256,
            request_size,
        },
        idempotent_final,
    })
}

fn validate_derived_method(supplied: Option<&str>, expected: &str) -> AppResult<()> {
    if supplied.is_some_and(|supplied| !supplied.trim().eq_ignore_ascii_case(expected)) {
        return Err(bad_request(format!(
            "method contradicts the server-derived value `{expected}`"
        )));
    }
    Ok(())
}

fn validate_derived_field(supplied: Option<&str>, expected: &str, field: &str) -> AppResult<()> {
    if supplied.is_some_and(|supplied| supplied.trim() != expected) {
        return Err(bad_request(format!(
            "{field} contradicts the server-derived value `{expected}`"
        )));
    }
    Ok(())
}

pub(super) fn required_descriptor_field<'a>(
    value: Option<&'a str>,
    name: &str,
) -> AppResult<&'a str> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| bad_request(format!("{name} is required for mutation preflight")))
}

fn decode_sha256(value: &str, name: &str) -> AppResult<Vec<u8>> {
    let decoded =
        hex::decode(value).map_err(|_| bad_request(format!("{name} must be hex SHA-256")))?;
    if decoded.len() != 32 {
        return Err(bad_request(format!("{name} must be hex SHA-256")));
    }
    Ok(decoded)
}
