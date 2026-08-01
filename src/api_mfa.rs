//! API MFA helpers for sensitive registry operations.

use crate::auth::Authentication;
use crate::metrics::InstanceMetrics;
use crate::middleware::idempotent_mutation::{IdempotentMutation, replay_response};
use crate::middleware::log_request::RequestLogExt;
use crate::models::{ApiMfaChallenge, ApiMfaGrant, OwnerKind, WebauthnCredential};
use crate::schema::{crate_owners, crates, users};
use crate::util::errors::{AppResult, BoxedAppError, bad_request, custom, server_error};
use axum::response::Response;
use diesel::prelude::*;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use http::{StatusCode, request::Parts};
use std::fmt;
use std::sync::Arc;
use std::time::Instant;

/// Recommended CLI poll interval for challenge acknowledgment (seconds).
///
/// Clients treat this as an advisory interval.
pub const RECOMMENDED_POLL_INTERVAL_SECS: u64 = 5;

/// Dangerous API operation that requires passkey acknowledgment when API MFA is enabled.
#[derive(Debug, Clone)]
pub struct ApiMfaOperation {
    pub kind: &'static str,
    pub crate_name: Option<String>,
    pub summary: String,
    /// Server-parsed fields compared with an untrusted preflight descriptor.
    pub facts: serde_json::Value,
}

impl ApiMfaOperation {
    /// Whether this request targets a Cargo mutation-authorization final endpoint.
    fn is_protocol_final(&self, parts: &Parts) -> bool {
        let method = &parts.method;
        let path = parts.uri.path();
        match self.kind {
            "publish" => method == http::Method::PUT && path == "/api/v1/crates/new",
            "yank" | "unyank" => {
                let Some(crate_name) = self.crate_name.as_deref() else {
                    return false;
                };
                let Some(version) = self
                    .facts
                    .get("version")
                    .and_then(serde_json::Value::as_str)
                else {
                    return false;
                };
                let action = if self.kind == "yank" {
                    "yank"
                } else {
                    "unyank"
                };
                let expected = format!("/api/v1/crates/{crate_name}/{version}/{action}");
                method
                    == if self.kind == "yank" {
                        http::Method::DELETE
                    } else {
                        http::Method::PUT
                    }
                    && path == expected
            }
            "owners" => {
                let Some(crate_name) = self.crate_name.as_deref() else {
                    return false;
                };
                (method == http::Method::PUT || method == http::Method::DELETE)
                    && path == format!("/api/v1/crates/{crate_name}/owners")
            }
            _ => false,
        }
    }

    fn new(kind: &'static str, crate_name: Option<String>, summary: String) -> Self {
        Self {
            kind,
            crate_name,
            summary,
            facts: serde_json::Value::Null,
        }
    }

    fn with_facts(mut self, facts: serde_json::Value) -> Self {
        self.facts = facts;
        self
    }

    /// Bind a publish approval to the exact metadata and tarball bytes.
    pub fn publish(
        crate_name: &str,
        version: &str,
        tarball_sha256: &[u8],
        tarball_size: u64,
    ) -> Self {
        Self::new(
            "publish",
            Some(crate_name.to_owned()),
            format!("Publish {crate_name} {version}"),
        )
        .with_facts(serde_json::json!({
            "version": version,
            "archive_sha256": hex::encode(tarball_sha256),
            "archive_size": tarball_size,
        }))
    }

    /// Bind a yank approval to the exact version and optional public message.
    pub fn yank(crate_name: &str, version: &str, yank_message: Option<&str>) -> Self {
        Self::new(
            "yank",
            Some(crate_name.to_owned()),
            format!("Yank {crate_name} {version}"),
        )
        .with_facts(serde_json::json!({
            "version": version,
            "yank_message": yank_message,
        }))
    }

    /// Bind an unyank approval to the exact version.
    pub fn unyank(crate_name: &str, version: &str) -> Self {
        Self::new(
            "unyank",
            Some(crate_name.to_owned()),
            format!("Unyank {crate_name} {version}"),
        )
        .with_facts(serde_json::json!({ "version": version }))
    }

    /// Bind an owner change to its direction and exact submitted owner list.
    pub fn change_owners(crate_name: &str, add: bool, owners: &[String]) -> Self {
        let direction = if add { "Add" } else { "Remove" };
        Self::new(
            "owners",
            Some(crate_name.to_owned()),
            format!("{direction} owners for {crate_name}: {}", owners.join(", ")),
        )
        .with_facts(serde_json::json!({
            "direction": if add { "add" } else { "remove" },
            "owners": owners,
        }))
    }

    /// Toggle `trustpub_only` on crate settings (`PATCH /api/v1/crates/{name}`).
    pub fn change_trustpub_only(crate_name: &str, enabled: bool) -> Self {
        Self::new(
            "change-trustpub-only",
            Some(crate_name.to_owned()),
            format!(
                "{} Trusted Publishing-only mode for {crate_name}",
                if enabled { "Enable" } else { "Disable" }
            ),
        )
    }

    /// Bind Trusted Publishing configuration creation to its exact fields.
    pub fn create_trusted_publishing(crate_name: &str, provider: &str) -> Self {
        Self::new(
            "change-trusted-publishing",
            Some(crate_name.to_owned()),
            format!("Create {provider} Trusted Publishing config for {crate_name}"),
        )
    }

    /// Bind Trusted Publishing configuration deletion to provider and row id.
    pub fn delete_trusted_publishing(crate_name: &str, provider: &str, id: i32) -> Self {
        let id = id.to_string();
        Self::new(
            "change-trusted-publishing",
            Some(crate_name.to_owned()),
            format!("Delete {provider} Trusted Publishing config {id} for {crate_name}"),
        )
    }

    /// Delete a crate (`DELETE /api/v1/crates/{name}`).
    pub fn delete_crate(crate_name: &str) -> Self {
        Self::new(
            "delete-crate",
            Some(crate_name.to_owned()),
            format!("Delete crate {crate_name}"),
        )
    }

    /// Accept a crate owner invitation (cookie session).
    pub fn accept_owner_invite(crate_name: &str) -> Self {
        Self::new(
            "accept-owner-invite",
            Some(crate_name.to_owned()),
            format!("Accept owner invitation for {crate_name}"),
        )
    }
}

/// Returns whether any individual owner of `crate_name` has API MFA enabled.
///
/// Unknown crate names return `false` (caller still enforces actor MFA / ownership later).
pub async fn crate_requires_api_mfa(
    crate_name: &str,
    conn: &mut AsyncPgConnection,
) -> AppResult<bool> {
    let requires = diesel::select(diesel::dsl::exists(
        crate_owners::table
            .inner_join(crates::table)
            .inner_join(users::table.on(crate_owners::owner_id.eq(users::id)))
            .filter(crates::name.eq(crate_name))
            .filter(crate_owners::owner_kind.eq(OwnerKind::User))
            .filter(crate_owners::deleted.eq(false))
            .filter(users::api_mfa_enabled.eq(true)),
    ))
    .get_result(conn)
    .await?;
    Ok(requires)
}

/// Shared dependencies for [`ensure_api_mfa`].
pub struct ApiMfaEnsureDeps<'a> {
    pub metrics: &'a InstanceMetrics,
    /// When false (`API_MFA_ENFORCEMENT_ENABLED=false`), skip enforcement entirely.
    pub enforcement_enabled: bool,
}

enum EnsureOutcome {
    Grant,
    /// Cookie session: must authorize on the settings page first (`400`).
    CookieAuthorize(BoxedAppError),
    Error(BoxedAppError),
}

/// Ensures requests satisfy API MFA when the user has it enabled.
///
/// Applies to both API tokens and website cookie sessions for publish, yank,
/// owner changes, crate delete, Trusted Publishing config changes, and
/// `trustpub_only` toggles. Trusted Publishing OIDC tokens are not routed
/// through this helper.
///
/// Token-authenticated Cargo operations (publish, yank, unyank, and owner
/// changes) require an exact ready mutation record supplied through
/// `Cargo-Mutation-Id`.
///
/// Cookie sessions without a grant are told to use Settings → API MFA → Authorize for 15 minutes.
pub async fn ensure_api_mfa(
    auth: &Authentication,
    parts: &Parts,
    conn: &mut AsyncPgConnection,
    deps: ApiMfaEnsureDeps<'_>,
    mut operation: ApiMfaOperation,
) -> AppResult<()> {
    let user = auth.user();
    let mutation_context = validate_idempotent_mutation(auth, parts, conn, &mut operation).await?;
    if let Some(context) = mutation_context {
        // The ready mutation record is the exact credential-and-request-bound grant.
        context.validate_execution();
        return Ok(());
    }
    if !deps.enforcement_enabled {
        return Ok(());
    }

    let crate_requires = if let Some(crate_name) = operation.crate_name.as_deref() {
        crate_requires_api_mfa(crate_name, conn).await?
    } else {
        false
    };

    if !user.api_mfa_enabled {
        if crate_requires {
            return Err(bad_request(
                "This crate requires API MFA because an owner enabled it. \
                 Sign in on the website, enable API MFA under Settings → API MFA, \
                 register a passkey, then retry.",
            ));
        }
        return Ok(());
    }

    if auth.api_token().is_some() && operation.is_protocol_final(parts) {
        return Err(custom(
            StatusCode::FORBIDDEN,
            "Cargo-Mutation-Id is required for this API MFA-protected operation; use a Cargo version that supports registry mutation authorization",
        ));
    }

    let started = Instant::now();
    let outcome = match ensure_api_mfa_inner(auth, conn).await {
        Ok(outcome) => outcome,
        Err(err) => EnsureOutcome::Error(err),
    };

    let (label, result) = match outcome {
        EnsureOutcome::Grant => {
            parts.request_log().add("api_mfa", "grant");
            ("grant", Ok(()))
        }
        EnsureOutcome::CookieAuthorize(err) => {
            parts.request_log().add("api_mfa", "cookie_authorize");
            ("cookie_authorize", Err(err))
        }
        EnsureOutcome::Error(err) => ("error", Err(err)),
    };

    deps.metrics
        .api_mfa_ensure_total
        .with_label_values(&[label])
        .inc();
    deps.metrics
        .api_mfa_ensure_duration_seconds
        .with_label_values(&[label])
        .observe(started.elapsed().as_secs_f64());

    result
}

/// Begins a validated Cargo mutation inside the endpoint's effect transaction.
pub async fn begin_mutation_execution(
    parts: &Parts,
    conn: &AsyncPgConnection,
) -> AppResult<Option<Arc<IdempotentMutation>>> {
    let context = parts.extensions.get::<Arc<IdempotentMutation>>().cloned();
    if let Some(context) = &context {
        if context.idempotent_final {
            context.begin_execution(conn).await?;
        } else {
            let app = parts
                .extensions
                .get::<crate::app::AppState>()
                .ok_or_else(|| server_error("mutation request is missing application state"))?;
            context.begin_core_execution(app).await?;
        }
    }
    Ok(context)
}

#[derive(Debug)]
struct ReplayedMutationResponse(ApiMfaChallenge);

impl fmt::Display for ReplayedMutationResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "replayed mutation {}", self.0.id)
    }
}

impl crate::util::errors::AppError for ReplayedMutationResponse {
    fn response(&self) -> Response {
        replay_response(&self.0).unwrap_or_else(|| {
            crate::util::errors::server_error("stored mutation response is incomplete").response()
        })
    }
}

async fn validate_idempotent_mutation(
    auth: &Authentication,
    parts: &Parts,
    conn: &mut AsyncPgConnection,
    operation: &mut ApiMfaOperation,
) -> AppResult<Option<Arc<IdempotentMutation>>> {
    let Some(context) = parts.extensions.get::<Arc<IdempotentMutation>>().cloned() else {
        return Ok(None);
    };
    let Some(token_id) = auth.api_token_id() else {
        return Err(bad_request(
            "Cargo-Mutation-Id requires API token authentication",
        ));
    };
    let challenge = ApiMfaChallenge::find(&context.id, conn)
        .await?
        .ok_or_else(|| bad_request("Cargo-Mutation-Id is unknown or expired"))?;
    if challenge.api_token_id != Some(token_id) {
        return Err(bad_request(
            "Cargo-Mutation-Id belongs to a different credential",
        ));
    }
    if challenge.request_method.as_deref() != Some(context.method.as_str())
        || challenge.request_endpoint.as_deref() != Some(context.endpoint.as_str())
        || challenge.request_sha256.as_deref() != Some(context.request_sha256.as_slice())
        || challenge.request_size != Some(context.request_size)
    {
        return Err(bad_request(
            "mutation request does not match its preflight descriptor",
        ));
    }
    if challenge.operation != operation.kind || challenge.crate_name != operation.crate_name {
        return Err(bad_request(
            "parsed mutation does not match its preflight operation",
        ));
    }
    let descriptor = challenge
        .descriptor_json
        .as_ref()
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| bad_request("Cargo-Mutation-Id does not identify a mutation preflight"))?;
    if let Some(facts) = operation.facts.as_object() {
        for (name, actual) in facts {
            if let Some(declared) = descriptor.get(name)
                && declared != actual
            {
                return Err(bad_request(format!(
                    "parsed mutation field `{name}` does not match its preflight descriptor"
                )));
            }
        }
    }
    if let Some(response) = replay_response(&challenge) {
        let _ = response;
        return Err(Box::new(ReplayedMutationResponse(challenge)));
    }
    if !challenge.is_acknowledged() {
        return Err(bad_request("mutation challenge has not been acknowledged"));
    }
    let has_live_grant = if challenge.idempotent_final {
        challenge.mutation_state.as_deref() == Some("receiving")
            && challenge
                .receive_expires_at
                .is_some_and(|deadline| deadline > chrono::Utc::now())
    } else {
        challenge.mutation_state.as_deref() == Some("ready")
            && challenge.expires_at > chrono::Utc::now()
    };
    if !has_live_grant {
        return Err(bad_request(
            "Cargo-Mutation-Id is outside its execution window",
        ));
    }

    Ok(Some(context))
}

async fn ensure_api_mfa_inner(
    auth: &Authentication,
    conn: &mut AsyncPgConnection,
) -> AppResult<EnsureOutcome> {
    let user = auth.user();

    let credentials = WebauthnCredential::for_user(user.id, conn).await?;
    if credentials.is_empty() {
        return Err(bad_request(
            "API MFA is enabled but no passkeys are registered. Sign in on the website, \
             request an email code under Settings → API MFA, and register a passkey \
             (or disable API MFA with an email code).",
        ));
    }

    if auth.api_token().is_some() {
        return Err(custom(
            StatusCode::FORBIDDEN,
            "API MFA-protected token operations require the Cargo mutation-authorization protocol",
        ));
    }

    if ApiMfaGrant::active_browser_for_user(user.id, conn)
        .await?
        .is_some()
    {
        return Ok(EnsureOutcome::Grant);
    }

    Ok(EnsureOutcome::CookieAuthorize(bad_request(
        "API MFA is enabled. Open Settings → API MFA, choose Authorize for 15 minutes, \
         complete passkey verification, then retry.",
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_parts(method: http::Method, uri: &str) -> Parts {
        http::Request::builder()
            .method(method)
            .uri(uri)
            .body(())
            .unwrap()
            .into_parts()
            .0
    }

    #[test]
    fn protocol_finals_are_exact_server_derived_routes() {
        let publish = ApiMfaOperation::publish("demo", "1.0.0", &[1; 32], 42);
        assert!(publish.is_protocol_final(&request_parts(http::Method::PUT, "/api/v1/crates/new")));

        let yank = ApiMfaOperation::yank("demo", "1.0.0", None);
        assert!(yank.is_protocol_final(&request_parts(
            http::Method::DELETE,
            "/api/v1/crates/demo/1.0.0/yank"
        )));
        assert!(!yank.is_protocol_final(&request_parts(
            http::Method::PATCH,
            "/api/v1/crates/demo/1.0.0"
        )));

        let owners = ApiMfaOperation::change_owners("demo", true, &["alice".into()]);
        assert!(owners.is_protocol_final(&request_parts(
            http::Method::PUT,
            "/api/v1/crates/demo/owners"
        )));
    }
}
