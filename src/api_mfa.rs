//! API MFA helpers: enforce passkey step-up for sensitive publish/yank/owner/settings actions.

use crate::auth::Authentication;
use crate::config::WebauthnConfig;
use crate::metrics::InstanceMetrics;
use crate::middleware::idempotent_mutation::{IdempotentMutation, replay_response};
use crate::middleware::log_request::RequestLogExt;
use crate::models::{
    ApiMfaChallenge, ApiMfaGrant, MAX_PENDING_CHALLENGES_PER_USER, NewApiMfaChallenge, OwnerKind,
    WebauthnCredential,
};
use crate::rate_limiter::{LimitedAction, RateLimiter};
use crate::schema::{crate_owners, crates, users};
use crate::util::errors::{ApiMfaRequired, AppResult, BoxedAppError, bad_request};
use axum::response::Response;
use diesel::prelude::*;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use http::request::Parts;
use sha2::{Digest, Sha256};
use std::fmt;
use std::sync::Arc;
use std::time::Instant;

/// Header carrying a one-time proof after passkey verification.
///
/// Clients may use the shorter `OTP` alias for compatibility.
pub const CARGO_STEP_UP_PROOF_HEADER: &str = "cargo-step-up-proof";
const OTP_HEADER: &str = "otp";

/// Optional localhost callback port for proof delivery.
pub const CARGO_STEP_UP_PORT_HEADER: &str = "cargo-step-up-port";

/// Client-held secret authorizing localhost callback port refreshes.
pub const CARGO_STEP_UP_CALLBACK_SECRET_HEADER: &str = "cargo-step-up-callback-secret";

/// Recommended CLI poll interval for challenge acknowledgment (seconds).
///
/// Clients treat this as an advisory interval.
pub const RECOMMENDED_POLL_INTERVAL_SECS: u64 = 5;

/// Optional loopback delivery details supplied by a Cargo client.
#[derive(Clone, Copy)]
pub(crate) struct ApiMfaCallback<'a> {
    pub(crate) port: Option<i32>,
    pub(crate) secret: Option<&'a str>,
}

/// Allowed operation values for API MFA and mutation authorization.
pub const ALLOWED_CHALLENGE_OPERATIONS: &[&str] = &[
    "publish",
    "yank",
    "unyank",
    "owners",
    "change-trustpub-only",
    "change-trusted-publishing",
    "delete-crate",
    "accept-owner-invite",
    "manual",
];

/// Normalizes and validates a preflight challenge operation label.
pub fn normalize_challenge_operation(raw: Option<&str>) -> AppResult<String> {
    let op = raw
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("manual");
    if ALLOWED_CHALLENGE_OPERATIONS.contains(&op) {
        return Ok(op.to_owned());
    }
    Err(bad_request(format!(
        "invalid operation `{op}`; allowed values: {}",
        ALLOWED_CHALLENGE_OPERATIONS.join(", ")
    )))
}

/// Dangerous API operation that requires passkey acknowledgment when API MFA is enabled.
#[derive(Debug, Clone)]
pub struct ApiMfaOperation {
    pub kind: &'static str,
    pub crate_name: Option<String>,
    pub mutation_fingerprint: Vec<u8>,
    pub summary: String,
    /// Server-parsed fields compared with an untrusted preflight descriptor.
    pub facts: serde_json::Value,
}

impl ApiMfaOperation {
    fn new(
        kind: &'static str,
        crate_name: Option<String>,
        summary: String,
        mutation_fields: &[&[u8]],
    ) -> Self {
        let mut hasher = Sha256::new();
        for field in std::iter::once(kind.as_bytes())
            .chain(crate_name.as_deref().map(str::as_bytes))
            .chain(mutation_fields.iter().copied())
        {
            hasher.update(field.len().to_be_bytes());
            hasher.update(field);
        }

        Self {
            kind,
            crate_name,
            mutation_fingerprint: hasher.finalize().to_vec(),
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
        metadata_sha256: &[u8],
        tarball_sha256: &[u8],
        tarball_size: u64,
    ) -> Self {
        Self::new(
            "publish",
            Some(crate_name.to_owned()),
            format!("Publish {crate_name} {version}"),
            &[version.as_bytes(), metadata_sha256, tarball_sha256],
        )
        .with_facts(serde_json::json!({
            "version": version,
            "archive_sha256": hex::encode(tarball_sha256),
            "archive_size": tarball_size,
        }))
    }

    /// Bind a yank approval to the exact version and optional public message.
    pub fn yank(crate_name: &str, version: &str, yank_message: Option<&str>) -> Self {
        let message = yank_message.unwrap_or_default();
        Self::new(
            "yank",
            Some(crate_name.to_owned()),
            format!("Yank {crate_name} {version}"),
            &[version.as_bytes(), message.as_bytes()],
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
            &[version.as_bytes()],
        )
        .with_facts(serde_json::json!({ "version": version }))
    }

    /// Bind an owner change to its direction and exact submitted owner list.
    pub fn change_owners(crate_name: &str, add: bool, owners: &[String]) -> Self {
        let direction = if add { "Add" } else { "Remove" };
        let mut fields = Vec::with_capacity(owners.len() + 1);
        fields.push(if add {
            b"add".as_slice()
        } else {
            b"remove".as_slice()
        });
        fields.extend(owners.iter().map(String::as_bytes));
        Self::new(
            "owners",
            Some(crate_name.to_owned()),
            format!("{direction} owners for {crate_name}: {}", owners.join(", ")),
            &fields,
        )
        .with_facts(serde_json::json!({
            "direction": if add { "add" } else { "remove" },
            "owners": owners,
        }))
    }

    /// Toggle `trustpub_only` on crate settings (`PATCH /api/v1/crates/{name}`).
    pub fn change_trustpub_only(crate_name: &str, enabled: bool) -> Self {
        let value = if enabled {
            b"true".as_slice()
        } else {
            b"false".as_slice()
        };
        Self::new(
            "change-trustpub-only",
            Some(crate_name.to_owned()),
            format!(
                "{} Trusted Publishing-only mode for {crate_name}",
                if enabled { "Enable" } else { "Disable" }
            ),
            &[value],
        )
    }

    /// Bind Trusted Publishing configuration creation to its exact fields.
    pub fn create_trusted_publishing(crate_name: &str, provider: &str, fields: &[&str]) -> Self {
        let mut mutation_fields = Vec::with_capacity(fields.len() + 2);
        mutation_fields.push(b"create".as_slice());
        mutation_fields.push(provider.as_bytes());
        mutation_fields.extend(fields.iter().map(|field| field.as_bytes()));
        Self::new(
            "change-trusted-publishing",
            Some(crate_name.to_owned()),
            format!("Create {provider} Trusted Publishing config for {crate_name}"),
            &mutation_fields,
        )
    }

    /// Bind Trusted Publishing configuration deletion to provider and row id.
    pub fn delete_trusted_publishing(crate_name: &str, provider: &str, id: i32) -> Self {
        let id = id.to_string();
        Self::new(
            "change-trusted-publishing",
            Some(crate_name.to_owned()),
            format!("Delete {provider} Trusted Publishing config {id} for {crate_name}"),
            &[b"delete", provider.as_bytes(), id.as_bytes()],
        )
    }

    /// Delete a crate (`DELETE /api/v1/crates/{name}`).
    pub fn delete_crate(crate_name: &str, message: Option<&str>) -> Self {
        Self::new(
            "delete-crate",
            Some(crate_name.to_owned()),
            format!("Delete crate {crate_name}"),
            &[message.unwrap_or_default().as_bytes()],
        )
    }

    /// Accept a crate owner invitation (cookie session).
    pub fn accept_owner_invite(crate_name: &str, invitation_id: i32) -> Self {
        let invitation_id = invitation_id.to_string();
        Self::new(
            "accept-owner-invite",
            Some(crate_name.to_owned()),
            format!("Accept owner invitation for {crate_name}"),
            &[invitation_id.as_bytes()],
        )
    }

    /// A preflight challenge never authorizes a mutation.
    pub fn manual(crate_name: Option<String>) -> Self {
        Self::new(
            "manual",
            crate_name,
            "Verify API MFA passkey".to_owned(),
            &[b"preflight-only"],
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
    pub webauthn: &'a WebauthnConfig,
    pub rate_limiter: &'a RateLimiter,
    pub metrics: &'a InstanceMetrics,
    /// When false (`API_MFA_ENFORCEMENT_ENABLED=false`), skip enforcement entirely.
    pub enforcement_enabled: bool,
}

enum EnsureOutcome {
    Grant,
    Otp,
    /// Token client: CLI handshake challenge (`403` `step_up_required`).
    Challenge(BoxedAppError),
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
/// Acceptance when MFA is enabled:
/// 1. An exact ready mutation record supplied through `Cargo-Mutation-Id`,
/// 2. A non-expired [`ApiMfaGrant`] covering this operation/crate,
/// 3. A valid unused proof for this operation/crate in `Cargo-Step-Up-Proof` (token clients), or
/// 4. For API tokens only: create/reuse a short-lived operation challenge (`403` handshake).
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
        // The ready mutation record is the exact credential-and-request-bound
        // grant. Its receive lease is independent of legacy general-purpose
        // API MFA grants.
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

    let token_id = auth.api_token().map(|token| token.id);

    let started = Instant::now();
    let outcome = match ensure_api_mfa_inner(auth, token_id, parts, conn, &deps, &operation).await {
        Ok(outcome) => outcome,
        Err(err) => EnsureOutcome::Error(err),
    };

    let (label, result) = match outcome {
        EnsureOutcome::Grant => {
            parts.request_log().add("api_mfa", "grant");
            ("grant", Ok(()))
        }
        EnsureOutcome::Otp => {
            parts.request_log().add("api_mfa", "otp");
            ("otp", Ok(()))
        }
        EnsureOutcome::Challenge(err) => {
            parts.request_log().add("api_mfa", "required");
            ("required", Err(err))
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
        context.begin_execution(conn).await?;
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
    if challenge.mutation_state.as_deref() != Some("receiving")
        || challenge
            .receive_expires_at
            .is_none_or(|deadline| deadline <= chrono::Utc::now())
    {
        return Err(bad_request(
            "Cargo-Mutation-Id is outside its receive lease",
        ));
    }

    // Proofs and grants were issued against the descriptor fingerprint, not
    // the older reactive fingerprint derived after parsing the mutation.
    operation.mutation_fingerprint = challenge.mutation_fingerprint;
    Ok(Some(context))
}

async fn ensure_api_mfa_inner(
    auth: &Authentication,
    token_id: Option<i32>,
    parts: &Parts,
    conn: &mut AsyncPgConnection,
    deps: &ApiMfaEnsureDeps<'_>,
    operation: &ApiMfaOperation,
) -> AppResult<EnsureOutcome> {
    let user = auth.user();

    // Prefer a supplied one-time proof over the concurrently available grant so
    // callback completion is consumed exactly once.
    if let (Some(token_id), Some(otp)) = (token_id, otp_from_headers(parts))
        && ApiMfaChallenge::consume_otp(
            user.id,
            token_id,
            &otp,
            operation.kind,
            operation.crate_name.as_deref(),
            &operation.mutation_fingerprint,
            conn,
        )
        .await?
    {
        return Ok(EnsureOutcome::Otp);
    }

    if ApiMfaGrant::has_active(
        user.id,
        token_id,
        operation.kind,
        operation.crate_name.as_deref(),
        &operation.mutation_fingerprint,
        conn,
    )
    .await?
    {
        if let Some(token_id) = token_id {
            ApiMfaChallenge::mark_callback_completed_by_grant(
                user.id,
                token_id,
                operation.kind,
                operation.crate_name.as_deref(),
                &operation.mutation_fingerprint,
                conn,
            )
            .await?;
        }
        return Ok(EnsureOutcome::Grant);
    }

    let credentials = WebauthnCredential::for_user(user.id, conn).await?;
    if credentials.is_empty() {
        return Err(bad_request(
            "API MFA is enabled but no passkeys are registered. Sign in on the website, \
             request an email code under Settings → API MFA, and register a passkey \
             (or disable API MFA with an email code).",
        ));
    }

    let Some(token_id) = token_id else {
        return Ok(EnsureOutcome::CookieAuthorize(bad_request(
            "API MFA is enabled. Open Settings → API MFA, choose Authorize for 15 minutes, \
             complete passkey verification, then retry.",
        )));
    };

    let localhost_port = mfa_port_from_headers(parts)?;
    let localhost_callback_secret = mfa_callback_secret_from_headers(parts)?;
    if localhost_port.is_some() != localhost_callback_secret.is_some() {
        return Err(bad_request(
            "Cargo-Step-Up-Port and Cargo-Step-Up-Callback-Secret must be supplied together",
        ));
    }
    let challenge = resolve_or_create_challenge(
        user.id,
        token_id,
        operation,
        ApiMfaCallback {
            port: localhost_port,
            secret: localhost_callback_secret.as_deref(),
        },
        conn,
        deps,
    )
    .await?;

    parts
        .request_log()
        .add("api_mfa_challenge_id", challenge.id.clone());

    Ok(EnsureOutcome::Challenge(step_up_required_error(
        deps.webauthn,
        &challenge,
        operation,
    )))
}

/// Builds absolute verification and poll URLs from their respective origins.
///
/// The verification page follows the `WebAuthn` RP origin, while polling stays on
/// the registry API origin so Cargo can enforce same-origin requests.
pub fn public_mfa_urls(webauthn: &WebauthnConfig, challenge_id: &str) -> (String, String) {
    let verification_base = webauthn.rp_origin.as_str().trim_end_matches('/');
    let api_base = webauthn.api_origin.as_str().trim_end_matches('/');
    (
        format!("{verification_base}/verify/{challenge_id}"),
        format!("{api_base}/api/v1/auth/challenges/{challenge_id}"),
    )
}

async fn resolve_or_create_challenge(
    user_id: i32,
    api_token_id: i32,
    operation: &ApiMfaOperation,
    callback: ApiMfaCallback<'_>,
    conn: &mut AsyncPgConnection,
    deps: &ApiMfaEnsureDeps<'_>,
) -> AppResult<ApiMfaChallenge> {
    // Reuse an in-flight pending challenge for the same token + operation.
    if let Some(existing) = ApiMfaChallenge::find_pending_for_operation(
        user_id,
        api_token_id,
        operation.kind,
        operation.crate_name.as_deref(),
        &operation.mutation_fingerprint,
        conn,
    )
    .await?
    {
        return refresh_challenge_localhost_callback(existing, callback, conn).await;
    }

    deps.rate_limiter
        .check_rate_limit(user_id, LimitedAction::ApiMfaChallengeCreate, conn)
        .await?;

    // Free unique-index slots held by expired pending rows for this key.
    ApiMfaChallenge::delete_expired_pending_for_operation(
        api_token_id,
        operation.kind,
        operation.crate_name.as_deref(),
        &operation.mutation_fingerprint,
        conn,
    )
    .await?;

    let pending = ApiMfaChallenge::count_pending_for_user(user_id, conn).await?;
    if pending >= MAX_PENDING_CHALLENGES_PER_USER {
        return Err(bad_request(format!(
            "too many pending API MFA challenges (max {MAX_PENDING_CHALLENGES_PER_USER}); \
             acknowledge or wait for existing ones to expire"
        )));
    }

    let (challenge, created) =
        insert_challenge_or_reuse_pending(user_id, api_token_id, operation, callback, conn).await?;

    if created {
        deps.metrics.api_mfa_challenges_created_total.inc();
    }
    Ok(challenge)
}

/// Refreshes a pending challenge's localhost callback without allowing downgrade.
///
/// Once callback mode is active, omitting `Cargo-Step-Up-Port` cannot switch the
/// challenge to the broader polling-grant flow. Replacing an existing port
/// requires the client-held secret that was stored when the challenge was
/// created.
pub(crate) async fn refresh_challenge_localhost_callback(
    existing: ApiMfaChallenge,
    callback: ApiMfaCallback<'_>,
    conn: &mut AsyncPgConnection,
) -> AppResult<ApiMfaChallenge> {
    let Some(localhost_port) = callback.port else {
        return Ok(existing);
    };

    match existing.localhost_port {
        Some(existing_port) if existing_port == localhost_port => Ok(existing),
        Some(_) => {
            let Some(secret) = callback.secret else {
                return Ok(existing);
            };
            let supplied_hash = ApiMfaChallenge::hash_localhost_callback_secret(secret);
            if existing.localhost_callback_secret_hash.as_deref() != Some(supplied_hash.as_slice())
            {
                return Ok(existing);
            }
            Ok(existing
                .update_localhost_callback(localhost_port, Some(supplied_hash), conn)
                .await?)
        }
        None => {
            let secret_hash = callback
                .secret
                .map(ApiMfaChallenge::hash_localhost_callback_secret);
            Ok(existing
                .update_localhost_callback(localhost_port, secret_hash, conn)
                .await?)
        }
    }
}

/// Inserts a challenge, or reuses the pending row when a concurrent insert hit the unique index.
///
/// Returns `(challenge, created)` where `created` is false on unique-violation reuse.
pub(crate) async fn insert_challenge_or_reuse_pending(
    user_id: i32,
    api_token_id: i32,
    operation: &ApiMfaOperation,
    callback: ApiMfaCallback<'_>,
    conn: &mut AsyncPgConnection,
) -> AppResult<(ApiMfaChallenge, bool)> {
    use diesel::result::{DatabaseErrorKind, Error as DieselError};

    match NewApiMfaChallenge::new(
        user_id,
        Some(api_token_id),
        crates_io_database::models::NewApiMfaChallengeOperation {
            operation: operation.kind.to_owned(),
            crate_name: operation.crate_name.clone(),
            mutation_fingerprint: operation.mutation_fingerprint.clone(),
            operation_summary: operation.summary.clone(),
            descriptor: None,
        },
        callback.port,
        callback.secret,
    )
    .insert(conn)
    .await
    {
        Ok(challenge) => Ok((challenge, true)),
        Err(DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, _)) => {
            let existing = ApiMfaChallenge::find_pending_for_operation(
                user_id,
                api_token_id,
                operation.kind,
                operation.crate_name.as_deref(),
                &operation.mutation_fingerprint,
                conn,
            )
            .await?
            .ok_or_else(|| {
                crate::util::errors::server_error(
                    "API MFA challenge unique conflict but no pending row found",
                )
            })?;
            let existing = refresh_challenge_localhost_callback(existing, callback, conn).await?;
            Ok((existing, false))
        }
        Err(err) => Err(err.into()),
    }
}

pub(crate) fn step_up_required_error(
    webauthn: &WebauthnConfig,
    challenge: &ApiMfaChallenge,
    operation: &ApiMfaOperation,
) -> BoxedAppError {
    let (verification_page_url, poll_url) = public_mfa_urls(webauthn, &challenge.id);

    let detail = format!(
        "Additional authentication is required. Open this link to verify with your passkey:\n\n\
         {verification_page_url}\n\nAfter verification, retry the request."
    );

    ApiMfaRequired {
        challenge_id: challenge.id.clone(),
        operation: operation.kind.to_string(),
        operation_summary: operation.summary.clone(),
        crate_name: operation.crate_name.clone(),
        poll_url,
        expires_at: challenge.expires_at,
        recommended_poll_interval_secs: RECOMMENDED_POLL_INTERVAL_SECS,
        detail,
    }
    .boxed()
}

fn otp_from_headers(parts: &Parts) -> Option<String> {
    parts
        .headers
        .get(CARGO_STEP_UP_PROOF_HEADER)
        .or_else(|| parts.headers.get(OTP_HEADER))
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

pub(crate) fn mfa_port_from_headers(parts: &Parts) -> AppResult<Option<i32>> {
    let Some(raw) = parts
        .headers
        .get(CARGO_STEP_UP_PORT_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return Ok(None);
    };

    let port: i32 = raw
        .parse()
        .map_err(|_| bad_request("Cargo-Step-Up-Port must be an integer between 1024 and 65535"))?;
    if !(1024..=65535).contains(&port) {
        return Err(bad_request(
            "Cargo-Step-Up-Port must be an integer between 1024 and 65535",
        ));
    }
    Ok(Some(port))
}

/// Reads and validates the optional loopback callback secret request header.
pub(crate) fn mfa_callback_secret_from_headers(parts: &Parts) -> AppResult<Option<String>> {
    let Some(secret) = parts
        .headers
        .get(CARGO_STEP_UP_CALLBACK_SECRET_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };

    let valid_length = (32..=128).contains(&secret.len());
    let valid_characters = secret
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
    if !valid_length || !valid_characters {
        return Err(bad_request(
            "Cargo-Step-Up-Callback-Secret must be 32 to 128 URL-safe characters",
        ));
    }
    Ok(Some(secret.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_mfa_urls_keep_polling_on_the_registry_api_origin() {
        let mut config = WebauthnConfig::for_testing();
        config.rp_origin = "http://localhost:5173".parse().unwrap();

        let (verification_page_url, poll_url) = public_mfa_urls(&config, "stp_test");

        assert_eq!(
            verification_page_url,
            "http://localhost:5173/verify/stp_test"
        );
        assert_eq!(
            poll_url,
            "http://localhost:8888/api/v1/auth/challenges/stp_test"
        );
    }
}
