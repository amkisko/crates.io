//! API MFA helpers: enforce passkey step-up for sensitive publish/yank/owner/settings actions.

use crate::auth::Authentication;
use crate::config::WebauthnConfig;
use crate::metrics::InstanceMetrics;
use crate::middleware::log_request::RequestLogExt;
use crate::models::{
    ApiMfaChallenge, ApiMfaGrant, MAX_PENDING_CHALLENGES_PER_USER, NewApiMfaChallenge, OwnerKind,
    WebauthnCredential,
};
use crate::rate_limiter::{LimitedAction, RateLimiter};
use crate::schema::{crate_owners, crates, users};
use crate::util::errors::{ApiMfaRequired, AppResult, BoxedAppError, bad_request};
use diesel::prelude::*;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use http::request::Parts;
use sha2::{Digest, Sha256};
use std::time::Instant;

/// Header carrying a one-time OTP after passkey verification (RubyGems-compatible alias: `OTP`).
pub const CRATES_OTP_HEADER: &str = "crates-otp";
const OTP_HEADER: &str = "otp";

/// Optional localhost callback port for RubyGems-style OTP delivery.
pub const CRATES_STEP_UP_PORT_HEADER: &str = "crates-step-up-port";

/// Client-held secret authorizing localhost callback port refreshes.
pub const CRATES_STEP_UP_CALLBACK_SECRET_HEADER: &str = "crates-step-up-callback-secret";

/// Optional client-supplied challenge id for idempotent handshake reuse.
pub const CRATES_STEP_UP_CHALLENGE_ID_HEADER: &str = "crates-step-up-challenge-id";

/// Recommended CLI poll interval for challenge acknowledgment (seconds).
///
/// This is a minimum interval (RFC 8628-style): clients must not poll faster.
pub const RECOMMENDED_POLL_INTERVAL_SECS: u64 = 5;

/// Optional loopback delivery details supplied by a Cargo client.
#[derive(Clone, Copy)]
pub(crate) struct ApiMfaCallback<'a> {
    pub(crate) port: Option<i32>,
    pub(crate) secret: Option<&'a str>,
}

/// Allowed `operation` values for preflight `POST /api/v1/auth/challenges`.
pub const ALLOWED_CHALLENGE_OPERATIONS: &[&str] = &[
    "publish",
    "yank",
    "unyank",
    "change-owners",
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
        }
    }

    /// Bind a publish approval to the exact metadata and tarball bytes.
    pub fn publish(
        crate_name: &str,
        version: &str,
        metadata_sha256: &[u8],
        tarball_sha256: &[u8],
    ) -> Self {
        Self::new(
            "publish",
            Some(crate_name.to_owned()),
            format!("Publish {crate_name} {version}"),
            &[version.as_bytes(), metadata_sha256, tarball_sha256],
        )
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
    }

    /// Bind an unyank approval to the exact version.
    pub fn unyank(crate_name: &str, version: &str) -> Self {
        Self::new(
            "unyank",
            Some(crate_name.to_owned()),
            format!("Unyank {crate_name} {version}"),
            &[version.as_bytes()],
        )
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
            "change-owners",
            Some(crate_name.to_owned()),
            format!("{direction} owners for {crate_name}: {}", owners.join(", ")),
            &fields,
        )
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
/// change-owners, crate delete, Trusted Publishing config changes, and
/// `trustpub_only` toggles. Trusted Publishing OIDC tokens are not routed
/// through this helper.
///
/// Acceptance when MFA is enabled:
/// 1. A non-expired [`ApiMfaGrant`] covering this operation/crate, or
/// 2. A valid unused OTP for this operation/crate in `Crates-OTP` / `OTP` (token clients), or
/// 3. For API tokens only: create/reuse a short-lived operation challenge (`403` handshake).
///
/// Cookie sessions without a grant are told to use Settings → API MFA → Authorize for 15 minutes.
pub async fn ensure_api_mfa(
    auth: &Authentication,
    parts: &Parts,
    conn: &mut AsyncPgConnection,
    deps: ApiMfaEnsureDeps<'_>,
    operation: ApiMfaOperation,
) -> AppResult<()> {
    let user = auth.user();
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
    if localhost_port.is_none() && localhost_callback_secret.is_some() {
        return Err(bad_request(
            "Crates-Step-Up-Callback-Secret requires Crates-Step-Up-Port",
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
        parts,
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
        localhost_callback_secret.as_deref(),
    )))
}

/// Builds absolute verification and poll URLs from the `WebAuthn` RP origin.
///
/// The verify page is a top-level capability URL (no crates.io cookie), modeled
/// after the `RubyGems` `/webauthn_verification/…` pattern.
pub fn public_mfa_urls(webauthn: &WebauthnConfig, challenge_id: &str) -> (String, String) {
    let base = webauthn.rp_origin.as_str().trim_end_matches('/');
    (
        format!("{base}/verify/{challenge_id}"),
        format!("{base}/api/v1/auth/challenges/{challenge_id}"),
    )
}

async fn resolve_or_create_challenge(
    user_id: i32,
    api_token_id: i32,
    operation: &ApiMfaOperation,
    callback: ApiMfaCallback<'_>,
    parts: &Parts,
    conn: &mut AsyncPgConnection,
    deps: &ApiMfaEnsureDeps<'_>,
) -> AppResult<ApiMfaChallenge> {
    // Explicit operation id from a previous 403 makes retries idempotent.
    if let Some(challenge_id) = challenge_id_from_headers(parts)
        && let Some(existing) = ApiMfaChallenge::find_active(&challenge_id, conn).await?
        && existing.user_id == user_id
        && existing.api_token_id == Some(api_token_id)
        && existing.operation == operation.kind
        && existing.crate_name.as_deref() == operation.crate_name.as_deref()
        && existing.mutation_fingerprint == operation.mutation_fingerprint
        && !existing.is_acknowledged()
    {
        return refresh_challenge_localhost_callback(existing, callback, conn).await;
    }

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
/// Once callback mode is active, omitting `Crates-Step-Up-Port` cannot switch the
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

fn step_up_required_error(
    webauthn: &WebauthnConfig,
    challenge: &ApiMfaChallenge,
    operation: &ApiMfaOperation,
    localhost_callback_secret: Option<&str>,
) -> BoxedAppError {
    let (mut verification_url, poll_url) = public_mfa_urls(webauthn, &challenge.id);
    if challenge.localhost_port.is_some()
        && let Some(secret) = localhost_callback_secret
        && challenge.localhost_callback_secret_matches(secret)
    {
        // URL fragments are not sent in HTTP requests or server access logs.
        verification_url.push_str("#callback_secret=");
        verification_url.push_str(secret);
    }

    let detail = format!(
        "Additional authentication is required. Open this link to verify with your passkey:\n\n\
         {verification_url}\n\nAfter verification, retry the request."
    );

    ApiMfaRequired {
        challenge_id: challenge.id.clone(),
        operation: operation.kind.to_string(),
        operation_summary: operation.summary.clone(),
        crate_name: operation.crate_name.clone(),
        verification_url,
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
        .get(CRATES_OTP_HEADER)
        .or_else(|| parts.headers.get(OTP_HEADER))
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

fn challenge_id_from_headers(parts: &Parts) -> Option<String> {
    parts
        .headers
        .get(CRATES_STEP_UP_CHALLENGE_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

fn mfa_port_from_headers(parts: &Parts) -> AppResult<Option<i32>> {
    let Some(raw) = parts
        .headers
        .get(CRATES_STEP_UP_PORT_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return Ok(None);
    };

    let port: i32 = raw.parse().map_err(|_| {
        bad_request("Crates-Step-Up-Port must be an integer between 1024 and 65535")
    })?;
    if !(1024..=65535).contains(&port) {
        return Err(bad_request(
            "Crates-Step-Up-Port must be an integer between 1024 and 65535",
        ));
    }
    Ok(Some(port))
}

pub(crate) fn mfa_callback_secret_from_headers(parts: &Parts) -> AppResult<Option<String>> {
    let Some(secret) = parts
        .headers
        .get(CRATES_STEP_UP_CALLBACK_SECRET_HEADER)
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
            "Crates-Step-Up-Callback-Secret must be 32 to 128 URL-safe characters",
        ));
    }
    Ok(Some(secret.to_owned()))
}
