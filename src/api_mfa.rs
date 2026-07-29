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
use std::time::Instant;

/// Header carrying a one-time OTP after passkey verification (RubyGems-compatible alias: `OTP`).
pub const CRATES_OTP_HEADER: &str = "crates-otp";
const OTP_HEADER: &str = "otp";

/// Optional localhost callback port for RubyGems-style OTP delivery.
pub const CRATES_MFA_PORT_HEADER: &str = "crates-mfa-port";

/// Client-held secret authorizing localhost callback port refreshes.
pub const CRATES_MFA_CALLBACK_SECRET_HEADER: &str = "crates-mfa-callback-secret";

/// Optional client-supplied operation id for idempotent handshake reuse.
pub const CRATES_MFA_OPERATION_ID_HEADER: &str = "crates-mfa-operation-id";

/// Recommended CLI poll interval for challenge acknowledgment (seconds).
pub const RECOMMENDED_POLL_INTERVAL_SECS: u64 = 2;

/// Allowed `operation` values for preflight `POST /api/v1/mfa/challenges`.
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
}

impl ApiMfaOperation {
    pub fn publish(crate_name: impl Into<String>) -> Self {
        Self {
            kind: "publish",
            crate_name: Some(crate_name.into()),
        }
    }

    pub fn yank(crate_name: impl Into<String>) -> Self {
        Self {
            kind: "yank",
            crate_name: Some(crate_name.into()),
        }
    }

    pub fn unyank(crate_name: impl Into<String>) -> Self {
        Self {
            kind: "unyank",
            crate_name: Some(crate_name.into()),
        }
    }

    pub fn change_owners(crate_name: impl Into<String>) -> Self {
        Self {
            kind: "change-owners",
            crate_name: Some(crate_name.into()),
        }
    }

    /// Toggle `trustpub_only` on crate settings (`PATCH /api/v1/crates/{name}`).
    pub fn change_trustpub_only(crate_name: impl Into<String>) -> Self {
        Self {
            kind: "change-trustpub-only",
            crate_name: Some(crate_name.into()),
        }
    }

    /// Create or delete Trusted Publishing configs for a crate.
    pub fn change_trusted_publishing(crate_name: impl Into<String>) -> Self {
        Self {
            kind: "change-trusted-publishing",
            crate_name: Some(crate_name.into()),
        }
    }

    /// Delete a crate (`DELETE /api/v1/crates/{name}`).
    pub fn delete_crate(crate_name: impl Into<String>) -> Self {
        Self {
            kind: "delete-crate",
            crate_name: Some(crate_name.into()),
        }
    }

    /// Accept a crate owner invitation (cookie session).
    pub fn accept_owner_invite(crate_name: impl Into<String>) -> Self {
        Self {
            kind: "accept-owner-invite",
            crate_name: Some(crate_name.into()),
        }
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
    /// Token client: CLI handshake challenge (`403` `mfa_required`).
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

    if ApiMfaGrant::has_active(
        user.id,
        token_id,
        operation.kind,
        operation.crate_name.as_deref(),
        conn,
    )
    .await?
    {
        return Ok(EnsureOutcome::Grant);
    }

    if let (Some(token_id), Some(otp)) = (token_id, otp_from_headers(parts))
        && ApiMfaChallenge::consume_otp(
            user.id,
            token_id,
            &otp,
            operation.kind,
            operation.crate_name.as_deref(),
            conn,
        )
        .await?
    {
        return Ok(EnsureOutcome::Otp);
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
            "Crates-MFA-Callback-Secret requires Crates-MFA-Port",
        ));
    }
    let challenge = resolve_or_create_challenge(
        user.id,
        token_id,
        operation,
        localhost_port,
        localhost_callback_secret.as_deref(),
        parts,
        conn,
        deps,
    )
    .await?;

    parts
        .request_log()
        .add("api_mfa_operation_id", challenge.id.clone());

    Ok(EnsureOutcome::Challenge(api_mfa_required_error(
        deps.webauthn,
        &challenge,
        operation,
    )))
}

/// Builds absolute verification and poll URLs from the `WebAuthn` RP origin.
///
/// The verify page is a top-level capability URL (no crates.io cookie), modeled
/// after the `RubyGems` `/webauthn_verification/…` pattern.
pub fn public_mfa_urls(webauthn: &WebauthnConfig, operation_id: &str) -> (String, String) {
    let base = webauthn.rp_origin.as_str().trim_end_matches('/');
    (
        format!("{base}/mfa/verify/{operation_id}"),
        format!("{base}/api/v1/mfa/challenges/{operation_id}"),
    )
}

async fn resolve_or_create_challenge(
    user_id: i32,
    api_token_id: i32,
    operation: &ApiMfaOperation,
    localhost_port: Option<i32>,
    localhost_callback_secret: Option<&str>,
    parts: &Parts,
    conn: &mut AsyncPgConnection,
    deps: &ApiMfaEnsureDeps<'_>,
) -> AppResult<ApiMfaChallenge> {
    // Explicit operation id from a previous 403 makes retries idempotent.
    if let Some(operation_id) = operation_id_from_headers(parts)
        && let Some(existing) = ApiMfaChallenge::find_active(&operation_id, conn).await?
        && existing.user_id == user_id
        && existing.api_token_id == Some(api_token_id)
        && existing.operation == operation.kind
        && existing.crate_name.as_deref() == operation.crate_name.as_deref()
        && !existing.is_acknowledged()
    {
        return refresh_challenge_localhost_callback(
            existing,
            localhost_port,
            localhost_callback_secret,
            conn,
        )
        .await;
    }

    // Reuse an in-flight pending challenge for the same token + operation.
    if let Some(existing) = ApiMfaChallenge::find_pending_for_operation(
        user_id,
        api_token_id,
        operation.kind,
        operation.crate_name.as_deref(),
        conn,
    )
    .await?
    {
        return refresh_challenge_localhost_callback(
            existing,
            localhost_port,
            localhost_callback_secret,
            conn,
        )
        .await;
    }

    deps.rate_limiter
        .check_rate_limit(user_id, LimitedAction::ApiMfaChallengeCreate, conn)
        .await?;

    // Free unique-index slots held by expired pending rows for this key.
    ApiMfaChallenge::delete_expired_pending_for_operation(
        api_token_id,
        operation.kind,
        operation.crate_name.as_deref(),
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

    let (challenge, created) = insert_challenge_or_reuse_pending(
        user_id,
        api_token_id,
        operation.kind,
        operation.crate_name.clone(),
        localhost_port,
        localhost_callback_secret,
        conn,
    )
    .await?;

    if created {
        deps.metrics.api_mfa_challenges_created_total.inc();
    }
    Ok(challenge)
}

/// Refreshes a pending challenge's localhost callback without allowing downgrade.
///
/// Once callback mode is active, omitting `Crates-MFA-Port` cannot switch the
/// challenge to the broader polling-grant flow. Replacing an existing port
/// requires the client-held secret that was stored when the challenge was
/// created.
async fn refresh_challenge_localhost_callback(
    existing: ApiMfaChallenge,
    localhost_port: Option<i32>,
    localhost_callback_secret: Option<&str>,
    conn: &mut AsyncPgConnection,
) -> AppResult<ApiMfaChallenge> {
    let Some(localhost_port) = localhost_port else {
        return Ok(existing);
    };

    match existing.localhost_port {
        Some(existing_port) if existing_port == localhost_port => Ok(existing),
        Some(_) => {
            let Some(secret) = localhost_callback_secret else {
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
            let secret_hash =
                localhost_callback_secret.map(ApiMfaChallenge::hash_localhost_callback_secret);
            Ok(existing
                .update_localhost_callback(localhost_port, secret_hash, conn)
                .await?)
        }
    }
}

/// Inserts a challenge, or reuses the pending row when a concurrent insert hit the unique index.
///
/// Returns `(challenge, created)` where `created` is false on unique-violation reuse.
pub async fn insert_challenge_or_reuse_pending(
    user_id: i32,
    api_token_id: i32,
    operation: &str,
    crate_name: Option<String>,
    localhost_port: Option<i32>,
    localhost_callback_secret: Option<&str>,
    conn: &mut AsyncPgConnection,
) -> AppResult<(ApiMfaChallenge, bool)> {
    use diesel::result::{DatabaseErrorKind, Error as DieselError};

    let crate_name_for_lookup = crate_name.clone();
    match NewApiMfaChallenge::new(
        user_id,
        Some(api_token_id),
        operation,
        crate_name,
        localhost_port,
        localhost_callback_secret,
    )
    .insert(conn)
    .await
    {
        Ok(challenge) => Ok((challenge, true)),
        Err(DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, _)) => {
            let existing = ApiMfaChallenge::find_pending_for_operation(
                user_id,
                api_token_id,
                operation,
                crate_name_for_lookup.as_deref(),
                conn,
            )
            .await?
            .ok_or_else(|| {
                crate::util::errors::server_error(
                    "API MFA challenge unique conflict but no pending row found",
                )
            })?;
            let existing = refresh_challenge_localhost_callback(
                existing,
                localhost_port,
                localhost_callback_secret,
                conn,
            )
            .await?;
            Ok((existing, false))
        }
        Err(err) => Err(err.into()),
    }
}

fn api_mfa_required_error(
    webauthn: &WebauthnConfig,
    challenge: &ApiMfaChallenge,
    operation: &ApiMfaOperation,
) -> BoxedAppError {
    let (verification_url, poll_url) = public_mfa_urls(webauthn, &challenge.id);

    let detail = format!(
        "API MFA required. Open this link to verify with your passkey:\n\n\
         {verification_url}\n\nAfter verification, retry the request."
    );

    ApiMfaRequired {
        operation_id: challenge.id.clone(),
        operation: operation.kind.to_string(),
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

fn operation_id_from_headers(parts: &Parts) -> Option<String> {
    parts
        .headers
        .get(CRATES_MFA_OPERATION_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

fn mfa_port_from_headers(parts: &Parts) -> AppResult<Option<i32>> {
    let Some(raw) = parts
        .headers
        .get(CRATES_MFA_PORT_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return Ok(None);
    };

    let port: i32 = raw
        .parse()
        .map_err(|_| bad_request("Crates-MFA-Port must be an integer between 1024 and 65535"))?;
    if !(1024..=65535).contains(&port) {
        return Err(bad_request(
            "Crates-MFA-Port must be an integer between 1024 and 65535",
        ));
    }
    Ok(Some(port))
}

fn mfa_callback_secret_from_headers(parts: &Parts) -> AppResult<Option<String>> {
    let Some(secret) = parts
        .headers
        .get(CRATES_MFA_CALLBACK_SECRET_HEADER)
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
            "Crates-MFA-Callback-Secret must be 32 to 128 URL-safe characters",
        ));
    }
    Ok(Some(secret.to_owned()))
}
