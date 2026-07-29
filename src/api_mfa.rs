//! API MFA helpers: enforce passkey step-up for sensitive publish/yank/owner actions.

use crate::auth::Authentication;
use crate::config::WebauthnConfig;
use crate::metrics::InstanceMetrics;
use crate::middleware::log_request::RequestLogExt;
use crate::models::{
    ApiMfaChallenge, ApiMfaGrant, MAX_PENDING_CHALLENGES_PER_USER, NewApiMfaChallenge,
    WebauthnCredential,
};
use crate::rate_limiter::{LimitedAction, RateLimiter};
use crate::util::errors::{ApiMfaRequired, AppResult, BoxedAppError, bad_request};
use diesel_async::AsyncPgConnection;
use http::request::Parts;
use std::time::Instant;

/// Header carrying a one-time OTP after passkey verification (RubyGems-compatible alias: `OTP`).
pub const CRATES_OTP_HEADER: &str = "crates-otp";
const OTP_HEADER: &str = "otp";

/// Optional localhost callback port for RubyGems-style OTP delivery.
pub const CRATES_MFA_PORT_HEADER: &str = "crates-mfa-port";

/// Optional client-supplied operation id for idempotent handshake reuse.
pub const CRATES_MFA_OPERATION_ID_HEADER: &str = "crates-mfa-operation-id";

/// Recommended CLI poll interval for challenge acknowledgment (seconds).
pub const RECOMMENDED_POLL_INTERVAL_SECS: u64 = 2;

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
}

/// Shared dependencies for [`ensure_api_mfa`].
pub struct ApiMfaEnsureDeps<'a> {
    pub webauthn: &'a WebauthnConfig,
    pub rate_limiter: &'a RateLimiter,
    pub metrics: &'a InstanceMetrics,
}

enum EnsureOutcome {
    Grant,
    Otp,
    /// Token client: CLI handshake challenge (`403` `api_mfa_required`).
    Challenge(BoxedAppError),
    /// Cookie session: must authorize on the settings page first (`400`).
    CookieAuthorize(BoxedAppError),
    Error(BoxedAppError),
}

/// Ensures requests satisfy API MFA when the user has it enabled.
///
/// Applies to both API tokens and website cookie sessions for publish, yank, and
/// change-owners. Trusted Publishing tokens are not routed through this helper.
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
    if !user.api_mfa_enabled {
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
        operation.kind,
        operation.crate_name.as_deref(),
        conn,
    )
    .await?
    {
        return Ok(EnsureOutcome::Grant);
    }

    if let Some(otp) = otp_from_headers(parts)
        && ApiMfaChallenge::consume_otp(
            user.id,
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
            "API MFA is enabled but no passkeys are registered. Sign in on the website and add a passkey under Settings → API MFA.",
        ));
    }

    let Some(token_id) = token_id else {
        return Ok(EnsureOutcome::CookieAuthorize(bad_request(
            "API MFA is enabled. Open Settings → API MFA, choose Authorize for 15 minutes, \
             complete passkey verification, then retry.",
        )));
    };

    let localhost_port = mfa_port_from_headers(parts)?;
    let challenge = resolve_or_create_challenge(
        user.id,
        token_id,
        operation,
        localhost_port,
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
/// after RubyGems `/webauthn_verification/…`.
pub fn public_mfa_urls(webauthn: &WebauthnConfig, operation_id: &str) -> (String, String) {
    let base = webauthn.rp_origin.as_str().trim_end_matches('/');
    (
        format!("{base}/webauthn-verify/{operation_id}"),
        format!("{base}/api/v1/me/api_mfa/challenges/{operation_id}"),
    )
}

async fn resolve_or_create_challenge(
    user_id: i32,
    api_token_id: i32,
    operation: &ApiMfaOperation,
    localhost_port: Option<i32>,
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
        return Ok(existing);
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
        return Ok(existing);
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

    let challenge = NewApiMfaChallenge::new(
        user_id,
        Some(api_token_id),
        operation.kind,
        operation.crate_name.clone(),
        localhost_port,
    )
    .insert(conn)
    .await?;

    deps.metrics.api_mfa_challenges_created_total.inc();
    Ok(challenge)
}

fn api_mfa_required_error(
    webauthn: &WebauthnConfig,
    challenge: &ApiMfaChallenge,
    operation: &ApiMfaOperation,
) -> BoxedAppError {
    let (verification_url, poll_url) = public_mfa_urls(webauthn, &challenge.id);

    let target = match &operation.crate_name {
        Some(name) => format!(" {} for `{name}`", operation.kind),
        None => format!(" {}", operation.kind),
    };

    let detail = format!(
        "API MFA required to{target}. Please visit the following URL to authenticate via security device \
         (operation_id={}):\n\n{verification_url}\n\n\
         Poll {poll_url} every {RECOMMENDED_POLL_INTERVAL_SECS}s until acknowledged, then retry this request.",
        challenge.id
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
