//! Validation and persistence of mutation-authorization preflights.

use axum::Json;
use axum::response::{IntoResponse, Response};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use http::{StatusCode, request::Parts};
use serde_json::json;

use crate::api_mfa::ApiMfaOperation;
use crate::app::AppState;
use crate::auth::AuthCheck;
use crate::models::token::EndpointScope;
use crate::models::{ApiMfaChallenge, Crate, NewApiMfaChallenge, NewApiMfaChallengeOperation};
use crate::util::errors::{AppResult, bad_request, server_error};
use crate::util::no_store;

use super::mutation_descriptor::{ValidatedMutationDescriptor, required_descriptor_field};
use super::{
    CreateChallengeRequest, CreateChallengeResponse, MutationCallbackRequest,
    create_api_mfa_challenge,
};

pub(super) const IDEMPOTENT_FINAL_EXTENSION: &str = "idempotent-final";
pub(super) const LOOPBACK_CALLBACK_EXTENSION: &str = "loopback-callback";

/// Preflight an exact version 1 registry mutation.
#[utoipa::path(
    post,
    path = "/api/v1/auth/mutation-challenges",
    request_body = inline(CreateChallengeRequest),
    security(("api_token" = [])),
    tag = "users",
    extensions(("x-internal" = json!(true))),
    responses(
        (status = 200, description = "Mutation is ready", body = inline(CreateChallengeResponse)),
        (status = 202, description = "Mutation authorization is pending", body = inline(CreateChallengeResponse)),
        (status = 403, description = "Waiting was not permitted")
    ),
)]
pub async fn create_mutation_authorization(
    app: AppState,
    req: Parts,
    body: Json<CreateChallengeRequest>,
) -> AppResult<Response> {
    if body.preflight_id.is_none() {
        return Err(bad_request("preflight_id is required"));
    }
    if !matches!(
        body.operation.as_deref().map(str::trim),
        Some("publish" | "yank" | "unyank" | "owners")
    ) {
        return Err(bad_request(
            "mutation preflight operation must be publish, yank, unyank, or owners",
        ));
    }
    create_api_mfa_challenge(app, req, body).await
}

#[derive(Debug)]
pub(super) struct ValidatedPreflight {
    pub(super) preflight_id: String,
    pub(super) allow_pending: bool,
    pub(super) callback_url: Option<String>,
    active_extensions: Vec<String>,
}

impl ValidatedPreflight {
    pub(super) fn idempotent_final(&self) -> bool {
        self.active_extensions
            .iter()
            .any(|extension| extension == IDEMPOTENT_FINAL_EXTENSION)
    }
}

pub(super) fn validate_preflight_fields(
    preflight_id: Option<&str>,
    allow_pending: Option<bool>,
    requested_extensions: Option<&[String]>,
    callback: Option<&MutationCallbackRequest>,
) -> AppResult<ValidatedPreflight> {
    let preflight_id = required_descriptor_field(preflight_id, "preflight_id")?;
    if !(22..=128).contains(&preflight_id.len())
        || !preflight_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(bad_request(
            "preflight_id must be 22–128 URL-safe ASCII characters",
        ));
    }
    let allow_pending =
        allow_pending.ok_or_else(|| bad_request("allow_pending is required for preflight"))?;
    let requested_extensions = requested_extensions
        .ok_or_else(|| bad_request("requested_extensions is required for preflight"))?;
    if requested_extensions.len() > 16 {
        return Err(bad_request(
            "requested_extensions may contain at most 16 names",
        ));
    }
    let mut active_extensions = Vec::new();
    for (index, extension) in requested_extensions.iter().enumerate() {
        if !(1..=64).contains(&extension.len())
            || !extension
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(bad_request(
                "extension names must be 1–64 lowercase ASCII letters, digits, or hyphens",
            ));
        }
        if requested_extensions[..index].contains(extension) {
            return Err(bad_request(format!(
                "requested_extensions contains duplicate `{extension}`"
            )));
        }
        if matches!(
            extension.as_str(),
            IDEMPOTENT_FINAL_EXTENSION | LOOPBACK_CALLBACK_EXTENSION
        ) {
            active_extensions.push(extension.clone());
        }
    }
    let callback_url = callback
        .map(|callback| validate_callback_url(&callback.url))
        .transpose()?;
    if !allow_pending && callback_url.is_some() {
        return Err(bad_request(
            "callback is not allowed when allow_pending is false",
        ));
    }
    let loopback_active = active_extensions
        .iter()
        .any(|extension| extension == LOOPBACK_CALLBACK_EXTENSION);
    if callback_url.is_some() != loopback_active {
        return Err(bad_request(
            "callback requires the active `loopback-callback` extension and vice versa",
        ));
    }
    Ok(ValidatedPreflight {
        preflight_id: preflight_id.to_owned(),
        allow_pending,
        callback_url,
        active_extensions,
    })
}

pub(super) fn validate_callback_url(raw: &str) -> AppResult<String> {
    let url = url::Url::parse(raw).map_err(|_| bad_request("callback.url is invalid"))?;
    let port = url
        .port()
        .ok_or_else(|| bad_request("callback.url must contain an explicit port"))?;
    let state = url.query().and_then(|query| query.strip_prefix("state="));
    let valid_state = state.is_some_and(|state| {
        (22..=128).contains(&state.len())
            && state
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    });
    if url.scheme() != "http"
        || url.host_str() != Some("127.0.0.1")
        || !(1024..=65535).contains(&port)
        || url.path() != "/cargo/registry-authorization"
        || !valid_state
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(bad_request(
            "callback.url must be http://127.0.0.1:{port}/cargo/registry-authorization?state={random}",
        ));
    }
    Ok(raw.to_owned())
}

pub(super) fn validate_preflight_retry(
    existing: &ApiMfaChallenge,
    protocol: &ValidatedPreflight,
    descriptor: &ValidatedMutationDescriptor,
) -> AppResult<()> {
    if existing.allow_pending != Some(protocol.allow_pending)
        || existing.callback_url != protocol.callback_url
        || existing.descriptor_json.as_ref() != Some(&descriptor.stored.descriptor_json)
        || existing.idempotent_final != descriptor.idempotent_final
    {
        return Err(bad_request(
            "preflight_id was already used with different request data",
        ));
    }
    Ok(())
}

pub(super) fn interaction_required_response() -> Response {
    (
        StatusCode::FORBIDDEN,
        no_store(),
        Json(json!({
            "status": "interaction_required",
            "protocol_version": 1,
            "active_extensions": [],
            "detail": "This operation requires registry authorization.",
        })),
    )
        .into_response()
}
pub(super) async fn auth_check_for_preflight(
    operation: &str,
    crate_name: Option<&str>,
    mut conn: &diesel_async::AsyncPgConnection,
) -> AppResult<AuthCheck> {
    let mut check = AuthCheck::default();
    if let Some(crate_name) = crate_name {
        check = check.for_crate(crate_name);
    }
    check = match operation {
        "publish" => {
            let crate_name = crate_name.ok_or_else(|| bad_request("crate is required"))?;
            let exists = Crate::by_name(crate_name)
                .select(Crate::as_select())
                .first(&mut conn)
                .await
                .optional()?
                .is_some();
            check.with_endpoint_scope(if exists {
                EndpointScope::PublishUpdate
            } else {
                EndpointScope::PublishNew
            })
        }
        "yank" | "unyank" => check.with_endpoint_scope(EndpointScope::Yank),
        "owners" => check.with_endpoint_scope(EndpointScope::ChangeOwners),
        _ => check,
    };
    Ok(check)
}

pub(super) async fn insert_preflight_or_reuse(
    user_id: i32,
    api_token_id: i32,
    operation: &ApiMfaOperation,
    descriptor: ValidatedMutationDescriptor,
    protocol: ValidatedPreflight,
    conn: &mut diesel_async::AsyncPgConnection,
) -> AppResult<(ApiMfaChallenge, bool)> {
    use diesel::result::{DatabaseErrorKind, Error as DieselError};

    let challenge = NewApiMfaChallenge::for_preflight(
        user_id,
        api_token_id,
        NewApiMfaChallengeOperation {
            operation: operation.kind.to_owned(),
            crate_name: operation.crate_name.clone(),
            mutation_fingerprint: operation.mutation_fingerprint.clone(),
            operation_summary: operation.summary.clone(),
            descriptor: Some(descriptor.stored),
        },
        protocol.preflight_id.clone(),
        protocol.allow_pending,
        protocol.callback_url.clone(),
        descriptor.idempotent_final,
    );
    match challenge.insert(conn).await {
        Ok(challenge) => Ok((challenge, true)),
        Err(DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, _)) => {
            let existing =
                ApiMfaChallenge::find_by_preflight_id(api_token_id, &protocol.preflight_id, conn)
                    .await?
                    .ok_or_else(|| {
                        server_error("preflight conflict without a reusable mutation record")
                    })?;
            if existing.allow_pending != challenge.allow_pending
                || existing.callback_url != challenge.callback_url
                || existing.descriptor_json != challenge.descriptor_json
                || existing.idempotent_final != challenge.idempotent_final
            {
                return Err(bad_request(
                    "preflight_id was already used with different request data",
                ));
            }
            Ok((existing, false))
        }
        Err(error) => Err(error.into()),
    }
}
