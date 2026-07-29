use crate::controllers::api_mfa::webauthn_util::complete_passkey_authentication;
use crate::email::EmailMessage;
use crate::models::{ApiToken, NewUserSecurityEvent, SecurityEventType};
use crate::schema::api_tokens;
use crate::views::EncodableApiTokenWithToken;
use anyhow::Context;

use crate::app::AppState;
use crate::auth::AuthCheck;
use crate::middleware::real_ip::RealIp;
use crate::models::token::{CrateScope, EndpointScope};
use crate::util::errors::{AppResult, bad_request, custom};
use crate::util::no_store;
use crate::util::token::PlainToken;

/// Maximum number of non-revoked, non-expired API tokens per user.
pub const MAX_ACTIVE_TOKENS_PER_USER: i64 = 50;
use axum::Json;
use axum::extract::{Path, Query};
use axum::response::{IntoResponse, Response};
use axum_extra::TypedHeader;
use axum_extra::headers::CacheControl;
use axum_extra::json;
use axum_extra::response::ErasedJson;
use chrono::{DateTime, Utc};
use diesel::data_types::PgInterval;
use diesel::dsl::{IntervalDsl, now};
use diesel::prelude::*;
use diesel::sql_types::Timestamptz;
use diesel_async::RunQueryDsl;
use http::request::Parts;
use http::{StatusCode, header};
use minijinja::context;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use tracing::{error, warn};

#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct GetParams {
    /// Include tokens that expired within the last `expired_days` days.
    ///
    /// By default, expired tokens are excluded from the response.
    expired_days: Option<i32>,
}

impl GetParams {
    fn expired_days_interval(&self) -> PgInterval {
        match self.expired_days {
            Some(days) if days > 0 => days,
            _ => 0,
        }
        .days()
    }
}

/// Response returned when listing API tokens for the authenticated user.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ApiTokenListResponse {
    pub api_tokens: Vec<ApiToken>,
}

/// List all API tokens of the authenticated user.
#[utoipa::path(
    get,
    path = "/api/v1/me/tokens",
    params(GetParams),
    security(("cookie" = [])),
    tag = "api_tokens",
    extensions(("x-internal" = json!(true))),
    responses((status = 200, description = "Successful Response", body = inline(ApiTokenListResponse))),
)]
pub async fn list_api_tokens(
    app: AppState,
    Query(params): Query<GetParams>,
    req: Parts,
) -> AppResult<(TypedHeader<CacheControl>, ErasedJson)> {
    let mut conn = app.db_read_prefer_primary().await?;
    let auth = AuthCheck::only_cookie().check(&req, &mut conn).await?;
    let user = auth.user();

    let tokens: Vec<ApiToken> = ApiToken::belonging_to(user)
        .select(ApiToken::as_select())
        .filter(api_tokens::revoked.eq(false))
        .filter(
            api_tokens::expired_at.is_null().or(api_tokens::expired_at
                .assume_not_null()
                .gt(now.into_sql::<Timestamptz>() - params.expired_days_interval())),
        )
        .order(api_tokens::id.desc())
        .load(&mut conn)
        .await?;

    Ok((no_store(), json!({ "api_tokens": tokens })))
}

/// Properties for a new API token.
#[derive(Deserialize, utoipa::ToSchema)]
pub struct NewApiToken {
    name: String,
    crate_scopes: Option<Vec<String>>,
    endpoint_scopes: Option<Vec<String>>,
    expired_at: Option<DateTime<Utc>>,
}

/// Request body for creating a new API token.
#[derive(Deserialize, utoipa::ToSchema)]
pub struct NewApiTokenRequest {
    #[schema(inline)]
    api_token: NewApiToken,
    /// Passkey assertion required when API MFA is enabled (after `authorize/start`).
    #[serde(default)]
    credential: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct CreateResponse {
    api_token: EncodableApiTokenWithToken,
}

/// Create a new API token.
#[utoipa::path(
    put,
    path = "/api/v1/me/tokens",
    request_body = inline(NewApiTokenRequest),
    security(("cookie" = [])),
    tag = "api_tokens",
    extensions(("x-internal" = json!(true))),
    responses((status = 200, description = "Successful Response", body = inline(CreateResponse))),
)]
pub async fn create_api_token(
    app: AppState,
    parts: Parts,
    Json(new): Json<NewApiTokenRequest>,
) -> AppResult<Json<CreateResponse>> {
    if new.api_token.name.is_empty() {
        return Err(bad_request("name must have a value"));
    }

    let mut conn = app.db_write().await?;
    let auth = AuthCheck::default().check(&parts, &mut conn).await?;

    if auth.api_token_id().is_some() {
        return Err(bad_request(
            "cannot use an API token to create a new API token",
        ));
    }

    let user = auth.user();

    // Check if token creation is disabled
    if let Some(disable_message) = &app.config.disable_token_creation {
        let client_ip = parts.extensions.get::<RealIp>().map(|ip| ip.to_string());
        let client_ip = client_ip.as_deref().unwrap_or("unknown");

        let mut headers = parts.headers.clone();
        headers.remove(header::AUTHORIZATION);
        headers.remove(header::COOKIE);

        warn!(
            network.client.ip = client_ip,
            http.headers = ?headers,
            "Blocked token creation for user `{}` (id: {}) due to disabled flag (token name: `{}`)",
            user.gh_login, user.id, new.api_token.name
        );

        let message = disable_message.clone();
        return Err(custom(StatusCode::SERVICE_UNAVAILABLE, message));
    }

    if app.config.api_mfa_enforcement_enabled && user.api_mfa_enabled {
        let Some(credential) = new.credential.as_ref() else {
            return Err(bad_request(
                "passkey verification required to create an API token while API MFA is enabled; \
                 complete authorize/start first and include the credential assertion",
            ));
        };
        complete_passkey_authentication(user.id, credential, &app.config.webauthn, &mut conn)
            .await?;
    }

    let api_token = mint_api_token_for_user(
        &app,
        user,
        &new.api_token.name,
        new.api_token.crate_scopes,
        new.api_token.endpoint_scopes,
        new.api_token.expired_at,
        &mut conn,
    )
    .await?;

    Ok(Json(CreateResponse { api_token }))
}

/// Shared mint path for Settings → New Token and CLI link-login approve.
pub async fn mint_api_token_for_user(
    app: &AppState,
    user: &crate::models::User,
    name: &str,
    crate_scopes: Option<Vec<String>>,
    endpoint_scopes: Option<Vec<String>>,
    expired_at: Option<DateTime<Utc>>,
    conn: &mut diesel_async::AsyncPgConnection,
) -> AppResult<EncodableApiTokenWithToken> {
    let count: i64 = ApiToken::belonging_to(user)
        .filter(api_tokens::revoked.eq(false))
        .filter(
            api_tokens::expired_at
                .is_null()
                .or(api_tokens::expired_at.gt(now)),
        )
        .count()
        .get_result(conn)
        .await?;
    if count >= MAX_ACTIVE_TOKENS_PER_USER {
        return Err(bad_request(format!(
            "maximum active tokens per user is: {MAX_ACTIVE_TOKENS_PER_USER}"
        )));
    }

    let crate_scopes = crate_scopes
        .map(|scopes| {
            scopes
                .into_iter()
                .map(CrateScope::try_from)
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()
        .map_err(|_err| bad_request("invalid crate scope"))?;

    let endpoint_scopes = endpoint_scopes
        .map(|scopes| {
            scopes
                .into_iter()
                .map(|scope| EndpointScope::try_from(scope.as_bytes()))
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()
        .map_err(|_err| bad_request("invalid endpoint scope"))?;

    let recipient = user.email(conn).await?;

    let plaintext = PlainToken::generate();

    let new_token = crate::models::token::NewApiToken::builder()
        .user_id(user.id)
        .name(name)
        .token(plaintext.hashed())
        .maybe_crate_scopes(crate_scopes)
        .maybe_endpoint_scopes(endpoint_scopes)
        .maybe_expired_at(expired_at)
        .build();

    if let Some(recipient) = recipient {
        let context = context! {
            token_name => name,
            user_name => &user.gh_login,
            domain => app.emails.domain,
        };

        // Token mint succeeded even if email delivery fails.
        if let Err(e) = send_creation_email(&app.emails, &recipient, context).await {
            error!("Failed to send token creation email: {e}")
        }
    }

    let token = new_token.insert(conn).await?;

    NewUserSecurityEvent::new(
        user.id,
        SecurityEventType::TokenCreated,
        Some(token.id),
        None,
        serde_json::json!({ "token_name": name }),
    )
    .record(conn)
    .await;

    Ok(EncodableApiTokenWithToken {
        token,
        plaintext: plaintext.expose_secret().to_string(),
    })
}

/// Response returned when getting an API token by ID.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ApiTokenGetResponse {
    pub api_token: ApiToken,
}

/// Find API token by id.
#[utoipa::path(
    get,
    path = "/api/v1/me/tokens/{id}",
    params(
        ("id" = i32, Path, description = "ID of the API token"),
    ),
    security(
        ("api_token" = []),
        ("cookie" = []),
    ),
    tag = "api_tokens",
    responses((status = 200, description = "Successful Response", body = inline(ApiTokenGetResponse))),
)]
pub async fn find_api_token(
    app: AppState,
    Path(id): Path<i32>,
    req: Parts,
) -> AppResult<(TypedHeader<CacheControl>, Json<ApiTokenGetResponse>)> {
    let mut conn = app.db_write().await?;
    let auth = AuthCheck::default().check(&req, &mut conn).await?;
    let user = auth.user();
    let api_token = ApiToken::belonging_to(user)
        .find(id)
        .select(ApiToken::as_select())
        .first(&mut conn)
        .await?;

    Ok((no_store(), Json(ApiTokenGetResponse { api_token })))
}

/// Revoke API token.
#[utoipa::path(
    delete,
    path = "/api/v1/me/tokens/{id}",
    params(
        ("id" = i32, Path, description = "ID of the API token"),
    ),
    security(
        ("api_token" = []),
        ("cookie" = []),
    ),
    tag = "api_tokens",
    responses((status = 200, description = "Successful Response", body = Object)),
)]
pub async fn revoke_api_token(
    app: AppState,
    Path(id): Path<i32>,
    req: Parts,
) -> AppResult<ErasedJson> {
    let mut conn = app.db_write().await?;
    let auth = AuthCheck::default().check(&req, &mut conn).await?;
    let user = auth.user();
    let token = ApiToken::belonging_to(user)
        .find(id)
        .select(ApiToken::as_select())
        .first(&mut conn)
        .await
        .optional()?;

    diesel::update(ApiToken::belonging_to(user).find(id))
        .set(api_tokens::revoked.eq(true))
        .execute(&mut conn)
        .await?;

    if let Some(token) = token {
        let ip = req.extensions.get::<RealIp>().map(|ip| ip.to_string());
        NewUserSecurityEvent::new(
            user.id,
            SecurityEventType::TokenRevoked,
            Some(token.id),
            ip,
            serde_json::json!({ "token_name": token.name }),
        )
        .record(&mut conn)
        .await;
    }

    Ok(json!({}))
}

/// Revoke the current API token.
///
/// This endpoint revokes the API token that is used to authenticate
/// the request.
#[utoipa::path(
    delete,
    path = "/api/v1/tokens/current",
    security(("api_token" = [])),
    tag = "api_tokens",
    responses((status = 204, description = "Successful Response")),
)]
pub async fn revoke_current_api_token(app: AppState, req: Parts) -> AppResult<Response> {
    let mut conn = app.db_write().await?;
    let auth = AuthCheck::default().check(&req, &mut conn).await?;
    let api_token_id = auth
        .api_token_id()
        .ok_or_else(|| bad_request("token not provided"))?;
    let user = auth.user();

    let token_name = api_tokens::table
        .find(api_token_id)
        .select(api_tokens::name)
        .first::<String>(&mut conn)
        .await
        .optional()?;

    diesel::update(api_tokens::table.filter(api_tokens::id.eq(api_token_id)))
        .set(api_tokens::revoked.eq(true))
        .execute(&mut conn)
        .await?;

    NewUserSecurityEvent::new(
        user.id,
        SecurityEventType::TokenRevoked,
        Some(api_token_id),
        req.extensions.get::<RealIp>().map(|ip| ip.to_string()),
        serde_json::json!({ "token_name": token_name }),
    )
    .record(&mut conn)
    .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn send_creation_email(
    emails: &crate::Emails,
    recipient: &str,
    context: impl Serialize,
) -> anyhow::Result<()> {
    let email = EmailMessage::from_template("new_token", context);
    let email = email.context("Failed to render email template")?;
    let result = emails.send(recipient, email).await;
    result.context("Failed to send email")
}
