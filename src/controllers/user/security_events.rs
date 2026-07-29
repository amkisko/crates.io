//! User-facing security activity feed.

use crate::app::AppState;
use crate::auth::AuthCheck;
use crate::controllers::helpers::pagination::{Page, PaginationOptions, PaginationQueryParams};
use crate::middleware::log_request::RequestLogExt;
use crate::models::UserSecurityEvent;
use crate::util::RequestUtils;
use crate::util::errors::AppResult;
use crate::util::no_store;
use axum::Json;
use axum_extra::TypedHeader;
use axum_extra::headers::CacheControl;
use chrono::{DateTime, Utc};
use http::request::Parts;
use indexmap::IndexMap;
use serde::Serialize;
use serde_json::Value as JsonValue;

/// A single security activity event returned to the Settings UI.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct EncodableSecurityEvent {
    /// Opaque event id (seek cursor).
    #[schema(example = 42)]
    pub id: i64,
    /// Event kind in `snake_case` (e.g. `token_created`, `session_login`).
    #[schema(example = "token_created")]
    pub event_type: String,
    /// Related API token id, if any.
    #[schema(example = 7)]
    pub api_token_id: Option<i32>,
    /// Truncated client IP when recorded (`/24` IPv4 or `/56` IPv6); never set for `token_used`.
    #[schema(example = "203.0.113.0/24")]
    pub ip: Option<String>,
    /// Allowlisted context only: `token_name`, `crate_name`, `operation`, `passkey_name`, `operation_id`.
    pub metadata: JsonValue,
    /// When the event was recorded.
    #[schema(example = "2026-07-29T12:00:00Z")]
    pub created_at: DateTime<Utc>,
}

impl From<UserSecurityEvent> for EncodableSecurityEvent {
    fn from(event: UserSecurityEvent) -> Self {
        let event_type: String = event.event_type.into();
        Self {
            id: event.id,
            event_type,
            api_token_id: event.api_token_id,
            ip: event.ip,
            metadata: event.metadata,
            created_at: event.created_at,
        }
    }
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ListSecurityEventsResponse {
    pub security_events: Vec<EncodableSecurityEvent>,
    pub meta: ListSecurityEventsMeta,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ListSecurityEventsMeta {
    /// Total number of retained events for this user.
    pub total: i64,
    /// Query string for the next page, when more results exist.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_page: Option<String>,
}

/// List recent security activity for the authenticated user.
///
/// Events are retained for 90 days. Cookie authentication only.
#[utoipa::path(
    get,
    path = "/api/v1/me/security_events",
    params(PaginationQueryParams),
    security(("cookie" = [])),
    tag = "users",
    extensions(("x-internal" = json!(true))),
    responses((status = 200, description = "Successful Response", body = inline(ListSecurityEventsResponse))),
)]
pub async fn list_security_events(
    app: AppState,
    req: Parts,
) -> AppResult<(TypedHeader<CacheControl>, Json<ListSecurityEventsResponse>)> {
    let mut conn = app.db_read_prefer_primary().await?;
    let auth = AuthCheck::only_cookie().check(&req, &mut conn).await?;
    let user = auth.user();

    let pagination: PaginationOptions = PaginationOptions::builder()
        .enable_pages(false)
        .enable_seek(true)
        .gather(&req)?;

    let after_id = match &pagination.page {
        Page::Unspecified => None,
        Page::Seek(s) => Some(s.decode::<i64>()?),
        Page::Numeric(_) => unreachable!("page-based pagination is disabled"),
    };

    let mut events =
        UserSecurityEvent::for_user(user.id, after_id, pagination.per_page + 1, &mut conn).await?;

    let next_page = if events.len() > pagination.per_page as usize {
        events.pop();
        if let Some(last) = events.last() {
            let mut params = IndexMap::new();
            params.insert(
                "seek".into(),
                crate::controllers::helpers::pagination::encode_seek(last.id)?,
            );
            Some(req.query_with_params(params))
        } else {
            None
        }
    } else {
        None
    };

    let total = UserSecurityEvent::count_for_user(user.id, &mut conn).await?;

    req.request_log().add("security_event_count", events.len());

    Ok((
        no_store(),
        Json(ListSecurityEventsResponse {
            security_events: events
                .into_iter()
                .map(EncodableSecurityEvent::from)
                .collect(),
            meta: ListSecurityEventsMeta { total, next_page },
        }),
    ))
}
