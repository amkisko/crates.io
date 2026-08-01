//! Endpoints for yanking and unyanking specific versions of crates

use super::CrateVersionPath;
use super::update::{authenticate, perform_version_yank_update};
use crate::api_mfa::{ApiMfaOperation, begin_mutation_execution, ensure_api_mfa};
use crate::app::AppState;
use crate::controllers::helpers::OkResponse;
use crate::rate_limiter::LimitedAction;
use crate::util::errors::AppResult;
use diesel_async::AsyncConnection;
use http::StatusCode;
use http::request::Parts;

/// Yank a crate version.
///
/// This does not delete a crate version, it makes the crate
/// version accessible only to crates that already have a
/// `Cargo.lock` containing this version.
///
/// Notes:
///
/// Version deletion is not implemented to avoid breaking builds,
/// and the goal of yanking a crate is to prevent crates
/// beginning to depend on the yanked crate version.
#[utoipa::path(
    delete,
    path = "/api/v1/crates/{name}/{version}/yank",
    params(CrateVersionPath),
    security(
        ("api_token" = []),
        ("cookie" = []),
    ),
    tag = "versions",
    responses((status = 200, description = "Successful Response", body = inline(OkResponse))),
)]
pub async fn yank_version(
    app: AppState,
    path: CrateVersionPath,
    req: Parts,
) -> AppResult<OkResponse> {
    modify_yank(path, app, req, true).await
}

/// Unyank a crate version.
#[utoipa::path(
    put,
    path = "/api/v1/crates/{name}/{version}/unyank",
    params(CrateVersionPath),
    security(
        ("api_token" = []),
        ("cookie" = []),
    ),
    tag = "versions",
    responses((status = 200, description = "Successful Response", body = inline(OkResponse))),
)]
pub async fn unyank_version(
    app: AppState,
    path: CrateVersionPath,
    req: Parts,
) -> AppResult<OkResponse> {
    modify_yank(path, app, req, false).await
}

/// Changes `yanked` flag on a crate version record
async fn modify_yank(
    path: CrateVersionPath,
    state: AppState,
    req: Parts,
    yanked: bool,
) -> AppResult<OkResponse> {
    // FIXME: Should reject bad requests before authentication, but can't due to
    // lifetime issues with `req`.

    let mut conn = state.db_write().await?;
    let (mut version, krate) = path.load_version_and_crate(&conn).await?;
    let auth = authenticate(&req, &mut conn, &krate.name).await?;
    let operation = if yanked {
        ApiMfaOperation::yank(&krate.name, &version.num, None)
    } else {
        ApiMfaOperation::unyank(&krate.name, &version.num)
    };
    ensure_api_mfa(
        &auth,
        &req,
        &mut conn,
        crate::api_mfa::ApiMfaEnsureDeps {
            metrics: &state.instance_metrics,
            enforcement_enabled: state.config.api_mfa_enforcement_enabled,
        },
        operation,
    )
    .await?;

    conn.transaction(async |conn| {
        state
            .rate_limiter
            .check_rate_limit(auth.user_id(), LimitedAction::YankUnyank, conn)
            .await?;

        let mutation = begin_mutation_execution(&req, conn).await?;
        perform_version_yank_update(
            &state,
            conn,
            &mut version,
            &krate,
            &auth,
            Some(yanked),
            None,
        )
        .await?;

        let response = OkResponse::new();
        if let Some(mutation) = mutation {
            mutation
                .finish_json(StatusCode::OK, &response, conn)
                .await?;
        }
        Ok(response)
    })
    .await
}
