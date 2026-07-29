use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Extension, Router};
use http::{Method, StatusCode};
use std::sync::Arc;
use utoipa_axum::routes;

use crate::Env;
use crate::app::AppState;
use crate::controllers::*;
use crate::openapi::{self, BaseOpenApi};
use crate::util::errors::not_found;

#[expect(
    deprecated,
    reason = "the deprecated routes remain part of the API document"
)]
fn build_openapi_router() -> utoipa_axum::router::OpenApiRouter<AppState> {
    BaseOpenApi::router()
        // Route used by both `cargo search` and the frontend
        .routes(routes!(krate::search::list_crates))
        // Routes used by `cargo`
        .routes(routes!(
            krate::publish::publish,
            krate::metadata::find_new_crate
        ))
        .routes(routes!(
            krate::owners::list_owners,
            krate::owners::add_owners,
            krate::owners::remove_owners
        ))
        .routes(routes!(version::yank::yank_version))
        .routes(routes!(version::yank::unyank_version))
        .routes(routes!(version::downloads::download_version))
        // Routes used by the frontend
        .routes(routes!(
            krate::metadata::find_crate,
            krate::update::update_crate,
            krate::delete::delete_crate
        ))
        .routes(routes!(
            version::metadata::find_version,
            version::update::update_version
        ))
        .routes(routes!(version::readme::get_version_readme))
        .routes(routes!(version::dependencies::get_version_dependencies))
        .routes(routes!(version::downloads::get_version_downloads))
        .routes(routes!(version::docs::rebuild_version_docs))
        .routes(routes!(version::authors::get_version_authors))
        .routes(routes!(krate::downloads::get_crate_downloads))
        .routes(routes!(krate::versions::list_versions))
        .routes(routes!(
            krate::follow::follow_crate,
            krate::follow::unfollow_crate
        ))
        .routes(routes!(krate::follow::get_following_crate))
        .routes(routes!(krate::owners::get_team_owners))
        .routes(routes!(krate::owners::get_user_owners))
        .routes(routes!(krate::rev_deps::list_reverse_dependencies))
        .routes(routes!(keyword::list_keywords))
        .routes(routes!(keyword::find_keyword))
        .routes(routes!(category::list_categories))
        .routes(routes!(category::find_category))
        .routes(routes!(category::list_category_slugs))
        .routes(routes!(user::other::find_user, user::update::update_user))
        .routes(routes!(user::other::get_user_stats))
        .routes(routes!(team::find_team))
        .routes(routes!(user::me::get_authenticated_user))
        .routes(routes!(user::me::get_authenticated_user_updates))
        .routes(routes!(token::list_api_tokens, token::create_api_token))
        .routes(routes!(token::find_api_token, token::revoke_api_token))
        .routes(routes!(token::revoke_current_api_token))
        .routes(routes!(user::security_events::list_security_events))
        .routes(routes!(cli_login::start::start_cli_login))
        .routes(routes!(cli_login::poll::poll_cli_login))
        .routes(routes!(
            cli_login::approve::get_cli_login_meta,
            cli_login::approve::approve_cli_login
        ))
        .routes(routes!(
            api_mfa::status::get_api_mfa_status,
            api_mfa::status::update_api_mfa_status
        ))
        .routes(routes!(api_mfa::email_codes::send_api_mfa_email_code))
        .routes(routes!(api_mfa::passkeys::start_webauthn_registration))
        .routes(routes!(api_mfa::passkeys::finish_webauthn_registration))
        .routes(routes!(api_mfa::passkeys::delete_webauthn_credential))
        .routes(routes!(api_mfa::authorize::start_api_mfa_authorize))
        .routes(routes!(api_mfa::authorize::finish_api_mfa_authorize))
        .routes(routes!(api_mfa::challenges::create_api_mfa_challenge))
        .routes(routes!(api_mfa::challenges::get_api_mfa_challenge))
        .routes(routes!(api_mfa::challenges::start_api_mfa_challenge))
        .routes(routes!(api_mfa::challenges::finish_api_mfa_challenge))
        .routes(routes!(
            api_mfa::challenges::recover_api_mfa_challenge_callback
        ))
        .routes(routes!(
            crate_owner_invitation::list_crate_owner_invitations_for_user
        ))
        .routes(routes!(
            crate_owner_invitation::list_crate_owner_invitations
        ))
        .routes(routes!(
            crate_owner_invitation::handle_crate_owner_invitation
        ))
        .routes(routes!(
            crate_owner_invitation::accept_crate_owner_invitation_with_token
        ))
        .routes(routes!(
            user::email_notifications::update_email_notifications
        ))
        .routes(routes!(summary::get_summary))
        .routes(routes!(user::email_verification::confirm_user_email))
        .routes(routes!(user::email_verification::resend_email_verification))
        .routes(routes!(site_metadata::get_site_metadata))
        // Session management
        .routes(routes!(session::begin_session))
        .routes(routes!(session::authorize_session))
        .routes(routes!(session::end_session))
        .routes(routes!(session::end_all_sessions))
        // OIDC / Trusted Publishing
        .routes(routes!(
            trustpub::tokens::exchange::exchange_trustpub_token,
            trustpub::tokens::revoke::revoke_trustpub_token
        ))
        .routes(routes!(
            trustpub::github_configs::create::create_trustpub_github_config,
            trustpub::github_configs::delete::delete_trustpub_github_config,
            trustpub::github_configs::list::list_trustpub_github_configs,
        ))
        .routes(routes!(
            trustpub::gitlab_configs::create::create_trustpub_gitlab_config,
            trustpub::gitlab_configs::delete::delete_trustpub_gitlab_config,
            trustpub::gitlab_configs::list::list_trustpub_gitlab_configs,
        ))
}

/// Builds the complete internal `OpenAPI` document without application state.
///
/// This keeps schema generation and contract tests independent of PostgreSQL.
pub(crate) fn build_openapi_document() -> utoipa::openapi::OpenApi {
    let (_, openapi) = build_openapi_router().split_for_parts();
    openapi
}

#[allow(deprecated)]
pub fn build_axum_router(state: AppState) -> Router<()> {
    let (router, openapi) = build_openapi_router().split_for_parts();

    let mut router = router
        // Metrics
        .route("/api/private/metrics/{kind}", get(metrics::prometheus))
        // Listing a user's crates for admin/support purposes
        .route("/api/private/admin_list/{username}", get(admin::list))
        // Alerts from GitHub scanning for exposed API tokens
        .route(
            "/api/github/secret-scanning/verify",
            post(github::secret_scanning::verify),
        );

    // Only serve the local checkout of the git index in development mode.
    // In production, for crates.io, cargo gets the index from
    // https://github.com/rust-lang/crates.io-index directly
    // or from the sparse index CDN https://index.crates.io.
    if state.config.env() == Env::Development {
        router = router.route(
            "/git/index/{*path}",
            get(git::http_backend).post(git::http_backend),
        );
    }

    router
        .route(
            "/api/openapi.json",
            get(openapi::handler).layer(Extension(Arc::new(openapi))),
        )
        .fallback(async |method: Method| match method {
            Method::HEAD => StatusCode::NOT_FOUND.into_response(),
            _ => not_found().into_response(),
        })
        .with_state(state)
}
