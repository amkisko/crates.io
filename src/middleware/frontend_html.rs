//! Serve the frontend HTML.
//!
//! Paths intended for the inner `api_handler` are passed along to the remaining middleware layers
//! as normal. Requests not intended for the backend will be served HTML to boot the SvelteKit
//! frontend.
//!
//! For now, there is an additional check to see if the `Accept` header contains "html". This is
//! likely to be removed in the future.

use std::borrow::Cow;
use std::ops::Not;
use std::sync::{Arc, LazyLock, OnceLock};

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use futures_util::FutureExt;
use futures_util::future::{BoxFuture, Shared};
use http::{HeaderMap, HeaderValue, Method, StatusCode, header};

use crate::app::AppState;
use crate::storage::StorageKey;

const OG_IMAGE_FALLBACK_URL: &str = "https://crates.io/assets/og-image.png";
const PATH_PREFIX_CRATES: &str = "/crates/";
const TEMPLATE_NAME: &str = "index";
const TEMPLATE_PATH: &str = "svelte/build/200.html";

/// Render environment and the verification page's build-derived CSP.
struct FrontendTemplate {
    env: minijinja::Environment<'static>,
    verification_csp: Option<HeaderValue>,
}

/// The [`Shared`] allows multiple tasks to wait on one initialization future.
type TemplateEnvFut = Shared<BoxFuture<'static, Arc<FrontendTemplate>>>;
type TemplateCache = moka::future::Cache<Cow<'static, str>, String>;

/// Initializes [`minijinja::Environment`] given the SvelteKit fallback
/// document at [`TEMPLATE_PATH`]. This should only be done once as it will
/// load said file from persistent storage.
async fn init_template_env() -> Arc<FrontendTemplate> {
    let mut env = minijinja::Environment::empty();

    let template = tokio::fs::read_to_string(TEMPLATE_PATH)
        .await
        .unwrap_or_else(|err| {
            panic!(
                "Error loading {TEMPLATE_PATH} template: {err}. Is the Svelte frontend built yet?"
            )
        });

    let verification_csp = verification_csp(&template);

    env.add_template_owned(TEMPLATE_NAME, template)
        .expect("Error loading template");

    Arc::new(FrontendTemplate {
        env,
        verification_csp,
    })
}

/// Builds the verification page policy from SvelteKit's generated inline-script hashes.
fn verification_csp(template: &str) -> Option<HeaderValue> {
    const META_PREFIX: &str = "<meta http-equiv=\"content-security-policy\" content=\"";

    let policy = template.split_once(META_PREFIX)?.1.split_once('"')?.0;
    let script_hashes = policy
        .split(';')
        .find_map(|directive| {
            let mut sources = directive.split_whitespace();
            (sources.next() == Some("script-src")).then(|| {
                sources
                    .filter(|source| source.starts_with("'sha256-") && source.ends_with('\''))
                    .collect::<Vec<_>>()
            })
        })?
        .join(" ");
    if script_hashes.is_empty() {
        return None;
    }

    let policy = format!(
        "default-src 'none'; base-uri 'none'; connect-src 'self'; \
         font-src 'self'; form-action 'self'; frame-ancestors 'none'; \
         img-src 'self' data: http://127.0.0.1:*; object-src 'none'; \
         script-src 'self' {script_hashes}; style-src 'self' 'unsafe-inline'"
    );
    HeaderValue::try_from(policy).ok()
}

/// Initializes the [`moka::future::Cache`] used to cache the rendered HTML.
fn init_html_cache(max_capacity: u64) -> TemplateCache {
    moka::future::CacheBuilder::new(max_capacity)
        .name("rendered_index_html")
        .build()
}

pub async fn serve(state: AppState, request: Request, next: Next) -> Response {
    static TEMPLATE_ENV: LazyLock<TemplateEnvFut> =
        LazyLock::new(|| init_template_env().boxed().shared());
    static RENDERED_HTML_CACHE: OnceLock<TemplateCache> = OnceLock::new();

    let path = &request.uri().path();
    // The "/git/" prefix is only used in development (when within a docker container)
    if path.starts_with("/api/") || path.starts_with("/git/") {
        next.run(request).await
    } else if request
        .headers()
        .get_all(header::ACCEPT)
        .iter()
        .any(|val| val.to_str().unwrap_or_default().contains("html"))
    {
        if !matches!(*request.method(), Method::HEAD | Method::GET) {
            let headers =
                HeaderMap::from_iter([(header::ALLOW, HeaderValue::from_static("GET,HEAD"))]);
            return (StatusCode::METHOD_NOT_ALLOWED, headers).into_response();
        }

        let crate_name = extract_crate_name(path);
        let key = crate_name.map(StorageKey::for_og_image);
        let og_image_url = key
            .map(|key| Cow::Owned(state.storage.location(&key)))
            .unwrap_or(Cow::Borrowed(OG_IMAGE_FALLBACK_URL));

        // Fetch the HTML from cache given `og_image_url` as key or render it
        let html_cache = RENDERED_HTML_CACHE
            .get_or_init(|| init_html_cache(state.config.frontend.html_render_cache_max_capacity));

        let template = (&*TEMPLATE_ENV).clone().await;
        let render_result = html_cache
            .entry_by_ref(&og_image_url)
            .or_try_insert_with::<_, minijinja::Error>(async {
                // Render the HTML given the OG image URL
                let html = template
                    .env
                    .get_template(TEMPLATE_NAME)?
                    .render(minijinja::context! { og_image_url})?;

                Ok(html)
            })
            .await;

        match render_result {
            Ok(entry) => {
                // Serve the static page to bootstrap the frontend
                let mut response = axum::response::Html(entry.into_value()).into_response();
                if path.starts_with("/verify/") {
                    let Some(verification_csp) = &template.verification_csp else {
                        tracing::error!("Svelte fallback document has no hash-based script policy");
                        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    };
                    response
                        .headers_mut()
                        .insert(header::CONTENT_SECURITY_POLICY, verification_csp.clone());
                }
                response
            }
            Err(err) => {
                tracing::error!("Error rendering HTML: {:?}", err);
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    } else {
        // Return a 404 to crawlers that don't send `Accept: text/hml`.
        // This is to preserve legacy behavior and will likely change.
        // Most of these crawlers probably won't execute our frontend JS anyway, but
        // it would be nice to bootstrap the app for crawlers that do execute JS.
        StatusCode::NOT_FOUND.into_response()
    }
}

/// Extracts the crate name from the path by stripping the
/// [`PATH_PREFIX_CRATES`] prefix and returning the first path segment from the
/// result. Returns `None` if the path was not prefixed with [`PATH_PREFIX_CRATES`].
fn extract_crate_name(path: &str) -> Option<&str> {
    let suffix = path.strip_prefix(PATH_PREFIX_CRATES)?;
    let len = suffix.find('/').unwrap_or(suffix.len());
    let krate = &suffix[..len];
    krate.is_empty().not().then_some(krate)
}

#[cfg(test)]
mod tests {
    use googletest::{assert_that, prelude::eq};

    use crate::middleware::frontend_html::{extract_crate_name, verification_csp};

    #[test]
    fn test_extract_crate_name() {
        const PATHS: &[(&str, Option<&str>)] = &[
            ("/crates/tokio", Some("tokio")),
            ("/crates/tokio/versions", Some("tokio")),
            ("/crates/tokio/", Some("tokio")),
            ("/", None),
            ("/crates", None),
            ("/crates/", None),
            ("/dashboard/", None),
            ("/settings/profile", None),
        ];

        for (path, expected) in PATHS.iter().copied() {
            assert_that!(extract_crate_name(path), eq(expected));
        }
    }

    #[test]
    fn verification_csp_allows_only_first_party_scripts_and_generated_hashes() {
        let html = r#"<meta http-equiv="content-security-policy" content="default-src 'self'; script-src 'self' 'unsafe-eval' 'sha256-first=' 'sha256-second='; style-src 'self' 'unsafe-inline'">"#;
        let csp = verification_csp(html).unwrap();
        let csp = csp.to_str().unwrap();

        assert!(csp.contains("default-src 'none'"));
        assert!(csp.contains("connect-src 'self'"));
        assert!(csp.contains("http://127.0.0.1:*"));
        assert!(csp.contains("frame-ancestors 'none'"));
        assert!(csp.contains("script-src 'self' 'sha256-first=' 'sha256-second='"));
        assert!(!csp.contains("unsafe-eval"));
        assert!(!csp.contains("script-src 'self' 'unsafe-inline'"));
        assert!(!csp.contains("https://"));
    }
}
