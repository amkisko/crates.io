use axum::extract::Request;
use axum::middleware::Next;
use axum::response::IntoResponse;
use axum_extra::headers::{CacheControl, Expires, HeaderMapExt};
use http::{HeaderMap, HeaderValue, header};
use std::time::{Duration, SystemTime};

// see http://nginx.org/en/docs/http/ngx_http_headers_module.html#add_header
const NGINX_SUCCESS_CODES: [u16; 10] = [200, 201, 204, 206, 301, 203, 303, 304, 307, 308];

const ONE_DAY: Duration = Duration::from_secs(24 * 60 * 60);
const ONE_YEAR: Duration = Duration::from_secs(365 * 24 * 60 * 60);

// SvelteKit's hash-based meta policy supplies the exact inline script hashes.
// This response policy intersects with it: `unsafe-inline` keeps those hashes
// usable without reintroducing `unsafe-eval` or unrelated network targets.
const VERIFICATION_CSP: &str = "default-src 'none'; base-uri 'none'; connect-src 'self'; \
    font-src 'self'; form-action 'self'; frame-ancestors 'none'; \
    img-src 'self' data: http://127.0.0.1:*; object-src 'none'; \
    script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'";

pub async fn add_common_headers(request: Request, next: Next) -> impl IntoResponse {
    let v = HeaderValue::from_static;

    let path = request.uri().path();
    let is_verification_page = path.starts_with("/verify/");

    const STATIC_FILES: [&str; 6] = [
        "/github-auth-loading.html",
        "/github-redirect.html",
        "/favicon.ico",
        "/robots.txt",
        "/opensearch.xml",
        "/.well-known/security.txt",
    ];
    let cache_duration = if STATIC_FILES.contains(&path) {
        Some(ONE_DAY)
    } else if path.starts_with("/_app/immutable/") {
        Some(10 * ONE_YEAR)
    } else {
        None
    };

    let response = next.run(request).await;

    let mut headers = HeaderMap::new();
    headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, v("*"));
    headers.insert(header::STRICT_TRANSPORT_SECURITY, v("max-age=31536000"));
    if is_verification_page {
        headers.insert(header::CONTENT_SECURITY_POLICY, v(VERIFICATION_CSP));
    }

    if let Some(cache_duration) = cache_duration
        && response.status().is_success()
    {
        expires(&mut headers, cache_duration);
    }

    if NGINX_SUCCESS_CODES.contains(&response.status().as_u16()) {
        headers.insert(header::X_CONTENT_TYPE_OPTIONS, v("nosniff"));
        headers.insert(header::X_FRAME_OPTIONS, v("SAMEORIGIN"));
        headers.insert(header::X_XSS_PROTECTION, v("0"));
    }

    (headers, response)
}

fn expires(headers: &mut HeaderMap, cache_duration: Duration) {
    headers.typed_insert(Expires::from(SystemTime::now() + cache_duration));
    headers.typed_insert(
        CacheControl::new()
            .with_public()
            .with_max_age(cache_duration),
    );
}

#[cfg(test)]
mod tests {
    use super::VERIFICATION_CSP;
    use axum::{Router, body::Body, middleware, routing::get};
    use http::{Request, header};
    use tower::ServiceExt;

    #[test]
    fn verification_csp_removes_application_wide_active_content_sources() {
        assert!(VERIFICATION_CSP.contains("default-src 'none'"));
        assert!(VERIFICATION_CSP.contains("connect-src 'self'"));
        assert!(VERIFICATION_CSP.contains("http://127.0.0.1:*"));
        assert!(VERIFICATION_CSP.contains("frame-ancestors 'none'"));
        assert!(!VERIFICATION_CSP.contains("unsafe-eval"));
        assert!(!VERIFICATION_CSP.contains("https://"));
    }

    #[tokio::test]
    async fn verification_route_gets_dedicated_csp_header() {
        let app = Router::new()
            .route("/verify/{id}", get(|| async { "verification" }))
            .layer(middleware::from_fn(super::add_common_headers));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/verify/stp_test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.headers().get(header::CONTENT_SECURITY_POLICY),
            Some(&VERIFICATION_CSP.parse().unwrap())
        );
    }
}
