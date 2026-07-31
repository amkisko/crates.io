//! Debug middleware that prints debug info to stdout

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::IntoResponse;
use http::HeaderName;
use tracing::debug;

fn is_sensitive_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "authorization"
            | "cookie"
            | "set-cookie"
            | "cargo-step-up-callback-secret"
            | "cargo-step-up-proof"
    )
}

pub async fn debug_requests(req: Request, next: Next) -> impl IntoResponse {
    debug!("  version: {:?}", req.version());
    debug!("  method: {:?}", req.method());
    debug!("  path: {}", req.uri().path());
    debug!("  query_string: {:?}", req.uri().query());
    for (k, ref v) in req.headers().iter() {
        if is_sensitive_header(k) {
            debug!("  hdr: {}=[REDACTED]", k);
        } else {
            debug!("  hdr: {}={:?}", k, v);
        }
    }

    let response = next.run(req).await;

    debug!("  <- {:?}", response.status());
    for (k, v) in response.headers().iter() {
        if is_sensitive_header(k) {
            debug!("  <- {k} [REDACTED]");
        } else {
            debug!("  <- {k} {v:?}");
        }
    }

    response
}

#[cfg(test)]
mod tests {
    use super::is_sensitive_header;

    #[test]
    fn redacts_step_up_credentials() {
        assert!(is_sensitive_header(
            &"cargo-step-up-callback-secret".parse().unwrap()
        ));
        assert!(is_sensitive_header(&"cargo-step-up-proof".parse().unwrap()));
        assert!(!is_sensitive_header(&"cargo-step-up-port".parse().unwrap()));
    }
}
