use super::{AppError, BoxedAppError};
use axum::response::{IntoResponse, Response};
use axum_extra::json;
use chrono::{DateTime, Utc};
use http::{HeaderValue, StatusCode, header};
use std::fmt;

/// Machine-readable error returned when a dangerous API action needs interactive step-up.
///
/// Wire `id` is `step_up_required` (condition, not factor). Product feature remains "API MFA".
#[derive(Debug, Clone)]
pub struct ApiMfaRequired {
    pub challenge_id: String,
    pub operation: String,
    pub operation_summary: String,
    pub crate_name: Option<String>,
    pub poll_url: String,
    pub expires_at: DateTime<Utc>,
    /// Suggested seconds between CLI polls of `poll_url`.
    pub recommended_poll_interval_secs: u64,
    pub detail: String,
}

impl ApiMfaRequired {
    pub fn boxed(self) -> BoxedAppError {
        Box::new(self)
    }
}

impl fmt::Display for ApiMfaRequired {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.detail.fmt(f)
    }
}

impl AppError for ApiMfaRequired {
    fn response(&self) -> Response {
        let json = json!({
            "errors": [{
                "detail": &self.detail,
                "id": "step_up_required",
                "protocol_version": 1,
                "challenge_id": &self.challenge_id,
                "operation": &self.operation,
                "operation_summary": &self.operation_summary,
                "crate": &self.crate_name,
                "poll_url": &self.poll_url,
                "expires_at": self.expires_at.to_rfc3339(),
                "recommended_poll_interval_secs": self.recommended_poll_interval_secs,
            }]
        });
        let mut response = (StatusCode::FORBIDDEN, json).into_response();
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn step_up_required_response_is_not_cacheable() {
        let response = ApiMfaRequired {
            challenge_id: "stp_test".into(),
            operation: "publish".into(),
            operation_summary: "Publish example 1.0.0".into(),
            crate_name: Some("example".into()),
            poll_url: "https://registry.example/api/v1/auth/challenges/stp_test".into(),
            expires_at: Utc::now(),
            recommended_poll_interval_secs: 5,
            detail: "Additional authentication is required".into(),
        }
        .response();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    }
}
