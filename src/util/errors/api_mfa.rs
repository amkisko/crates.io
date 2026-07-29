use super::{AppError, BoxedAppError};
use axum::response::{IntoResponse, Response};
use axum_extra::json;
use chrono::{DateTime, Utc};
use http::StatusCode;
use std::fmt;

/// Machine-readable error returned when a dangerous API action needs passkey acknowledgment.
#[derive(Debug, Clone)]
pub struct ApiMfaRequired {
    pub operation_id: String,
    pub operation: String,
    pub crate_name: Option<String>,
    pub verification_url: String,
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
                "id": "api_mfa_required",
                "operation_id": &self.operation_id,
                "operation": &self.operation,
                "crate": &self.crate_name,
                "verification_url": &self.verification_url,
                "poll_url": &self.poll_url,
                "expires_at": self.expires_at.to_rfc3339(),
                "recommended_poll_interval_secs": self.recommended_poll_interval_secs,
            }]
        });
        (StatusCode::FORBIDDEN, json).into_response()
    }
}
