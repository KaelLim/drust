use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;

/// Canonical JSON error response used across the JSON API surface
/// (`src/tenant/*`, `src/rpc/*`). The wire shape is
/// `{"error_code": <code>, "message": <message>}` with the given
/// HTTP status.
///
/// `src/mgmt/*` admin-UI handlers continue to return bare-string
/// responses for browser-facing pages; vocabulary consolidation
/// (and any mgmt migration) is Phase B.
pub fn json_error(status: StatusCode, code: &str, message: &str) -> Response {
    let mut resp = Json(json!({
        "error_code": code,
        "message": message,
    }))
    .into_response();
    *resp.status_mut() = status;
    resp
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    UnknownField,
    TypeMismatch,
    UnknownCollection,
    QueryForbidden,
    QueryTimeout,
    QueryTooLarge,
    QuotaExceeded,
    RateLimited,
    TenantNotFound,
    Unauthenticated,
    WriteDenied,
    Internal,
}

#[derive(Debug, Clone, Serialize)]
pub struct ToolError {
    pub code: ErrorCode,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl ToolError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            details: None,
        }
    }
    pub fn with_details(mut self, v: serde_json::Value) -> Self {
        self.details = Some(v);
        self
    }
}

impl std::fmt::Display for ToolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for ToolError {}
