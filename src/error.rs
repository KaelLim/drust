use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

/// Canonical JSON error response used across the JSON API surface
/// (`src/tenant/*`, `src/rpc/*`). The wire shape is
/// `{"error_code": <code>, "message": <message>}` with the given
/// HTTP status.
///
/// `src/mgmt/*` admin-UI handlers continue to return bare-string
/// responses for browser-facing pages; vocabulary consolidation
/// (and any mgmt migration) is out of scope here.
pub fn json_error(status: StatusCode, code: &str, message: &str) -> Response {
    let mut resp = Json(json!({
        "error_code": code,
        "message": message,
    }))
    .into_response();
    *resp.status_mut() = status;
    resp
}
