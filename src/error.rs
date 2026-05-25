use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use crate::safety::error_fixes;

/// Canonical JSON error response. v1.26: auto-attaches `suggested_fix`
/// from the static catalog when the code is known. Unknown codes
/// produce a body without the field (omitted via JSON `Option` shape —
/// a missing key, not `null`).
///
/// Wire shape:
/// ```json
/// {"error_code": "<code>", "message": "<message>", "suggested_fix": "<fix>"}
/// ```
/// `suggested_fix` absent when no catalog entry exists.
pub fn json_error(status: StatusCode, code: &str, message: &str) -> Response {
    let mut body = serde_json::Map::new();
    body.insert("error_code".into(), json!(code));
    body.insert("message".into(), json!(message));
    if let Some(fix) = error_fixes::lookup(code) {
        body.insert("suggested_fix".into(), json!(fix));
    }
    let mut resp = Json(serde_json::Value::Object(body)).into_response();
    *resp.status_mut() = status;
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    #[tokio::test]
    async fn known_code_gets_suggested_fix() {
        let resp = json_error(StatusCode::FORBIDDEN, "LARGE_TABLE", "boom");
        let bytes = to_bytes(resp.into_body(), 4096).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["error_code"], "LARGE_TABLE");
        assert!(v["suggested_fix"].as_str().unwrap().contains("force"));
    }

    #[tokio::test]
    async fn unknown_code_omits_suggested_fix() {
        let resp = json_error(StatusCode::BAD_REQUEST, "MADE_UP_CODE", "boom");
        let bytes = to_bytes(resp.into_body(), 4096).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(v.get("suggested_fix").is_none());
    }
}
