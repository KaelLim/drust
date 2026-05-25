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

/// v1.26 — Context-aware variant of `json_error`. Use this at the 4
/// sites where we have enough information at the error point to
/// substitute variables (field name, dim, existing list) into the fix
/// string. Falls back to the static catalog if `contextual_fix`
/// returns nothing — but currently every `ErrorContext` variant
/// always builds a string, so the fallback is defensive.
pub fn json_error_with_context(
    status: StatusCode,
    code: &str,
    message: &str,
    ctx: &crate::safety::error_fixes::ErrorContext<'_>,
) -> Response {
    let fix = crate::safety::error_fixes::contextual_fix(ctx);
    let mut body = serde_json::Map::new();
    body.insert("error_code".into(), json!(code));
    body.insert("message".into(), json!(message));
    body.insert("suggested_fix".into(), json!(fix));
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

    #[tokio::test]
    async fn with_context_substitutes_variables() {
        use crate::safety::error_fixes::ErrorContext;
        let resp = json_error_with_context(
            StatusCode::BAD_REQUEST,
            "FIELD_NOT_FOUND",
            "unknown field",
            &ErrorContext::FieldNotFound {
                field: "xyz",
                collection: "posts",
                existing: &["id".into(), "title".into()],
            },
        );
        let bytes = to_bytes(resp.into_body(), 4096).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let fix = v["suggested_fix"].as_str().unwrap();
        assert!(fix.contains("`xyz`"));
        assert!(fix.contains("`posts`"));
        assert!(fix.contains("id, title"));
    }
}
