use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::safety::error_fixes;

/// v1.43 — true when a rusqlite error is a native CHECK-constraint
/// violation (as opposed to UNIQUE / FK / NOT NULL). Used by the REST
/// create/update arms (and the MCP write backstop) to map the raw SQLite
/// CHECK message onto the typed `CHECK_CONSTRAINT_FAILED` code for admin
/// REST / stored-RPC / edge-function / numeric-enum writes that bypass the
/// app-layer structured pre-check.
///
/// Gated on the SQLite EXTENDED result code `SQLITE_CONSTRAINT_CHECK`, NOT a
/// case-insensitive substring of the message: a UNIQUE / NOT NULL / FK
/// violation on a column whose NAME contains "check" (e.g. `check_sum`)
/// produces a message like `UNIQUE constraint failed: t.check_sum`, which a
/// substring match would mislabel as a CHECK failure. The extended code is
/// exact and never collides with column names.
pub fn is_check_violation(e: &rusqlite::Error) -> bool {
    matches!(
        e,
        rusqlite::Error::SqliteFailure(err, _)
            if err.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_CHECK
    )
}

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

/// v1.29.6 — same as `json_error` but additionally emits an
/// `error_aliases` JSON array of semantically-equivalent codes.
/// Use during error-code migration so old clients continue catching
/// the primary `error_code` while new clients can switch to the
/// canonical name.
///
/// Wire shape:
/// ```json
/// {"error_code": "WRITE_DENIED",
///  "error_aliases": ["SERVICE_REQUIRED"],
///  "message": "...",
///  "suggested_fix": "..."}
/// ```
pub fn json_error_with_aliases(
    status: StatusCode,
    code: &str,
    aliases: &[&str],
    message: &str,
) -> Response {
    let mut body = serde_json::Map::new();
    body.insert("error_code".into(), json!(code));
    body.insert("error_aliases".into(), json!(aliases));
    body.insert("message".into(), json!(message));
    if let Some(fix) = crate::safety::error_fixes::lookup(code) {
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

    #[test]
    fn is_check_violation_distinguishes_check_from_unique_on_check_named_col() {
        let c = rusqlite::Connection::open_in_memory().unwrap();
        c.execute_batch(
            "CREATE TABLE t (id INTEGER PRIMARY KEY, n INTEGER CHECK(n >= 0), \
             check_sum TEXT UNIQUE);",
        )
        .unwrap();
        // A genuine CHECK violation is detected.
        let e_check = c
            .execute("INSERT INTO t(n, check_sum) VALUES (-1, 'a')", [])
            .unwrap_err();
        assert!(is_check_violation(&e_check), "real CHECK must be detected");
        // A UNIQUE violation on a column NAMED `check_sum` must NOT be
        // misclassified — the message contains "check" but the extended code is
        // SQLITE_CONSTRAINT_UNIQUE, not _CHECK.
        c.execute("INSERT INTO t(n, check_sum) VALUES (1, 'dup')", [])
            .unwrap();
        let e_unique = c
            .execute("INSERT INTO t(n, check_sum) VALUES (2, 'dup')", [])
            .unwrap_err();
        assert!(
            !is_check_violation(&e_unique),
            "UNIQUE on a check_* column must NOT be misclassified as CHECK"
        );
    }

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

    #[tokio::test]
    async fn json_error_with_aliases_emits_array() {
        let resp = json_error_with_aliases(
            StatusCode::FORBIDDEN,
            "WRITE_DENIED",
            &["SERVICE_REQUIRED"],
            "service required",
        );
        let bytes = to_bytes(resp.into_body(), 4096).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["error_code"], "WRITE_DENIED");
        assert_eq!(v["error_aliases"], serde_json::json!(["SERVICE_REQUIRED"]));
        assert_eq!(v["message"], "service required");
    }

    #[tokio::test]
    async fn json_error_with_aliases_emits_suggested_fix() {
        let resp = json_error_with_aliases(
            StatusCode::FORBIDDEN,
            "WRITE_DENIED",
            &["SERVICE_REQUIRED"],
            "service required",
        );
        let bytes = to_bytes(resp.into_body(), 4096).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        // WRITE_DENIED is in the suggested_fix catalog
        assert!(v["suggested_fix"].as_str().unwrap().contains("service"));
    }
}
