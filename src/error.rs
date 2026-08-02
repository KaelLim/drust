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

/// v1.50 (Spec B, Task 3) — build the sentinel `rusqlite::Error` a DB write
/// choke point returns from INSIDE its writer transaction when the tenant's
/// hard quota is exceeded. The message is prefixed `TENANT_QUOTA_EXCEEDED: …`
/// so BOTH surfaces map it uniformly: REST via `is_quota_exceeded` → 507, and
/// MCP via `bail_mcp`'s `<CODE>: <message>` convention. Same shape as the
/// module-local `policy_check_sentinel` / `invalid_input` helpers.
pub fn quota_exceeded_error(e: crate::storage::quota::QuotaError) -> rusqlite::Error {
    let crate::storage::quota::QuotaError::TenantQuotaExceeded { usage, limit, .. } = e;
    rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(1),
        Some(format!(
            "TENANT_QUOTA_EXCEEDED: tenant storage usage {usage}B would exceed the {limit}B limit"
        )),
    )
}

/// v1.50 — true when a rusqlite error is the tenant-quota sentinel produced by
/// `quota_exceeded_error`. The REST create/update handlers use this to map the
/// closure's `Err` onto a 507 `TENANT_QUOTA_EXCEEDED`. Substring match on the
/// code prefix, mirroring `policy::is_policy_check_failure`.
pub fn is_quota_exceeded(e: &rusqlite::Error) -> bool {
    e.to_string().contains("TENANT_QUOTA_EXCEEDED")
}

/// Stringify a rusqlite error WITHOUT the SQL text the error may embed.
///
/// rusqlite returns `Error::SqlInputError { msg, sql, offset }` whenever
/// `sqlite3_prepare_v3` fails with a code that maps to `ErrorCode::Unknown`
/// (i.e. plain `SQLITE_ERROR`: syntax error, `no such column`, `no such
/// table` — exactly what schema drift produces on a statement that was valid
/// when it was stored) and `sqlite3_error_offset` is non-negative. Its
/// `Display` is `"{msg} in {sql} at offset {offset}"` — **the whole failing
/// statement, verbatim, string literals included**.
///
/// That statement is not the caller's to see. A stored RPC body is tenant
/// CONFIGURATION: `redact_rpc_obj` strips `sql` from the `rpcs` MCP resource
/// and `redact_cron` strips the same text back out of the cron resource's
/// `last_error`, both on purpose — yet an `anon_callable` RPC over a
/// collection that has since lost a field would hand an UNAUTHENTICATED
/// caller the entire body, hardcoded credentials and all, inside the 400 it
/// returns. So every rusqlite error crossing an executor boundary is
/// stringified through here instead of `to_string()`.
///
/// `msg` + `offset` survive, so the operator still reads "no such column:
/// status at offset 63" and a service caller can fetch the body back with
/// `list_rpc` — an explicit, authorized call.
///
/// Authorizer denials are unaffected: `SQLITE_AUTH` maps to
/// `ErrorCode::AuthorizationForStatementDenied`, never `Unknown`, so they
/// arrive as `SqliteFailure` ("not authorized" / "access to X.Y is
/// prohibited") and pass through byte-identical.
pub fn sqlite_error_without_sql(e: &rusqlite::Error) -> String {
    match e {
        rusqlite::Error::SqlInputError { msg, offset, .. } => format!("{msg} at offset {offset}"),
        other => other.to_string(),
    }
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

    /// v1.58 — the SQL a prepare failure embeds must not survive
    /// stringification. Also PINS the upstream behavior the helper exists for:
    /// if a future rusqlite stops embedding the statement, the second assert
    /// fires and the guard can be retired deliberately rather than rotting.
    #[test]
    fn sqlite_error_without_sql_strips_the_statement_rusqlite_embeds() {
        const SECRET: &str = "sk-live-9f2c";
        let c = rusqlite::Connection::open_in_memory().unwrap();
        c.execute_batch("CREATE TABLE events (api_key TEXT);")
            .unwrap();
        // Shape of a stored RPC body after the collection lost a field.
        let sql = "SELECT 1 FROM events WHERE api_key = 'sk-live-9f2c' AND status = 'ok'";
        let e = c.prepare(sql).unwrap_err();
        assert!(
            matches!(e, rusqlite::Error::SqlInputError { .. }),
            "prepare failure must still be SqlInputError: {e:?}"
        );
        assert!(
            e.to_string().contains(SECRET),
            "to_string() must still be the leaky one, else this helper is dead code: {e}"
        );

        let safe = sqlite_error_without_sql(&e);
        assert!(
            !safe.contains(SECRET),
            "credential survived redaction: {safe}"
        );
        assert!(
            !safe.contains("SELECT 1 FROM events"),
            "statement survived redaction: {safe}"
        );
        assert!(
            safe.contains("no such column: status"),
            "the diagnostic must survive: {safe}"
        );
    }

    /// Every other variant passes through byte-identical — `is_check_violation`,
    /// `is_quota_exceeded` and the several `contains("no such table")` reader
    /// tolerances all read `SqliteFailure` messages.
    #[test]
    fn sqlite_error_without_sql_passes_non_prepare_errors_through() {
        let c = rusqlite::Connection::open_in_memory().unwrap();
        c.execute_batch("CREATE TABLE t (n INTEGER CHECK(n >= 0));")
            .unwrap();
        let e = c.execute("INSERT INTO t(n) VALUES (-1)", []).unwrap_err();
        assert_eq!(sqlite_error_without_sql(&e), e.to_string());
        let sentinel =
            quota_exceeded_error(crate::storage::quota::QuotaError::TenantQuotaExceeded {
                usage: 1,
                incoming: 0,
                limit: 0,
            });
        assert!(
            sqlite_error_without_sql(&sentinel).contains("TENANT_QUOTA_EXCEEDED"),
            "the drust sentinel prefix must survive — 507 mapping reads it"
        );
    }

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
