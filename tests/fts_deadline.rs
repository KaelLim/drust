//! Wave 2 M3 Task 6 — the wall-clock deadline is armed on the bound-select read
//! faces, not just the raw `/query` executor.
//!
//! `$fts` (and any caller-influenced filter) reaches SQLite through five reader
//! closures; v1.58.5 only armed the deadline on `execute_read_query*`. This binary
//! pins that the guard is now armed on the two primary anon-reachable faces —
//! REST `/list` (rows+count) and `/aggregate` — plus the MCP `list_records`
//! mirror. A large table + a tiny `DRUST_QUERY_DEADLINE_MS` makes a full-scan
//! filter run far longer than the budget: WITH the guard the scan is interrupted
//! (500 `DB_ERROR` / an `Err`); WITHOUT it the scan completes (200 / `Ok`). The
//! status is the distinguishing signal, so the test is not timing-flaky.
//!
//! ONE test only: `query_deadline()` caches `DRUST_QUERY_DEADLINE_MS` in a
//! process-global `OnceLock`, so a second test setting a different value would
//! race. This is the only place in the binary that touches the env var.

#[path = "helpers.rs"]
mod helpers;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::mcp::server::McpRegistry;
use drust::mcp::tools::read::{ListRecordsArgs, list_records};
use drust::mcp::tools::schema::{FieldSpec, create_collection};
use drust::storage::pool::TenantRegistry;
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

use helpers::spin_up_tenant;

// 300k rows: a single full-scan LIKE over the ~25-char `body` column is tens of
// ms of CPU — comfortably longer than the 1ms budget on any realistic machine,
// so the interrupt fires mid-scan deterministically.
const ROWS: i64 = 300_000;

/// A filter that matches nothing and therefore forces a full table scan.
fn scan_filter() -> Value {
    json!({"body": {"like": "%zzz-no-such-substring-zzz%"}})
}

fn text_field(name: &str) -> FieldSpec {
    FieldSpec {
        name: name.into(),
        sql_type: "text".into(),
        nullable: true,
        unique: false,
        default_value: None,
        foreign_key: None,
        dim: None,
        description: None,
        ..Default::default()
    }
}

async fn post(app: &axum::Router, uri: &str, tok: &str, body: Value) -> (StatusCode, Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 65_536)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn deadline_is_armed_on_the_bound_select_faces() {
    // SAFETY: set before query_deadline()'s OnceLock is first read — no face has
    // armed the guard yet (spin-up + seeding never call query_deadline). This is
    // the only test in this binary that touches the env var.
    unsafe {
        std::env::set_var("DRUST_QUERY_DEADLINE_MS", "1");
    }

    let (app, tok, dir) = spin_up_tenant("dl").await;

    // Create `big(title, body)` and bulk-seed ROWS rows via a single recursive-CTE
    // INSERT on the writer (fast; bypasses quota/history, fine for a fixture).
    let tr = Arc::new(TenantRegistry::new(dir.path().to_path_buf(), 2));
    let s = McpRegistry::new(tr).get_or_create("dl").await.unwrap();
    create_collection(&s, "big", &[text_field("title"), text_field("body")])
        .await
        .unwrap();
    s.inner()
        .pool
        .with_writer(move |c| {
            c.execute_batch(&format!(
                "INSERT INTO big(title, body) \
                 SELECT 'row' || x, 'body content number ' || x \
                 FROM (WITH RECURSIVE g(x) AS ( \
                        SELECT 1 UNION ALL SELECT x + 1 FROM g WHERE x < {ROWS} \
                      ) SELECT x FROM g);"
            ))
        })
        .await
        .unwrap();

    // ── REST /list: a full scan under a 1ms budget must be interrupted ──
    let start = std::time::Instant::now();
    let (st, body) = post(
        &app,
        "/t/dl/collections/big/list",
        &tok,
        json!({"filter": scan_filter()}),
    )
    .await;
    let elapsed = start.elapsed();
    assert_eq!(
        st,
        StatusCode::INTERNAL_SERVER_ERROR,
        "the /list scan should have been interrupted (500), got {st}: {body:?} — \
         the deadline guard is not armed on the /list rows closure"
    );
    assert_eq!(body["error_code"], "DB_ERROR", "{body:?}");
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "the interrupted /list must return promptly, took {elapsed:?}"
    );

    // ── REST /aggregate: same face, same guard ─────────────────────────
    let (st, body) = post(
        &app,
        "/t/dl/collections/big/aggregate",
        &tok,
        json!({"metrics": [{"op": "count"}], "filter": scan_filter()}),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::INTERNAL_SERVER_ERROR,
        "the /aggregate scan should have been interrupted (500), got {st}: {body:?}"
    );
    assert_eq!(body["error_code"], "DB_ERROR", "{body:?}");

    // ── MCP list_records mirror: the rows closure propagates the interrupt ─
    let err = list_records(
        &s,
        ListRecordsArgs {
            collection: "big".into(),
            filter: Some(scan_filter()),
            sort: None,
            page: None,
            per_page: None,
            select: None,
        },
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        err.to_lowercase().contains("interrupt"),
        "the MCP list scan should have been interrupted, got: {err} — \
         the deadline guard is not armed on the MCP rows closure"
    );
}
