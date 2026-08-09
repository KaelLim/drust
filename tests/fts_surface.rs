//! Wave 2 M3 Task 6 — `FTS_QUERY_INVALID` across the anon-reachable read faces.
//!
//! A malformed fts5 MATCH is parsed only at STEP time (a plain SQLITE_ERROR), so
//! without the structural pre-probe it would surface as a generic 500. Task 6
//! runs `SELECT rowid FROM "<head>" WHERE "<head>" MATCH ? LIMIT 1` on a reader
//! BEFORE the main statement and maps a failure to `400 FTS_QUERY_INVALID` on
//! every face — never by message-substring. Pinned here on REST `/list`,
//! `/aggregate`, and the MCP `list_records` mirror, with a well-formed `$fts`
//! kept green as the regression control.

#[path = "helpers.rs"]
mod helpers;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::mcp::server::{DrustMcp, McpRegistry};
use drust::mcp::tools::fts::create_fts_index;
use drust::mcp::tools::read::{ListRecordsArgs, aggregate, list_records};
use drust::mcp::tools::schema::{FieldSpec, create_collection};
use drust::mcp::tools::write::insert_record;
use drust::storage::pool::TenantRegistry;
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

use helpers::spin_up_tenant;

const BAD_MATCH: &str = "foo AND (";
const GOOD_MATCH: &str = "hospital";

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

/// Build a DrustMcp over the SAME data dir the HTTP app uses, then create a
/// unicode61-indexed `docs` collection (unicode61 always MATCHes, so a malformed
/// query reaches the fts5 parser rather than the trigram LIKE fallback) with one
/// row. Done BEFORE the app first describes `docs`, so the app reads it fresh.
async fn mcp_over(dir: &tempfile::TempDir, tenant: &str) -> DrustMcp {
    let tr = Arc::new(TenantRegistry::new(dir.path().to_path_buf(), 2));
    McpRegistry::new(tr).get_or_create(tenant).await.unwrap()
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

fn list_args(query: &str) -> ListRecordsArgs {
    ListRecordsArgs {
        collection: "docs".into(),
        filter: Some(json!({"$fts": {"index": "main", "query": query}})),
        sort: None,
        page: None,
        per_page: None,
        select: None,
    }
}

#[tokio::test]
async fn malformed_fts_match_is_400_not_500_across_faces() {
    let (app, tok, dir) = spin_up_tenant("blog").await;

    // Create the collection + unicode61 fts index + one row via a co-located MCP.
    let s = mcp_over(&dir, "blog").await;
    create_collection(&s, "docs", &[text_field("title")])
        .await
        .unwrap();
    create_fts_index(&s, "docs", "main", &["title".into()], Some("unicode61"))
        .await
        .unwrap();
    insert_record(&s, "docs", json!({"title": "hospital report"}))
        .await
        .unwrap();

    // ── REST /list ────────────────────────────────────────────────────
    let (st, body) = post(
        &app,
        "/t/blog/collections/docs/list",
        &tok,
        json!({"filter": {"$fts": {"index": "main", "query": BAD_MATCH}}}),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::BAD_REQUEST,
        "malformed /list must be 400: {body:?}"
    );
    assert_eq!(body["error_code"], "FTS_QUERY_INVALID", "{body:?}");

    // Regression: a well-formed `$fts` still returns the matching row.
    let (st, body) = post(
        &app,
        "/t/blog/collections/docs/list",
        &tok,
        json!({"filter": {"$fts": {"index": "main", "query": GOOD_MATCH}}}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{body:?}");
    assert_eq!(body["total"], 1, "well-formed $fts must match: {body:?}");

    // ── REST /aggregate ───────────────────────────────────────────────
    let (st, body) = post(
        &app,
        "/t/blog/collections/docs/aggregate",
        &tok,
        json!({
            "metrics": [{"op": "count"}],
            "filter": {"$fts": {"index": "main", "query": BAD_MATCH}}
        }),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::BAD_REQUEST,
        "malformed /aggregate must be 400: {body:?}"
    );
    assert_eq!(body["error_code"], "FTS_QUERY_INVALID", "{body:?}");

    // ── MCP list_records mirror ───────────────────────────────────────
    let err = list_records(&s, list_args(BAD_MATCH))
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("FTS_QUERY_INVALID"),
        "MCP malformed $fts must carry the sentinel, got: {err}"
    );
    let ok = list_records(&s, list_args(GOOD_MATCH)).await.unwrap();
    assert_eq!(ok["total"], 1, "MCP well-formed $fts must match: {ok}");

    // ── MCP aggregate mirror ──────────────────────────────────────────
    let err = aggregate(
        &s,
        drust::mcp::tools::read::AggregateArgs {
            collection: "docs".into(),
            filter: Some(json!({"$fts": {"index": "main", "query": BAD_MATCH}})),
            group_by: None,
            metrics: vec![drust::query::list_builder::AggregateMetric {
                op: "count".into(),
                field: None,
                alias: None,
            }],
            sort: None,
            page: None,
            per_page: None,
        },
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("FTS_QUERY_INVALID"),
        "MCP aggregate malformed $fts must carry the sentinel, got: {err}"
    );
}
