//! v1.21 — MCP `list_records` tool tests.
//!
//! Mirrors `mcp_vector.rs` shape for the direct-call cases and drives the
//! account-level `/mcp` endpoint for tools/list + user-token rejection.

#[path = "helpers.rs"]
mod helpers;

use axum::http::StatusCode;
use drust::mcp::server::McpRegistry;
use drust::mcp::tools::read::{ListRecordsArgs, list_records};
use drust::mcp::tools::schema::{FieldSpec, create_collection};
use drust::mcp::tools::write::insert_record;
use drust::query::list_builder::SortSpec;
use drust::storage::pool::TenantRegistry;
use serde_json::{Value, json};
use std::sync::Arc;

// ──────────────────────────────────────────────────────────────────────
// Direct-call scaffold (same as tests/mcp_vector.rs)
// ──────────────────────────────────────────────────────────────────────

async fn svc(dir: &tempfile::TempDir) -> drust::mcp::server::DrustMcp {
    let data = dir.path().to_path_buf();
    let tr = Arc::new(TenantRegistry::new(data.clone(), 2));
    let _ = drust::storage::tenant_db::open_write(&data, "blog").unwrap();
    let reg = McpRegistry::new(tr);
    reg.get_or_create("blog").await.unwrap()
}

/// Create a `posts(title, score)` collection.
async fn make_posts(s: &drust::mcp::server::DrustMcp) {
    create_collection(
        s,
        "posts",
        &[
            FieldSpec {
                name: "title".into(),
                sql_type: "text".into(),
                nullable: false,
                unique: false,
                default_value: None,
                foreign_key: None,
                dim: None,
                description: None,
                ..Default::default()
            },
            FieldSpec {
                name: "score".into(),
                sql_type: "integer".into(),
                nullable: false,
                unique: false,
                default_value: None,
                foreign_key: None,
                dim: None,
                description: None,
                ..Default::default()
            },
        ],
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn list_records_happy_path() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    make_posts(&s).await;
    for (title, score) in &[("alpha", 1i64), ("beta", 2), ("gamma", 3)] {
        insert_record(&s, "posts", json!({"title": title, "score": score}))
            .await
            .unwrap();
    }
    let out = list_records(
        &s,
        ListRecordsArgs {
            collection: "posts".into(),
            filter: None,
            sort: None,
            page: None,
            per_page: None,
            select: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(out["total"], 3, "got {out:?}");
    let rows = out["records"].as_array().unwrap();
    assert_eq!(rows.len(), 3);
}

#[tokio::test]
async fn list_records_filter_and_sort_same_rows_as_rest() {
    // The two surfaces share the same builder, so we just need to prove
    // the MCP path threads the FilterAst + SortSpec through.
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    make_posts(&s).await;
    for (title, score) in &[("alpha", 5i64), ("beta", 10), ("gamma", 15)] {
        insert_record(&s, "posts", json!({"title": title, "score": score}))
            .await
            .unwrap();
    }
    let out = list_records(
        &s,
        ListRecordsArgs {
            collection: "posts".into(),
            filter: Some(json!({"score": {"gte": 10}})),
            sort: Some(SortSpec {
                field: "score".into(),
                dir: "desc".into(),
            }),
            page: None,
            per_page: None,
            select: None,
        },
    )
    .await
    .unwrap();
    let rows = out["records"].as_array().unwrap();
    let titles: Vec<&str> = rows.iter().map(|r| r["title"].as_str().unwrap()).collect();
    assert_eq!(titles, vec!["gamma", "beta"], "got {out:?}");
}

#[tokio::test]
async fn list_records_accepts_double_encoded_string_filter() {
    // Regression (v1.58.6): many MCP clients serialize the object-typed
    // `filter` argument to a JSON *string*. Before the fix this failed with
    // "did not match any variant of untagged enum FilterAst"; now the tool
    // decodes one string layer and filters identically to the object form.
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    make_posts(&s).await;
    for (title, score) in &[("alpha", 5i64), ("beta", 10), ("gamma", 15)] {
        insert_record(&s, "posts", json!({"title": title, "score": score}))
            .await
            .unwrap();
    }
    let out = list_records(
        &s,
        ListRecordsArgs {
            collection: "posts".into(),
            // A JSON string, not an object — the double-encoding case.
            filter: Some(json!("{\"score\":{\"gte\":10}}")),
            sort: Some(SortSpec {
                field: "score".into(),
                dir: "desc".into(),
            }),
            page: None,
            per_page: None,
            select: None,
        },
    )
    .await
    .unwrap();
    let rows = out["records"].as_array().unwrap();
    let titles: Vec<&str> = rows.iter().map(|r| r["title"].as_str().unwrap()).collect();
    assert_eq!(titles, vec!["gamma", "beta"], "got {out:?}");
}

#[tokio::test]
async fn list_records_unparseable_string_filter_gives_shape_hint() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    make_posts(&s).await;
    let err = list_records(
        &s,
        ListRecordsArgs {
            collection: "posts".into(),
            filter: Some(json!("not a filter")),
            sort: None,
            page: None,
            per_page: None,
            select: None,
        },
    )
    .await
    .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("FILTER_PARSE_ERROR"), "got: {msg}");
    assert!(
        msg.contains("JSON object"),
        "want teaching hint, got: {msg}"
    );
    assert!(
        !msg.contains("did not match any variant"),
        "raw serde noise leaked: {msg}"
    );
}

#[tokio::test]
async fn aggregate_accepts_double_encoded_string_filter() {
    // aggregate.filter shares the identical rewired parse as list_records.filter;
    // prove the double-encoded-string path end-to-end on the aggregate tool too.
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    make_posts(&s).await;
    for (title, score) in &[("alpha", 5i64), ("beta", 10), ("gamma", 15)] {
        insert_record(&s, "posts", json!({"title": title, "score": score}))
            .await
            .unwrap();
    }
    let out = drust::mcp::tools::read::aggregate(
        &s,
        drust::mcp::tools::read::AggregateArgs {
            collection: "posts".into(),
            // A JSON string, not an object.
            filter: Some(json!("{\"score\":{\"gte\":10}}")),
            group_by: None,
            metrics: vec![drust::query::list_builder::AggregateMetric {
                op: "count".into(),
                field: None,
                alias: Some("n".into()),
            }],
            sort: None,
            page: None,
            per_page: None,
        },
    )
    .await
    .unwrap();
    let rows = out["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 1, "got {out:?}");
    assert_eq!(rows[0]["n"], 2, "score>=10 matches beta+gamma; got {out:?}");
}

#[tokio::test]
async fn list_records_protected_collection_is_collection_not_found() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    let err = list_records(
        &s,
        ListRecordsArgs {
            collection: "_system_users".into(),
            filter: None,
            sort: None,
            page: None,
            per_page: None,
            select: None,
        },
    )
    .await
    .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("COLLECTION_NOT_FOUND"),
        "expected COLLECTION_NOT_FOUND, got: {msg}"
    );
}

// ──────────────────────────────────────────────────────────────────────
// Protocol level: user-token rejection + tools/list on the account endpoint
// ──────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn user_token_via_mcp_is_rejected() {
    // A user session token gets no MCP at all: the account-level endpoint
    // accepts MCP OAuth access tokens only (invariant 9), so any other bearer
    // is a 401 invalid_token whatever tool it would have reached.
    let h = helpers::spin_up_account_mcp("mcp-user-rej").await;
    helpers::account_allow_self_register(&h).await;
    let user_tok =
        helpers::register_and_login_via_app(&h.app, &h.tid, "u@example.test", "pw-123456").await;
    let auth = format!("Bearer {user_tok}");
    let (status, headers, body) = helpers::mcp_raw(
        &h.app,
        "POST",
        &[("authorization", auth.as_str())],
        Some(helpers::mcp_init("2024-11-05")),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let v: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["error_code"], "MCP_OAUTH_REQUIRED");
    let www = headers["www-authenticate"].to_str().unwrap();
    assert!(www.contains("error=\"invalid_token\""), "{www}");
}

#[tokio::test]
async fn tools_list_contains_list_records() {
    let h = helpers::spin_up_account_mcp("mcp-tlist").await;
    let (status, _, msgs) = helpers::mcp_rpc(
        &h.app,
        Some(&h.access),
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let tools = msgs
        .iter()
        .find_map(|m| m["result"]["tools"].as_array().cloned())
        .expect("tools/list must return a tools array");
    let tool = tools
        .iter()
        .find(|t| t["name"] == "list_records")
        .unwrap_or_else(|| panic!("list_records must be in catalog; got: {tools:?}"));
    let required = tool["inputSchema"]["required"]
        .as_array()
        .unwrap_or_else(|| panic!("no required array: {}", tool["inputSchema"]));
    assert!(
        required.iter().any(|r| r == "tenant"),
        "list_records must require `tenant` on the account endpoint: {required:?}"
    );
}
