//! v1.54 — MCP `aggregate` tool tests (SQLite Wave 1 M1).
//!
//! Direct-call scaffold mirrors `mcp_list_records.rs`. MCP is service-only at
//! the transport layer, so `read::aggregate` bypasses owner/policy (`None,
//! None`) — the row-authorization lockstep with `/list` is proven on the REST
//! face in `tests/aggregate.rs`; here we prove the tool threads the builder.

#[path = "helpers.rs"]
mod helpers;

use drust::mcp::server::McpRegistry;
use drust::mcp::tools::read::{AggregateArgs, aggregate};
use drust::mcp::tools::schema::{FieldSpec, create_collection};
use drust::mcp::tools::write::insert_record;
use drust::query::list_builder::{AggregateMetric, SortSpec};
use drust::storage::pool::TenantRegistry;
use serde_json::json;
use std::sync::Arc;

async fn svc(dir: &tempfile::TempDir) -> drust::mcp::server::DrustMcp {
    let data = dir.path().to_path_buf();
    let tr = Arc::new(TenantRegistry::new(data.clone(), 2));
    let _ = drust::storage::tenant_db::open_write(&data, "blog").unwrap();
    let reg = McpRegistry::new(tr);
    reg.get_or_create("blog").await.unwrap()
}

fn tf(name: &str, ty: &str) -> FieldSpec {
    FieldSpec {
        name: name.into(),
        sql_type: ty.into(),
        nullable: false,
        unique: false,
        default_value: None,
        foreign_key: None,
        dim: None,
        description: None,
        ..Default::default()
    }
}

async fn make_posts(s: &drust::mcp::server::DrustMcp) {
    create_collection(s, "posts", &[tf("status", "text"), tf("score", "integer")])
        .await
        .unwrap();
}

fn metric(op: &str, field: Option<&str>, alias: Option<&str>) -> AggregateMetric {
    AggregateMetric {
        op: op.into(),
        field: field.map(str::to_string),
        alias: alias.map(str::to_string),
    }
}

async fn seed(s: &drust::mcp::server::DrustMcp) {
    for (status, score) in &[("published", 10i64), ("published", 30), ("draft", 5)] {
        insert_record(s, "posts", json!({"status": status, "score": score}))
            .await
            .unwrap();
    }
}

fn args(collection: &str, metrics: Vec<AggregateMetric>) -> AggregateArgs {
    AggregateArgs {
        collection: collection.into(),
        filter: None,
        group_by: None,
        metrics,
        sort: None,
        page: None,
        per_page: None,
    }
}

#[tokio::test]
async fn aggregate_count_star_over_all_rows() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    make_posts(&s).await;
    seed(&s).await;
    let out = aggregate(&s, args("posts", vec![metric("count", None, Some("n"))]))
        .await
        .unwrap();
    let rows = out["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["n"], 3);
}

#[tokio::test]
async fn aggregate_group_by_with_sum_and_sort() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    make_posts(&s).await;
    seed(&s).await;
    let out = aggregate(
        &s,
        AggregateArgs {
            collection: "posts".into(),
            filter: None,
            group_by: Some(vec!["status".into()]),
            metrics: vec![
                metric("count", None, Some("n")),
                metric("sum", Some("score"), Some("total")),
            ],
            sort: Some(SortSpec {
                field: "total".into(),
                dir: "desc".into(),
            }),
            page: None,
            per_page: None,
        },
    )
    .await
    .unwrap();
    let rows = out["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 2, "two status groups");
    assert_eq!(rows[0]["status"], "published");
    assert_eq!(rows[0]["n"], 2);
    assert_eq!(rows[0]["total"], 40);
    assert_eq!(rows[1]["status"], "draft");
    assert_eq!(rows[1]["total"], 5);
}

#[tokio::test]
async fn aggregate_filter_narrows_the_set() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    make_posts(&s).await;
    seed(&s).await;
    let out = aggregate(
        &s,
        AggregateArgs {
            collection: "posts".into(),
            filter: Some(json!({"score": {"gte": 10}})),
            group_by: None,
            metrics: vec![metric("count", None, Some("n"))],
            sort: None,
            page: None,
            per_page: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(out["rows"][0]["n"], 2, "only the two score>=10 rows");
}

#[tokio::test]
async fn aggregate_no_metrics_is_typed_error() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    make_posts(&s).await;
    let err = aggregate(&s, args("posts", vec![])).await.unwrap_err();
    assert!(err.to_string().contains("AGG_NO_METRICS"), "got {err}");
}

#[tokio::test]
async fn aggregate_duplicate_alias_is_typed_error() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    make_posts(&s).await;
    let err = aggregate(
        &s,
        AggregateArgs {
            collection: "posts".into(),
            filter: None,
            group_by: None,
            metrics: vec![
                metric("count", None, Some("x")),
                metric("sum", Some("score"), Some("x")),
            ],
            sort: None,
            page: None,
            per_page: None,
        },
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("AGG_ALIAS_DUPLICATE"), "got {err}");
}

#[tokio::test]
async fn aggregate_unknown_field_is_typed_error() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    make_posts(&s).await;
    let err = aggregate(&s, args("posts", vec![metric("sum", Some("nope"), None)]))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("AGG_FIELD_UNKNOWN"), "got {err}");
}

#[tokio::test]
async fn aggregate_protected_collection_is_not_found() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    let err = aggregate(&s, args("_system_files", vec![metric("count", None, None)]))
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("COLLECTION_NOT_FOUND"),
        "got {err}"
    );
}
