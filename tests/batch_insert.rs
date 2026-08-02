//! v1.55 — MCP `insert_records` (batch insert) tests (SQLite Wave 1 M2).
//!
//! Direct-call scaffold mirrors `mcp_aggregate.rs`. The headline invariant is
//! ATOMICITY: a mid-batch failure rolls back every data row AND every
//! `_system_record_history` row (capture runs inside the same writer tx).

#[path = "helpers.rs"]
mod helpers;

use drust::mcp::server::McpRegistry;
use drust::mcp::tools::batch::batch_insert;
use drust::mcp::tools::schema::{FieldSpec, create_collection};
use drust::storage::pool::TenantRegistry;
use drust::storage::record_history::AuditActor;
use serde_json::{Value, json};
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

async fn make_notes(s: &drust::mcp::server::DrustMcp) {
    create_collection(s, "notes", &[tf("body", "text")])
        .await
        .unwrap();
}

/// Fresh reader pool on the same data dir (the MCP scaffold's "blog" tenant)
/// for direct data / history counts.
async fn count_rows(dir: &tempfile::TempDir, table: &str) -> i64 {
    let tr = TenantRegistry::new(dir.path().to_path_buf(), 2);
    let pool = tr.get_or_create("blog").unwrap();
    let sql = format!("SELECT COUNT(*) FROM \"{}\"", table.replace('"', "\"\""));
    pool.with_reader(move |c| c.query_row(&sql, [], |r| r.get::<_, i64>(0)))
        .await
        .unwrap()
}

#[tokio::test]
async fn batch_inserts_all_rows_atomically() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    make_notes(&s).await;

    // Happy path: 3 rows in ONE call.
    let out = batch_insert(
        &s,
        "notes",
        vec![
            json!({"body":"a"}),
            json!({"body":"b"}),
            json!({"body":"c"}),
        ],
        AuditActor::service(),
    )
    .await
    .unwrap();
    assert_eq!(out["count"], 3);
    assert_eq!(out["inserted"].as_array().unwrap().len(), 3);
    assert_eq!(count_rows(&d, "notes").await, 3);
    assert_eq!(
        count_rows(&d, "_system_record_history").await,
        3,
        "3 per-row history rows"
    );

    // Atomic failure: row 2 has an unknown field → the WHOLE batch rolls back,
    // including row 1's already-inserted data + history.
    let err = batch_insert(
        &s,
        "notes",
        vec![json!({"body":"d"}), json!({"nope":"x"})],
        AuditActor::service(),
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("unknown field"), "got {err}");
    assert_eq!(
        count_rows(&d, "notes").await,
        3,
        "no partial insert — still 3"
    );
    assert_eq!(
        count_rows(&d, "_system_record_history").await,
        3,
        "no orphan history from the failed batch"
    );
}

#[tokio::test]
async fn batch_empty_rejected() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    make_notes(&s).await;
    let err = batch_insert(&s, "notes", vec![], AuditActor::service())
        .await
        .unwrap_err();
    assert!(err.to_string().contains("BATCH_EMPTY"), "got {err}");
}

#[tokio::test]
async fn batch_too_large_rejected() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    make_notes(&s).await;
    // Default cap 1000 → 1001 rows rejected up front, before any insert.
    let rows: Vec<Value> = (0..1001)
        .map(|i| json!({"body": format!("r{i}")}))
        .collect();
    let err = batch_insert(&s, "notes", rows, AuditActor::service())
        .await
        .unwrap_err();
    assert!(err.to_string().contains("BATCH_TOO_LARGE"), "got {err}");
    assert_eq!(count_rows(&d, "notes").await, 0, "nothing inserted");
}

#[tokio::test]
async fn batch_protected_collection_refused() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    let err = batch_insert(
        &s,
        "_system_files",
        vec![json!({"x":"y"})],
        AuditActor::service(),
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string().contains("PROTECTED_COLLECTION"),
        "got {err}"
    );
}
