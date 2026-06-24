//! WS2 Task 2.1 — parity oracle for the MCP `insert_record` / `update_record`
//! RETURNING refactor. These assertions must hold BOTH before (read-back via a
//! follow-up SELECT) and after (`INSERT/UPDATE ... RETURNING *`) the refactor:
//!
//!   * the returned row hides declared vector columns (default-hide on read),
//!   * scalar columns round-trip,
//!   * `id` is present on insert,
//!   * an update of a missing id reproduces the not-found arm.
//!
//! Written first per TDD so the behavior is locked before the implementation
//! changes (the body still does a real SELECT today; switching to RETURNING
//! must not move any of these needles).

use drust::mcp::server::McpRegistry;
use drust::mcp::tools::schema::{FieldSpec, create_collection};
use drust::mcp::tools::write::{insert_record, update_record};
use drust::storage::pool::TenantRegistry;
use std::sync::Arc;

async fn svc(dir: &tempfile::TempDir) -> drust::mcp::server::DrustMcp {
    let data = dir.path().to_path_buf();
    let tr = Arc::new(TenantRegistry::new(data.clone(), 2));
    let _ = drust::storage::tenant_db::open_write(&data, "blog").unwrap();
    let reg = McpRegistry::new(tr);
    reg.get_or_create("blog").await.unwrap()
}

/// `docs(title text, embedding vector dim=3)`.
async fn make_docs(s: &drust::mcp::server::DrustMcp) {
    create_collection(
        s,
        "docs",
        &[
            FieldSpec {
                name: "title".into(),
                sql_type: "text".into(),
                nullable: false,
                ..Default::default()
            },
            FieldSpec {
                name: "embedding".into(),
                sql_type: "vector".into(),
                nullable: true,
                dim: Some(3),
                ..Default::default()
            },
        ],
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn insert_and_update_return_same_row_and_hide_vectors() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    make_docs(&s).await;

    let resp = insert_record(
        &s,
        "docs",
        serde_json::json!({"title": "a", "embedding": [0.1, 0.2, 0.3]}),
    )
    .await
    .unwrap();
    // insert_record returns {"id": <i64>, "record": {...}}.
    let id = resp["id"].as_i64().expect("insert returns a numeric id");
    let inserted = &resp["record"];
    // Vector column hidden in the returned row.
    assert!(
        inserted.get("embedding").is_none(),
        "vector must be hidden on the returned row, got: {inserted}"
    );
    assert_eq!(inserted["title"], "a");
    assert_eq!(inserted["id"].as_i64(), Some(id));
    // BLOB never leaks as {"__blob_bytes": n} for the hidden vector.
    assert!(inserted.to_string().find("__blob_bytes").is_none());

    let uresp = update_record(&s, "docs", id, serde_json::json!({"title": "b"}))
        .await
        .unwrap();
    // update_record returns {"record": {...}}.
    let updated = &uresp["record"];
    assert_eq!(updated["title"], "b");
    assert_eq!(updated["id"].as_i64(), Some(id));
    assert!(
        updated.get("embedding").is_none(),
        "vector must stay hidden on the updated row"
    );

    // Update of a missing id → not-found arm preserved (Err).
    let miss = update_record(&s, "docs", 999_999, serde_json::json!({"title": "x"})).await;
    assert!(miss.is_err(), "update of a missing id must error");
}
