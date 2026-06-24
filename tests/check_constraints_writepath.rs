// WS6 Task 6.3 — the MCP write path pre-validates structured constraints and
// rejects a violation with a typed `CHECK_CONSTRAINT_FAILED` message (rather
// than letting the native CHECK surface a raw SQLite string). In-range writes
// pass. Covers both insert_record and update_record.

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

async fn make_people(s: &drust::mcp::server::DrustMcp) {
    create_collection(
        s,
        "people",
        &[
            FieldSpec {
                name: "age".into(),
                sql_type: "integer".into(),
                nullable: true,
                min: Some(0.0),
                max: Some(150.0),
                ..Default::default()
            },
            FieldSpec {
                name: "role".into(),
                sql_type: "text".into(),
                nullable: true,
                enum_values: Some(vec!["admin".into(), "user".into()]),
                ..Default::default()
            },
        ],
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn insert_rejects_with_typed_error() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    make_people(&s).await;

    // App-layer pre-check → typed message, not a raw SQLite string.
    let over = insert_record(&s, "people", serde_json::json!({"age": 999}))
        .await
        .unwrap_err();
    assert!(
        over.to_string().contains("CHECK_CONSTRAINT_FAILED"),
        "got: {over}"
    );
    let off_enum = insert_record(&s, "people", serde_json::json!({"role": "ghost"}))
        .await
        .unwrap_err();
    assert!(
        off_enum.to_string().contains("CHECK_CONSTRAINT_FAILED"),
        "got: {off_enum}"
    );

    // In-range passes.
    insert_record(
        &s,
        "people",
        serde_json::json!({"age": 20, "role": "admin"}),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn update_rejects_with_typed_error() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    make_people(&s).await;

    let ins = insert_record(&s, "people", serde_json::json!({"age": 20}))
        .await
        .unwrap();
    let id = ins["id"].as_i64().unwrap();

    let err = update_record(&s, "people", id, serde_json::json!({"age": 999}))
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("CHECK_CONSTRAINT_FAILED"),
        "got: {err}"
    );

    // In-range update passes.
    update_record(&s, "people", id, serde_json::json!({"age": 30}))
        .await
        .unwrap();
}

/// A numeric (integer/real/boolean) enum field rejects an out-of-enum JSON
/// NUMBER with the typed `CHECK_CONSTRAINT_FAILED` — not the raw native CHECK
/// string. Before the type-aware pre-check, the enum was only checked inside
/// `if let Some(s) = v.as_str()`, so a JSON number slipped past the app
/// pre-check and surfaced the SQLite "CHECK constraint failed" message on MCP.
#[tokio::test]
async fn numeric_enum_number_rejected_with_typed_error() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    create_collection(
        &s,
        "ratings",
        &[FieldSpec {
            name: "rating".into(),
            sql_type: "integer".into(),
            nullable: true,
            enum_values: Some(vec!["1".into(), "2".into()]),
            ..Default::default()
        }],
    )
    .await
    .unwrap();

    // JSON number 3 is out of the numeric enum {1,2}.
    let err = insert_record(&s, "ratings", serde_json::json!({"rating": 3}))
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("CHECK_CONSTRAINT_FAILED"),
        "numeric enum violation must be typed, got: {err}"
    );
    // A valid numeric enum value passes.
    insert_record(&s, "ratings", serde_json::json!({"rating": 2}))
        .await
        .unwrap();
}

#[test]
fn check_constraint_failed_is_in_error_fix_catalog() {
    let fix = drust::safety::error_fixes::lookup("CHECK_CONSTRAINT_FAILED");
    assert!(
        fix.is_some(),
        "CHECK_CONSTRAINT_FAILED must have a suggested fix"
    );
}
