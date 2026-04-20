mod helpers;
use drust::mcp::server::McpRegistry;
use drust::mcp::tools::schema::{add_field, create_collection, FieldSpec};
use drust::mcp::tools::write::{delete_record, insert_record, update_record};
use drust::storage::pool::TenantRegistry;
use std::sync::Arc;

async fn svc(dir: &tempfile::TempDir) -> drust::mcp::server::DrustMcp {
    let data = dir.path().to_path_buf();
    let tr = Arc::new(TenantRegistry::new(data.clone(), 2));
    let _ = drust::storage::tenant_db::open_write(&data, "blog").unwrap();
    let reg = McpRegistry::new(tr);
    reg.get_or_create("blog").await.unwrap()
}

#[tokio::test]
async fn create_insert_update_delete_roundtrip() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    create_collection(
        &s,
        "posts",
        &[FieldSpec { name: "title".into(), sql_type: "text".into(), nullable: false, unique: false, default_value: None }],
    )
    .await
    .unwrap();
    let ins = insert_record(&s, "posts", serde_json::json!({"title":"a"})).await.unwrap();
    let id = ins["id"].as_i64().unwrap();
    let upd = update_record(&s, "posts", id, serde_json::json!({"title":"b"})).await.unwrap();
    assert_eq!(upd["record"]["title"], "b");
    let del = delete_record(&s, "posts", id).await.unwrap();
    assert_eq!(del["ok"], true);
}

#[tokio::test]
async fn add_field_adds_column() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    create_collection(
        &s,
        "posts",
        &[FieldSpec { name: "title".into(), sql_type: "text".into(), nullable: false, unique: false, default_value: None }],
    )
    .await
    .unwrap();
    add_field(&s, "posts", FieldSpec {
        name: "views".into(),
        sql_type: "integer".into(),
        nullable: true,
        unique: false,
        default_value: Some(serde_json::json!(0)),
    })
    .await
    .unwrap();
    let ins = insert_record(&s, "posts", serde_json::json!({"title":"a","views":5})).await.unwrap();
    assert_eq!(ins["record"]["views"], 5);
}
