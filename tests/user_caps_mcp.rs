mod helpers;
use drust::mcp::server::McpRegistry;
use drust::mcp::tools::schema::{FieldSpec, create_collection, set_user_caps};
use drust::storage::pool::TenantRegistry;
use drust::storage::schema::DmlVerb;
use std::sync::Arc;

async fn svc(dir: &tempfile::TempDir) -> drust::mcp::server::DrustMcp {
    let data = dir.path().to_path_buf();
    let tr = Arc::new(TenantRegistry::new(data.clone(), 2));
    let _ = drust::storage::tenant_db::open_write(&data, "blog").unwrap();
    let reg = McpRegistry::new(tr);
    reg.get_or_create("blog").await.unwrap()
}

fn title_field() -> FieldSpec {
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
    }
}

#[tokio::test]
async fn set_user_caps_round_trip_and_describe_reflects_it() {
    use drust::mcp::tools::exploration::describe_collection as describe_mcp;
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    create_collection(&s, "posts", &[title_field()])
        .await
        .unwrap();

    // Default: select-only (default_user_caps == {select}).
    let d0 = describe_mcp(&s, "posts").await.unwrap();
    let caps0: Vec<String> = d0["user_caps"]
        .as_array()
        .expect("describe_collection must surface user_caps (Group 1 field wiring)")
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(caps0, vec!["select"]);

    // Open up insert + update; drop select.
    let resp = set_user_caps(&s, "posts", &[DmlVerb::Insert, DmlVerb::Update])
        .await
        .unwrap();
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["collection"], "posts");
    let returned: Vec<String> = resp["user_caps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(returned, vec!["insert", "update"]);

    let d1 = describe_mcp(&s, "posts").await.unwrap();
    let caps1: Vec<String> = d1["user_caps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(caps1, vec!["insert", "update"]);

    // Empty caps lock the user role out completely.
    let resp = set_user_caps(&s, "posts", &[]).await.unwrap();
    assert_eq!(resp["user_caps"].as_array().unwrap().len(), 0);
    let d2 = describe_mcp(&s, "posts").await.unwrap();
    assert!(d2["user_caps"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn set_user_caps_rejects_system_prefix() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    let err = set_user_caps(&s, "_system_files", &[DmlVerb::Select])
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("protected") && msg.contains("_system_"),
        "expected _system_ protection error, got: {msg}"
    );
}

#[tokio::test]
async fn set_user_caps_rejects_unknown_collection() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    let err = set_user_caps(&s, "ghosts", &[DmlVerb::Select])
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("COLLECTION_NOT_FOUND") || msg.contains("unknown collection"),
        "expected unknown-collection rejection, got: {msg}"
    );
}
