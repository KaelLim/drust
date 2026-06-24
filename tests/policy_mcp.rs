//! Integration: MCP set_policy / get_policies / clear_policy delegates.
//! Drives the delegate fns directly (same pattern as mcp_realtime_tool.rs),
//! plus get_schema_overview enrichment that surfaces effective policies.

use drust::mcp::server::{DrustMcp, McpRegistry};
use drust::mcp::tools::schema::FieldSpec;
use drust::storage::pool::TenantRegistry;
use serde_json::json;
use std::sync::Arc;

async fn svc(dir: &tempfile::TempDir, tenant: &str) -> DrustMcp {
    let data = dir.path().to_path_buf();
    let tr = Arc::new(TenantRegistry::new(data.clone(), 2));
    let _ = drust::storage::tenant_db::open_write(&data, tenant).unwrap();
    let reg = McpRegistry::new(tr);
    reg.get_or_create(tenant).await.unwrap()
}

fn field(name: &str, ty: &str) -> FieldSpec {
    FieldSpec {
        name: name.into(),
        sql_type: ty.into(),
        nullable: true,
        unique: false,
        default_value: None,
        foreign_key: None,
        dim: None,
        description: None,
        ..Default::default()
    }
}

async fn make_posts(mcp: &DrustMcp) {
    drust::mcp::tools::schema::create_collection(
        mcp,
        "posts",
        &[field("title", "text"), field("owner", "text")],
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn mcp_set_get_policy_round_trip() {
    let d = tempfile::tempdir().unwrap();
    let mcp = svc(&d, "mcppol").await;
    make_posts(&mcp).await;

    // Set a select policy: USING owner == $auth.id
    let using = json!({ "owner": { "$auth": "id" } });
    let v =
        drust::mcp::tools::policy::set_policy(&mcp, "posts", "select", Some(using.clone()), None)
            .await
            .unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["collection"], "posts");
    assert_eq!(v["op"], "select");

    // get_policies round-trips the stored select.using.
    let got = drust::mcp::tools::policy::get_policies(&mcp, "posts")
        .await
        .unwrap();
    assert_eq!(got["stored"]["select"]["using"], using);
    // Unset ops are absent (skip_serializing_if).
    assert!(got["stored"].get("insert").is_none());
}

#[tokio::test]
async fn mcp_set_policy_bad_field_errors() {
    let d = tempfile::tempdir().unwrap();
    let mcp = svc(&d, "mcppol-bad").await;
    make_posts(&mcp).await;

    // USING references a column that does not exist on the collection.
    let using = json!({ "nonexistent": { "$auth": "id" } });
    let err = drust::mcp::tools::policy::set_policy(&mcp, "posts", "select", Some(using), None)
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("nonexistent") || msg.to_lowercase().contains("unknown field"),
        "expected unknown-field validation error, got: {msg}"
    );

    // And nothing was persisted (the write must not land on a validation failure).
    let got = drust::mcp::tools::policy::get_policies(&mcp, "posts")
        .await
        .unwrap();
    assert!(got["stored"].get("select").is_none());
}

#[tokio::test]
async fn mcp_clear_policy() {
    let d = tempfile::tempdir().unwrap();
    let mcp = svc(&d, "mcppol-clear").await;
    make_posts(&mcp).await;

    let using = json!({ "owner": { "$auth": "id" } });
    drust::mcp::tools::policy::set_policy(&mcp, "posts", "update", Some(using), None)
        .await
        .unwrap();
    // Present before clear.
    let got = drust::mcp::tools::policy::get_policies(&mcp, "posts")
        .await
        .unwrap();
    assert!(got["stored"].get("update").is_some());

    // Clear it.
    let v = drust::mcp::tools::policy::clear_policy(&mcp, "posts", "update")
        .await
        .unwrap();
    assert_eq!(v["ok"], true);

    let got = drust::mcp::tools::policy::get_policies(&mcp, "posts")
        .await
        .unwrap();
    assert!(got["stored"].get("update").is_none());
}

#[tokio::test]
async fn mcp_set_policy_rejects_system_collection() {
    let d = tempfile::tempdir().unwrap();
    let mcp = svc(&d, "mcppol-sys").await;
    let using = json!({ "id": 1 });
    let err =
        drust::mcp::tools::policy::set_policy(&mcp, "_system_users", "select", Some(using), None)
            .await
            .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("system collection") || msg.contains("_system_"),
        "expected protected-collection error, got: {msg}"
    );
}

#[tokio::test]
async fn mcp_set_policy_unknown_collection_errors() {
    let d = tempfile::tempdir().unwrap();
    let mcp = svc(&d, "mcppol-ghost").await;
    let using = json!({ "id": 1 });
    let err = drust::mcp::tools::policy::set_policy(&mcp, "ghost", "select", Some(using), None)
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("unknown collection") || msg.contains("no such"),
        "expected unknown-collection error, got: {msg}"
    );
}

#[tokio::test]
async fn mcp_set_policy_bad_op_errors() {
    let d = tempfile::tempdir().unwrap();
    let mcp = svc(&d, "mcppol-badop").await;
    make_posts(&mcp).await;
    let using = json!({ "owner": { "$auth": "id" } });
    let err = drust::mcp::tools::policy::set_policy(&mcp, "posts", "upsert", Some(using), None)
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.to_lowercase().contains("op") || msg.contains("select|insert|update|delete"),
        "expected bad-op error, got: {msg}"
    );
}

#[tokio::test]
async fn overview_surfaces_effective_policies() {
    let d = tempfile::tempdir().unwrap();
    let mcp = svc(&d, "mcppol-ov").await;
    make_posts(&mcp).await;
    // A second collection with NO policy — overview must still surface a
    // (empty) `policies` key so the model can tell "no policy" from "omitted".
    drust::mcp::tools::schema::create_collection(&mcp, "tags", &[field("name", "text")])
        .await
        .unwrap();
    let using = json!({ "owner": { "$auth": "id" } });
    drust::mcp::tools::policy::set_policy(&mcp, "posts", "select", Some(using.clone()), None)
        .await
        .unwrap();

    let ov = drust::mcp::tools::exploration::get_schema_overview(&mcp)
        .await
        .unwrap();
    let find = |name: &str| {
        ov["collections"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == name)
            .cloned()
            .unwrap_or_else(|| panic!("{name} in overview"))
    };
    let posts = find("posts");
    // policies must ALWAYS be present (so the model can tell "no policy" from
    // "key omitted"), and the select.using must round-trip.
    assert!(
        posts.get("policies").is_some(),
        "policies key must be present"
    );
    assert_eq!(posts["policies"]["select"]["using"], using);

    // The no-policy collection still carries an (empty) policies object.
    let tags = find("tags");
    assert_eq!(
        tags["policies"],
        json!({}),
        "no-policy collection -> empty policies object"
    );
}
