//! Integration: MCP set_realtime tool round-trip.

use drust::mcp::server::{DrustMcp, McpRegistry};
use drust::storage::pool::TenantRegistry;
use std::sync::Arc;

async fn svc(dir: &tempfile::TempDir, tenant: &str) -> DrustMcp {
    let data = dir.path().to_path_buf();
    let tr = Arc::new(TenantRegistry::new(data.clone(), 2));
    let _ = drust::storage::tenant_db::open_write(&data, tenant).unwrap();
    let reg = McpRegistry::new(tr);
    reg.get_or_create(tenant).await.unwrap()
}

#[tokio::test]
async fn mcp_set_realtime_round_trip() {
    let d = tempfile::tempdir().unwrap();
    let mcp = svc(&d, "mcprt").await;
    // Create a regular user collection via the MCP create_collection path so
    // the meta row exists too.
    drust::mcp::tools::schema::create_collection(
        &mcp,
        "posts",
        &[drust::mcp::tools::schema::FieldSpec {
            name: "title".into(),
            sql_type: "text".into(),
            nullable: false,
            unique: false,
            default_value: None,
            foreign_key: None,
            dim: None,
        }],
    )
    .await
    .unwrap();

    // create_collection seeds realtime_enabled = 0 (opt-in posture, Task 3).
    // Flip it on via the new MCP tool.
    let v = drust::mcp::tools::realtime::set_realtime(&mcp, "posts", true)
        .await
        .unwrap();
    assert_eq!(v["realtime_enabled"], true);
    assert_eq!(v["ok"], true);

    // Verify the meta row landed.
    let pool = mcp.inner().pool.clone();
    let n: i64 = pool
        .with_reader(|c| {
            c.query_row(
                "SELECT realtime_enabled FROM _system_collection_meta WHERE collection_name='posts'",
                [],
                |r| r.get(0),
            )
        })
        .await
        .unwrap();
    assert_eq!(n, 1);

    // Flip back off — still works.
    let v = drust::mcp::tools::realtime::set_realtime(&mcp, "posts", false)
        .await
        .unwrap();
    assert_eq!(v["realtime_enabled"], false);
}

#[tokio::test]
async fn mcp_set_realtime_rejects_system_collection() {
    let d = tempfile::tempdir().unwrap();
    let mcp = svc(&d, "mcprt-sys").await;
    let err = drust::mcp::tools::realtime::set_realtime(&mcp, "_system_users", true)
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("system collection") || msg.contains("_system_"),
        "expected protected-collection error, got: {msg}"
    );
}

#[tokio::test]
async fn mcp_set_realtime_unknown_collection_errors() {
    let d = tempfile::tempdir().unwrap();
    let mcp = svc(&d, "mcprt-ghost").await;
    let err = drust::mcp::tools::realtime::set_realtime(&mcp, "ghost", true)
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("unknown collection") || msg.contains("no such"),
        "expected unknown-collection error, got: {msg}"
    );
}
