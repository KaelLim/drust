//! Integration tests for v1.16 per-collection SSE realtime toggle.
//! Additional tests for the SSE gate and PUT endpoint added in
//! later tasks.

use drust::mcp::server::McpRegistry;
use drust::mcp::tools::schema::{FieldSpec, create_collection};
use drust::storage::pool::TenantRegistry;
use std::sync::Arc;

async fn svc(dir: &tempfile::TempDir, tenant: &str) -> drust::mcp::server::DrustMcp {
    let data = dir.path().to_path_buf();
    let tr = Arc::new(TenantRegistry::new(data.clone(), 2));
    let _ = drust::storage::tenant_db::open_write(&data, tenant).unwrap();
    let reg = McpRegistry::new(tr);
    reg.get_or_create(tenant).await.unwrap()
}

#[tokio::test]
async fn create_collection_defaults_realtime_enabled_to_zero() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d, "rt").await;
    create_collection(
        &s,
        "events",
        &[FieldSpec {
            name: "label".into(),
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

    // Read the meta row directly through the pool. McpRegistry has a
    // tenant pool — reach it via the same path the production handler
    // uses (s.inner().pool).
    let pool = s.inner().pool.clone();
    let v: i64 = pool
        .with_reader(|c| {
            c.query_row(
                "SELECT realtime_enabled FROM _system_collection_meta WHERE collection_name='events'",
                [],
                |r| r.get(0),
            )
        })
        .await
        .unwrap();
    assert_eq!(
        v, 0,
        "new collections should be opt-in (realtime_enabled=0)"
    );
}
