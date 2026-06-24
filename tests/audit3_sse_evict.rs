//! audit3 (2026-06-23) F3 — revoking anon read access (anon_caps or a tightened
//! select policy) must drop in-flight anon SSE subscribers, not just invalidate
//! the schema cache for the next connect.
//!
//! The subscribe handler captures anon_caps + the select-policy ONCE at connect
//! and never re-reads them, so without an explicit `evict_collection` an already
//! connected anon kept receiving Created/Updated/Deleted events for the full
//! connection lifetime after the admin revoked its read access. These tests
//! subscribe directly to the bus (standing in for an in-flight SSE subscriber)
//! and assert the channel is closed once the caps/policy write path runs.

use drust::mcp::server::{DrustMcp, McpRegistry};
use drust::mcp::tools::schema::FieldSpec;
use drust::storage::pool::TenantRegistry;
use std::sync::Arc;

async fn svc(dir: &tempfile::TempDir, tenant: &str) -> DrustMcp {
    let data = dir.path().to_path_buf();
    let tr = Arc::new(TenantRegistry::new(data.clone(), 2));
    let _ = drust::storage::tenant_db::open_write(&data, tenant).unwrap();
    let reg = McpRegistry::new(tr);
    reg.get_or_create(tenant).await.unwrap()
}

async fn seed_posts(mcp: &DrustMcp) {
    drust::mcp::tools::schema::create_collection(
        mcp,
        "posts",
        &[FieldSpec {
            name: "title".into(),
            sql_type: "text".into(),
            nullable: false,
            unique: false,
            default_value: None,
            foreign_key: None,
            dim: None,
            description: None,
            ..Default::default()
        }],
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn set_anon_caps_evicts_in_flight_subscriber() {
    let d = tempfile::tempdir().unwrap();
    let mcp = svc(&d, "a3f3-caps").await;
    seed_posts(&mcp).await;

    let tenant = mcp.inner().tenant_id.clone();
    let mut rx = mcp.inner().bus.subscribe(&tenant, "posts");

    // Revoke anon read access entirely.
    drust::mcp::tools::schema::set_anon_caps(&mcp, "posts", &[])
        .await
        .unwrap();

    // The broadcast channel must have been evicted → recv returns Closed.
    assert!(
        rx.recv().await.is_err(),
        "revoking anon_caps must evict the in-flight SSE subscriber (audit3 F3)"
    );
}

#[tokio::test]
async fn set_policy_evicts_in_flight_subscriber() {
    let d = tempfile::tempdir().unwrap();
    let mcp = svc(&d, "a3f3-policy").await;
    seed_posts(&mcp).await;

    let tenant = mcp.inner().tenant_id.clone();
    let mut rx = mcp.inner().bus.subscribe(&tenant, "posts");

    // Attach a restrictive select policy (references the real `title` column).
    drust::mcp::tools::policy::set_policy(
        &mcp,
        "posts",
        "select",
        Some(serde_json::json!({"title": "published"})),
        None,
    )
    .await
    .unwrap();

    assert!(
        rx.recv().await.is_err(),
        "tightening a select policy must evict the in-flight SSE subscriber (audit3 F3)"
    );
}

#[tokio::test]
async fn clear_policy_also_evicts_in_flight_subscriber() {
    // Clearing a policy loosens access; eviction is for freshness/consistency
    // (the subscriber re-gates on reconnect). Asserts the clear path also evicts.
    let d = tempfile::tempdir().unwrap();
    let mcp = svc(&d, "a3f3-clear").await;
    seed_posts(&mcp).await;
    drust::mcp::tools::policy::set_policy(
        &mcp,
        "posts",
        "select",
        Some(serde_json::json!({"title": "published"})),
        None,
    )
    .await
    .unwrap();

    let tenant = mcp.inner().tenant_id.clone();
    let mut rx = mcp.inner().bus.subscribe(&tenant, "posts");
    drust::mcp::tools::policy::clear_policy(&mcp, "posts", "select")
        .await
        .unwrap();
    assert!(
        rx.recv().await.is_err(),
        "clearing a policy must also evict the in-flight SSE subscriber (audit3 F3)"
    );
}

#[tokio::test]
async fn set_owner_field_evicts_in_flight_subscriber() {
    // Making a collection owner-scoped RESTRICTS anon read (anon can no longer
    // subscribe), so an anon connected beforehand must be evicted (audit3 F3 —
    // the parallel site the first pass missed).
    let d = tempfile::tempdir().unwrap();
    let mcp = svc(&d, "a3f3-owner").await;
    let inner = mcp.inner();
    // posts with a user_id FK to _system_users (owner_field requires the FK).
    inner
        .pool
        .with_writer(|c| {
            c.execute_batch(
                "PRAGMA foreign_keys = ON;
                 CREATE TABLE posts (
                     id      INTEGER PRIMARY KEY AUTOINCREMENT,
                     user_id TEXT REFERENCES _system_users(id),
                     title   TEXT
                 );",
            )
        })
        .await
        .unwrap();

    let tenant = inner.tenant_id.clone();
    let mut rx = inner.bus.subscribe(&tenant, "posts");

    drust::mcp::tools::owner_field::set_owner_field(
        &inner.pool,
        "posts".to_string(),
        Some("user_id".to_string()),
        "own".to_string(),
        &inner.bus,
        &tenant,
    )
    .await
    .unwrap();

    assert!(
        rx.recv().await.is_err(),
        "owner-scoping a collection must evict the in-flight anon SSE subscriber (audit3 F3)"
    );
}
