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
use drust::tenant::events::Event;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast::error::RecvError;

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

// ── E4 (S-44) — drop_collection must evict too ──────────────────────────────
//
// A dropped collection's in-flight subscribers captured their gate against the
// OLD table, and `publish` never re-checks it — so without an evict, a
// same-name recreate would stream the NEW table's rows to them (even though a
// fresh connect is refused: `create_collection` starts realtime OFF).

fn plain_text_field(name: &str) -> FieldSpec {
    FieldSpec {
        name: name.into(),
        sql_type: "text".into(),
        nullable: false,
        ..Default::default()
    }
}

#[tokio::test]
async fn drop_collection_evicts_in_flight_subscriber() {
    let d = tempfile::tempdir().unwrap();
    let mcp = svc(&d, "e4-drop").await;
    seed_posts(&mcp).await;

    let tenant = mcp.inner().tenant_id.clone();
    let mut rx = mcp.inner().bus.subscribe(&tenant, "posts");

    drust::mcp::tools::schema::drop_collection(&mcp, "posts")
        .await
        .unwrap();

    // Bounded: before the fix the channel was never removed, so recv parks
    // forever instead of failing.
    let got = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await;
    assert!(
        matches!(got, Ok(Err(RecvError::Closed))),
        "drop_collection must evict the in-flight SSE subscriber (E4), got {got:?}"
    );
}

#[tokio::test]
async fn drop_collection_evicts_only_its_own_channel() {
    let d = tempfile::tempdir().unwrap();
    let mcp = svc(&d, "e4-drop-own").await;
    seed_posts(&mcp).await;
    drust::mcp::tools::schema::create_collection(&mcp, "notes", &[plain_text_field("title")])
        .await
        .unwrap();

    let tenant = mcp.inner().tenant_id.clone();
    let mut rx_posts = mcp.inner().bus.subscribe(&tenant, "posts");
    let mut rx_notes = mcp.inner().bus.subscribe(&tenant, "notes");

    drust::mcp::tools::schema::drop_collection(&mcp, "posts")
        .await
        .unwrap();

    mcp.inner()
        .bus
        .publish(&tenant, "notes", Event::Deleted { id: 7 });
    let notes = tokio::time::timeout(Duration::from_secs(2), rx_notes.recv()).await;
    assert!(
        matches!(notes, Ok(Ok(Event::Deleted { id: 7 }))),
        "a sibling collection's subscriber must survive the drop, got {notes:?}"
    );
    let posts = tokio::time::timeout(Duration::from_secs(2), rx_posts.recv()).await;
    assert!(
        matches!(posts, Ok(Err(RecvError::Closed))),
        "the dropped collection's subscriber must be evicted, got {posts:?}"
    );
}

#[tokio::test]
async fn failed_drop_collection_does_not_evict() {
    // Pins only "a refused pre-check keeps the stream": the FK refusal happens on
    // the reader, before the write tx. "Evict only after the commit" is guarded
    // by the structural pin in src/mcp/tools/schema.rs (drop_collection_order_pin).
    let d = tempfile::tempdir().unwrap();
    let mcp = svc(&d, "e4-drop-fk").await;
    drust::mcp::tools::schema::create_collection(&mcp, "authors", &[plain_text_field("name")])
        .await
        .unwrap();
    drust::mcp::tools::schema::create_collection(
        &mcp,
        "posts",
        &[FieldSpec {
            name: "author_id".into(),
            sql_type: "integer".into(),
            nullable: false,
            foreign_key: Some("authors".into()),
            ..Default::default()
        }],
    )
    .await
    .unwrap();

    let tenant = mcp.inner().tenant_id.clone();
    let mut rx = mcp.inner().bus.subscribe(&tenant, "authors");

    let err = drust::mcp::tools::schema::drop_collection(&mcp, "authors")
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("foreign-key references"),
        "expected the FK refusal, got: {err}"
    );

    mcp.inner()
        .bus
        .publish(&tenant, "authors", Event::Deleted { id: 1 });
    let got = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await;
    assert!(
        matches!(got, Ok(Ok(Event::Deleted { id: 1 }))),
        "a refused drop must not evict, got {got:?}"
    );
}
