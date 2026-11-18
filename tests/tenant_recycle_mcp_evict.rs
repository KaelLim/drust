//! E5 — tenant soft-delete and id-recycle must retire the tenant's MCP state:
//! the `McpRegistry` entry whose `DrustMcp` owns the tenant's
//! `Arc<TenantPool>`.
//!
//! Before E5, soft-delete dropped only an outer service cache, so the old pool kept
//! its SQLite connections open on the file just moved into `_trash`, and a
//! create that recycled the id handed the NEW tenant's MCP that old pool —
//! reading the previous tenant's rows while REST served the new database.
//!
//! Driven at the registry layer for the inner cache, and over the account-level
//! `/mcp` for what a client sees after a soft delete or an id recycle.
//!
//! Every `get_or_create(..)` return value is dropped immediately (`let _ =` or
//! a block): a binding would keep the `DrustMcp`, and with it the pool, alive
//! past the eviction under test.

mod helpers;

use axum::body::to_bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use drust::mgmt::tenants::TenantsState;
use drust::storage::pool::{SharedTenantPool, TenantPool};
use serde_json::{Value, json};
use std::sync::atomic::Ordering::SeqCst;
use std::sync::{Arc, Weak};

// ---------------------------------------------------------------- handlers

async fn soft_delete(state: &TenantsState, admin: i64, id: &str) -> StatusCode {
    drust::mgmt::tenants::soft_delete_tenant(
        State(state.clone()),
        axum::Extension(drust::auth::middleware::AdminId(admin)),
        axum::Extension(drust::mgmt::admin_profile::AdminProfileExt::placeholder()),
        Path(id.to_string()),
    )
    .await
    .status()
}

async fn create(state: &TenantsState, admin: i64, id: &str) -> axum::response::Response {
    drust::mgmt::tenants::create_tenant_json(
        State(state.clone()),
        axum::Extension(drust::auth::middleware::AdminId(admin)),
        axum::Extension(drust::mgmt::admin_profile::AdminProfileExt::placeholder()),
        axum::Json(drust::mgmt::tenants::CreateTenantJson {
            id: Some(id.to_string()),
            name: id.to_string(),
            quota_db_mb: None,
            quota_rows: None,
        }),
    )
    .await
}

// ------------------------------------------------------------------ markers

async fn plant_marker(pool: &SharedTenantPool) {
    pool.with_writer(|c| {
        c.execute_batch("CREATE TABLE e5_marker(x); INSERT INTO e5_marker VALUES (1);")
    })
    .await
    .unwrap();
}

async fn has_marker(pool: &SharedTenantPool) -> bool {
    pool.with_writer(|c| {
        c.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE name = 'e5_marker'",
            [],
            |r| r.get::<_, i64>(0),
        )
    })
    .await
    .unwrap()
        == 1
}

async fn wait_until_dead(weak: &Weak<TenantPool>) -> bool {
    // Session close runs on a background task — yield until it lands. The 5 s
    // bound is a hang guard, not a tuning knob: do not raise it to hide a
    // session task that never ends.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if weak.upgrade().is_none() {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    weak.upgrade().is_none()
}

// ------------------------------------------------- account endpoint client

/// The management state over the harness's own meta, registry, MCP registry
/// and buses: soft delete and create evict exactly what the account endpoint
/// reads from.
fn state_of(h: &helpers::AccountMcpHarness) -> TenantsState {
    TenantsState::test_default(
        h.meta.clone(),
        h.dir.path().to_path_buf(),
        h.tenants.clone(),
        h.mcp.clone(),
        h.bus.clone(),
        h.bus_rooms.clone(),
    )
}

/// The tool result of `list_collections` on the account endpoint.
async fn collections(h: &helpers::AccountMcpHarness) -> Value {
    helpers::mcp_call(&h.app, &h.access, &h.tid, "list_collections", json!({})).await
}

/// The collection names in a successful `list_collections` result.
fn names(m: &Value) -> Vec<String> {
    let text = m["result"]["content"][0]["text"]
        .as_str()
        .expect("tool text");
    let v: Value = serde_json::from_str(text).expect("tool JSON");
    v["collections"]
        .as_array()
        .expect("collections array")
        .iter()
        .map(|c| c["name"].as_str().expect("name").to_string())
        .collect()
}

// -------------------------------------------------------------------- tests

#[tokio::test]
async fn soft_delete_drops_the_inner_mcp_and_releases_the_pool() {
    let (state, inner, _d) = helpers::tenants_state_with_mcp("t1").await;
    let _ = inner.get_or_create("t1").await.unwrap();
    let weak = Arc::downgrade(&state.tenants.get_or_create("t1").unwrap());
    assert_eq!(inner.cached_count(), 1);

    assert_eq!(soft_delete(&state, 1, "t1").await, StatusCode::NO_CONTENT);
    assert_eq!(inner.cached_count(), 0, "inner McpRegistry not evicted");
    assert!(
        weak.upgrade().is_none(),
        "the soft-deleted tenant's pool is still held — its connections stay open on _trash"
    );
}

#[tokio::test]
async fn recycled_id_mcp_reads_the_new_database_not_the_trashed_one() {
    let (state, inner, d) = helpers::tenants_state_with_mcp("t1").await;
    let _ = inner.get_or_create("t1").await.unwrap();
    {
        let old = inner.get_or_create("t1").await.unwrap();
        plant_marker(&old.inner().pool).await;
    }
    assert_eq!(soft_delete(&state, 1, "t1").await, StatusCode::NO_CONTENT);
    assert_eq!(create(&state, 1, "t1").await.status(), StatusCode::CREATED);

    let d1 = inner.get_or_create("t1").await.unwrap();
    let pool = d1.inner().pool.clone();
    assert!(
        Arc::ptr_eq(&pool, &state.tenants.get_or_create("t1").unwrap()),
        "MCP and REST must serve the same database after a recycle"
    );
    assert!(
        !has_marker(&pool).await,
        "the recycled id's MCP sees the previous tenant's data"
    );

    // The previous tenant's data is intact in its _trash recovery copy.
    let trash = d.path().join("_trash");
    let old_dir = std::fs::read_dir(&trash)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("t1-"))
        })
        .expect("soft-delete left a _trash/t1-<ts> copy");
    let c = rusqlite::Connection::open(old_dir.join("data.sqlite")).unwrap();
    let n: i64 = c
        .query_row("SELECT COUNT(*) FROM e5_marker", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 1, "the trashed copy must keep the old tenant's rows");
}

#[tokio::test]
async fn account_endpoint_releases_the_pool_after_soft_delete() {
    let h = helpers::spin_up_account_mcp("t1").await;
    let state = state_of(&h);
    let first = collections(&h).await;
    assert_ne!(first["result"]["isError"], json!(true), "{first}");
    let weak = Arc::downgrade(&h.tenants.get_if_live("t1").expect("live pool"));
    assert_eq!(
        soft_delete(&state, h.admin_id, "t1").await,
        StatusCode::NO_CONTENT
    );
    assert!(
        wait_until_dead(&weak).await,
        "the soft-deleted tenant's pool is still held"
    );
    let after = collections(&h).await;
    assert_eq!(
        after["result"]["isError"],
        json!(true),
        "a deleted tenant must not be served: {after}"
    );
}

#[tokio::test]
async fn account_endpoint_reads_the_new_database_after_recycle() {
    let h = helpers::spin_up_account_mcp("t1").await;
    let state = state_of(&h);
    helpers::create_collection_via_pool(
        &h.tenants.get_if_live("t1").unwrap(),
        "e5_old",
        &[("x", "text")],
    )
    .await;
    let before = collections(&h).await;
    assert!(
        names(&before).iter().any(|n| n == "e5_old"),
        "fixture: the old collection must be visible first: {before}"
    );
    assert_eq!(
        soft_delete(&state, h.admin_id, "t1").await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        create(&state, h.admin_id, "t1").await.status(),
        StatusCode::CREATED
    );
    let after = collections(&h).await;
    assert_ne!(after["result"]["isError"], json!(true), "{after}");
    assert!(
        !names(&after).iter().any(|n| n == "e5_old"),
        "the recycled id must read the NEW database: {after}"
    );
}

#[tokio::test]
async fn recycle_sweeps_state_that_reappeared_after_soft_delete() {
    let (state, inner, _d) = helpers::tenants_state_with_mcp("t1").await;
    assert_eq!(soft_delete(&state, 1, "t1").await, StatusCode::NO_CONTENT);

    // A request that raced the soft-delete re-opens a pool (rebuilding
    // `tenants/t1`) and populates MCP after the eviction ran.
    let r = state.tenants.get_or_create("t1").unwrap();
    let _ = inner.get_or_create("t1").await.unwrap();
    plant_marker(&r).await;
    drop(r);

    // A live neighbour on both layers (fresh id: its create evicts nothing).
    assert_eq!(create(&state, 1, "t2").await.status(), StatusCode::CREATED);
    let _ = inner.get_or_create("t2").await.unwrap();
    let t2_before = inner.get_or_create("t2").await.unwrap().inner();

    // 1 from the soft-delete above; the recycle must add exactly one more.
    let h1 = state.bus_rooms.tenant_epoch_handle("t1");
    let e0 = h1.load(SeqCst);

    assert_eq!(create(&state, 1, "t1").await.status(), StatusCode::CREATED);

    assert_eq!(
        inner.cached_count(),
        1,
        "only t2 may remain in the inner registry"
    );
    let d1 = inner.get_or_create("t1").await.unwrap();
    let pool = d1.inner().pool.clone();
    let rest = state.tenants.get_or_create("t1").unwrap();
    assert!(
        Arc::ptr_eq(&pool, &rest),
        "MCP and REST must share one pool"
    );
    assert!(
        !has_marker(&pool).await,
        "MCP still serves the racing request's stale pool"
    );
    assert!(
        !has_marker(&rest).await,
        "REST still serves the racing request's stale pool"
    );
    assert_eq!(
        h1.load(SeqCst),
        e0 + 1,
        "the recycle did not run the full eviction"
    );
    let t2_after = inner.get_or_create("t2").await.unwrap().inner();
    assert!(
        Arc::ptr_eq(&t2_before, &t2_after),
        "the recycle evicted another tenant"
    );
}

#[tokio::test]
async fn create_on_a_live_id_evicts_nothing() {
    let (state, inner, _d) = helpers::tenants_state_with_mcp("t1").await;
    let _ = inner.get_or_create("t1").await.unwrap();
    let before = inner.get_or_create("t1").await.unwrap().inner();
    let h = state.bus_rooms.tenant_epoch_handle("t1");
    let e0 = h.load(SeqCst);
    let _rx = state.bus.subscribe("t1", "items");

    let resp = create(&state, 1, "t1").await;
    assert!(
        !resp.status().is_success(),
        "a create on a live id must be refused, got {}",
        resp.status()
    );
    assert_eq!(inner.cached_count(), 1);
    let after = inner.get_or_create("t1").await.unwrap().inner();
    assert!(
        Arc::ptr_eq(&before, &after),
        "a refused create evicted the live MCP"
    );
    assert_eq!(
        h.load(SeqCst),
        e0,
        "a refused create bumped the live tenant's epoch"
    );
    assert_eq!(
        state.bus.channel_count(),
        1,
        "a refused create dropped SSE channels"
    );
}

#[tokio::test]
async fn fresh_create_does_not_evict() {
    let (state, _inner, _d) = helpers::tenants_state_with_mcp("t1").await;
    let h = state.bus_rooms.tenant_epoch_handle("fresh");

    let resp = create(&state, 1, "fresh").await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    assert_eq!(
        h.load(SeqCst),
        0,
        "a fresh create must not run the eviction sequence"
    );
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort();
    assert_eq!(keys, ["initial_token", "initial_tokens", "tenant"]);
}
