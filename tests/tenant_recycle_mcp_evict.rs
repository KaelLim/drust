//! E5 — tenant soft-delete and id-recycle must retire the per-tenant MCP state
//! as a whole: the outer rmcp service, the inner `McpRegistry` entry whose
//! `DrustMcp` owns the tenant's `Arc<TenantPool>`, and every live rmcp session
//! (each session task holds its own `DrustMcpService` → `DrustMcp` → pool).
//!
//! Before E5, soft-delete dropped only the outer service, so the old pool kept
//! its SQLite connections open on the file just moved into `_trash`, and a
//! create that recycled the id handed the NEW tenant's MCP that old pool —
//! reading the previous tenant's rows while REST served the new database.
//!
//! Driven at the registry / handler layer (`state.mcp.get_or_create` returns
//! the same rmcp service `mcp_dispatch` forwards to verbatim), never through
//! the `/t/<id>/mcp` route, so the bearer layer and role gate are out of scope
//! here — `tests/mcp_protocol.rs` covers those.
//!
//! Every `get_or_create(..)` return value is dropped immediately (`let _ =` or
//! a block): the outer service's factory closure captures the `DrustMcp`, so a
//! binding would keep the pool alive past the eviction under test.

mod helpers;

use axum::body::{Body, to_bytes};
use axum::extract::{Path, State};
use axum::http::{Method, Request, StatusCode, header};
use axum::response::IntoResponse;
use drust::mgmt::tenants::TenantsState;
use drust::storage::pool::{SharedTenantPool, TenantPool};
use serde_json::{Value, json};
use std::sync::atomic::Ordering::SeqCst;
use std::sync::{Arc, Weak};
use tower::ServiceExt;

// ---------------------------------------------------------------- handlers

async fn soft_delete(state: &TenantsState, id: &str) -> StatusCode {
    drust::mgmt::tenants::soft_delete_tenant(
        State(state.clone()),
        axum::Extension(drust::auth::middleware::AdminId(1)),
        axum::Extension(drust::mgmt::admin_profile::AdminProfileExt::placeholder()),
        Path(id.to_string()),
    )
    .await
    .status()
}

async fn create(state: &TenantsState, id: &str) -> axum::response::Response {
    drust::mgmt::tenants::create_tenant_json(
        State(state.clone()),
        axum::Extension(drust::auth::middleware::AdminId(1)),
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

// ------------------------------------------------------- mini MCP client

fn mcp_post(tenant: &str, session: Option<&str>, body: Value) -> Request<Body> {
    let mut b = Request::builder()
        .method(Method::POST)
        .uri(format!("/t/{tenant}/mcp"))
        .header(header::HOST, "127.0.0.1")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream");
    if let Some(sid) = session {
        b = b.header("mcp-session-id", sid);
    }
    b.body(Body::from(body.to_string())).unwrap()
}

async fn parse_mcp_body(resp: axum::response::Response) -> Vec<Value> {
    let ct = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    if ct.starts_with("text/event-stream") {
        let mut out = Vec::new();
        for frame in text.split("\n\n") {
            for line in frame.lines() {
                if let Some(data) = line.strip_prefix("data:") {
                    let trimmed = data.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    out.push(
                        serde_json::from_str(trimmed)
                            .unwrap_or_else(|e| panic!("bad SSE JSON {trimmed:?}: {e}")),
                    );
                }
            }
        }
        out
    } else {
        vec![serde_json::from_str(&text).unwrap_or_else(|e| panic!("bad JSON {text:?}: {e}"))]
    }
}

/// Forward one request exactly as `mcp_dispatch` does (`(*svc).clone().oneshot`),
/// dropping the service handle before returning.
async fn send(state: &TenantsState, tenant: &str, req: Request<Body>) -> axum::response::Response {
    let svc = state.mcp.get_or_create(tenant).await.unwrap();
    let owned = (*svc).clone();
    drop(svc);
    owned.oneshot(req).await.unwrap().into_response()
}

async fn open_session(state: &TenantsState, tenant: &str) -> String {
    let init = mcp_post(
        tenant,
        None,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "e5", "version": "0"}
            }
        }),
    );
    let resp = send(state, tenant, init).await;
    assert_eq!(resp.status(), StatusCode::OK, "initialize failed");
    let sid = resp
        .headers()
        .get("mcp-session-id")
        .expect("initialize must return mcp-session-id")
        .to_str()
        .unwrap()
        .to_string();
    let _ = parse_mcp_body(resp).await;
    let ack = mcp_post(
        tenant,
        Some(&sid),
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    );
    let _ = send(state, tenant, ack).await;
    sid
}

async fn call_list_collections(
    state: &TenantsState,
    tenant: &str,
    sid: &str,
) -> (StatusCode, Vec<String>) {
    let call = mcp_post(
        tenant,
        Some(sid),
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": { "name": "list_collections", "arguments": {} }
        }),
    );
    let resp = send(state, tenant, call).await;
    let status = resp.status();
    if status != StatusCode::OK {
        return (status, Vec::new());
    }
    let msgs = parse_mcp_body(resp).await;
    let content = msgs
        .iter()
        .find_map(|m| m["result"]["content"].as_array().cloned())
        .unwrap_or_else(|| panic!("tools/call must return a content array: {msgs:?}"));
    let text = content[0]["text"].as_str().expect("text content");
    let parsed: Value = serde_json::from_str(text).unwrap();
    let names = parsed["collections"]
        .as_array()
        .unwrap_or_else(|| panic!("no collections array: {parsed:?}"))
        .iter()
        .filter_map(|c| c["name"].as_str().map(str::to_string))
        .collect();
    (status, names)
}

// -------------------------------------------------------------------- tests

#[tokio::test]
async fn soft_delete_drops_the_inner_mcp_and_releases_the_pool() {
    let (state, inner, _d) = helpers::tenants_state_with_mcp("t1").await;
    let _ = state.mcp.get_or_create("t1").await.unwrap();
    let weak = Arc::downgrade(&state.tenants.get_or_create("t1").unwrap());
    assert_eq!(inner.cached_count(), 1);

    assert_eq!(soft_delete(&state, "t1").await, StatusCode::NO_CONTENT);
    assert_eq!(state.mcp.cached_count(), 0, "outer MCP service not evicted");
    assert_eq!(inner.cached_count(), 0, "inner McpRegistry not evicted");
    assert!(
        weak.upgrade().is_none(),
        "the soft-deleted tenant's pool is still held — its connections stay open on _trash"
    );
}

#[tokio::test]
async fn soft_delete_closes_live_mcp_sessions_and_releases_the_pool() {
    let (state, _inner, _d) = helpers::tenants_state_with_mcp("t1").await;
    assert_eq!(create(&state, "t2").await.status(), StatusCode::CREATED);
    let weak = Arc::downgrade(&state.tenants.get_or_create("t1").unwrap());
    let _s1 = open_session(&state, "t1").await;
    let s2 = open_session(&state, "t2").await;

    assert_eq!(soft_delete(&state, "t1").await, StatusCode::NO_CONTENT);
    assert!(
        wait_until_dead(&weak).await,
        "a live MCP session on the soft-deleted tenant still holds its pool (rmcp's 24 h \
         keep-alive would keep it open)"
    );
    let (status, _) = call_list_collections(&state, "t2", &s2).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "another tenant's live session must survive"
    );
}

#[tokio::test]
async fn recycled_id_mcp_reads_the_new_database_not_the_trashed_one() {
    let (state, inner, d) = helpers::tenants_state_with_mcp("t1").await;
    let _ = state.mcp.get_or_create("t1").await.unwrap();
    {
        let old = inner.get_or_create("t1").await.unwrap();
        plant_marker(&old.inner().pool).await;
    }
    assert_eq!(soft_delete(&state, "t1").await, StatusCode::NO_CONTENT);
    assert_eq!(create(&state, "t1").await.status(), StatusCode::CREATED);

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
async fn recycled_id_mcp_session_lists_only_the_new_database() {
    let (state, _inner, _d) = helpers::tenants_state_with_mcp("t1").await;
    helpers::create_collection_via_pool(
        &state.tenants.get_or_create("t1").unwrap(),
        "e5_old",
        &[("x", "text")],
    )
    .await;
    let s0 = open_session(&state, "t1").await;
    let (status, names) = call_list_collections(&state, "t1", &s0).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        names.iter().any(|n| n == "e5_old"),
        "mini client sanity: expected e5_old, got {names:?}"
    );

    assert_eq!(soft_delete(&state, "t1").await, StatusCode::NO_CONTENT);
    assert_eq!(create(&state, "t1").await.status(), StatusCode::CREATED);

    let s1 = open_session(&state, "t1").await;
    let (status, names) = call_list_collections(&state, "t1", &s1).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !names.iter().any(|n| n == "e5_old"),
        "the recycled id's MCP session lists the previous tenant's collection: {names:?}"
    );
}

#[tokio::test]
async fn recycle_sweeps_state_that_reappeared_after_soft_delete() {
    let (state, inner, _d) = helpers::tenants_state_with_mcp("t1").await;
    assert_eq!(soft_delete(&state, "t1").await, StatusCode::NO_CONTENT);

    // A request that raced the soft-delete re-opens a pool (rebuilding
    // `tenants/t1`) and populates MCP after the eviction ran.
    let r = state.tenants.get_or_create("t1").unwrap();
    let _ = state.mcp.get_or_create("t1").await.unwrap();
    plant_marker(&r).await;
    drop(r);

    // A live neighbour on both layers (fresh id: its create evicts nothing).
    assert_eq!(create(&state, "t2").await.status(), StatusCode::CREATED);
    let _ = state.mcp.get_or_create("t2").await.unwrap();
    let t2_before = inner.get_or_create("t2").await.unwrap().inner();

    // 1 from the soft-delete above; the recycle must add exactly one more.
    let h1 = state.bus_rooms.tenant_epoch_handle("t1");
    let e0 = h1.load(SeqCst);

    assert_eq!(create(&state, "t1").await.status(), StatusCode::CREATED);

    assert_eq!(
        inner.cached_count(),
        1,
        "only t2 may remain in the inner registry"
    );
    assert_eq!(
        state.mcp.cached_count(),
        1,
        "only t2 may remain in the outer registry"
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
    let _ = state.mcp.get_or_create("t1").await.unwrap();
    let before = inner.get_or_create("t1").await.unwrap().inner();
    let h = state.bus_rooms.tenant_epoch_handle("t1");
    let e0 = h.load(SeqCst);
    let _rx = state.bus.subscribe("t1", "items");

    let resp = create(&state, "t1").await;
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

    let resp = create(&state, "fresh").await;
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
