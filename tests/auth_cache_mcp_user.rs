// tests/auth_cache_mcp_user.rs — hooks 7-MCP / 8-MCP.
//
// Seam (per plan Task 12, "choose the lighter seam"): the cache is threaded
// into MCP state (`DrustMcpInner.auth_cache`, `McpRegistry` ctors) and the
// tool fns `delete_user` / `revoke_user_sessions` take `Option<&AuthCache>`
// and invalidate inside the fn — so the invalidation logic is exercised
// directly here, and `with_bus_and_storage_threads_cache_into_inner` locks
// the registry → `DrustMcpInner` wiring (a regression to `None` would
// silently stop all MCP invalidations).
mod helpers;

use drust::storage::pool::TenantRegistry;
use drust::tenant::auth_cache::{AuthCache, CachedAuth};
use std::sync::Arc;
use std::time::Duration;

fn user_entry(tenant: &str, uid: &str) -> CachedAuth {
    CachedAuth::User {
        tenant_id: tenant.to_string(),
        user_id: uid.to_string(),
        expires_at: chrono::Utc::now() + chrono::Duration::days(1),
        publish_user_allowed: false,
        publish_anon_allowed: false,
        file_caps: Default::default(),
    }
}

#[tokio::test]
async fn mcp_delete_user_clears_cached_entries() {
    let (pool, _dir, uid) = helpers::seed_user_for_mcp("t1").await;
    let cache = Arc::new(AuthCache::new(Duration::from_secs(10), 200_000));
    cache.insert("h".to_string(), user_entry("t1", &uid));
    // A different user's entry must survive the per-user clear.
    cache.insert("other".to_string(), user_entry("t1", "u-other"));

    let _ = drust::mcp::tools::user::delete_user(&pool, uid.clone(), Some(&*cache))
        .await
        .unwrap();
    assert_eq!(
        cache.len(),
        1,
        "MCP delete_user cleared the cached User entry, sparing u-other"
    );
    assert!(cache.get("other").is_some());
}

#[tokio::test]
async fn mcp_revoke_user_sessions_clears_cached_entries() {
    let (pool, _dir, uid) = helpers::seed_user_for_mcp("t1").await;
    let cache = Arc::new(AuthCache::new(Duration::from_secs(10), 200_000));
    cache.insert("s1".to_string(), user_entry("t1", &uid));
    cache.insert("s2".to_string(), user_entry("t1", &uid));
    cache.insert("other".to_string(), user_entry("t1", "u-other"));

    let v = drust::mcp::tools::user::revoke_user_sessions(&pool, uid.clone(), Some(&*cache))
        .await
        .unwrap();
    assert_eq!(v["revoked"], 1, "the seeded session row was revoked");
    assert_eq!(
        cache.len(),
        1,
        "MCP revoke_user_sessions cleared both of the user's entries"
    );
    assert!(cache.get("other").is_some());
}

#[tokio::test]
async fn with_bus_and_storage_threads_cache_into_inner() {
    let dir = tempfile::tempdir().unwrap();
    helpers::seed_tenant_fs(&dir, "t-mcpwire");
    let tenants = Arc::new(TenantRegistry::new(dir.path().to_path_buf(), 2));
    let cache = Arc::new(AuthCache::new(Duration::from_secs(10), 200_000));
    let webhooks = drust::tenant::WebhookDispatcher::new(tenants.clone(), None);
    let rooms_cfg = drust::tenant::rooms::RoomsConfig::test_defaults();
    let bucket = rooms_cfg.bucket();
    let audit = Arc::new(tokio::sync::Mutex::new(
        drust::safety::audit_db::open_audit_db_memory().unwrap(),
    ));
    let reg = drust::mcp::server::McpRegistry::with_bus_and_storage(
        tenants.clone(),
        drust::tenant::events::EventBus::new(),
        webhooks,
        None,
        String::new(),
        Arc::new([0u8; 32]),
        None,
        52_428_800,
        1_000_000,
        audit,
        drust::tenant::rooms::RoomBus::new(),
        bucket,
        rooms_cfg,
        cache.clone(),
        drust::functions::dispatcher::FunctionDispatcher::new(
            tenants.clone(),
            tokio::sync::mpsc::channel(8).0,
            drust::functions::FnConfig::test_default(),
        ),
    );
    let svc = reg.get_or_create("t-mcpwire").await.unwrap();
    let threaded = svc
        .inner()
        .auth_cache
        .clone()
        .expect("prod ctor must thread the auth cache into DrustMcpInner");
    assert!(
        Arc::ptr_eq(&threaded, &cache),
        "DrustMcpInner.auth_cache is the SAME Arc main.rs constructed"
    );

    // Test-only ctor stays cache-less: MCP tools see None and skip the hook.
    let reg2 =
        drust::mcp::server::McpRegistry::with_bus(tenants, drust::tenant::events::EventBus::new());
    let svc2 = reg2.get_or_create("t-mcpwire").await.unwrap();
    assert!(svc2.inner().auth_cache.is_none());
}
