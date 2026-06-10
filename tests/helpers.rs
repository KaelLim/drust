#![allow(dead_code)]

use axum::Router;
use drust::auth::bearer::{generate_token, hash_token};
use drust::mcp::http_registry::McpHttpRegistry;
use drust::mcp::server::McpRegistry;
use drust::storage::meta::open_meta;
use drust::storage::pool::{SharedTenantPool, TenantRegistry};
use drust::tenant::router::TenantAuthState;
use drust::tenant::{TenantStack, WebhookDispatcher, build_tenant_router, events::EventBus};
use std::sync::Arc;
use tokio::sync::Mutex;

pub fn test_mcp_http(tenants: Arc<TenantRegistry>, bus: EventBus) -> Arc<McpHttpRegistry> {
    Arc::new(McpHttpRegistry::new(Arc::new(McpRegistry::with_bus(
        tenants, bus,
    ))))
}

pub async fn spin_up_tenant(tenant: &str) -> (Router, String, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let conn = open_meta(&data.join("meta.sqlite")).unwrap();
    conn.execute(
        "INSERT INTO tenants (id, name) VALUES (?1, 'x')",
        rusqlite::params![tenant],
    )
    .unwrap();
    let tok = generate_token();
    conn.execute(
        "INSERT INTO tokens (tenant_id, token_hash) VALUES (?1, ?2)",
        rusqlite::params![tenant, hash_token(&tok)],
    )
    .unwrap();
    let _ = drust::storage::tenant_db::open_write(&data, tenant).unwrap();
    drust::db::migrations::run_migrations(&conn, &data).unwrap();
    let tenants = Arc::new(TenantRegistry::new(data.clone(), 2));
    let bus = EventBus::new();
    let webhooks = WebhookDispatcher::new(tenants.clone(), None);
    let meta = Arc::new(Mutex::new(conn));
    let state = TenantAuthState::test_default(meta, tenants.clone());
    let stack = TenantStack {
        auth: state,
        bus: bus.clone(),
        bus_rooms: drust::tenant::rooms::RoomBus::new(),
        bucket: drust::tenant::rooms::RoomsConfig::test_defaults().bucket(),
        rooms_cfg: drust::tenant::rooms::RoomsConfig::test_defaults(),
        mcp: test_mcp_http(tenants, bus),
        files: None,
        webhooks,
        cors_origins: Vec::new(),
    };
    let app = build_tenant_router(stack);
    (app, tok, dir)
}

pub async fn grab_pool(tenant: &str, dir: &tempfile::TempDir) -> SharedTenantPool {
    let reg = TenantRegistry::new(dir.path().to_path_buf(), 2);
    reg.get_or_open(tenant).unwrap()
}

/// Like `spin_up_tenant` but inserts the token with an explicit role
/// (`"anon"` or `"service"`).
pub async fn spin_up_tenant_with_role(
    tenant: &str,
    role: &str,
) -> (Router, String, tempfile::TempDir) {
    let (app, tok, _cache, dir) = spin_up_tenant_with_role_cached(tenant, role).await;
    (app, tok, dir)
}

/// Like `spin_up_tenant_with_role`, but ALSO returns the stack's `AuthCache`
/// handle (v1.35 Finding #3). Tests that flip auth-relevant `meta.sqlite`
/// columns OUT-OF-BAND (raw SQL — no production handler, so no invalidation
/// hook fires) must mirror the handlers' invalidation themselves, e.g.
/// `cache.clear_tenant(tenant)` after the flip; otherwise the flipped value
/// is invisible until the safety TTL expires.
pub async fn spin_up_tenant_with_role_cached(
    tenant: &str,
    role: &str,
) -> (
    Router,
    String,
    Arc<drust::tenant::auth_cache::AuthCache>,
    tempfile::TempDir,
) {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let conn = open_meta(&data.join("meta.sqlite")).unwrap();
    conn.execute(
        "INSERT INTO tenants (id, name) VALUES (?1, 'x')",
        rusqlite::params![tenant],
    )
    .unwrap();
    let tok = generate_token();
    conn.execute(
        "INSERT INTO tokens (tenant_id, token_hash, role) VALUES (?1, ?2, ?3)",
        rusqlite::params![tenant, hash_token(&tok), role],
    )
    .unwrap();
    let _ = drust::storage::tenant_db::open_write(&data, tenant).unwrap();
    drust::db::migrations::run_migrations(&conn, &data).unwrap();
    let tenants = Arc::new(TenantRegistry::new(data.clone(), 2));
    let bus = EventBus::new();
    let webhooks = WebhookDispatcher::new(tenants.clone(), None);
    let meta = Arc::new(Mutex::new(conn));
    let state = TenantAuthState::test_default(meta, tenants.clone());
    let cache = state.auth_cache.clone();
    let stack = TenantStack {
        auth: state,
        bus: bus.clone(),
        bus_rooms: drust::tenant::rooms::RoomBus::new(),
        bucket: drust::tenant::rooms::RoomsConfig::test_defaults().bucket(),
        rooms_cfg: drust::tenant::rooms::RoomsConfig::test_defaults(),
        mcp: test_mcp_http(tenants, bus),
        files: None,
        webhooks,
        cors_origins: Vec::new(),
    };
    let app = build_tenant_router(stack);
    (app, tok, cache, dir)
}

/// Like `spin_up_tenant_with_role` but uses a specific `index_large_table_rows`
/// threshold. Useful for regression-testing that the configured threshold is
/// plumbed end-to-end (REST + MCP + admin) rather than a hardcoded default.
pub async fn spin_up_tenant_with_threshold(
    tenant: &str,
    role: &str,
    index_large_table_rows: u64,
) -> (Router, String, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let conn = open_meta(&data.join("meta.sqlite")).unwrap();
    conn.execute(
        "INSERT INTO tenants (id, name) VALUES (?1, 'x')",
        rusqlite::params![tenant],
    )
    .unwrap();
    let tok = generate_token();
    conn.execute(
        "INSERT INTO tokens (tenant_id, token_hash, role) VALUES (?1, ?2, ?3)",
        rusqlite::params![tenant, hash_token(&tok), role],
    )
    .unwrap();
    let _ = drust::storage::tenant_db::open_write(&data, tenant).unwrap();
    drust::db::migrations::run_migrations(&conn, &data).unwrap();
    let tenants = Arc::new(TenantRegistry::new(data.clone(), 2));
    let bus = EventBus::new();
    let webhooks = WebhookDispatcher::new(tenants.clone(), None);
    let meta = Arc::new(Mutex::new(conn));
    let mut state = TenantAuthState::test_default(meta, tenants.clone());
    state.index_large_table_rows = index_large_table_rows;
    let stack = TenantStack {
        auth: state,
        bus: bus.clone(),
        bus_rooms: drust::tenant::rooms::RoomBus::new(),
        bucket: drust::tenant::rooms::RoomsConfig::test_defaults().bucket(),
        rooms_cfg: drust::tenant::rooms::RoomsConfig::test_defaults(),
        mcp: test_mcp_http(tenants, bus),
        files: None,
        webhooks,
        cors_origins: Vec::new(),
    };
    let app = build_tenant_router(stack);
    (app, tok, dir)
}

/// Seed a `posts` collection with an `author_id INTEGER` field on tenant
/// `tenant` by writing directly through the pool.  The pool is opened from
/// the same TempDir that `spin_up_tenant*` created.
pub async fn seed_posts_collection(
    _app: &Router,
    _tok: &str,
    tenant: &str,
    dir: &tempfile::TempDir,
) {
    let pool = grab_pool(tenant, dir).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE IF NOT EXISTS posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                author_id INTEGER
            );",
        )
    })
    .await
    .unwrap();
}

pub async fn spin_up_tenant_self_register(tenant: &str) -> (Router, String, tempfile::TempDir) {
    let (router, tid, dir) = spin_up_tenant(tenant).await;
    let meta_path = dir.path().join("meta.sqlite");
    rusqlite::Connection::open(&meta_path)
        .unwrap()
        .execute(
            "UPDATE tenants SET allow_self_register = 1 WHERE id = ?1",
            rusqlite::params![tenant],
        )
        .unwrap();
    (router, tid, dir)
}

/// Register a user and log them in via the tenant auth endpoints, returning
/// the session token. Uses `oneshot` — no live server required.
pub async fn register_and_login_via_app(app: &Router, tid: &str, email: &str, pw: &str) -> String {
    use axum::body::Body;
    use axum::http::{Request, header};
    use tower::ServiceExt;

    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{tid}/auth/register"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({"email": email, "password": pw}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{tid}/auth/login"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({"email": email, "password": pw}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(resp.into_body(), 65_536)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    v["token"].as_str().unwrap().to_string()
}

/// Spin up a tenant with a service token AND an anon token, with
/// `allow_self_register = 1` enabled.
///
/// Returns `(app, tenant_id, service_token, anon_token, dir)`.
pub async fn spin_up_dual_role_self_register(
    tenant: &str,
) -> (Router, String, String, String, tempfile::TempDir) {
    let (app, svc_tok, dir) = spin_up_tenant_with_role(tenant, "service").await;
    // Enable self-registration on the tenant.
    let meta_path = dir.path().join("meta.sqlite");
    rusqlite::Connection::open(&meta_path)
        .unwrap()
        .execute(
            "UPDATE tenants SET allow_self_register = 1 WHERE id = ?1",
            rusqlite::params![tenant],
        )
        .unwrap();
    // Insert a second token with role = 'anon' for the same tenant.
    let anon_tok = generate_token();
    let anon_hash = hash_token(&anon_tok);
    rusqlite::Connection::open(&meta_path)
        .unwrap()
        .execute(
            "INSERT INTO tokens (tenant_id, token_hash, role) VALUES (?1, ?2, 'anon')",
            rusqlite::params![tenant, anon_hash],
        )
        .unwrap();
    (app, tenant.to_string(), svc_tok, anon_tok, dir)
}

pub fn seed_tenant_fs(dir: &tempfile::TempDir, tenant: &str) {
    use drust::storage::meta::open_meta;
    let data = dir.path().to_path_buf();
    let conn = open_meta(&data.join("meta.sqlite")).unwrap();
    conn.execute(
        "INSERT OR IGNORE INTO tenants (id, name) VALUES (?1, 'x')",
        rusqlite::params![tenant],
    )
    .unwrap();
    let _ = drust::storage::tenant_db::open_write(&data, tenant).unwrap();
    drust::db::migrations::run_migrations(&conn, &data).unwrap();
}

/// Build a real `TenantsState` for `tenant` (service token seeded) that
/// shares `cache`, so auth-cache hook tests can fire admin handlers directly
/// and observe the cache.
pub async fn tenants_state_with_cache(
    tenant: &str,
    cache: Arc<drust::tenant::auth_cache::AuthCache>,
) -> (drust::mgmt::tenants::TenantsState, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let conn = open_meta(&data.join("meta.sqlite")).unwrap();
    conn.execute(
        "INSERT INTO tenants (id, name) VALUES (?1, 'x')",
        rusqlite::params![tenant],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO tokens (tenant_id, token_hash, role) VALUES (?1, 'seed', 'service')",
        rusqlite::params![tenant],
    )
    .unwrap();
    let _ = drust::storage::tenant_db::open_write(&data, tenant).unwrap();
    drust::db::migrations::run_migrations(&conn, &data).unwrap();
    let tenants = Arc::new(TenantRegistry::new(data.clone(), 2));
    let bus = EventBus::new();
    let meta = Arc::new(Mutex::new(conn));
    let mut state = drust::mgmt::tenants::TenantsState::test_default(
        meta,
        data,
        tenants.clone(),
        test_mcp_http(tenants, bus.clone()),
        bus,
        drust::tenant::rooms::RoomBus::new(),
    );
    state.auth_cache = cache;
    (state, dir)
}

/// Build a real `MgmtState` sharing `cache`, with one `admins` row id=`admin_id`
/// so admin-PAT reroll's INSERT satisfies its FK. For hook-2 tests.
pub async fn mgmt_state_with_cache_and_admin(
    admin_id: i64,
    cache: Arc<drust::tenant::auth_cache::AuthCache>,
) -> (drust::mgmt::routes::MgmtState, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let conn = open_meta(&data.join("meta.sqlite")).unwrap();
    // run_migrations creates _admin_tokens, which the reroll handler
    // UPDATEs + INSERTs into.
    drust::db::migrations::run_migrations(&conn, &data).unwrap();
    conn.execute(
        "INSERT INTO admins (id, username, email, password_hash) VALUES (?1, 'a', 'a@x', 'x')",
        rusqlite::params![admin_id],
    )
    .unwrap();
    let tenants = Arc::new(TenantRegistry::new(data.clone(), 2));
    let bus = EventBus::new();
    let meta = Arc::new(Mutex::new(conn));
    let mut state = drust::mgmt::routes::MgmtState::test_default(
        meta,
        data,
        tenants.clone(),
        test_mcp_http(tenants, bus.clone()),
        bus,
        drust::tenant::rooms::RoomBus::new(),
    );
    state.auth_cache = cache;
    (state, dir)
}

/// Seed a tenant with one `_system_users` row + an active session; returns
/// `(pool, tempdir, user_id)`. For the MCP hook-7/8 auth-cache tests that
/// call the tool fns in `drust::mcp::tools::user` directly.
pub async fn seed_user_for_mcp(tenant: &str) -> (SharedTenantPool, tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    seed_tenant_fs(&dir, tenant);
    let tenants = TenantRegistry::new(dir.path().to_path_buf(), 2);
    let pool = tenants.get_or_open(tenant).unwrap();
    let uid = "u-mcp-cache".to_string();
    let uid2 = uid.clone();
    pool.with_writer(move |c| {
        c.execute(
            "INSERT INTO _system_users (id, email, password_hash, created_at, updated_at) \
             VALUES (?1, 'u@x', 'h', datetime('now'), datetime('now'))",
            rusqlite::params![uid2],
        )?;
        c.execute(
            "INSERT INTO _system_sessions \
             (token_hash, user_id, created_at, expires_at, last_seen_at) \
             VALUES ('sess-hash-mcp', ?1, datetime('now'), datetime('now', '+1 day'), \
             datetime('now'))",
            rusqlite::params![uid2],
        )
    })
    .await
    .unwrap();
    (pool, dir, uid)
}

/// Real `TenantAuthState` for `tenant` sharing `cache`. For hook-7/8/9 REST tests.
pub async fn auth_state_with_cache(
    tenant: &str,
    cache: Arc<drust::tenant::auth_cache::AuthCache>,
) -> (TenantAuthState, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let conn = open_meta(&data.join("meta.sqlite")).unwrap();
    conn.execute(
        "INSERT INTO tenants (id, name) VALUES (?1, 'x')",
        rusqlite::params![tenant],
    )
    .unwrap();
    let _ = drust::storage::tenant_db::open_write(&data, tenant).unwrap();
    drust::db::migrations::run_migrations(&conn, &data).unwrap();
    let tenants = Arc::new(TenantRegistry::new(data, 2));
    let meta = Arc::new(Mutex::new(conn));
    let mut state = TenantAuthState::test_default(meta, tenants);
    state.auth_cache = cache;
    (state, dir)
}

/// Like `auth_state_with_cache`, but seeds one `_system_users` row in the
/// tenant db and returns its id. The state carries the fresh cache that
/// `test_default` builds — reach it via `state.auth_cache.clone()`. For the
/// hook-8 (user-delete cascade) REST test.
pub async fn auth_state_with_seeded_user(
    tenant: &str,
) -> (TenantAuthState, tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let conn = open_meta(&data.join("meta.sqlite")).unwrap();
    conn.execute(
        "INSERT INTO tenants (id, name) VALUES (?1, 'x')",
        rusqlite::params![tenant],
    )
    .unwrap();
    let _ = drust::storage::tenant_db::open_write(&data, tenant).unwrap();
    drust::db::migrations::run_migrations(&conn, &data).unwrap();
    let tenants = Arc::new(TenantRegistry::new(data, 2));
    let pool = tenants.get_or_open(tenant).unwrap();
    let uid = "u-del-cache".to_string();
    let uid2 = uid.clone();
    pool.with_writer(move |c| {
        c.execute(
            "INSERT INTO _system_users (id, email, password_hash, created_at, updated_at) \
             VALUES (?1, 'u@x', 'h', datetime('now'), datetime('now'))",
            rusqlite::params![uid2],
        )
    })
    .await
    .unwrap();
    let meta = Arc::new(Mutex::new(conn));
    let state = TenantAuthState::test_default(meta, tenants);
    (state, dir, uid)
}
