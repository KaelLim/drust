#![allow(dead_code)]

use axum::Router;
use drust::auth::bearer::{generate_token, hash_token};
use drust::mcp::http_registry::McpHttpRegistry;
use drust::mcp::server::McpRegistry;
use drust::safety::audit::AuditLog;
use drust::safety::rate_limit::RateLimiter;
use drust::storage::meta::open_meta;
use drust::storage::pool::{SharedTenantPool, TenantRegistry};
use drust::tenant::router::TenantAuthState;
use drust::tenant::{TenantStack, build_tenant_router, events::EventBus};
use std::sync::Arc;
use std::time::Duration;
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
    let tenants = Arc::new(TenantRegistry::new(data.clone(), 2));
    let bus = EventBus::new();
    let state = TenantAuthState {
        meta: Arc::new(Mutex::new(conn)),
        registry: tenants.clone(),
        limiter: Arc::new(RateLimiter::new(10_000, Duration::from_secs(1))),
        audit: Arc::new(AuditLog::new(dir.path().join("audit"))),
    };
    let stack = TenantStack {
        auth: state,
        bus: bus.clone(),
        mcp: test_mcp_http(tenants, bus),
        files: None,
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
    let tenants = Arc::new(TenantRegistry::new(data.clone(), 2));
    let bus = EventBus::new();
    let state = TenantAuthState {
        meta: Arc::new(Mutex::new(conn)),
        registry: tenants.clone(),
        limiter: Arc::new(RateLimiter::new(10_000, Duration::from_secs(1))),
        audit: Arc::new(AuditLog::new(dir.path().join("audit"))),
    };
    let stack = TenantStack {
        auth: state,
        bus: bus.clone(),
        mcp: test_mcp_http(tenants, bus),
        files: None,
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
}
