#![allow(dead_code)]

use axum::Router;
use drust::auth::bearer::{generate_token, hash_token};
use drust::mcp::http_registry::McpHttpRegistry;
use drust::mcp::server::McpRegistry;
use drust::safety::audit::AuditLog;
use drust::safety::rate_limit::RateLimiter;
use drust::safety::rate_limit_ip::IpRateLimit;
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
    drust::db::migrations::run_migrations(&conn, &data).unwrap();
    let tenants = Arc::new(TenantRegistry::new(data.clone(), 2));
    let bus = EventBus::new();
    let state = TenantAuthState {
        meta: Arc::new(Mutex::new(conn)),
        registry: tenants.clone(),
        limiter: Arc::new(RateLimiter::new(10_000, Duration::from_secs(1))),
        audit: Arc::new(AuditLog::new(dir.path().join("audit"))),
        index_large_table_rows: 1_000_000,
        register_rl: Arc::new(IpRateLimit::new(3, Duration::from_secs(60), 4096)),
        login_rl: Arc::new(IpRateLimit::new(5, Duration::from_secs(60), 4096)),
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
    drust::db::migrations::run_migrations(&conn, &data).unwrap();
    let tenants = Arc::new(TenantRegistry::new(data.clone(), 2));
    let bus = EventBus::new();
    let state = TenantAuthState {
        meta: Arc::new(Mutex::new(conn)),
        registry: tenants.clone(),
        limiter: Arc::new(RateLimiter::new(10_000, Duration::from_secs(1))),
        audit: Arc::new(AuditLog::new(dir.path().join("audit"))),
        index_large_table_rows: 1_000_000,
        register_rl: Arc::new(IpRateLimit::new(3, Duration::from_secs(60), 4096)),
        login_rl: Arc::new(IpRateLimit::new(5, Duration::from_secs(60), 4096)),
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
    let state = TenantAuthState {
        meta: Arc::new(Mutex::new(conn)),
        registry: tenants.clone(),
        limiter: Arc::new(RateLimiter::new(10_000, Duration::from_secs(1))),
        audit: Arc::new(AuditLog::new(dir.path().join("audit"))),
        index_large_table_rows,
        register_rl: Arc::new(IpRateLimit::new(3, Duration::from_secs(60), 4096)),
        login_rl: Arc::new(IpRateLimit::new(5, Duration::from_secs(60), 4096)),
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
pub async fn register_and_login_via_app(
    app: &Router,
    tid: &str,
    email: &str,
    pw: &str,
) -> String {
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
    let bytes = axum::body::to_bytes(resp.into_body(), 65_536).await.unwrap();
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
