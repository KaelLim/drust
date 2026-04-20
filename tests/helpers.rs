#![allow(dead_code)]

use axum::Router;
use drust::auth::bearer::{generate_token, hash_token};
use drust::storage::meta::open_meta;
use drust::storage::pool::{SharedTenantPool, TenantRegistry};
use drust::tenant::router::TenantAuthState;
use drust::tenant::{TenantStack, build_tenant_router, events::EventBus};
use std::sync::Arc;
use tokio::sync::Mutex;

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
    let state = TenantAuthState {
        meta: Arc::new(Mutex::new(conn)),
        registry: Arc::new(TenantRegistry::new(data.clone(), 2)),
    };
    let stack = TenantStack {
        auth: state,
        bus: EventBus::new(),
    };
    let app = build_tenant_router(stack);
    (app, tok, dir)
}

pub async fn grab_pool(tenant: &str, dir: &tempfile::TempDir) -> SharedTenantPool {
    let reg = TenantRegistry::new(dir.path().to_path_buf(), 2);
    reg.get_or_open(tenant).unwrap()
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
