// tests/auth_cache_hit.rs — Spec test 1: a second identical service request
// is a cache HIT (skips meta CTE), observable via hit/miss counters.
mod helpers;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::auth::bearer::{generate_token, hash_token};
use drust::storage::meta::open_meta;
use drust::storage::pool::TenantRegistry;
use drust::tenant::auth_cache::AuthCache;
use drust::tenant::router::TenantAuthState;
use drust::tenant::{TenantStack, WebhookDispatcher, build_tenant_router, events::EventBus};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tower::ServiceExt;

async fn spin_with_cache(
    tenant: &str,
    role: &str,
) -> (axum::Router, String, Arc<AuthCache>, tempfile::TempDir) {
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
    let cache = Arc::new(AuthCache::new(Duration::from_secs(10), 200_000));
    let mut state = TenantAuthState::test_default(meta, tenants.clone());
    state.auth_cache = cache.clone();
    let stack = TenantStack {
        auth: state,
        bus: bus.clone(),
        bus_rooms: drust::tenant::rooms::RoomBus::new(),
        bucket: drust::tenant::rooms::RoomsConfig::test_defaults().bucket(),
        rooms_cfg: drust::tenant::rooms::RoomsConfig::test_defaults(),
        mcp: helpers::test_mcp_http(tenants, bus),
        files: None,
        webhooks,
        cors_origins: Vec::new(),
    };
    (build_tenant_router(stack), tok, cache, dir)
}

async fn auth_get(app: &axum::Router, tid: &str, tok: &str) -> StatusCode {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/t/{tid}/collections"))
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    resp.status()
}

#[tokio::test]
async fn second_service_request_is_cache_hit() {
    let (app, tok, cache, _dir) = spin_with_cache("t-hit", "service").await;
    let s1 = auth_get(&app, "t-hit", &tok).await;
    assert!(s1.is_success(), "first request authed, got {s1}");
    assert_eq!(cache.misses(), 1, "first request is a miss");
    assert_eq!(cache.hits(), 0);

    let s2 = auth_get(&app, "t-hit", &tok).await;
    assert!(s2.is_success(), "second request authed, got {s2}");
    assert_eq!(cache.hits(), 1, "second request is a HIT (skipped meta CTE)");
    assert_eq!(cache.misses(), 1, "miss count unchanged on the hit");
}
