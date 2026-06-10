// tests/auth_cache_missed_hook_ttl.rs — Spec test 3 (Layer 2 safety TTL).
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

#[tokio::test]
async fn missed_hook_revocation_honored_within_safety_ttl() {
    let tenant = "t-ttl";
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
        "INSERT INTO tokens (tenant_id, token_hash, role) VALUES (?1, ?2, 'service')",
        rusqlite::params![tenant, hash_token(&tok)],
    )
    .unwrap();
    let _ = drust::storage::tenant_db::open_write(&data, tenant).unwrap();
    drust::db::migrations::run_migrations(&conn, &data).unwrap();
    let tenants = Arc::new(TenantRegistry::new(data.clone(), 2));
    let bus = EventBus::new();
    let webhooks = WebhookDispatcher::new(tenants.clone(), None);
    let meta = Arc::new(Mutex::new(conn));
    // Injected short TTL — the whole point of safety_ttl being a field.
    let cache = Arc::new(AuthCache::new(Duration::from_millis(50), 200_000));
    let mut state = TenantAuthState::test_default(meta.clone(), tenants.clone());
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
    let app = build_tenant_router(stack);

    let get = |t: String| {
        let app = app.clone();
        async move {
            app.oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/t/{tenant}/collections"))
                    .header(header::AUTHORIZATION, format!("Bearer {t}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
        }
    };

    assert!(get(tok.clone()).await.is_success(), "fills cache");

    // MISSED hook: revoke directly in meta.sqlite, do NOT clear the cache.
    {
        let c = meta.lock().await;
        c.execute(
            "UPDATE tokens SET revoked_at = datetime('now') WHERE tenant_id = ?1",
            rusqlite::params![tenant],
        )
        .unwrap();
    }

    // Still authenticates immediately — the stale cache entry is live.
    assert!(
        get(tok.clone()).await.is_success(),
        "stale cache still authenticates within TTL"
    );

    // After the 50 ms TTL, the entry expires → DB re-read → revoked → 401.
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert_eq!(
        get(tok.clone()).await,
        StatusCode::UNAUTHORIZED,
        "missed-hook revocation honored within safety_ttl"
    );
}
