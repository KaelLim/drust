// tests/auth_cache_user_expiry.rs — Spec test 4.
mod helpers;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::auth::bearer::{generate_token, hash_token};
use drust::storage::meta::open_meta;
use drust::storage::pool::TenantRegistry;
use drust::tenant::auth_cache::{AuthCache, CachedAuth};
use drust::tenant::router::TenantAuthState;
use drust::tenant::{TenantStack, WebhookDispatcher, build_tenant_router, events::EventBus};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tower::ServiceExt;

#[tokio::test]
async fn expired_user_entry_rejected_from_cache_without_db_read() {
    let tenant = "t-userexp";
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let conn = open_meta(&data.join("meta.sqlite")).unwrap();
    conn.execute(
        "INSERT INTO tenants (id, name) VALUES (?1, 'x')",
        rusqlite::params![tenant],
    )
    .unwrap();
    let svc = generate_token();
    conn.execute(
        "INSERT INTO tokens (tenant_id, token_hash, role) VALUES (?1, ?2, 'service')",
        rusqlite::params![tenant, hash_token(&svc)],
    )
    .unwrap();
    let _ = drust::storage::tenant_db::open_write(&data, tenant).unwrap();
    drust::db::migrations::run_migrations(&conn, &data).unwrap();
    let tenants = Arc::new(TenantRegistry::new(data.clone(), 2));
    let bus = EventBus::new();
    let webhooks = WebhookDispatcher::new(tenants.clone(), None);
    let meta = Arc::new(Mutex::new(conn));
    let cache = Arc::new(AuthCache::new(Duration::from_secs(10), 200_000));

    // A user token that has NO _system_sessions row (so any DB lookup would
    // 401 on its own) — but we seed a cached entry with a PAST expiry. The
    // cached self-check must reject WITHOUT consulting the DB.
    let user_tok = drust::auth::user_session::generate_token();
    let user_hash = drust::auth::bearer::hash_token(&user_tok); // the hex hash the layer keys on
    cache.insert(
        user_hash,
        CachedAuth::User {
            tenant_id: tenant.to_string(),
            user_id: "u-gone".to_string(),
            expires_at: chrono::Utc::now() - chrono::Duration::hours(1),
            publish_user_allowed: false,
            publish_anon_allowed: false,
        },
    );

    let mut state = TenantAuthState::test_default(meta, tenants.clone());
    state.auth_cache = cache.clone();
    let (functions, functions_exec, fn_cfg) = drust::functions::test_stack_parts(tenants.clone());
    let stack = TenantStack {
        auth: state,
        bus: bus.clone(),
        bus_rooms: drust::tenant::rooms::RoomBus::new(),
        bucket: drust::tenant::rooms::RoomsConfig::test_defaults().bucket(),
        rooms_cfg: drust::tenant::rooms::RoomsConfig::test_defaults(),
        mcp: helpers::test_mcp_http(tenants, bus),
        files: None,
        webhooks,
        functions,
        functions_exec,
        fn_cfg,
        cors_origins: Vec::new(),
    };
    let app = build_tenant_router(stack);

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/t/{tenant}/collections"))
                .header(header::AUTHORIZATION, format!("Bearer {user_tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "expired cached User must 401 via self-check"
    );
    // The stale entry was dropped on the failed self-check.
    assert_eq!(cache.len(), 0, "expired entry purged on reject");
}
