//! v1.58 P1-6 — a soft-deleted tenant must not be recreated on disk by a
//! background path.
//!
//! Several background call sites used the create-on-open accessor, while
//! `functions/executor.rs` and `functions/runtime.rs` deliberately used
//! `get_if_live` with a comment explaining exactly this hazard. A soft-delete
//! landing mid-loop rebuilt `tenants/<id>/data.sqlite` OUTSIDE `_trash`, and the
//! janitor only sweeps `_trash/*`, so the directory leaked permanently.
//!
//! The same hazard reaches the DATA PLANE through the auth-cache hit branch of
//! `bearer_auth_layer`: that branch is consulted BEFORE the bearer CTE (the only
//! thing that filters `deleted_at IS NULL`), so a cached identity carries no meta
//! check at all. `soft_delete_tenant` renames the directory, evicts the pool and
//! only then clears the auth cache — and a request that read the cache entry
//! before that clear and was descheduled widens the window arbitrarily. Both
//! cache arms therefore use `get_if_live` and 404 on a stale entry.

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

#[test]
fn get_if_live_refuses_a_soft_deleted_tenant_and_get_or_create_still_creates() {
    let dir = tempfile::tempdir().unwrap();
    let reg = TenantRegistry::new(dir.path().to_path_buf(), 2);

    // A live tenant: created, then reachable both ways.
    let _ = reg.get_or_create("live").unwrap();
    assert!(reg.get_if_live("live").is_some());

    // Simulate the soft-delete: evict the cached pool and move the directory
    // aside exactly as `soft_delete` does.
    reg.evict("live");
    let src = dir.path().join("tenants").join("live");
    let dst = dir.path().join("_trash").join("live-20260802");
    std::fs::create_dir_all(dst.parent().unwrap()).unwrap();
    std::fs::rename(&src, &dst).unwrap();

    assert!(
        reg.get_if_live("live").is_none(),
        "get_if_live must report a soft-deleted tenant as gone"
    );
    assert!(
        !src.exists(),
        "get_if_live must not have recreated the tenant directory"
    );

    // The creation path is unchanged and still creates.
    let _ = reg.get_or_create("brand-new").unwrap();
    assert!(dir.path().join("tenants").join("brand-new").exists());
}

struct Fixture {
    app: axum::Router,
    token: String,
    cache: Arc<AuthCache>,
    tenants: Arc<TenantRegistry>,
    dir: tempfile::TempDir,
}

impl Fixture {
    fn tenant_dir(&self, tenant: &str) -> std::path::PathBuf {
        self.dir.path().join("tenants").join(tenant)
    }

    /// Everything `soft_delete_tenant` does to the filesystem and the pool
    /// registry, but NOT `auth_cache.clear_tenant` — that is exactly the state a
    /// request sees when it read its cache entry before the clear (or landed in
    /// the two statements between the rename and the clear).
    fn soft_delete_without_clearing_cache(&self, tenant: &str) {
        self.tenants.evict(tenant);
        let dst = self.dir.path().join("_trash").join(format!("{tenant}-ts"));
        std::fs::create_dir_all(dst.parent().unwrap()).unwrap();
        std::fs::rename(self.tenant_dir(tenant), &dst).unwrap();
    }

    async fn get_collections(&self, tenant: &str, bearer: &str) -> StatusCode {
        self.app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/t/{tenant}/collections"))
                    .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
    }
}

async fn spin(tenant: &str) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let conn = open_meta(&data.join("meta.sqlite")).unwrap();
    conn.execute(
        "INSERT INTO tenants (id, name) VALUES (?1, 'x')",
        rusqlite::params![tenant],
    )
    .unwrap();
    let token = generate_token();
    conn.execute(
        "INSERT INTO tokens (tenant_id, token_hash, role) VALUES (?1, ?2, 'service')",
        rusqlite::params![tenant, hash_token(&token)],
    )
    .unwrap();
    let _ = drust::storage::tenant_db::open_write(&data, tenant).unwrap();
    drust::db::migrations::run_migrations(&conn, &data).unwrap();
    let tenants = Arc::new(TenantRegistry::new(data.clone(), 2));
    let bus = EventBus::new();
    let webhooks = WebhookDispatcher::new(tenants.clone(), None);
    let meta = Arc::new(Mutex::new(conn));
    let cache = Arc::new(AuthCache::new(Duration::from_secs(10), 200_000));
    let mut auth = TenantAuthState::test_default(meta, tenants.clone());
    auth.auth_cache = cache.clone();
    let bus_rooms = helpers::shared_bus_rooms(&mut auth);
    let (functions, functions_exec, fn_cfg) = drust::functions::test_stack_parts(tenants.clone());
    let stack = TenantStack {
        auth,
        bus: bus.clone(),
        bus_rooms: bus_rooms.clone(),
        bucket: drust::tenant::rooms::RoomsConfig::test_defaults().bucket(),
        rooms_cfg: drust::tenant::rooms::RoomsConfig::test_defaults(),
        mcp: helpers::test_mcp_http(tenants.clone(), bus, bus_rooms.clone()),
        files: None,
        webhooks,
        functions,
        functions_exec,
        fn_cfg,
        cron: std::sync::Arc::new(drust::cron::CronState::test_default()),
        cors_origins: Vec::new(),
    };
    Fixture {
        app: build_tenant_router(stack),
        token,
        cache,
        tenants,
        dir,
    }
}

#[tokio::test]
async fn cached_bearer_hit_does_not_resurrect_a_soft_deleted_tenant() {
    let tenant = "t-cachedbearer";
    let fx = spin(tenant).await;

    // Warm the auth cache with a real request so the second one is a HIT and
    // never reaches the bearer CTE.
    let first = fx.get_collections(tenant, &fx.token).await;
    assert!(first.is_success(), "first request should auth, got {first}");
    assert_eq!(fx.cache.misses(), 1);

    fx.soft_delete_without_clearing_cache(tenant);

    let second = fx.get_collections(tenant, &fx.token).await;
    assert_eq!(fx.cache.hits(), 1, "second request must be a cache HIT");
    assert_eq!(
        second,
        StatusCode::NOT_FOUND,
        "a stale cached bearer for a soft-deleted tenant must fail closed"
    );
    assert!(
        !fx.tenant_dir(tenant).exists(),
        "the cache-hit branch must not recreate tenants/{tenant} outside _trash"
    );
}

#[tokio::test]
async fn cached_user_hit_does_not_resurrect_a_soft_deleted_tenant() {
    let tenant = "t-cacheduser";
    let fx = spin(tenant).await;

    // Seed a live (non-expired) user entry directly: the User arm reconstructs
    // the identity from the cache and never reads _system_sessions, so this is
    // the same state a logged-in end user's second request reaches.
    let user_tok = drust::auth::user_session::generate_token();
    fx.cache.insert(
        hash_token(&user_tok),
        CachedAuth::User {
            tenant_id: tenant.to_string(),
            user_id: "u-1".to_string(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            publish_user_allowed: false,
            publish_anon_allowed: false,
            file_caps: Default::default(),
            quota_tier: 1,
        },
    );

    fx.soft_delete_without_clearing_cache(tenant);

    let status = fx.get_collections(tenant, &user_tok).await;
    assert_eq!(fx.cache.hits(), 1, "request must be a cache HIT");
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a stale cached user session for a soft-deleted tenant must fail closed"
    );
    assert!(
        !fx.tenant_dir(tenant).exists(),
        "the cache-hit branch must not recreate tenants/{tenant} outside _trash"
    );
}
