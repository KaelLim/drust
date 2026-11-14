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
//!
//! The bearer layer's DB arm, `register`, `login` and both tenant OAuth
//! endpoints prove liveness in `meta` and then open the pool after releasing
//! the lock — they use `get_if_live` too, and `register` additionally filters
//! `deleted_at IS NULL`.

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

    fn meta(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(self.dir.path().join("meta.sqlite")).unwrap()
    }

    fn allow_self_register(&self, tenant: &str) {
        self.meta()
            .execute(
                "UPDATE tenants SET allow_self_register = 1 WHERE id = ?1",
                rusqlite::params![tenant],
            )
            .unwrap();
    }

    /// The whole `soft_delete_tenant` order: meta `deleted_at`, rename into
    /// `_trash` + pool evict, then the auth-cache clear.
    fn full_soft_delete(&self, tenant: &str) {
        self.meta()
            .execute(
                "UPDATE tenants SET deleted_at = datetime('now') WHERE id = ?1",
                rusqlite::params![tenant],
            )
            .unwrap();
        self.soft_delete_without_clearing_cache(tenant);
        self.cache.clear_tenant(tenant);
    }

    /// One request; returns the status and the RAW body (JSON endpoints are
    /// parsed by the test, OAuth refusals are plain text).
    async fn send(
        &self,
        method: &str,
        uri: &str,
        bearer: Option<&str>,
        json: Option<serde_json::Value>,
    ) -> (StatusCode, String) {
        let mut req = Request::builder().method(method).uri(uri);
        if let Some(b) = bearer {
            req = req.header(header::AUTHORIZATION, format!("Bearer {b}"));
        }
        let body = match json {
            Some(v) => {
                req = req.header(header::CONTENT_TYPE, "application/json");
                Body::from(v.to_string())
            }
            None => Body::empty(),
        };
        let resp = self
            .app
            .clone()
            .oneshot(req.body(body).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }
}

fn error_code(body: &str) -> String {
    let v: serde_json::Value = serde_json::from_str(body).unwrap();
    v["error_code"].as_str().unwrap_or_default().to_string()
}

fn register_body() -> Option<serde_json::Value> {
    Some(serde_json::json!({"email": "a@b.co", "password": "correct-horse-1"}))
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

// --- Request paths that prove liveness in `meta`, release the lock, then open
// the pool. `soft_delete_without_clearing_cache` leaves meta saying "live" with
// the file already in `_trash` and the pool evicted: the window between the
// meta check and the open.

#[tokio::test]
async fn register_on_a_soft_deleted_tenant_is_refused_and_recreates_nothing() {
    let tenant = "t-reg-del";
    let fx = spin(tenant).await;
    fx.allow_self_register(tenant);
    fx.full_soft_delete(tenant);

    let (status, body) = fx
        .send(
            "POST",
            &format!("/t/{tenant}/auth/register"),
            None,
            register_body(),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body: {body}");
    assert_eq!(error_code(&body), "SELF_REGISTER_DISABLED");
    assert!(
        !fx.tenant_dir(tenant).exists(),
        "register must not recreate tenants/{tenant} outside _trash"
    );
    assert_eq!(fx.tenants.cached_count(), 0, "no pool may be cached");
}

#[tokio::test]
async fn register_on_a_soft_deleted_tenant_answers_exactly_like_an_unknown_id() {
    let tenant = "t-reg-del2";
    let fx = spin(tenant).await;
    fx.allow_self_register(tenant);
    fx.full_soft_delete(tenant);

    let deleted = fx
        .send(
            "POST",
            &format!("/t/{tenant}/auth/register"),
            None,
            register_body(),
        )
        .await;
    let unknown = fx
        .send("POST", "/t/t-never/auth/register", None, register_body())
        .await;
    assert_eq!(
        deleted, unknown,
        "a deleted tenant must be indistinguishable from an unknown id"
    );
    assert!(!fx.tenant_dir(tenant).exists());
    assert!(!fx.tenant_dir("t-never").exists());
}

#[tokio::test]
async fn register_when_the_dir_vanished_after_the_meta_check_recreates_nothing() {
    let tenant = "t-reg-race";
    let fx = spin(tenant).await;
    fx.allow_self_register(tenant);
    fx.soft_delete_without_clearing_cache(tenant);

    let (status, body) = fx
        .send(
            "POST",
            &format!("/t/{tenant}/auth/register"),
            None,
            register_body(),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "body: {body}");
    assert_eq!(error_code(&body), "TENANT_NOT_FOUND");
    assert!(!fx.tenant_dir(tenant).exists());
    assert_eq!(fx.tenants.cached_count(), 0);
}

#[tokio::test]
async fn login_when_the_dir_vanished_after_the_meta_check_recreates_nothing() {
    let tenant = "t-login-race";
    let fx = spin(tenant).await;
    fx.soft_delete_without_clearing_cache(tenant);

    let (status, body) = fx
        .send(
            "POST",
            &format!("/t/{tenant}/auth/login"),
            None,
            register_body(),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");
    assert_eq!(error_code(&body), "INVALID_CREDENTIALS");
    assert!(
        !fx.tenant_dir(tenant).exists(),
        "login must not recreate tenants/{tenant} outside _trash"
    );
    assert_eq!(fx.tenants.cached_count(), 0);
}

#[tokio::test]
async fn bearer_db_arm_does_not_resurrect_when_the_dir_vanished_after_the_cte() {
    let tenant = "t-dbarm-race";
    let fx = spin(tenant).await;
    // No warm-up request: the auth cache is empty, so this goes to the CTE.
    fx.soft_delete_without_clearing_cache(tenant);

    let first = fx.get_collections(tenant, &fx.token).await;
    assert_eq!(first, StatusCode::NOT_FOUND);
    assert_eq!(fx.cache.misses(), 1, "must have taken the DB arm");
    assert_eq!(fx.cache.hits(), 0);
    assert!(
        !fx.tenant_dir(tenant).exists(),
        "the DB arm must not recreate tenants/{tenant} outside _trash"
    );
    assert_eq!(fx.tenants.cached_count(), 0);

    // The refusal must not have populated the auth cache.
    let second = fx.get_collections(tenant, &fx.token).await;
    assert_eq!(second, StatusCode::NOT_FOUND);
    assert_eq!(fx.cache.misses(), 2, "second request must miss again");
    assert_eq!(fx.cache.hits(), 0);
}

#[tokio::test]
async fn oauth_start_when_the_dir_vanished_recreates_nothing() {
    let tenant = "t-oauth-start-race";
    let fx = spin(tenant).await;
    fx.soft_delete_without_clearing_cache(tenant);

    let (status, body) = fx
        .send(
            "GET",
            &format!("/t/{tenant}/oauth/google/start?redirect_uri=https%3A%2F%2Fexample.test%2Fcb"),
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "body: {body}");
    assert_eq!(body, "tenant not found");
    assert!(!fx.tenant_dir(tenant).exists());
}

#[tokio::test]
async fn oauth_callback_when_the_dir_vanished_recreates_nothing() {
    let tenant = "t-oauth-cb-race";
    let fx = spin(tenant).await;
    fx.soft_delete_without_clearing_cache(tenant);

    let (status, body) = fx
        .send(
            "GET",
            &format!("/t/{tenant}/oauth/google/callback?code=x&state=y"),
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "body: {body}");
    assert_eq!(body, "tenant not found");
    assert!(!fx.tenant_dir(tenant).exists());
}

// --- Unchanged behaviour (green today, must stay green).

#[tokio::test]
async fn bearer_db_arm_opens_a_live_tenant_on_a_cold_registry() {
    let tenant = "t-dbarm-live";
    let fx = spin(tenant).await;
    assert_eq!(fx.tenants.cached_count(), 0);

    let first = fx.get_collections(tenant, &fx.token).await;
    assert_eq!(first, StatusCode::OK);
    assert_eq!(fx.cache.misses(), 1);
    assert_eq!(fx.tenants.cached_count(), 1);

    let second = fx.get_collections(tenant, &fx.token).await;
    assert_eq!(second, StatusCode::OK);
    assert_eq!(fx.cache.hits(), 1);
}

#[tokio::test]
async fn register_and_login_on_a_live_tenant_are_unchanged() {
    let tenant = "t-reg-live";
    let fx = spin(tenant).await;
    fx.allow_self_register(tenant);
    assert_eq!(fx.tenants.cached_count(), 0);

    let (status, body) = fx
        .send(
            "POST",
            &format!("/t/{tenant}/auth/register"),
            None,
            register_body(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "body: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(v["user_id"].is_string());
    assert_eq!(v["email"], "a@b.co");

    let (status, body) = fx
        .send(
            "POST",
            &format!("/t/{tenant}/auth/login"),
            None,
            register_body(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(v["token"].is_string());
    assert!(fx.tenant_dir(tenant).exists());
}

#[tokio::test]
async fn user_session_db_arm_on_a_cold_registry_is_unchanged() {
    let tenant = "t-user-cold";
    let fx = spin(tenant).await;
    fx.allow_self_register(tenant);
    let tok =
        helpers::register_and_login_via_app(&fx.app, tenant, "u@b.co", "correct-horse-1").await;
    fx.tenants.evict(tenant);
    let m0 = fx.cache.misses();

    let (status, body) = fx
        .send("GET", &format!("/t/{tenant}/me"), Some(&tok), None)
        .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(fx.cache.misses(), m0 + 1, "must have taken the DB arm");
    assert_eq!(fx.tenants.cached_count(), 1);
}

#[tokio::test]
async fn register_on_an_unknown_tenant_is_still_refused() {
    let fx = spin("t-a").await;
    let (status, body) = fx
        .send("POST", "/t/t-ghost/auth/register", None, register_body())
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body: {body}");
    assert_eq!(error_code(&body), "SELF_REGISTER_DISABLED");
    assert!(!fx.tenant_dir("t-ghost").exists());
}
