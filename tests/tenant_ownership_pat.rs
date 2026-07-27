//! v1.50 Task 8 — member-PAT data-plane scoping (security core).
//!
//! A member admin's PAT only resolves on tenants that admin owns: any other
//! tenant gets `403 PAT_TENANT_DENIED` (alias `WRITE_DENIED`) from the bearer
//! CTE deny in `tenant::router`. Owner PATs keep the historical cross-tenant
//! reach byte-for-byte. The auth cache cannot re-open the hole: cross-tenant
//! requests fall through to the DB path by construction, and same-tenant
//! stale entries are evicted by hook 13 (`change_role`) and the T7 ownership
//! transfer hook — both pinned here end-to-end through the mgmt router.

mod helpers;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::auth::admin_token;
use drust::mgmt::routes::MgmtState;
use drust::storage::meta::{bootstrap_admin, open_meta};
use drust::storage::pool::TenantRegistry;
use drust::tenant::auth_cache::AuthCache;
use drust::tenant::router::TenantAuthState;
use drust::tenant::{TenantStack, WebhookDispatcher, build_tenant_router, events::EventBus};
use rusqlite::params;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use tokio::sync::Mutex;
use tower::ServiceExt;

struct Fixture {
    /// Data-plane router (`/t/{id}/...`).
    tenant_app: axum::Router,
    /// Admin-plane router (`/login`, `/admin/...`) sharing meta + auth cache.
    mgmt_app: axum::Router,
    member_pat: String,
    owner2_pat: String,
    owner2_id: i64,
    _dir: tempfile::TempDir,
}

/// Seed: root owner (id 1, "root"/"hunter2") + a second owner admin + one
/// member admin, each with a PAT. Tenants: `t-own` owned by the member,
/// `t-other` owned by root. Data-plane and mgmt routers share the SAME
/// meta connection and the SAME auth cache, so eviction hooks fired by
/// admin-plane mutations are observable on the data plane.
async fn spin_up() -> Fixture {
    let dir = tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let log_dir = data.join("audit");
    std::fs::create_dir_all(&log_dir).unwrap();
    let mut conn = open_meta(&data.join("meta.sqlite")).unwrap();
    bootstrap_admin(&mut conn, "root", "hunter2").unwrap();
    drust::db::migrations::run_migrations(&conn, &data).unwrap();
    // root (id 1) is now the sole owner via the v1.29.0 role backfill.

    // Admins inserted AFTER run_migrations: no auto-minted PATs to dodge.
    conn.execute(
        "INSERT INTO admins (username, password_hash, email, role) \
         VALUES ('own2', '$oauth-only$', 'own2@example.com', 'owner')",
        [],
    )
    .unwrap();
    let owner2_id = conn.last_insert_rowid();
    conn.execute(
        "INSERT INTO admins (username, password_hash, email, role) \
         VALUES ('mem', '$oauth-only$', 'mem@example.com', 'member')",
        [],
    )
    .unwrap();
    let member_id = conn.last_insert_rowid();

    // Tenants with explicit owners (inserted post-migration so the ownership
    // backfill never touches them).
    conn.execute(
        "INSERT INTO tenants (id, name, owner_admin_id) VALUES ('t-own', 'Own', ?1)",
        params![member_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO tenants (id, name, owner_admin_id) VALUES ('t-other', 'Other', 1)",
        [],
    )
    .unwrap();
    let _ = drust::storage::tenant_db::open_write(&data, "t-own").unwrap();
    let _ = drust::storage::tenant_db::open_write(&data, "t-other").unwrap();

    // One PAT per non-root admin.
    let member_pat = admin_token::generate_token();
    conn.execute(
        "INSERT INTO _admin_tokens (admin_id, token_hash) VALUES (?1, ?2)",
        params![member_id, admin_token::hash_token(&member_pat)],
    )
    .unwrap();
    let owner2_pat = admin_token::generate_token();
    conn.execute(
        "INSERT INTO _admin_tokens (admin_id, token_hash) VALUES (?1, ?2)",
        params![owner2_id, admin_token::hash_token(&owner2_pat)],
    )
    .unwrap();

    // Shared handles.
    let meta = Arc::new(Mutex::new(conn));
    let tenants = Arc::new(TenantRegistry::new(data.clone(), 4));
    let cache = Arc::new(AuthCache::new(Duration::from_secs(10), 200_000));

    // Data-plane router.
    let bus = EventBus::new();
    let webhooks = WebhookDispatcher::new(tenants.clone(), None);
    let mut auth = TenantAuthState::test_default(meta.clone(), tenants.clone());
    auth.auth_cache = cache.clone();
    let (functions, functions_exec, fn_cfg) = drust::functions::test_stack_parts(tenants.clone());
    let tenant_app = build_tenant_router(TenantStack {
        auth,
        bus: bus.clone(),
        bus_rooms: drust::tenant::rooms::RoomBus::new(),
        bucket: drust::tenant::rooms::RoomsConfig::test_defaults().bucket(),
        rooms_cfg: drust::tenant::rooms::RoomsConfig::test_defaults(),
        mcp: helpers::test_mcp_http(tenants.clone(), bus),
        files: None,
        webhooks,
        functions,
        functions_exec,
        fn_cfg,
        cron: Arc::new(drust::cron::CronState::test_default()),
        cors_origins: Vec::new(),
    });

    // Mgmt router over the SAME meta + auth cache.
    let mcp = Arc::new(drust::mcp::http_registry::McpHttpRegistry::new(Arc::new(
        drust::mcp::server::McpRegistry::new(tenants.clone()),
    )));
    let mut mgmt = MgmtState::test_default(
        meta,
        data.clone(),
        tenants,
        mcp,
        drust::tenant::events::EventBus::new(),
        drust::tenant::rooms::RoomBus::new(),
    );
    mgmt.log_dir = log_dir;
    mgmt.auth_cache = cache;
    let mgmt_app = mgmt.with_data_dir(data);

    Fixture {
        tenant_app,
        mgmt_app,
        member_pat,
        owner2_pat,
        owner2_id,
        _dir: dir,
    }
}

/// GET a bearer-authed data-plane route; returns (status, body).
async fn data_get(app: &axum::Router, tenant: &str, bearer: &str) -> (StatusCode, String) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/t/{tenant}/collections"))
                .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1_048_576)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

async fn login(app: &axum::Router, username: &str, password: &str) -> String {
    let form = format!("username={username}&password={password}");
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "login failed");
    let sc = resp
        .headers()
        .get(header::SET_COOKIE)
        .expect("no Set-Cookie on login")
        .to_str()
        .unwrap();
    sc.split(';').next().unwrap().to_string()
}

async fn admin_patch(
    app: &axum::Router,
    cookie: &str,
    uri: &str,
    body: serde_json::Value,
) -> (StatusCode, String) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(uri)
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1_048_576)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

// ─── 1. member PAT on an owned tenant keeps working ──────────────────────────

#[tokio::test]
async fn member_pat_resolves_on_owned_tenant() {
    let f = spin_up().await;
    let (status, body) = data_get(&f.tenant_app, "t-own", &f.member_pat).await;
    assert_eq!(status, StatusCode::OK, "member PAT on owned tenant: {body}");
}

// ─── 2. member PAT cross-tenant → 403 PAT_TENANT_DENIED ──────────────────────

#[tokio::test]
async fn member_pat_denied_on_foreign_tenant_with_typed_code() {
    let f = spin_up().await;
    let (status, body) = data_get(&f.tenant_app, "t-other", &f.member_pat).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "expected 403, got: {body}");
    assert!(
        body.contains("PAT_TENANT_DENIED"),
        "expected PAT_TENANT_DENIED, got {body}"
    );
    assert!(
        body.contains("WRITE_DENIED"),
        "expected WRITE_DENIED legacy alias, got {body}"
    );
}

// ─── 3. warming the cache on an owned tenant must not open a foreign one ─────

#[tokio::test]
async fn cache_warm_on_owned_tenant_does_not_grant_foreign() {
    let f = spin_up().await;
    // Fill the cache with a legitimate hit bound to t-own …
    let (s1, b1) = data_get(&f.tenant_app, "t-own", &f.member_pat).await;
    assert_eq!(s1, StatusCode::OK, "warm-up on owned tenant: {b1}");
    // … then a cross-tenant request must fall through to the DB deny.
    let (s2, b2) = data_get(&f.tenant_app, "t-other", &f.member_pat).await;
    assert_eq!(s2, StatusCode::FORBIDDEN, "cache warm must not grant: {b2}");
    assert!(b2.contains("PAT_TENANT_DENIED"), "got {b2}");
}

// ─── 4. owner PAT keeps historical cross-tenant reach (zero regression) ──────

#[tokio::test]
async fn owner_pat_keeps_cross_tenant_reach() {
    let f = spin_up().await;
    // t-own is owned by the member admin, t-other by root — the second owner
    // admin owns neither, yet reaches both.
    let (s1, b1) = data_get(&f.tenant_app, "t-own", &f.owner2_pat).await;
    assert_eq!(s1, StatusCode::OK, "owner PAT on t-own: {b1}");
    let (s2, b2) = data_get(&f.tenant_app, "t-other", &f.owner2_pat).await;
    assert_eq!(s2, StatusCode::OK, "owner PAT on t-other: {b2}");
}

// ─── 5. owner→member role flip re-scopes the PAT immediately (hook 13) ───────

#[tokio::test]
async fn role_flip_to_member_rescopes_pat_immediately() {
    let f = spin_up().await;
    // Warm the cache with an owner-privileged hit bound to t-other.
    let (s1, b1) = data_get(&f.tenant_app, "t-other", &f.owner2_pat).await;
    assert_eq!(s1, StatusCode::OK, "pre-flip owner reach: {b1}");

    // Demote own2 to member through the real admin-team route.
    let cookie = login(&f.mgmt_app, "root", "hunter2").await;
    let (status, body) = admin_patch(
        &f.mgmt_app,
        &cookie,
        &format!("/admin/team/{}/role", f.owner2_id),
        serde_json::json!({"role": "member"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "role change failed: {body}");

    // Immediately after (no TTL wait): the cached t-other entry must be gone
    // (hook 13) and the DB path must deny — own2 does not own t-other.
    let (s2, b2) = data_get(&f.tenant_app, "t-other", &f.owner2_pat).await;
    assert_eq!(
        s2,
        StatusCode::FORBIDDEN,
        "demoted admin's PAT must lose foreign tenants immediately: {b2}"
    );
    assert!(b2.contains("PAT_TENANT_DENIED"), "got {b2}");
}

// ─── 6. ownership transfer away denies the ex-owner's PAT immediately ────────

#[tokio::test]
async fn ownership_transfer_away_denies_member_pat_immediately() {
    let f = spin_up().await;
    // Warm the cache with a legitimate hit bound to t-own.
    let (s1, b1) = data_get(&f.tenant_app, "t-own", &f.member_pat).await;
    assert_eq!(s1, StatusCode::OK, "pre-transfer owned reach: {b1}");

    // Root transfers t-own away (member → own2) through the T7 route, whose
    // hook evicts both admins' PAT cache entries.
    let cookie = login(&f.mgmt_app, "root", "hunter2").await;
    let (status, body) = admin_patch(
        &f.mgmt_app,
        &cookie,
        "/admin/api/tenants/t-own/owner",
        serde_json::json!({"owner_admin_id": f.owner2_id}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "transfer failed: {body}");

    // Immediately after (no TTL wait): member PAT loses the tenant.
    let (s2, b2) = data_get(&f.tenant_app, "t-own", &f.member_pat).await;
    assert_eq!(
        s2,
        StatusCode::FORBIDDEN,
        "ex-owner member PAT must lose the transferred tenant immediately: {b2}"
    );
    assert!(b2.contains("PAT_TENANT_DENIED"), "got {b2}");
}
