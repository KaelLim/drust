//! Service-key-only guard for the data-plane files router (#1 security fix).
//!
//! Two layers of proof:
//!   - Section 1 (this file, first): unit-tests `require_service_layer`'s logic
//!     by injecting a real `TenantRef` (built like `tests/large_upload_tus.rs`)
//!     via an `Extension` layer — covers anon/user/service AND the fail-closed
//!     "no TenantRef in extensions" branch. No token seeding, no router stack.
//!   - Section 2 (added in Task 2): drives the REAL production router built by
//!     `build_tenant_router` with `files: Some(..)`, so the test fails until the
//!     guard is actually mounted in `src/tenant/mod.rs` — a genuine red→green on
//!     production wiring, not a replica.

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use drust::storage::pool::TenantRegistry;
use drust::tenant::router::{TenantRef, TokenRole, require_service_layer};
use std::sync::Arc;
use tower::ServiceExt;

/// Pull `error_code` out of a JSON error body; returns "" for a non-JSON body
/// (e.g. the probe handler's plain-text success response).
async fn body_error_code(resp: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), 65_536).await.unwrap();
    let v: serde_json::Value =
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    v["error_code"].as_str().unwrap_or("").to_string()
}

/// Build a real `TenantRef` (4 fields, incl. a real `pool`) for `role`, exactly
/// as `tests/large_upload_tus.rs::setup` does. The returned `TempDir` must be
/// kept alive for the life of the request (it backs the tenant db).
fn make_tref(tid: &str, role: TokenRole) -> (tempfile::TempDir, TenantRef) {
    let dir = tempfile::tempdir().unwrap();
    drust::storage::tenant_db::open_write(dir.path(), tid).unwrap();
    let registry = Arc::new(TenantRegistry::new(dir.path().to_path_buf(), 2));
    let pool = registry.get_or_open(tid).unwrap();
    let tref = TenantRef {
        tenant_id: tid.to_string(),
        token_hint: "t".into(),
        pool,
        role,
    };
    (dir, tref)
}

/// Mount the guard over a probe handler, inject a `TenantRef` of `role` via an
/// `Extension` layer applied OUTER to the guard (so it lands in extensions
/// before the guard reads it — mirrors how `bearer_auth_layer` feeds the guard
/// in production). Returns (status, error_code).
async fn guard_status_for(role: TokenRole) -> (StatusCode, String) {
    let (_dir, tref) = make_tref("guard-probe", role);
    let app = Router::new()
        .route("/probe", get(|| async { "reached-handler" }))
        // guard: applied first -> INNER -> runs after the Extension injector.
        .layer(axum::middleware::from_fn(require_service_layer))
        // injector: applied last -> OUTER -> inserts TenantRef before the guard.
        .layer(axum::Extension(tref));
    let resp = app
        .oneshot(Request::builder().uri("/probe").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let code = body_error_code(resp).await;
    (status, code)
}

#[tokio::test]
async fn guard_denies_anon_403_write_denied() {
    let (status, code) = guard_status_for(TokenRole::Anon).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(code, "WRITE_DENIED");
}

#[tokio::test]
async fn guard_denies_user_403_write_denied() {
    // The User arm is the second half of `require_service`'s
    // `matches!(role, Anon | User)` — exercised here without seeding a real
    // `_system_sessions` row (the full-stack path covers anon; user takes the
    // identical code path in the guard).
    let (status, code) = guard_status_for(TokenRole::User).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(code, "WRITE_DENIED");
}

#[tokio::test]
async fn guard_passes_service_reaches_handler() {
    let (status, code) = guard_status_for(TokenRole::Service).await;
    assert_eq!(status, StatusCode::OK, "service must reach the handler");
    assert_eq!(code, "", "success body is plain text, not a WRITE_DENIED error");
}

/// Fail-closed: a request reaching the guard with NO `TenantRef` in extensions
/// (which should be impossible behind `bearer_auth_layer`, but proves the guard
/// never runs the handler "open" if the layer order is ever broken) is denied.
#[tokio::test]
async fn guard_fails_closed_without_tenantref() {
    let app = Router::new()
        .route("/probe", get(|| async { "reached-handler" }))
        .layer(axum::middleware::from_fn(require_service_layer));
    let resp = app
        .oneshot(Request::builder().uri("/probe").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_error_code(resp).await, "WRITE_DENIED");
}

// ─── Section 2: production-router wiring via build_tenant_router ──────────────
// These drive the REAL production router (the same `build_tenant_router` used by
// `tests/helpers.rs`) with the files plane MOUNTED (`files: Some(..)`), so they
// FAIL until the guard is actually wired into `src/tenant/mod.rs` — a genuine
// red->green on production wiring, not a replica that mounts the guard itself.

use drust::auth::bearer::{generate_token, hash_token};
use drust::mcp::http_registry::McpHttpRegistry;
use drust::mcp::server::McpRegistry;
use drust::mgmt::tenant_files::TenantFilesState;
use drust::storage::garage::GarageClient;
use drust::storage::meta::open_meta;
use drust::tenant::events::EventBus;
use drust::tenant::rooms::{RoomBus, RoomsConfig};
use drust::tenant::router::TenantAuthState;
use drust::tenant::{TenantStack, WebhookDispatcher, build_tenant_router};
use tokio::sync::Mutex;

fn mem_garage() -> Arc<GarageClient> {
    Arc::new(GarageClient::from_store(
        Arc::new(object_store::memory::InMemory::new()),
        "unused",
    ))
}

/// Build the REAL production tenant router with the files plane MOUNTED, seeding
/// a service + anon token and an empty `_system_files` table (migrations do not
/// create it, and `list` SELECTs it). `cors_origins` is passed through to
/// `build_cors_layer` for the preflight test. Returns (app, service, anon, dir).
async fn files_stack(
    tenant: &str,
    cors_origins: Vec<String>,
) -> (Router, String, String, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let conn = open_meta(&data.join("meta.sqlite")).unwrap();
    conn.execute(
        "INSERT INTO tenants (id, name) VALUES (?1, 'x')",
        rusqlite::params![tenant],
    )
    .unwrap();
    let svc = generate_token();
    let anon = generate_token();
    conn.execute(
        "INSERT INTO tokens (tenant_id, token_hash, label, role) VALUES (?1, ?2, 'svc', 'service')",
        rusqlite::params![tenant, hash_token(&svc)],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO tokens (tenant_id, token_hash, label, role) VALUES (?1, ?2, 'anon', 'anon')",
        rusqlite::params![tenant, hash_token(&anon)],
    )
    .unwrap();
    drust::storage::tenant_db::open_write(&data, tenant).unwrap();
    // Bearer-auth CTE reads the v1.32.5 allow_*_publish columns; migrate so it
    // doesn't 404 every authed request.
    drust::db::migrations::run_migrations(&conn, &data).unwrap();

    let tenants = Arc::new(TenantRegistry::new(data.clone(), 2));
    // `_system_files` is not created by migrations; the `list` handler SELECTs
    // it, so create an empty one for a clean 200 on service GET /files.
    {
        let pool = tenants.get_or_open(tenant).unwrap();
        pool.with_writer(|c| {
            c.execute_batch(
                "CREATE TABLE IF NOT EXISTS _system_files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key TEXT NOT NULL UNIQUE, original_name TEXT NOT NULL,
                    content_type TEXT, size_bytes INTEGER NOT NULL DEFAULT 0,
                    content_disposition TEXT, visibility TEXT NOT NULL DEFAULT 'public',
                    cache_control TEXT, meta_json TEXT,
                    uploaded_at TEXT NOT NULL DEFAULT (datetime('now')),
                    uploader TEXT NOT NULL DEFAULT 'service');",
            )
        })
        .await
        .unwrap();
    }

    let bus = EventBus::new();
    let webhooks = WebhookDispatcher::new(tenants.clone(), None);
    let meta = Arc::new(Mutex::new(conn));
    let auth_state = TenantAuthState::test_default(meta, tenants.clone());
    let files_state =
        TenantFilesState::test_default(Some(mem_garage()), data.clone(), tenants.clone());
    let mcp = Arc::new(McpHttpRegistry::new(Arc::new(McpRegistry::with_bus(
        tenants.clone(),
        bus.clone(),
    ))));
    let stack = TenantStack {
        auth: auth_state,
        bus: bus.clone(),
        bus_rooms: RoomBus::new(),
        bucket: RoomsConfig::test_defaults().bucket(),
        rooms_cfg: RoomsConfig::test_defaults(),
        mcp,
        files: Some(files_state),
        webhooks,
        cors_origins,
    };
    (build_tenant_router(stack), svc, anon, dir)
}

fn req(method: &str, uri: &str, bearer: Option<&str>) -> Request<Body> {
    let mut b = Request::builder().method(method).uri(uri);
    if let Some(t) = bearer {
        b = b.header("authorization", format!("Bearer {t}"));
    }
    b.body(Body::empty()).unwrap()
}

/// Every data-plane routed method on the production files router: all 8 Mode-A
/// methods (incl. PATCH = set_visibility) + the 5 Mode-B tus methods.
fn data_plane_routes(tenant: &str, key: &str, sess: &str) -> Vec<(&'static str, String)> {
    vec![
        ("POST", format!("/t/{tenant}/files")),
        ("GET", format!("/t/{tenant}/files")),
        ("GET", format!("/t/{tenant}/files/{key}")),
        ("DELETE", format!("/t/{tenant}/files/{key}")),
        ("PATCH", format!("/t/{tenant}/files/{key}")),
        ("GET", format!("/t/{tenant}/files/{key}/bytes")),
        ("POST", format!("/t/{tenant}/files/{key}/sign")),
        ("POST", format!("/t/{tenant}/uploads")),
        ("GET", format!("/t/{tenant}/uploads")),
        ("PATCH", format!("/t/{tenant}/uploads/{sess}")),
        ("HEAD", format!("/t/{tenant}/uploads/{sess}")),
        ("DELETE", format!("/t/{tenant}/uploads/{sess}")),
    ]
}

/// The core security property, end-to-end through the production router:
/// anon and no-token are DENIED on every data-plane routed method; a service
/// token is NEVER blocked by the guard (handler status varies, but never
/// 403/WRITE_DENIED). Fails until the guard is mounted in `src/tenant/mod.rs`.
#[tokio::test]
async fn dataplane_all_methods_deny_non_service_pass_service() {
    let (app, svc, anon, _dir) = files_stack("blog", Vec::new()).await;
    let key = "ffffffff-0000-0000-0000-0000000000aa.txt";
    let sess = "00000000-0000-0000-0000-000000000000";
    for (method, uri) in data_plane_routes("blog", key, sess) {
        // anon -> 403 WRITE_DENIED (guard fires after bearer resolves Anon).
        let r = app
            .clone()
            .oneshot(req(method, &uri, Some(&anon)))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::FORBIDDEN, "anon {method} {uri}");
        if method != "HEAD" {
            assert_eq!(
                body_error_code(r).await,
                "WRITE_DENIED",
                "anon body {method} {uri}"
            );
        }

        // no token -> denied by bearer BEFORE the guard (401/403), never 2xx.
        let r = app.clone().oneshot(req(method, &uri, None)).await.unwrap();
        assert!(
            r.status() == StatusCode::UNAUTHORIZED || r.status() == StatusCode::FORBIDDEN,
            "no-token {method} {uri} must be denied, got {}",
            r.status()
        );

        // service -> guard must NOT block; handler status varies (200/400/404/
        // 422/503) but it must never be the guard's 403 WRITE_DENIED.
        let r = app
            .clone()
            .oneshot(req(method, &uri, Some(&svc)))
            .await
            .unwrap();
        assert_ne!(
            r.status(),
            StatusCode::FORBIDDEN,
            "service must pass guard {method} {uri}"
        );
        if method != "HEAD" {
            assert_ne!(
                body_error_code(r).await,
                "WRITE_DENIED",
                "service must not get WRITE_DENIED {method} {uri}"
            );
        }
    }
}

/// Concrete service-success cell: GET /files (list) returns 200 with an empty
/// `_system_files` table — tightens "not 403" to a real success on the one
/// route that can succeed with no seeded object.
#[tokio::test]
async fn dataplane_service_get_list_200() {
    let (app, svc, _anon, _dir) = files_stack("svc200", Vec::new()).await;
    let r = app
        .oneshot(req("GET", "/t/svc200/files", Some(&svc)))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
}
