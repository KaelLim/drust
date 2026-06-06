//! v1.28 back-compat: verify that legacy ?tab= query params on the admin
//! collection page produce 302 redirects to the new ?view= scheme.

use axum::body::Body;
use axum::http::{Request, header};
use drust::mgmt::routes::MgmtState;
use drust::storage::meta::{bootstrap_admin, open_meta};
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::Mutex;
use tower::ServiceExt;

const ADMIN: &str = "root";
const PWD: &str = "hunter2";
const TENANT: &str = "acme";

async fn app_with_tenant_and_notes() -> (axum::Router, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let mut conn = open_meta(&data_dir.join("meta.sqlite")).unwrap();
    bootstrap_admin(&mut conn, ADMIN, PWD).unwrap();
    conn.execute(
        "INSERT INTO tenants (id, name) VALUES (?1, ?2)",
        rusqlite::params![TENANT, "Acme"],
    )
    .unwrap();
    // Open tenant DB so tenant directory + SCHEMA_SQL tables get created.
    let writer = drust::storage::tenant_db::open_write(&data_dir, TENANT).unwrap();
    // run_migrations creates _system_users, _system_sessions, etc.
    drust::db::migrations::run_migrations(&conn, &data_dir).unwrap();

    // Create a `notes` collection so the handler finds it and can issue the
    // redirect (without it, describe_collection returns None → 404).
    writer
        .execute(
            "CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT NOT NULL)",
            [],
        )
        .unwrap();
    // Register it in _system_collection_meta so describe_collection finds it.
    writer
        .execute(
            "INSERT OR IGNORE INTO _system_collection_meta \
             (collection_name, anon_caps_json, realtime_enabled) VALUES (?1, ?2, ?3)",
            rusqlite::params!["notes", r#"["select"]"#, 1],
        )
        .unwrap();
    drop(writer);

    let tenants = Arc::new(drust::storage::pool::TenantRegistry::new(
        data_dir.clone(),
        2,
    ));
    let bus = drust::tenant::events::EventBus::new();
    let mcp = Arc::new(drust::mcp::http_registry::McpHttpRegistry::new(Arc::new(
        drust::mcp::server::McpRegistry::new(tenants.clone()),
    )));
    let mut state = MgmtState::test_default(
        Arc::new(Mutex::new(conn)),
        data_dir.clone(),
        tenants,
        mcp,
        bus,
        drust::tenant::rooms::RoomBus::new(),
    );
    state.log_dir = std::env::temp_dir();
    let router = state.with_data_dir(data_dir);
    (router, dir)
}

async fn login(app: &axum::Router) -> String {
    let form = format!("username={ADMIN}&password={PWD}");
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
    let sc = resp
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap();
    sc.split(';').next().unwrap().to_string()
}

async fn get_admin(app: &axum::Router, cookie: &str, path: &str) -> axum::http::Response<Body> {
    app.clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(path)
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn tab_schema_redirects_to_view_definition() {
    let (app, _dir) = app_with_tenant_and_notes().await;
    let cookie = login(&app).await;
    let resp = get_admin(
        &app,
        &cookie,
        &format!("/admin/tenants/{TENANT}/collections/notes?tab=schema"),
    )
    .await;
    // axum Redirect::to emits 303 See Other (the existing browse.rs convention)
    assert!(
        resp.status().is_redirection(),
        "expected redirect, got {}",
        resp.status()
    );
    let loc = resp
        .headers()
        .get("location")
        .expect("Location header missing")
        .to_str()
        .unwrap();
    assert!(
        loc.contains("view=definition") || loc.contains("view%3Ddefinition"),
        "expected view=definition in Location, got: {loc}"
    );
}

#[tokio::test]
async fn tab_indexes_redirects_to_view_definition() {
    let (app, _dir) = app_with_tenant_and_notes().await;
    let cookie = login(&app).await;
    let resp = get_admin(
        &app,
        &cookie,
        &format!("/admin/tenants/{TENANT}/collections/notes?tab=indexes"),
    )
    .await;
    assert!(
        resp.status().is_redirection(),
        "expected redirect, got {}",
        resp.status()
    );
    let loc = resp
        .headers()
        .get("location")
        .expect("Location header missing")
        .to_str()
        .unwrap();
    assert!(
        loc.contains("view=definition") || loc.contains("view%3Ddefinition"),
        "expected view=definition in Location, got: {loc}"
    );
}

#[tokio::test]
async fn tab_anon_redirects_to_view_table() {
    let (app, _dir) = app_with_tenant_and_notes().await;
    let cookie = login(&app).await;
    let resp = get_admin(
        &app,
        &cookie,
        &format!("/admin/tenants/{TENANT}/collections/notes?tab=anon"),
    )
    .await;
    assert!(
        resp.status().is_redirection(),
        "expected redirect, got {}",
        resp.status()
    );
    let loc = resp
        .headers()
        .get("location")
        .expect("Location header missing")
        .to_str()
        .unwrap();
    assert!(
        loc.contains("view=table") || loc.contains("view%3Dtable"),
        "expected view=table in Location, got: {loc}"
    );
}
