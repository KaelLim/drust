//! v1.41.0 integration tests for the `user_caps` admin UI surface.
//! Mirrors `tests/admin_description_write.rs`: mounts only the user-caps
//! route handler-level (no admin-session middleware) and round-trips a
//! repeated-checkbox form through `axum_extra::extract::Form`.

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::routing::post;
use drust::mgmt::browse::update_user_caps;
use drust::mgmt::tenants::TenantsState;
use drust::storage::schema::{DmlVerb, describe_collection};
use drust::storage::meta::open_meta;
use drust::storage::tenant_db::open_read;
use std::collections::BTreeSet;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::Mutex;
use tower::ServiceExt;

async fn build_app(tenant_id: &str) -> (Router, std::path::PathBuf, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let conn = open_meta(&data_dir.join("meta.sqlite")).unwrap();
    conn.execute(
        "INSERT INTO tenants (id, name) VALUES (?1, 'x')",
        rusqlite::params![tenant_id],
    )
    .unwrap();
    let _ = drust::storage::tenant_db::open_write(&data_dir, tenant_id).unwrap();
    drust::db::migrations::run_migrations(&conn, &data_dir).unwrap();

    let meta = Arc::new(Mutex::new(conn));
    let tenants = Arc::new(drust::storage::pool::TenantRegistry::new(
        data_dir.clone(),
        2,
    ));
    let bus = drust::tenant::events::EventBus::new();
    let mcp = Arc::new(drust::mcp::http_registry::McpHttpRegistry::new(Arc::new(
        drust::mcp::server::McpRegistry::new(tenants.clone()),
    )));
    let bus_rooms = drust::tenant::rooms::RoomBus::new();
    let state = TenantsState::test_default(meta, data_dir.clone(), tenants, mcp, bus, bus_rooms);
    let app = Router::new()
        .route(
            "/admin/tenants/{id}/collections/{coll}/user-caps",
            post(update_user_caps),
        )
        .with_state(state);
    (app, data_dir, dir)
}

/// Seed a fresh `posts` collection with anon_caps = [select] so we can
/// prove the user-caps write lands on a SEPARATE column.
async fn seed_posts(data_dir: &std::path::Path, tenant_id: &str) {
    let pool = drust::storage::pool::TenantRegistry::new(data_dir.to_path_buf(), 2);
    let pool = pool.get_or_open(tenant_id).unwrap();
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE IF NOT EXISTS posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
             );
             INSERT INTO _system_collection_meta (collection_name, anon_caps_json)
                  VALUES ('posts', '[\"select\"]')
                  ON CONFLICT DO NOTHING;",
        )
    })
    .await
    .unwrap();
}

async fn post_form(app: &Router, uri: &str, body: &str) -> axum::http::Response<Body> {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn admin_update_user_caps_round_trip() {
    let tid = "admin-user-caps-rt";
    let (app, data_dir, _d) = build_app(tid).await;
    seed_posts(&data_dir, tid).await;

    // POST repeated checkbox keys — only axum_extra::Form decodes these into
    // Vec<String>; plain axum::Form would 422.
    let resp = post_form(
        &app,
        &format!("/admin/tenants/{tid}/collections/posts/user-caps"),
        "caps=select&caps=insert",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "expected 303 redirect");
    let loc = resp
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        loc.contains("/collections/posts?tab=schema"),
        "redirect should match anon-caps target, got: {loc}"
    );

    // Read the persisted user_caps back through describe_collection.
    let rconn = open_read(&data_dir, tid).unwrap();
    let schema = describe_collection(&rconn, "posts").unwrap().unwrap();
    let mut want: BTreeSet<DmlVerb> = BTreeSet::new();
    want.insert(DmlVerb::Select);
    want.insert(DmlVerb::Insert);
    assert_eq!(schema.user_caps, want, "user_caps should reflect the POSTed checkboxes");

    // The split must hold: anon_caps untouched (still just select).
    let mut anon_want: BTreeSet<DmlVerb> = BTreeSet::new();
    anon_want.insert(DmlVerb::Select);
    assert_eq!(schema.anon_caps, anon_want, "anon_caps must NOT change");
}

#[tokio::test]
async fn admin_update_user_caps_empty_locks_user_role() {
    let tid = "admin-user-caps-empty";
    let (app, data_dir, _d) = build_app(tid).await;
    seed_posts(&data_dir, tid).await;

    // Empty form (no caps= keys) → user_caps becomes the empty set.
    let resp = post_form(
        &app,
        &format!("/admin/tenants/{tid}/collections/posts/user-caps"),
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    let rconn = open_read(&data_dir, tid).unwrap();
    let schema = describe_collection(&rconn, "posts").unwrap().unwrap();
    assert!(schema.user_caps.is_empty(), "empty form locks the user role");
}

#[test]
fn zh_tw_has_user_section_key() {
    // build.rs does not check en-present-but-zh-missing keys (build.rs:67-112);
    // this is the only guard that the zh-TW translation actually shipped.
    let zh = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/locales/zh-TW.toml"))
        .expect("read zh-TW.toml");
    let table = zh
        .split("[collection_page.settings.section]")
        .nth(1)
        .expect("zh-TW.toml must contain [collection_page.settings.section] table");
    // Stop at the next table header so we only inspect this table's body.
    let body = table.split("\n[").next().unwrap();
    assert!(
        body.lines().any(|l| l.trim_start().starts_with("user ")
            || l.trim_start().starts_with("user=")),
        "zh-TW.toml [collection_page.settings.section] must define `user`, got:\n{body}"
    );
}
