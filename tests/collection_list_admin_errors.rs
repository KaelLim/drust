//! Error-path integration tests for the v1.28 admin _list endpoint.
//!
//! Covers: unknown filter op, unknown filter field, unknown sort field,
//! and missing collection.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::mgmt::routes::MgmtState;
use drust::storage::meta::{bootstrap_admin, open_meta};
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::Mutex;
use tower::ServiceExt;

const ADMIN: &str = "root";
const PWD: &str = "hunter2";
const TENANT: &str = "acme";

// ── boilerplate ───────────────────────────────────────────────────────────────

async fn app_with_tenant() -> (axum::Router, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let mut conn = open_meta(&data_dir.join("meta.sqlite")).unwrap();
    bootstrap_admin(&mut conn, ADMIN, PWD).unwrap();
    conn.execute(
        "INSERT INTO tenants (id, name) VALUES (?1, ?2)",
        rusqlite::params![TENANT, "Acme"],
    )
    .unwrap();
    let _ = drust::storage::tenant_db::open_write(&data_dir, TENANT).unwrap();
    drust::db::migrations::run_migrations(&conn, &data_dir).unwrap();

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

async fn body_json(resp: axum::http::Response<Body>) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 4_000_000)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap_or_else(
        |_| serde_json::json!({ "_raw": String::from_utf8_lossy(&bytes).to_string() }),
    )
}

async fn post_list(
    app: &axum::Router,
    cookie: &str,
    coll: &str,
    body: serde_json::Value,
) -> axum::http::Response<Body> {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/admin/tenants/{TENANT}/collections/{coll}/_list"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, cookie)
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

/// Seed a minimal `notes` table (title only) for error-path tests.
async fn seed_notes_minimal() -> (axum::Router, String, tempfile::TempDir) {
    let (app, dir) = app_with_tenant().await;
    {
        let writer = drust::storage::tenant_db::open_write(dir.path(), TENANT).unwrap();
        writer
            .execute_batch(
                "CREATE TABLE notes (
                    id    INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL
                );
                INSERT INTO notes (title) VALUES ('alpha'), ('beta');",
            )
            .unwrap();
    }
    let cookie = login(&app).await;
    (app, cookie, dir)
}

// ── error tests ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn unknown_op_returns_400_invalid_filter() {
    let (app, cookie, _dir) = seed_notes_minimal().await;
    let resp = post_list(
        &app,
        &cookie,
        "notes",
        serde_json::json!({
            "filters": [{"field": "title", "op": "matches_regex", "value": "x"}],
            "page": 1,
            "per_page": 10
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let j = body_json(resp).await;
    assert_eq!(
        j["error_code"], "INVALID_FILTER",
        "expected INVALID_FILTER, got {j}"
    );
}

#[tokio::test]
async fn unknown_field_returns_400_invalid_filter() {
    let (app, cookie, _dir) = seed_notes_minimal().await;
    let resp = post_list(
        &app,
        &cookie,
        "notes",
        serde_json::json!({
            "filters": [{"field": "no_such_column", "op": "eq", "value": "x"}],
            "page": 1,
            "per_page": 10
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let j = body_json(resp).await;
    assert_eq!(
        j["error_code"], "INVALID_FILTER",
        "expected INVALID_FILTER for unknown field, got {j}"
    );
}

#[tokio::test]
async fn unknown_sort_field_returns_400() {
    let (app, cookie, _dir) = seed_notes_minimal().await;
    let resp = post_list(
        &app,
        &cookie,
        "notes",
        serde_json::json!({
            "filters": [],
            "sort": {"field": "missing_col", "dir": "asc"},
            "page": 1,
            "per_page": 10
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let j = body_json(resp).await;
    assert_eq!(
        j["error_code"], "UNKNOWN_SORT_FIELD",
        "expected UNKNOWN_SORT_FIELD, got {j}"
    );
}

#[tokio::test]
async fn missing_collection_returns_404() {
    let (app, _dir) = app_with_tenant().await;
    let cookie = login(&app).await;
    let resp = post_list(
        &app,
        &cookie,
        "no_such_coll",
        serde_json::json!({"filters": [], "page": 1, "per_page": 10}),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let j = body_json(resp).await;
    assert_eq!(
        j["error_code"], "COLLECTION_NOT_FOUND",
        "expected COLLECTION_NOT_FOUND, got {j}"
    );
}
