//! Integration tests for admin-session-protected index DDL + EXPLAIN endpoints.
//!
//! Routes tested:
//!   POST   /admin/tenants/{id}/collections/{coll}/_indexes
//!   DELETE /admin/tenants/{id}/collections/{coll}/_indexes/{name}
//!   POST   /admin/tenants/{id}/collections/{coll}/_explain

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

/// Build a router with one tenant ("acme") and a "posts" collection.
async fn app_with_tenant_and_coll() -> (axum::Router, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let mut conn = open_meta(&data_dir.join("meta.sqlite")).unwrap();
    bootstrap_admin(&mut conn, ADMIN, PWD).unwrap();
    conn.execute(
        "INSERT INTO tenants (id, name) VALUES (?1, ?2)",
        rusqlite::params!["acme", "Acme Inc"],
    )
    .unwrap();
    // Open the tenant DB and create the posts table.
    let writer = drust::storage::tenant_db::open_write(&data_dir, "acme").unwrap();
    writer
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS posts (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                author_id INTEGER
            );",
        )
        .unwrap();
    drop(writer);

    let tenants = Arc::new(drust::storage::pool::TenantRegistry::new(data_dir.clone(), 2));
    let bus = drust::tenant::events::EventBus::new();
    let mcp = Arc::new(drust::mcp::http_registry::McpHttpRegistry::new(Arc::new(
        drust::mcp::server::McpRegistry::new(tenants.clone()),
    )));
    let state = MgmtState {
        meta: Arc::new(Mutex::new(conn)),
        session_ttl_days: 7,
        garage: None,
        public_base_url: "http://localhost:8793".to_string(),
        max_upload_bytes: 52_428_800,
        garage_client_key_id: String::new(),
        disk_min_free_pct: 20,
        log_dir: std::env::temp_dir(),
        url_sign_secret: Arc::new([0u8; 32]),
        tenants,
        mcp,
        bus,
        index_large_table_rows: 1_000_000,
        public_url: String::new(),
        oauth_registry: Arc::new(drust::oauth::ProviderRegistry::from_env_empty()),
        oauth_allowlist: Arc::new(std::collections::HashSet::new()),
    };
    let router = state.with_data_dir(data_dir);
    (router, dir)
}

/// POST /login and return the `drust_session=…` cookie string.
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
    serde_json::from_slice(&bytes).unwrap_or_else(|_| {
        serde_json::json!({ "_raw": String::from_utf8_lossy(&bytes).to_string() })
    })
}

// ── unauthenticated guard ─────────────────────────────────────────────────────

#[tokio::test]
async fn create_index_unauthenticated_redirects_to_login() {
    let (app, _dir) = app_with_tenant_and_coll().await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/tenants/acme/collections/posts/_indexes")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"fields":["author_id"]}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        matches!(
            resp.status(),
            StatusCode::SEE_OTHER | StatusCode::TEMPORARY_REDIRECT | StatusCode::FOUND
        ),
        "expected redirect, got {}",
        resp.status()
    );
    let loc = resp
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(loc.contains("/login"), "expected /login redirect, got {loc}");
}

// ── create index ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn admin_can_create_index() {
    let (app, _dir) = app_with_tenant_and_coll().await;
    let cookie = login(&app).await;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/tenants/acme/collections/posts/_indexes")
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"fields":["author_id"]}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "body: {:?}",
        body_json(resp).await
    );
}

#[tokio::test]
async fn create_index_unknown_tenant_404() {
    let (app, _dir) = app_with_tenant_and_coll().await;
    let cookie = login(&app).await;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/tenants/no-such/collections/posts/_indexes")
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"fields":["author_id"]}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ── drop index ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn admin_can_drop_index() {
    let (app, _dir) = app_with_tenant_and_coll().await;
    let cookie = login(&app).await;

    // Create first.
    let cr = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/tenants/acme/collections/posts/_indexes")
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"fields":["author_id"]}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cr.status(), StatusCode::CREATED);

    // Drop by auto-generated name.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/admin/tenants/acme/collections/posts/_indexes/idx_posts_author_id")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let body = body_json(resp).await;
    assert!(status.is_success(), "drop failed: {status} — {body}");
    assert_eq!(body["ok"], true);
    assert_eq!(body["dropped_name"], "idx_posts_author_id");
}

#[tokio::test]
async fn drop_index_unknown_index_404() {
    let (app, _dir) = app_with_tenant_and_coll().await;
    let cookie = login(&app).await;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/admin/tenants/acme/collections/posts/_indexes/idx_no_such")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ── explain ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn admin_can_explain() {
    let (app, _dir) = app_with_tenant_and_coll().await;
    let cookie = login(&app).await;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/tenants/acme/collections/posts/_explain")
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"sql":"SELECT * FROM posts WHERE author_id = 1"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert!(body["plan"].is_array(), "expected plan array, got {body}");
}

#[tokio::test]
async fn explain_unknown_tenant_404() {
    let (app, _dir) = app_with_tenant_and_coll().await;
    let cookie = login(&app).await;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/tenants/no-such/collections/posts/_explain")
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"sql":"SELECT * FROM posts"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn explain_rejects_write_sql() {
    let (app, _dir) = app_with_tenant_and_coll().await;
    let cookie = login(&app).await;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/tenants/acme/collections/posts/_explain")
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"sql":"INSERT INTO posts(author_id) VALUES(1)"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_json(resp).await;
    let code = body["error_code"].as_str().unwrap_or("");
    assert!(
        code == "SQL_NOT_ALLOWED" || code == "SQL_PARSE_ERROR" || code == "SQL_ERROR",
        "unexpected error_code: {code}"
    );
}
