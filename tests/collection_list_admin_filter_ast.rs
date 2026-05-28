//! Integration tests for the v1.28 admin _list endpoint — one test per
//! filter operator, plus a two-triple AND case.
//!
//! Fixture: `notes` table with 5 rows.
//!   id | title       | score
//!   1  | apple       | 1
//!   2  | banana      | 2
//!   3  | cherry      | 3
//!   4  | date        | 4
//!   5  | elderberry  | 5

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

    let tenants = Arc::new(drust::storage::pool::TenantRegistry::new(data_dir.clone(), 2));
    let bus = drust::tenant::events::EventBus::new();
    let mcp = Arc::new(drust::mcp::http_registry::McpHttpRegistry::new(Arc::new(
        drust::mcp::server::McpRegistry::new(tenants.clone()),
    )));
    let state = MgmtState {
        meta: Arc::new(Mutex::new(conn)),
        audit_meta_read: Arc::new(Mutex::new(
            drust::safety::audit_db::open_audit_db_memory().unwrap(),
        )),
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
        admin_login_rl: Arc::new(drust::safety::rate_limit_ip::IpRateLimit::new(
            5,
            std::time::Duration::from_secs(60),
            4096,
        )),
        admin_oauth_callback_rl: Arc::new(drust::safety::rate_limit_ip::IpRateLimit::new(
            5,
            std::time::Duration::from_secs(60),
            4096,
        )),
    };
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
    serde_json::from_slice(&bytes).unwrap_or_else(|_| {
        serde_json::json!({ "_raw": String::from_utf8_lossy(&bytes).to_string() })
    })
}

async fn post_list(
    app: &axum::Router,
    cookie: &str,
    body: serde_json::Value,
) -> axum::http::Response<Body> {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/admin/tenants/{TENANT}/collections/notes/_list"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, cookie)
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

/// Build app + seed the `notes` table; return (router, cookie, dir).
async fn seed_notes() -> (axum::Router, String, tempfile::TempDir) {
    let (app, dir) = app_with_tenant().await;
    {
        let writer = drust::storage::tenant_db::open_write(dir.path(), TENANT).unwrap();
        writer
            .execute_batch(
                "CREATE TABLE notes (
                    id    INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT    NOT NULL,
                    score INTEGER
                );
                INSERT INTO notes (title, score) VALUES
                    ('apple',      1),
                    ('banana',     2),
                    ('cherry',     3),
                    ('date',       4),
                    ('elderberry', 5);",
            )
            .unwrap();
    }
    let cookie = login(&app).await;
    (app, cookie, dir)
}

/// Run a _list request and return the number of rows in the response.
async fn row_count(app: &axum::Router, cookie: &str, filters: serde_json::Value) -> usize {
    let resp = post_list(
        app,
        cookie,
        serde_json::json!({
            "filters": filters,
            "page": 1,
            "per_page": 50
        }),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "expected 200 for filters {filters}"
    );
    let j = body_json(resp).await;
    j["rows"].as_array().unwrap().len()
}

// ── operator tests ────────────────────────────────────────────────────────────

#[tokio::test]
async fn op_eq() {
    let (app, cookie, _dir) = seed_notes().await;
    // apple only → 1
    let n = row_count(
        &app,
        &cookie,
        serde_json::json!([{"field":"title","op":"eq","value":"apple"}]),
    )
    .await;
    assert_eq!(n, 1, "eq title=apple expected 1 row");
}

#[tokio::test]
async fn op_ne() {
    let (app, cookie, _dir) = seed_notes().await;
    // everything except apple → 4
    let n = row_count(
        &app,
        &cookie,
        serde_json::json!([{"field":"title","op":"ne","value":"apple"}]),
    )
    .await;
    assert_eq!(n, 4, "ne title=apple expected 4 rows");
}

#[tokio::test]
async fn op_gt() {
    let (app, cookie, _dir) = seed_notes().await;
    // score > 3 → date(4) + elderberry(5) = 2
    let n = row_count(
        &app,
        &cookie,
        serde_json::json!([{"field":"score","op":"gt","value":3}]),
    )
    .await;
    assert_eq!(n, 2, "gt score>3 expected 2 rows");
}

#[tokio::test]
async fn op_gte() {
    let (app, cookie, _dir) = seed_notes().await;
    // score >= 3 → cherry(3), date(4), elderberry(5) = 3
    let n = row_count(
        &app,
        &cookie,
        serde_json::json!([{"field":"score","op":"gte","value":3}]),
    )
    .await;
    assert_eq!(n, 3, "gte score>=3 expected 3 rows");
}

#[tokio::test]
async fn op_lt() {
    let (app, cookie, _dir) = seed_notes().await;
    // score < 3 → apple(1), banana(2) = 2
    let n = row_count(
        &app,
        &cookie,
        serde_json::json!([{"field":"score","op":"lt","value":3}]),
    )
    .await;
    assert_eq!(n, 2, "lt score<3 expected 2 rows");
}

#[tokio::test]
async fn op_lte() {
    let (app, cookie, _dir) = seed_notes().await;
    // score <= 3 → apple(1), banana(2), cherry(3) = 3
    let n = row_count(
        &app,
        &cookie,
        serde_json::json!([{"field":"score","op":"lte","value":3}]),
    )
    .await;
    assert_eq!(n, 3, "lte score<=3 expected 3 rows");
}

#[tokio::test]
async fn op_contains() {
    let (app, cookie, _dir) = seed_notes().await;
    // "err" appears in cherry (ch-err-y) and elderberry (eld-err-berry) → 2
    let n = row_count(
        &app,
        &cookie,
        serde_json::json!([{"field":"title","op":"contains","value":"err"}]),
    )
    .await;
    assert_eq!(n, 2, "contains 'err' expected 2 rows (cherry, elderberry)");
}

#[tokio::test]
async fn op_starts_with() {
    let (app, cookie, _dir) = seed_notes().await;
    // starts with 'a' → apple = 1
    let n = row_count(
        &app,
        &cookie,
        serde_json::json!([{"field":"title","op":"starts_with","value":"a"}]),
    )
    .await;
    assert_eq!(n, 1, "starts_with 'a' expected 1 row (apple)");
}

#[tokio::test]
async fn op_ends_with() {
    let (app, cookie, _dir) = seed_notes().await;
    // ends with 'y' → cherry, elderberry = 2
    let n = row_count(
        &app,
        &cookie,
        serde_json::json!([{"field":"title","op":"ends_with","value":"y"}]),
    )
    .await;
    assert_eq!(n, 2, "ends_with 'y' expected 2 rows (cherry, elderberry)");
}

#[tokio::test]
async fn op_between() {
    let (app, cookie, _dir) = seed_notes().await;
    // score between [2,4] → banana(2), cherry(3), date(4) = 3
    let n = row_count(
        &app,
        &cookie,
        serde_json::json!([{"field":"score","op":"between","value":[2,4]}]),
    )
    .await;
    assert_eq!(n, 3, "between [2,4] expected 3 rows");
}

#[tokio::test]
async fn op_is_null() {
    let (app, cookie, _dir) = seed_notes().await;
    // title is NOT NULL so is_null should return 0 rows
    let n = row_count(
        &app,
        &cookie,
        serde_json::json!([{"field":"title","op":"is_null","value":null}]),
    )
    .await;
    assert_eq!(n, 0, "is_null on non-null column expected 0 rows");
}

#[tokio::test]
async fn op_is_not_null() {
    let (app, cookie, _dir) = seed_notes().await;
    // all 5 titles are non-null
    let n = row_count(
        &app,
        &cookie,
        serde_json::json!([{"field":"title","op":"is_not_null","value":null}]),
    )
    .await;
    assert_eq!(n, 5, "is_not_null on populated column expected 5 rows");
}

#[tokio::test]
async fn op_and_two_filters() {
    let (app, cookie, _dir) = seed_notes().await;
    // score >= 2 AND score <= 4 → banana(2), cherry(3), date(4) = 3
    let n = row_count(
        &app,
        &cookie,
        serde_json::json!([
            {"field":"score","op":"gte","value":2},
            {"field":"score","op":"lte","value":4}
        ]),
    )
    .await;
    assert_eq!(n, 3, "score>=2 AND score<=4 expected 3 rows");
}
