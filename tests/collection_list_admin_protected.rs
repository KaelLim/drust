//! Verify the v1.28 admin _list endpoint can read _system_* tables
//! (authorizer bypass for admin path) and that password_hash is masked.

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
    // Open tenant DB so the tenant directory + SCHEMA_SQL tables get created.
    let _ = drust::storage::tenant_db::open_write(&data_dir, TENANT).unwrap();
    // run_migrations creates _system_users, _system_sessions, etc.
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
        oauth_register_rl: Arc::new(drust::safety::rate_limit_ip::IpRateLimit::new(
            10,
            std::time::Duration::from_secs(3600),
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
    coll: &str,
    body: serde_json::Value,
) -> axum::http::Response<Body> {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/admin/tenants/{TENANT}/collections/{coll}/_list"
                ))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, cookie)
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn admin_list_can_read_system_users() {
    let (app, _dir) = app_with_tenant().await;
    let cookie = login(&app).await;
    let resp = post_list(
        &app,
        &cookie,
        "_system_users",
        serde_json::json!({"filters": [], "page": 1, "per_page": 10}),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "admin path must bypass authorizer for _system_*; body: {:?}",
        body_json(resp).await
    );
}

#[tokio::test]
async fn password_hash_is_masked() {
    let (app, dir) = app_with_tenant().await;

    // Insert a user directly into the tenant DB to keep this test self-contained.
    let data_dir = dir.path();
    let writer = drust::storage::tenant_db::open_write(data_dir, TENANT).unwrap();
    writer
        .execute(
            "INSERT INTO _system_users \
             (id, email, password_hash, verified, created_at, updated_at) \
             VALUES (?1, ?2, ?3, 0, datetime('now'), datetime('now'))",
            rusqlite::params!["u-1", "alice@example.com", "$argon2id$totally-fake-hash"],
        )
        .unwrap();
    drop(writer);

    let cookie = login(&app).await;
    let resp = post_list(
        &app,
        &cookie,
        "_system_users",
        serde_json::json!({"filters": [], "page": 1, "per_page": 10}),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let j = body_json(resp).await;
    let cols = j["columns"].as_array().unwrap();
    let pw_idx = cols
        .iter()
        .position(|c| c == "password_hash")
        .expect("password_hash must appear in columns");
    let rows = j["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 1, "expected exactly one user row");
    let masked = rows[0][pw_idx].as_str().unwrap();
    assert_eq!(
        masked,
        "\u{25cf}\u{25cf}\u{25cf}\u{25cf}",
        "password_hash must be masked with 4 bullet characters"
    );
}
