//! Integration tests: OAuth 2.1 /authorize — GET consent screen + POST code issuance.
//!
//! Covers:
//!   1. GET /oauth/authorize without a session cookie → 303 to /drust/login
//!      with a `drust_oauth_intent` cookie containing the original OAuth URL.
//!   2. GET /oauth/authorize with a valid admin session → 200 consent page.
//!   3. POST /oauth/authorize (decision=approve) with a valid session →
//!      303 to redirect_uri with `?code=...&state=...`.
//!
//! v1.29.0 — Task 14.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::auth::session::create_session;
use drust::db::migrations::{SQL_CREATE_OAUTH_CLIENTS_IF_NOT_EXISTS, SQL_CREATE_OAUTH_CODES_IF_NOT_EXISTS};
use drust::mgmt::routes::MgmtState;
use drust::storage::meta::{bootstrap_admin, open_meta};
use rusqlite::params;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::Mutex;
use tower::ServiceExt;

// ─── helpers ─────────────────────────────────────────────────────────────────

fn build_state(conn: rusqlite::Connection, data_dir: PathBuf, log_dir: PathBuf) -> MgmtState {
    let tenants = Arc::new(drust::storage::pool::TenantRegistry::new(data_dir, 2));
    let bus = drust::tenant::events::EventBus::new();
    let mcp = Arc::new(drust::mcp::http_registry::McpHttpRegistry::new(Arc::new(
        drust::mcp::server::McpRegistry::new(tenants.clone()),
    )));
    MgmtState {
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
        log_dir,
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
    }
}

/// Spin up a router with a bootstrapped admin and a registered OAuth client.
/// Returns (router, session_token, client_id, dir).
async fn spin_up_with_client() -> (axum::Router, String, String, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let log_dir = data_dir.join("audit");
    std::fs::create_dir_all(&log_dir).unwrap();
    let mut conn = open_meta(&data_dir.join("meta.sqlite")).unwrap();
    bootstrap_admin(&mut conn, "root", "hunter2").unwrap();
    drust::db::migrations::run_migrations(&conn, &data_dir).unwrap();

    // Manually ensure OAuth tables exist (run_migrations includes them, but belt + suspenders)
    conn.execute_batch(SQL_CREATE_OAUTH_CLIENTS_IF_NOT_EXISTS).unwrap();
    conn.execute_batch(SQL_CREATE_OAUTH_CODES_IF_NOT_EXISTS).unwrap();

    // Insert a registered client
    let client_id = "drust_client_testclient001";
    conn.execute(
        "INSERT OR IGNORE INTO _oauth_clients (id, client_name, redirect_uris_json)
         VALUES (?1, 'TestClient', ?2)",
        params![
            client_id,
            r#"["http://localhost:55555/callback"]"#,
        ],
    )
    .unwrap();

    // Create a valid admin session (admin_id=1 bootstrapped above)
    let session_token = create_session(&mut conn, 1, 86400).unwrap();

    let state = build_state(conn, data_dir.clone(), log_dir);
    let router = state.with_data_dir(data_dir);
    (router, session_token, client_id.to_string(), dir)
}

fn authorize_uri(client_id: &str) -> String {
    format!(
        "/oauth/authorize?response_type=code&client_id={client_id}\
         &redirect_uri=http%3A%2F%2Flocalhost%3A55555%2Fcallback\
         &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM\
         &code_challenge_method=S256\
         &state=teststate123\
         &resource=https%3A%2F%2Ftool.tzuchi-org.tw%2Fdrust%2Ft%2Fsome-tenant%2Fmcp\
         &scope=drust"
    )
}

fn extract_set_cookie(resp: &axum::response::Response, name: &str) -> Option<String> {
    for val in resp.headers().get_all(header::SET_COOKIE).iter() {
        let s = val.to_str().ok()?;
        if let Some(v) = s.strip_prefix(&format!("{name}=")) {
            let value = v.split(';').next().unwrap_or("").to_string();
            return Some(value);
        }
    }
    None
}

// ─── tests ───────────────────────────────────────────────────────────────────

/// T1: GET /oauth/authorize without a session → 303 to /drust/login
/// and the drust_oauth_intent cookie is set with the original OAuth URL path.
#[tokio::test]
async fn authorize_get_no_session_redirects_to_login_with_intent_cookie() {
    let (app, _session, client_id, _dir) = spin_up_with_client().await;
    let uri = authorize_uri(&client_id);
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(&uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Must redirect to login
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers().get(header::LOCATION).unwrap().to_str().unwrap();
    assert_eq!(location, "/drust/login");

    // Intent cookie must be set
    let intent = extract_set_cookie(&resp, "drust_oauth_intent");
    assert!(
        intent.is_some(),
        "drust_oauth_intent cookie should be set; headers: {:?}",
        resp.headers()
    );
    let decoded = urlencoding::decode(intent.as_deref().unwrap()).unwrap();
    assert!(
        decoded.contains("/oauth/authorize"),
        "intent cookie should contain /oauth/authorize, got: {decoded}"
    );
    assert!(
        decoded.contains(&client_id),
        "intent cookie should contain client_id, got: {decoded}"
    );
}

/// T2: GET /oauth/authorize with a valid admin session → 200 consent page.
#[tokio::test]
async fn authorize_get_with_session_renders_consent_page() {
    let (app, session_token, client_id, _dir) = spin_up_with_client().await;
    let uri = authorize_uri(&client_id);
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(&uri)
                .header(
                    header::COOKIE,
                    format!("drust_session={session_token}"),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 65536 * 4).await.unwrap();
    let html = String::from_utf8_lossy(&body);
    assert!(
        html.contains("TestClient"),
        "consent page should mention the client name, got:\n{html}"
    );
    assert!(
        html.contains("/drust/oauth/authorize"),
        "consent page should have form posting to /drust/oauth/authorize"
    );
}

/// T3: POST /oauth/authorize (decision=approve) with valid session →
/// 303 redirect to redirect_uri with ?code=...&state=teststate123
#[tokio::test]
async fn authorize_post_approve_issues_code_and_redirects() {
    let (app, session_token, client_id, _dir) = spin_up_with_client().await;
    let body_str = format!(
        "client_id={client_id}\
         &redirect_uri=http%3A%2F%2Flocalhost%3A55555%2Fcallback\
         &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM\
         &code_challenge_method=S256\
         &state=teststate123\
         &resource=https%3A%2F%2Ftool.tzuchi-org.tw%2Fdrust%2Ft%2Fsome-tenant%2Fmcp\
         &scope=drust\
         &decision=approve"
    );
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/authorize")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, format!("drust_session={session_token}"))
                .body(Body::from(body_str))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers().get(header::LOCATION).unwrap().to_str().unwrap();
    assert!(
        location.starts_with("http://localhost:55555/callback?code="),
        "location should start with redirect_uri?code=..., got: {location}"
    );
    assert!(
        location.contains("state=teststate123"),
        "location should carry state param, got: {location}"
    );
    // Code must start with drust_ac_
    let code_part = location
        .split("code=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap();
    let code = urlencoding::decode(code_part).unwrap();
    assert!(
        code.starts_with("drust_ac_"),
        "issued code should start with drust_ac_, got: {code}"
    );
}
