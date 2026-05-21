//! Integration tests for T27 + T28:
//!   T27: _system_users virtual sidebar entry + password_hash column masking.
//!   T28: POST /admin/tenants/{id}/allow-self-register toggle endpoint.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::mgmt::routes::MgmtState;
use drust::storage::meta::{bootstrap_admin, open_meta};
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::Mutex;
use tower::ServiceExt;

mod helpers;

const ADMIN: &str = "root";
const PWD: &str = "hunter2";
const TENANT: &str = "t-aui1";

// ─── App spin-up ─────────────────────────────────────────────────────────────

/// Spin up a full admin router (same pattern as audit_ui_routes.rs) plus a
/// real tenant so the sidebar + collection_rows_page handlers can do their
/// work. Returns (router, tenant_id, svc_token, _tempdir).
async fn admin_app_with_tenant() -> (axum::Router, String, String, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let mut conn = open_meta(&data_dir.join("meta.sqlite")).unwrap();
    bootstrap_admin(&mut conn, ADMIN, PWD).unwrap();

    // Insert tenant + service token (plain, not role-bearing — sufficient for
    // the admin-side tests since we don't hit tenant routes here).
    let svc_tok = drust::auth::bearer::generate_token();
    let svc_hash = drust::auth::bearer::hash_token(&svc_tok);
    conn.execute(
        "INSERT INTO tenants (id, name) VALUES (?1, ?2)",
        rusqlite::params![TENANT, "UI Test Tenant"],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO tokens (tenant_id, token_hash, plaintext, role) VALUES (?1, ?2, ?3, 'service')",
        rusqlite::params![TENANT, svc_hash, svc_tok],
    )
    .unwrap();

    // Initialise data.sqlite (so open_read works) + run migrations (creates
    // _system_users table).
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
    let state = MgmtState {
        meta: Arc::new(Mutex::new(conn)),
        session_ttl_days: 7,
        garage: None,
        public_base_url: "http://localhost:8793".to_string(),
        max_upload_bytes: 52_428_800,
        garage_client_key_id: String::new(),
        disk_min_free_pct: 20,
        log_dir: PathBuf::from("/tmp"),
        url_sign_secret: Arc::new([0u8; 32]),
        tenants,
        mcp,
        bus,
        index_large_table_rows: 1_000_000,
        public_url: String::new(),
        oauth_registry: Arc::new(drust::oauth::ProviderRegistry::from_env_empty()),
        oauth_allowlist: Arc::new(std::collections::HashSet::new()),
        admin_login_rl: Arc::new(drust::safety::rate_limit_ip::IpRateLimit::new(5, std::time::Duration::from_secs(60), 4096)),
        admin_oauth_callback_rl: Arc::new(drust::safety::rate_limit_ip::IpRateLimit::new(5, std::time::Duration::from_secs(60), 4096)),
    };
    let router = state.with_data_dir(data_dir);
    (router, TENANT.to_string(), svc_tok, dir)
}

async fn login_cookie(app: &axum::Router) -> String {
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

async fn body_string(resp: axum::http::Response<Body>) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), 4_000_000)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

// ─── T27 tests ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn sidebar_html_contains_system_users_entry() {
    let (app, tid, _svc, _dir) = admin_app_with_tenant().await;
    let cookie = login_cookie(&app).await;

    // The sidebar is included on the _api_keys page — quickest page to hit.
    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/admin/tenants/{tid}/_api_keys"))
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let html = body_string(resp).await;
    // The virtual sidebar entry must appear with the right href.
    assert!(
        html.contains(&format!(
            "/drust/admin/tenants/{tid}/collections/_system_users"
        )),
        "sidebar should contain _system_users link"
    );
    assert!(
        html.contains("_system_users"),
        "sidebar should contain _system_users label"
    );
}

#[tokio::test]
async fn system_users_collection_page_returns_200() {
    let (app, tid, _svc, _dir) = admin_app_with_tenant().await;
    let cookie = login_cookie(&app).await;

    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/admin/tenants/{tid}/collections/_system_users"
                ))
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "_system_users collection page should return 200"
    );
    let html = body_string(resp).await;
    // The page should show the column header — email column should be present.
    assert!(
        html.contains("email") || html.contains("_system_users"),
        "page should mention _system_users or its columns"
    );
}

/// T27 — password_hash masking unit test.
///
/// We call the private helper indirectly by testing the rendered output of the
/// admin UI after seeding a real user row. The PHC string must not appear in
/// the HTML; the masked sentinel must appear instead.
#[tokio::test]
async fn password_hash_is_masked_in_system_users_page() {
    use drust::storage::pool::TenantRegistry;
    let dir = tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let mut conn = open_meta(&data_dir.join("meta.sqlite")).unwrap();
    bootstrap_admin(&mut conn, ADMIN, PWD).unwrap();

    conn.execute(
        "INSERT INTO tenants (id, name) VALUES (?1, ?2)",
        rusqlite::params![TENANT, "Mask Test"],
    )
    .unwrap();
    // Initialise data.sqlite + migrations (_system_users table).
    let _ = drust::storage::tenant_db::open_write(&data_dir, TENANT).unwrap();
    drust::db::migrations::run_migrations(&conn, &data_dir).unwrap();

    // Seed a user directly into _system_users with a fake argon2 PHC string.
    let fake_phc = "$argon2id$v=19$m=65536,t=3,p=4$fakesaltsaltsalt$fakehashhashhash";
    {
        let reg = TenantRegistry::new(data_dir.clone(), 2);
        let pool = reg.get_or_open(TENANT).unwrap();
        pool.with_writer(|c| {
            c.execute(
                "INSERT INTO _system_users (id, email, password_hash, verified, profile, created_at, updated_at) \
                 VALUES ('u-test-1', 'user@example.com', ?1, 0, '{}', datetime('now'), datetime('now'))",
                rusqlite::params![fake_phc],
            )
        })
        .await
        .unwrap();
    }

    let tenants = Arc::new(drust::storage::pool::TenantRegistry::new(
        data_dir.clone(),
        2,
    ));
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
        log_dir: PathBuf::from("/tmp"),
        url_sign_secret: Arc::new([0u8; 32]),
        tenants,
        mcp,
        bus,
        index_large_table_rows: 1_000_000,
        public_url: String::new(),
        oauth_registry: Arc::new(drust::oauth::ProviderRegistry::from_env_empty()),
        oauth_allowlist: Arc::new(std::collections::HashSet::new()),
        admin_login_rl: Arc::new(drust::safety::rate_limit_ip::IpRateLimit::new(5, std::time::Duration::from_secs(60), 4096)),
        admin_oauth_callback_rl: Arc::new(drust::safety::rate_limit_ip::IpRateLimit::new(5, std::time::Duration::from_secs(60), 4096)),
    };
    let router = state.with_data_dir(data_dir);
    let cookie = login_cookie(&router).await;

    let resp = router
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/admin/tenants/{TENANT}/collections/_system_users"
                ))
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let html = body_string(resp).await;

    // The email should be visible.
    assert!(
        html.contains("user@example.com"),
        "user email should appear in the table"
    );
    // The argon2 PHC string must NOT appear anywhere in the HTML.
    assert!(
        !html.contains("$argon2"),
        "argon2 PHC string must not appear in HTML — it should be masked"
    );
    // The masked sentinel must appear.
    assert!(
        html.contains('\u{25cf}'),
        "masked sentinel (●) must appear in place of password_hash"
    );
}

// ─── T28 tests ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn toggle_self_register_enables_and_disables() {
    let (app, tid, _svc, _dir) = admin_app_with_tenant().await;
    let cookie = login_cookie(&app).await;

    // Enable self-registration.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/admin/tenants/{tid}/allow-self-register"))
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"enabled":true}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "enable should return 200");
    let bytes = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["enabled"], serde_json::json!(true));

    // Disable self-registration.
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/admin/tenants/{tid}/allow-self-register"))
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"enabled":false}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "disable should return 200");
    let bytes = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["enabled"], serde_json::json!(false));
}

#[tokio::test]
async fn toggle_self_register_returns_404_for_unknown_tenant() {
    let (app, _tid, _svc, _dir) = admin_app_with_tenant().await;
    let cookie = login_cookie(&app).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/tenants/no-such-tenant/allow-self-register")
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"enabled":true}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn api_keys_page_shows_registration_toggle_card() {
    let (app, tid, _svc, _dir) = admin_app_with_tenant().await;
    let cookie = login_cookie(&app).await;

    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/admin/tenants/{tid}/_api_keys"))
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let html = body_string(resp).await;
    // The Registration card must appear.
    assert!(
        html.contains("allow-self-register"),
        "api_keys page should include the self-register toggle endpoint"
    );
    assert!(
        html.contains("self-reg-toggle"),
        "api_keys page should include the checkbox id"
    );
}
