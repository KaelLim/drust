//! Integration tests for /admin/audit and /admin/tenants/{id}/_logs.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::mgmt::routes::MgmtState;
use drust::storage::meta::{bootstrap_admin, open_meta};
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::Mutex;
use tower::ServiceExt;

const ADMIN: &str = "root";
const PWD: &str = "hunter2";

async fn app_with_log_dir(log_dir: PathBuf) -> (axum::Router, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let mut conn = open_meta(&data_dir.join("meta.sqlite")).unwrap();
    bootstrap_admin(&mut conn, ADMIN, PWD).unwrap();
    // Insert a test tenant so the per-tenant route can find it.
    conn.execute(
        "INSERT INTO tenants (id, name) VALUES (?1, ?2)",
        rusqlite::params!["acme", "Acme Inc"],
    )
    .unwrap();
    // Initialise its data.sqlite so the sidebar context loader doesn't fail.
    let _ = drust::storage::tenant_db::open_write(&data_dir, "acme").unwrap();
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
        log_dir,
        url_sign_secret: Arc::new([0u8; 32]),
        tenants,
        mcp,
        bus,
        index_large_table_rows: 1_000_000,
    };
    let router = state.with_data_dir(data_dir);
    (router, dir)
}

fn write_audit_fixture(log_dir: &std::path::Path) {
    // Use timestamps anchored to "now" (UTC) so the fixture sits inside every
    // window choice (1h / 24h / 7d) regardless of when the test runs.
    let now = chrono::Utc::now();
    let ts_ok = now - chrono::Duration::seconds(120);
    let ts_err = now - chrono::Duration::seconds(60);
    let day = now.format("%Y-%m-%d");
    let ts_ok_s = ts_ok.format("%Y-%m-%dT%H:%M:%S%.3fZ");
    let ts_err_s = ts_err.format("%Y-%m-%dT%H:%M:%S%.3fZ");
    let line_ok = format!(
        r#"{{"ts":"{ts_ok_s}","tenant":"acme","token_hint":"hashOK01","op":"GET /records","status":"ok","duration_ms":42}}"#
    );
    let line_err = format!(
        r#"{{"ts":"{ts_err_s}","tenant":"beta","token_hint":"hashERR1","op":"POST /records","status":"error","duration_ms":12}}"#
    );
    std::fs::create_dir_all(log_dir).unwrap();
    std::fs::write(
        log_dir.join(format!("audit-{day}.jsonl")),
        format!("{line_ok}\n{line_err}\n"),
    )
    .unwrap();
}

async fn login_session_cookie(app: &axum::Router) -> String {
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
    // Extract `drust_session=...` up to the first `;`.
    let cookie = sc.split(';').next().unwrap().to_string();
    cookie
}

async fn body_string(resp: axum::http::Response<Body>) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), 4_000_000)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn host_audit_unauthenticated_redirects_to_login() {
    let log_dir = tempdir().unwrap();
    let (app, _meta) = app_with_log_dir(log_dir.path().to_path_buf()).await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/audit")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        matches!(
            resp.status(),
            StatusCode::SEE_OTHER | StatusCode::TEMPORARY_REDIRECT | StatusCode::FOUND
        ),
        "got {}",
        resp.status()
    );
    let loc = resp
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(loc.contains("/login"), "got Location: {loc}");
}

#[tokio::test]
async fn host_audit_with_session_renders_overview() {
    let log_dir = tempdir().unwrap();
    write_audit_fixture(log_dir.path());
    let (app, _meta) = app_with_log_dir(log_dir.path().to_path_buf()).await;
    let cookie = login_session_cookie(&app).await;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/audit")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("Audit"));
    assert!(body.contains("Top tenants"), "host scope must show Top tenants block");
}

#[tokio::test]
async fn host_audit_browse_filters_status_error() {
    let log_dir = tempdir().unwrap();
    write_audit_fixture(log_dir.path());
    let (app, _meta) = app_with_log_dir(log_dir.path().to_path_buf()).await;
    let cookie = login_session_cookie(&app).await;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/audit?tab=browse&status=error")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("hashERR1"), "error entry should be visible");
    assert!(!body.contains("hashOK01"), "ok entry should be filtered out");
}

#[tokio::test]
async fn tenant_logs_unknown_id_404() {
    let log_dir = tempdir().unwrap();
    let (app, _meta) = app_with_log_dir(log_dir.path().to_path_buf()).await;
    let cookie = login_session_cookie(&app).await;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/tenants/no-such-tenant/_logs")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn tenant_logs_known_id_renders_no_top_tenants() {
    let log_dir = tempdir().unwrap();
    write_audit_fixture(log_dir.path());
    let (app, _meta) = app_with_log_dir(log_dir.path().to_path_buf()).await;
    let cookie = login_session_cookie(&app).await;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/tenants/acme/_logs")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("_logs"));
    assert!(
        !body.contains("Top tenants"),
        "tenant scope must NOT show Top tenants"
    );
}

#[tokio::test]
async fn host_audit_overview_contains_top_tenants_with_data() {
    let log_dir = tempdir().unwrap();
    write_audit_fixture(log_dir.path());
    let (app, _meta) = app_with_log_dir(log_dir.path().to_path_buf()).await;
    let cookie = login_session_cookie(&app).await;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/audit?tab=overview&window=1h")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    // Both fixture tenants present in Top tenants table.
    assert!(body.contains("acme"));
    assert!(body.contains("beta"));
}
