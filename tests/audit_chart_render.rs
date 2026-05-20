//! v1.17 integration tests — verify the audit pages render with the
//! new chart grid on the overview tab.
//!
//! Reuses the proven app-building shape from tests/audit_ui_routes.rs:
//! same admin creds (root/hunter2), same MgmtState plumbing, same
//! login-cookie helper. Admin pages require an authenticated session,
//! so every test first POSTs /login.

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
    conn.execute(
        "INSERT INTO tenants (id, name) VALUES (?1, ?2)",
        rusqlite::params!["acme", "Acme Inc"],
    )
    .unwrap();
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
        public_url: String::new(),
        oauth_registry: Arc::new(drust::oauth::ProviderRegistry::from_env_empty()),
        oauth_allowlist: Arc::new(std::collections::HashSet::new()),
    };
    let router = state.with_data_dir(data_dir);
    (router, dir)
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
    let sc = resp.headers().get(header::SET_COOKIE).unwrap().to_str().unwrap();
    sc.split(';').next().unwrap().to_string()
}

async fn body_text(resp: axum::http::Response<Body>) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), 4_000_000).await.unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

fn write_entry(log_dir: &std::path::Path, ts: &str, tenant: &str, status: &str, code: Option<&str>) {
    use std::io::Write;
    let date = &ts[..10];
    let path = log_dir.join(format!("audit-{date}.jsonl"));
    std::fs::create_dir_all(log_dir).unwrap();
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .unwrap();
    let code_part = match code {
        Some(c) => format!(r#","error_code":"{c}""#),
        None => String::new(),
    };
    writeln!(
        f,
        r#"{{"ts":"{ts}","tenant":"{tenant}","token_hint":"h","op":"GET /x","status":"{status}","duration_ms":42{code_part}}}"#
    )
    .unwrap();
}

#[tokio::test]
async fn audit_host_page_overview_renders_all_four_charts() {
    let log_td = tempdir().unwrap();
    let log_dir = log_td.path();
    let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    for _ in 0..5 { write_entry(log_dir, &ts, "acme", "ok", None); }
    for _ in 0..2 { write_entry(log_dir, &ts, "acme", "error", Some("HTTP_404")); }

    let (app, _data_td) = app_with_log_dir(log_dir.to_path_buf()).await;
    let cookie = login_session_cookie(&app).await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/audit?tab=overview&window=1h")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let html = body_text(resp).await;
    assert!(html.contains("Requests over time"));
    assert!(html.contains("Top error codes"));
    assert!(html.contains("Latency distribution"));
    assert!(html.contains("Top tenants"));
    let svg_count = html.matches("<svg").count();
    assert!(
        svg_count >= 4,
        "expected ≥4 SVG tags (one per chart card), got {svg_count}"
    );
}

#[tokio::test]
async fn audit_host_page_browse_tab_has_no_charts() {
    let log_td = tempdir().unwrap();
    let (app, _data_td) = app_with_log_dir(log_td.path().to_path_buf()).await;
    let cookie = login_session_cookie(&app).await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/audit?tab=browse&window=1h")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let html = body_text(resp).await;
    assert!(
        !html.contains("Requests over time"),
        "browse tab must NOT render the chart grid"
    );
}

#[tokio::test]
async fn audit_tenant_page_overview_renders_three_charts_no_tenant_card() {
    let log_td = tempdir().unwrap();
    let log_dir = log_td.path();
    let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    write_entry(log_dir, &ts, "acme", "ok", None);

    let (app, _data_td) = app_with_log_dir(log_dir.to_path_buf()).await;
    let cookie = login_session_cookie(&app).await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/tenants/acme/_logs?tab=overview&window=1h")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let html = body_text(resp).await;
    assert!(html.contains("Requests over time"));
    assert!(html.contains("Top error codes"));
    assert!(html.contains("Latency distribution"));
    assert!(
        !html.contains("Top tenants"),
        "per-tenant page must NOT show the Top tenants chart"
    );
}

#[tokio::test]
async fn audit_page_with_zero_entries_renders_without_panic() {
    let log_td = tempdir().unwrap();
    let (app, _data_td) = app_with_log_dir(log_td.path().to_path_buf()).await;
    let cookie = login_session_cookie(&app).await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/audit?tab=overview&window=1h")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let html = body_text(resp).await;
    assert!(
        html.contains("no data") || html.contains("chart-grid"),
        "page must render gracefully with zero entries"
    );
}
