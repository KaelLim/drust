//! T8.3: GET /admin/api/audit + /admin/api/tenants/{id}/audit — JSON twins of
//! the audit UI pages. Helpers copied from tests/audit_ui_routes.rs:19-137.

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

struct TestAuditDb {
    conn: Arc<Mutex<rusqlite::Connection>>,
    _dir: tempfile::TempDir,
}

impl TestAuditDb {
    fn new() -> Self {
        let dir = tempdir().unwrap();
        let path = dir.path().join("meta_logs.sqlite");
        let conn = drust::safety::audit_db::open_audit_db_write(&path).unwrap();
        Self {
            conn: Arc::new(Mutex::new(conn)),
            _dir: dir,
        }
    }

    async fn seed_from_jsonl(&self, log_dir: &std::path::Path) {
        let now = chrono::Utc::now();
        let scan = drust::mgmt::audit::scan_window(log_dir, drust::mgmt::audit::Window::D7, now);
        let conn = self.conn.lock().await;
        let mut stmt = conn
            .prepare(
                "INSERT INTO audit (ts, tenant, token_hint, op, status, duration_ms,
                                    error_code, auth_method, oauth_email, oauth_error_code,
                                    caller_ip, user_agent, extra)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            )
            .unwrap();
        for entry in scan.entries {
            let hoist = drust::safety::audit_db::hoist_indexed_fields(&entry);
            stmt.execute(rusqlite::params![
                entry.ts,
                entry.tenant,
                entry.token_hint,
                entry.op,
                entry.status,
                entry.duration_ms as i64,
                entry.error_code,
                entry.auth_method,
                entry.oauth_email,
                entry.oauth_error_code,
                hoist.caller_ip,
                hoist.user_agent,
                hoist.remaining_json,
            ])
            .unwrap();
        }
    }
}

async fn app_with_log_dir(log_dir: PathBuf) -> (axum::Router, TestAuditDb, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let mut conn = open_meta(&data_dir.join("meta.sqlite")).unwrap();
    bootstrap_admin(&mut conn, ADMIN, PWD).unwrap();
    drust::db::migrations::run_migrations(&conn, &data_dir).unwrap();
    conn.execute(
        "INSERT INTO tenants (id, name) VALUES (?1, ?2)",
        rusqlite::params!["acme", "Acme Inc"],
    )
    .unwrap();
    let _ = drust::storage::tenant_db::open_write(&data_dir, "acme").unwrap();
    let tenants = Arc::new(drust::storage::pool::TenantRegistry::new(
        data_dir.clone(),
        2,
    ));
    let bus = drust::tenant::events::EventBus::new();
    let mcp = Arc::new(drust::mcp::http_registry::McpHttpRegistry::new(Arc::new(
        drust::mcp::server::McpRegistry::new(tenants.clone()),
    )));
    let audit_db = TestAuditDb::new();
    let mut state = MgmtState::test_default(
        Arc::new(Mutex::new(conn)),
        data_dir.clone(),
        tenants,
        mcp,
        bus,
        drust::tenant::rooms::RoomBus::new(),
    );
    state.audit_meta_read = audit_db.conn.clone();
    state.log_dir = log_dir;
    let router = state.with_data_dir(data_dir);
    (router, audit_db, dir)
}

fn write_audit_fixture(log_dir: &std::path::Path) {
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

async fn login(app: &axum::Router, username: &str, password: &str) -> String {
    let form = format!("username={username}&password={password}");
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
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "login failed");
    let sc = resp
        .headers()
        .get(header::SET_COOKIE)
        .expect("no Set-Cookie on login")
        .to_str()
        .unwrap();
    sc.split(';').next().unwrap().to_string()
}

async fn body_json(resp: axum::http::Response<Body>) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1_000_000)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

#[tokio::test]
async fn audit_json_overview_and_tenant_filter() {
    let dir = tempdir().unwrap();
    let log_dir = dir.path().join("audit");
    write_audit_fixture(&log_dir); // acme/ok + beta/error (audit_ui_routes.rs:116)
    let (app, audit_db, _d) = app_with_log_dir(log_dir.clone()).await;
    audit_db.seed_from_jsonl(&log_dir).await; // load rows into audit DB
    let cookie = login(&app, "root", "hunter2").await;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/api/audit?tab=overview&window=24h")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["overview"]["total"], 2);
    assert_eq!(body["overview"]["error_count"], 1);

    // tenant-scoped → only acme's row
    let t = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/api/tenants/acme/audit?tab=overview&window=24h")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(body_json(t).await["overview"]["total"], 1);

    // browse → entries array with op
    let b = app
        .oneshot(
            Request::builder()
                .uri("/admin/api/audit?tab=browse&window=24h")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bb = body_json(b).await;
    assert!(
        bb["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["op"] == "GET /records")
    );
}
