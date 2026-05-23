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

/// Test-only audit DB handle. Owns the underlying tempdir so the SQLite
/// file outlives the test. Exposes a `seed_from_jsonl` shortcut so the
/// fixture-readback tests don't need to duplicate the parse+insert dance.
struct TestAuditDb {
    conn: Arc<Mutex<rusqlite::Connection>>,
    _dir: tempfile::TempDir, // keeps the on-disk file alive
}

impl TestAuditDb {
    fn new() -> Self {
        let dir = tempdir().unwrap();
        let path = dir.path().join("meta_logs.sqlite");
        // Opens read-write + applies SCHEMA_SQL so the SELECTs in the
        // audit handler can prepare against the real schema. Production
        // uses open_audit_db_read here; in tests we use the rw conn
        // directly so the same Mutex<Connection> can also INSERT.
        let conn = drust::safety::audit_db::open_audit_db_write(&path).unwrap();
        Self {
            conn: Arc::new(Mutex::new(conn)),
            _dir: dir,
        }
    }

    /// Parse every audit JSONL file in `log_dir` (production parser via
    /// `scan_window` with a wide-enough window to catch the fixture rows)
    /// and INSERT each entry directly into the audit DB. Mirrors the
    /// production writer task's INSERT shape — same column order, same
    /// `hoist_indexed_fields` extraction of `caller_ip` / `user_agent`
    /// out of the `extra` blob.
    async fn seed_from_jsonl(&self, log_dir: &std::path::Path) {
        let now = chrono::Utc::now();
        let scan = drust::mgmt::audit::scan_window(
            log_dir,
            drust::mgmt::audit::Window::D7,
            now,
        );
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
            let hoist = drust::safety::audit_db::hoist_indexed_fields(entry.extra);
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
    let audit_db = TestAuditDb::new();
    let state = MgmtState {
        meta: Arc::new(Mutex::new(conn)),
        audit_meta_read: audit_db.conn.clone(),
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
        admin_login_rl: Arc::new(drust::safety::rate_limit_ip::IpRateLimit::new(5, std::time::Duration::from_secs(60), 4096)),
        admin_oauth_callback_rl: Arc::new(drust::safety::rate_limit_ip::IpRateLimit::new(5, std::time::Duration::from_secs(60), 4096)),
    };
    let router = state.with_data_dir(data_dir);
    (router, audit_db, dir)
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

/// Write a fixture that includes typed OAuth fields + extra map keys,
/// and an admin-plane row with tenant="-".
fn write_oauth_audit_fixture(log_dir: &std::path::Path) {
    let now = chrono::Utc::now();
    let ts1 = now - chrono::Duration::seconds(180);
    let ts2 = now - chrono::Duration::seconds(90);
    let ts3 = now - chrono::Duration::seconds(30);
    let day = now.format("%Y-%m-%d");
    // Tenant OAuth success row: has auth_method, oauth_email, auth_kind, auth_user_id.
    let line_oauth_ok = format!(
        r#"{{"ts":"{ts1}","tenant":"acme","token_hint":"hashTOK1","op":"oauth_callback","status":"ok","duration_ms":55,"auth_method":"oauth_google","oauth_email":"user@example.com","auth_kind":"user","auth_user_id":"u-abc-123"}}"#,
        ts1 = ts1.format("%Y-%m-%dT%H:%M:%S%.3fZ"),
    );
    // Tenant OAuth failure row: has oauth_error_code.
    let line_oauth_err = format!(
        r#"{{"ts":"{ts2}","tenant":"acme","token_hint":"hashTOK2","op":"oauth_callback","status":"error","duration_ms":10,"auth_method":"oauth_github","oauth_email":"bad@example.com","oauth_error_code":"oauth_state_mismatch"}}"#,
        ts2 = ts2.format("%Y-%m-%dT%H:%M:%S%.3fZ"),
    );
    // Admin-plane row: tenant="-", auth_method set (admin OAuth login).
    let line_admin = format!(
        r#"{{"ts":"{ts3}","tenant":"-","token_hint":"-","op":"admin_oauth_callback","status":"ok","duration_ms":33,"auth_method":"oauth_google","oauth_email":"admin@example.com"}}"#,
        ts3 = ts3.format("%Y-%m-%dT%H:%M:%S%.3fZ"),
    );
    std::fs::create_dir_all(log_dir).unwrap();
    std::fs::write(
        log_dir.join(format!("audit-{day}.jsonl")),
        format!("{line_oauth_ok}\n{line_oauth_err}\n{line_admin}\n"),
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
    let (app, audit_db, _meta) = app_with_log_dir(log_dir.path().to_path_buf()).await;
    audit_db.seed_from_jsonl(log_dir.path()).await;
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
    let (app, audit_db, _meta) = app_with_log_dir(log_dir.path().to_path_buf()).await;
    audit_db.seed_from_jsonl(log_dir.path()).await;
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
    let (app, audit_db, _meta) = app_with_log_dir(log_dir.path().to_path_buf()).await;
    audit_db.seed_from_jsonl(log_dir.path()).await;
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
    let (app, audit_db, _meta) = app_with_log_dir(log_dir.path().to_path_buf()).await;
    audit_db.seed_from_jsonl(log_dir.path()).await;
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
    let (app, audit_db, _meta) = app_with_log_dir(log_dir.path().to_path_buf()).await;
    audit_db.seed_from_jsonl(log_dir.path()).await;
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
    let (app, audit_db, _meta) = app_with_log_dir(log_dir.path().to_path_buf()).await;
    audit_db.seed_from_jsonl(log_dir.path()).await;
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

#[tokio::test]
async fn browse_renders_typed_oauth_fields_and_extra_map() {
    let log_dir = tempdir().unwrap();
    write_oauth_audit_fixture(log_dir.path());
    let (app, audit_db, _meta) = app_with_log_dir(log_dir.path().to_path_buf()).await;
    audit_db.seed_from_jsonl(log_dir.path()).await;
    let cookie = login_session_cookie(&app).await;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/audit?tab=browse")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;

    // Typed OAuth fields must appear in the rendered details block.
    assert!(body.contains("auth_method"), "auth_method label must render");
    assert!(body.contains("oauth_google"), "oauth_google value must render");
    assert!(body.contains("oauth_email"), "oauth_email label must render");
    assert!(body.contains("user@example.com"), "oauth_email value must render");
    assert!(body.contains("oauth_error_code"), "oauth_error_code label must render");
    assert!(body.contains("oauth_state_mismatch"), "oauth_error_code value must render");

    // Extra map keys (auth_kind, auth_user_id) must appear in the extra JSON block.
    assert!(body.contains("auth_kind"), "extra map key auth_kind must render");
    assert!(body.contains("u-abc-123"), "extra map value auth_user_id must render");
}

#[tokio::test]
async fn browse_admin_plane_row_shows_admin_text_not_broken_link() {
    let log_dir = tempdir().unwrap();
    write_oauth_audit_fixture(log_dir.path());
    let (app, audit_db, _meta) = app_with_log_dir(log_dir.path().to_path_buf()).await;
    audit_db.seed_from_jsonl(log_dir.path()).await;
    let cookie = login_session_cookie(&app).await;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/audit?tab=browse")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;

    // Admin-plane rows (tenant="-") must render as a lilac "admin" pill, not a broken link.
    assert!(
        body.contains(r#"<span class="pill lilac">admin</span>"#),
        "admin sentinel must render as <span class=\"pill lilac\">admin</span>"
    );
    assert!(
        !body.contains("/drust/admin/tenants/-/_logs"),
        "broken link to /tenants/-/_logs must not appear"
    );
}

#[tokio::test]
async fn host_browse_renders_tenant_datalist_with_names() {
    let log_dir = tempdir().unwrap();
    write_audit_fixture(log_dir.path());
    let (app, audit_db, _meta) = app_with_log_dir(log_dir.path().to_path_buf()).await;
    audit_db.seed_from_jsonl(log_dir.path()).await;
    let cookie = login_session_cookie(&app).await;
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/audit?tab=browse")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(
        body.contains(r#"<datalist id="tenant-list">"#),
        "host scope must render tenant datalist"
    );
    // The seeded tenant ("Acme Inc") must appear as an option label.
    assert!(body.contains("Acme Inc"), "datalist must render tenant display name");
    assert!(
        body.contains(r#"value="acme""#),
        "datalist option value must be the tenant id"
    );
}

#[tokio::test]
async fn host_browse_renders_op_datalist() {
    let log_dir = tempdir().unwrap();
    write_audit_fixture(log_dir.path());
    let (app, audit_db, _meta) = app_with_log_dir(log_dir.path().to_path_buf()).await;
    audit_db.seed_from_jsonl(log_dir.path()).await;
    let cookie = login_session_cookie(&app).await;
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/audit?tab=browse")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains(r#"<datalist id="op-list">"#));
    // Fixture writes two distinct ops; both must appear as datalist options.
    assert!(body.contains(r#"<option value="GET /records""#));
    assert!(body.contains(r#"<option value="POST /records""#));
}

#[tokio::test]
async fn tenant_browse_does_not_render_tenant_datalist() {
    let log_dir = tempdir().unwrap();
    write_audit_fixture(log_dir.path());
    let (app, audit_db, _meta) = app_with_log_dir(log_dir.path().to_path_buf()).await;
    audit_db.seed_from_jsonl(log_dir.path()).await;
    let cookie = login_session_cookie(&app).await;
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/tenants/acme/_logs?tab=browse")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    // Tenant scope does NOT show the tenant dropdown (only one tenant in view).
    assert!(
        !body.contains(r#"<datalist id="tenant-list">"#),
        "tenant scope must not render tenant datalist"
    );
    // But op datalist remains.
    assert!(body.contains(r#"<datalist id="op-list">"#));
}

#[tokio::test]
async fn host_browse_rows_have_data_idx_attribute() {
    let log_dir = tempdir().unwrap();
    write_audit_fixture(log_dir.path());
    let (app, audit_db, _meta) = app_with_log_dir(log_dir.path().to_path_buf()).await;
    audit_db.seed_from_jsonl(log_dir.path()).await;
    let cookie = login_session_cookie(&app).await;
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/audit?tab=browse")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains(r#"data-idx="0""#), "first row must carry data-idx=0");
    assert!(body.contains(r#"data-idx="1""#), "second row must carry data-idx=1");
    assert!(
        body.contains(r#"role="button""#),
        "tl-row must carry role=button for click-to-modal affordance"
    );
}

#[tokio::test]
async fn host_browse_embeds_entries_json_script() {
    let log_dir = tempdir().unwrap();
    write_audit_fixture(log_dir.path());
    let (app, audit_db, _meta) = app_with_log_dir(log_dir.path().to_path_buf()).await;
    audit_db.seed_from_jsonl(log_dir.path()).await;
    let cookie = login_session_cookie(&app).await;
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/audit?tab=browse")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(
        body.contains(r#"<script id="audit-entries" type="application/json">"#),
        "JSON blob script tag missing"
    );
    // Entry payload must include tenant_name resolution.
    assert!(
        body.contains(r#""tenant_name":"Acme Inc""#),
        "JSON payload must carry resolved tenant_name for known id"
    );
}

#[tokio::test]
async fn host_browse_pill_shows_tenant_name_not_uuid() {
    let log_dir = tempdir().unwrap();
    write_audit_fixture(log_dir.path());
    let (app, audit_db, _meta) = app_with_log_dir(log_dir.path().to_path_buf()).await;
    audit_db.seed_from_jsonl(log_dir.path()).await;
    let cookie = login_session_cookie(&app).await;
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/audit?tab=browse")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    // The pill content must be the resolved name ("Acme Inc"), not the raw id ("acme").
    assert!(
        body.contains(r#"title="acme"#) && body.contains(">Acme Inc<"),
        "pill must show name as text and id as title"
    );
}
