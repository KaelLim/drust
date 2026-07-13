//! Task 8 (v1.48) — admin `⏰ _cron` page: render + create form + toggle +
//! delete over the full mgmt router, plus the shared sidebar `_cron` entry.
//!
//! Harness mirrors `tests/tenant_settings.rs`: real `MgmtState` router (so
//! `admin_session_layer` cookie-or-PAT gating is exercised end to end)
//! authenticated with a known admin PAT bearer. All mutations route through
//! the shared `cron::ops` cores, so target validation / index reload are the
//! same the REST + MCP faces get.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::auth::admin_token;
use drust::mgmt::routes::MgmtState;
use drust::storage::meta::{bootstrap_admin, open_meta};
use drust::storage::pool::TenantRegistry;
use rusqlite::params;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::Mutex;
use tower::ServiceExt;

const TID: &str = "tenant-cron-admin-1";

/// Full mgmt router + one tenant + a seeded function target `f1` (every
/// create in these tests points at it) + a known active admin PAT.
async fn app() -> (axum::Router, String, Arc<TenantRegistry>, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let mut conn = open_meta(&data_dir.join("meta.sqlite")).unwrap();
    bootstrap_admin(&mut conn, "root", "pw").unwrap();
    conn.execute(
        "INSERT INTO tenants (id, name) VALUES (?1, 'Cron Tenant')",
        params![TID],
    )
    .unwrap();
    let _ = drust::storage::tenant_db::open_write(&data_dir, TID).unwrap();
    drust::db::migrations::run_migrations(&conn, &data_dir).unwrap();
    conn.execute(
        "UPDATE _admin_tokens SET revoked_at = datetime('now') \
         WHERE admin_id = 1 AND revoked_at IS NULL",
        [],
    )
    .unwrap();
    let pat = admin_token::generate_token();
    conn.execute(
        "INSERT INTO _admin_tokens (admin_id, token_hash) VALUES (1, ?1)",
        params![admin_token::hash_token(&pat)],
    )
    .unwrap();

    let tenants = Arc::new(TenantRegistry::new(data_dir.clone(), 2));
    // Seed the function target the create form points at (ops::create_job
    // validates target existence through the same get_function REST uses).
    let pool = tenants.get_or_open(TID).unwrap();
    drust::functions::schema::create_function(
        &pool,
        drust::functions::schema::CreateFunctionParams {
            name: "f1".into(),
            wasm_sha256: "00".repeat(32),
            size_bytes: 1,
            triggers_json: "[]".into(),
            description: String::new(),
        },
        10,
    )
    .await
    .unwrap();

    let bus = drust::tenant::events::EventBus::new();
    let mcp = Arc::new(drust::mcp::http_registry::McpHttpRegistry::new(Arc::new(
        drust::mcp::server::McpRegistry::new(tenants.clone()),
    )));
    let state = MgmtState::test_default(
        Arc::new(Mutex::new(conn)),
        data_dir.clone(),
        tenants.clone(),
        mcp,
        bus,
        drust::tenant::rooms::RoomBus::new(),
    );
    let router = state.with_data_dir(data_dir);
    (router, pat, tenants, dir)
}

/// Fetch an admin HTML page with the PAT bearer; returns (status, body).
async fn send_page(app: &axum::Router, uri: String, pat: &str) -> (StatusCode, String) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {pat}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 8 << 20)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// Send a form-encoded POST with the PAT bearer; returns (status, body) —
/// the create error path re-renders the page (200 + banner) instead of
/// redirecting, so callers need the body too.
async fn post_form(
    app: &axum::Router,
    uri: String,
    pat: &str,
    body: String,
) -> (StatusCode, String) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {pat}"))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 8 << 20)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// `(schedule, active)` for a job off the tenant db, or None when the row —
/// or the whole `_system_cron_jobs` table — does not exist.
fn job_row(dir: &tempfile::TempDir, name: &str) -> Option<(String, i64)> {
    let c = rusqlite::Connection::open(dir.path().join("tenants").join(TID).join("data.sqlite"))
        .unwrap();
    match c.query_row(
        "SELECT schedule, active FROM _system_cron_jobs WHERE name = ?1",
        params![name],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)),
    ) {
        Ok(v) => Some(v),
        Err(rusqlite::Error::QueryReturnedNoRows) => None,
        Err(rusqlite::Error::SqliteFailure(_, Some(msg))) if msg.contains("no such table") => None,
        Err(e) => panic!("job_row: {e}"),
    }
}

/// Create the standard test job through the admin form; asserts the 303.
async fn create_tick(app: &axum::Router, pat: &str) {
    let (st, body) = post_form(
        app,
        format!("/admin/tenants/{TID}/_cron"),
        pat,
        "name=tick&schedule=*%2F5+*+*+*+*&target_kind=function&target_name=f1&payload=".into(),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::SEE_OTHER,
        "create must redirect; got {body}"
    );
}

/// (a) GET `_cron` renders 200 with the empty state; the SHARED sidebar (on
/// another tenant page) links the `_cron` virtual entry.
#[tokio::test]
async fn cron_page_renders_empty_state_and_shared_sidebar_entry() {
    let (app, pat, _tenants, _dir) = app().await;

    let (status, html) = send_page(&app, format!("/admin/tenants/{TID}/_cron"), &pat).await;
    assert_eq!(status, StatusCode::OK, "cron page must render");
    assert!(
        html.contains("No cron jobs yet"),
        "empty-state text must be present"
    );
    assert!(
        html.contains(&format!("/admin/tenants/{TID}/_cron")),
        "create form / sidebar must target the _cron routes"
    );

    // Another page including the shared sidebar must link the new entry.
    let (status, html) = send_page(&app, format!("/admin/tenants/{TID}/_settings"), &pat).await;
    assert_eq!(status, StatusCode::OK, "settings page must render");
    assert!(
        html.contains(&format!("/admin/tenants/{TID}/_cron")),
        "shared sidebar must contain the _cron entry"
    );
}

/// (b) POST create form → redirect; the page then lists the job with its
/// schedule and target.
#[tokio::test]
async fn create_form_adds_job_and_page_lists_it() {
    let (app, pat, _tenants, dir) = app().await;
    create_tick(&app, &pat).await;
    assert_eq!(
        job_row(&dir, "tick"),
        Some(("*/5 * * * *".into(), 1)),
        "job stored active with the decoded schedule"
    );

    let (status, html) = send_page(&app, format!("/admin/tenants/{TID}/_cron"), &pat).await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("tick"), "job name listed");
    assert!(html.contains("*/5 * * * *"), "schedule listed");
    assert!(html.contains("function:f1"), "target listed as kind:name");
    assert!(
        !html.contains("No cron jobs yet"),
        "empty state must be gone"
    );
}

/// Create with an invalid schedule re-renders the page with an error banner
/// (no redirect) and writes nothing.
#[tokio::test]
async fn create_with_invalid_schedule_rerenders_with_error() {
    let (app, pat, _tenants, dir) = app().await;
    let (st, html) = post_form(
        &app,
        format!("/admin/tenants/{TID}/_cron"),
        &pat,
        "name=badjob&schedule=@daily&target_kind=function&target_name=f1&payload=".into(),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "error path re-renders the page");
    assert!(
        html.contains("CRON_INVALID_SCHEDULE"),
        "banner must carry the wire code; got: {}",
        &html[..html.len().min(500)]
    );
    assert_eq!(job_row(&dir, "badjob"), None, "nothing written");
}

/// (c) toggle flips active off (page shows the re-enable action) and back on.
#[tokio::test]
async fn toggle_flips_active_and_page_shows_state() {
    let (app, pat, _tenants, dir) = app().await;
    create_tick(&app, &pat).await;

    let (st, _) = post_form(
        &app,
        format!("/admin/tenants/{TID}/_cron/tick/toggle"),
        &pat,
        String::new(),
    )
    .await;
    assert_eq!(st, StatusCode::SEE_OTHER, "toggle redirects back");
    assert_eq!(
        job_row(&dir, "tick"),
        Some(("*/5 * * * *".into(), 0)),
        "toggle must deactivate"
    );
    let (_, html) = send_page(&app, format!("/admin/tenants/{TID}/_cron"), &pat).await;
    assert!(
        html.contains(">Enable<"),
        "inactive job offers the Enable action"
    );

    // Toggle back on round-trips.
    let (st, _) = post_form(
        &app,
        format!("/admin/tenants/{TID}/_cron/tick/toggle"),
        &pat,
        String::new(),
    )
    .await;
    assert_eq!(st, StatusCode::SEE_OTHER);
    assert_eq!(job_row(&dir, "tick"), Some(("*/5 * * * *".into(), 1)));
    let (_, html) = send_page(&app, format!("/admin/tenants/{TID}/_cron"), &pat).await;
    assert!(
        html.contains(">Disable<"),
        "active job offers the Disable action"
    );
}

/// (d) delete removes the job (and is idempotent); the page returns to the
/// empty state.
#[tokio::test]
async fn delete_removes_job_and_page_returns_to_empty() {
    let (app, pat, _tenants, dir) = app().await;
    create_tick(&app, &pat).await;

    let (st, _) = post_form(
        &app,
        format!("/admin/tenants/{TID}/_cron/tick/delete"),
        &pat,
        String::new(),
    )
    .await;
    assert_eq!(st, StatusCode::SEE_OTHER, "delete redirects back");
    assert_eq!(job_row(&dir, "tick"), None, "job row removed");

    let (status, html) = send_page(&app, format!("/admin/tenants/{TID}/_cron"), &pat).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains("No cron jobs yet"),
        "page returns to the empty state"
    );

    // Deleting a gone job is idempotent (functions_admin delete pattern).
    let (st, _) = post_form(
        &app,
        format!("/admin/tenants/{TID}/_cron/tick/delete"),
        &pat,
        String::new(),
    )
    .await;
    assert_eq!(st, StatusCode::SEE_OTHER, "second delete still redirects");
}

/// All `_cron` admin routes live inside the `admin_session_layer`-gated
/// router: no bearer + JSON Accept → 401, never the handler.
#[tokio::test]
async fn cron_admin_routes_require_admin_auth() {
    let (app, _pat, _tenants, _dir) = app().await;
    for (method, uri) in [
        ("GET", format!("/admin/tenants/{TID}/_cron")),
        ("POST", format!("/admin/tenants/{TID}/_cron")),
        ("POST", format!("/admin/tenants/{TID}/_cron/tick/toggle")),
        ("POST", format!("/admin/tenants/{TID}/_cron/tick/delete")),
    ] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(&uri)
                    .header(header::ACCEPT, "application/json")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "{method} {uri} must be admin-gated"
        );
    }
}
