//! v1.32.1 D1 — auth/audit attribution tests, ported from JSONL to SQLite.
//!
//! These tests verify that audit rows emitted by the auth handlers
//! (`/auth/register`, `/auth/login`, `/me`, plain bearer GET) carry the
//! expected `auth_kind` / `auth_method` / `auth_user_id` / `email`
//! fields. Previously they read daily `audit-YYYY-MM-DD.jsonl` files
//! from the tenant's audit dir; v1.25.2 / v1.32.1 (D1) retired the
//! JSONL writer so they now read the process-global SQLite audit DB
//! (filtered by tenant id to stay isolated from parallel tests).

use axum::body::Body;
use axum::http::{Request, header};
use drust::safety::audit_db::{AuditWriter, open_audit_db_read, open_audit_db_write};
use serde_json::json;
use std::path::PathBuf;
use tempfile::tempdir;
use tower::ServiceExt;

mod helpers;

/// One process-wide audit writer, initialised on first call. Writer
/// runs on a dedicated `std::thread` with its own tokio runtime so the
/// task outlives individual `#[tokio::test]` runtimes (each test drops
/// its runtime on completion). Mirrors `tests/common/oauth_helpers.rs::TEST_AUDIT_DB`.
fn ensure_global_audit_writer() -> &'static PathBuf {
    static AUDIT_PATH: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    AUDIT_PATH.get_or_init(|| {
        let dir = Box::new(tempdir().unwrap());
        let path = dir.path().join("test_auth_audit.sqlite");
        let conn = open_audit_db_write(&path).unwrap();
        let (tx_ready, rx_ready) = std::sync::mpsc::channel::<()>();
        std::thread::Builder::new()
            .name("test-auth-audit-writer".into())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("build writer runtime");
                rt.block_on(async move {
                    let writer = AuditWriter::new(conn);
                    drust::safety::audit_db::init_globals(writer);
                    let _ = tx_ready.send(());
                    std::future::pending::<()>().await;
                });
            })
            .expect("spawn audit writer thread");
        rx_ready.recv().expect("audit writer init signal");
        let path_clone = path.clone();
        Box::leak(dir);
        path_clone
    })
}

/// Read every audit row whose tenant matches `tenant`, returning
/// flattened JSON objects (top-level columns merged with the `extra`
/// JSON blob) so the existing assertions like `row["auth_kind"]`,
/// `row["email"]`, `row["auth_user_id"]` work unchanged.
fn read_audit_rows_for_tenant(tenant: &str) -> Vec<serde_json::Value> {
    let path = ensure_global_audit_writer();
    let r = open_audit_db_read(path).unwrap();
    let _ = r.execute_batch("PRAGMA wal_checkpoint(PASSIVE);");
    let mut stmt = r
        .prepare(
            "SELECT tenant, status, op, auth_method, extra \
             FROM audit WHERE tenant = ?1 ORDER BY id ASC",
        )
        .unwrap();
    stmt.query_map(rusqlite::params![tenant], |r| {
        let tenant: Option<String> = r.get(0)?;
        let status: Option<String> = r.get(1)?;
        let op: Option<String> = r.get(2)?;
        let auth_method: Option<String> = r.get(3)?;
        let extra_json: Option<String> = r.get(4)?;
        let mut map = serde_json::Map::new();
        if let Some(t) = tenant {
            map.insert("tenant".into(), serde_json::Value::String(t));
        }
        if let Some(s) = status {
            map.insert("status".into(), serde_json::Value::String(s));
        }
        if let Some(o) = op {
            map.insert("op".into(), serde_json::Value::String(o));
        }
        if let Some(a) = auth_method {
            map.insert("auth_method".into(), serde_json::Value::String(a));
        }
        if let Some(extra_str) = extra_json {
            if let Ok(serde_json::Value::Object(extra_map)) =
                serde_json::from_str::<serde_json::Value>(&extra_str)
            {
                for (k, v) in extra_map {
                    map.entry(k).or_insert(v);
                }
            }
        }
        Ok(serde_json::Value::Object(map))
    })
    .unwrap()
    .filter_map(Result::ok)
    .collect()
}

async fn flush_audit() {
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
}

fn post_json(tid: &str, path: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!("/t/{tid}{path}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

#[tokio::test]
async fn login_audit_records_email_and_auth_user_id() {
    ensure_global_audit_writer();
    let (app, tid, _svc, _anon, _dir) =
        helpers::spin_up_dual_role_self_register("t-aud1").await;
    let _ = app
        .clone()
        .oneshot(post_json(
            &tid,
            "/auth/register",
            json!({"email":"a@b.com","password":"longpassword"}),
        ))
        .await
        .unwrap();
    let _ = app
        .oneshot(post_json(
            &tid,
            "/auth/login",
            json!({"email":"a@b.com","password":"longpassword"}),
        ))
        .await
        .unwrap();
    flush_audit().await;
    let rows = read_audit_rows_for_tenant(&tid);
    let login = rows
        .iter()
        .find(|l| l["op"].as_str().unwrap_or("").contains("/auth/login"))
        .expect("audit must record /auth/login");
    assert_eq!(
        login["email"].as_str().unwrap(),
        "a@b.com",
        "login row must carry email: {login}"
    );
    assert!(
        login["auth_user_id"].as_str().is_some(),
        "login success must record the resolved user id: {login}"
    );
}

#[tokio::test]
async fn audit_never_records_password() {
    ensure_global_audit_writer();
    let secret = "BoldenburgRedAxiom77";
    let (app, tid, _svc, _anon, _dir) =
        helpers::spin_up_dual_role_self_register("t-aud2").await;
    let _ = app
        .clone()
        .oneshot(post_json(
            &tid,
            "/auth/register",
            json!({"email":"a@b.com","password":secret}),
        ))
        .await
        .unwrap();
    let _ = app
        .clone()
        .oneshot(post_json(
            &tid,
            "/auth/login",
            json!({"email":"a@b.com","password":secret}),
        ))
        .await
        .unwrap();
    let _ = app
        .oneshot(post_json(
            &tid,
            "/auth/login",
            json!({"email":"a@b.com","password":"WRONG"}),
        ))
        .await
        .unwrap();
    flush_audit().await;
    let rows = read_audit_rows_for_tenant(&tid);
    for l in &rows {
        let s = serde_json::to_string(l).unwrap();
        assert!(
            !s.contains(secret),
            "S6 violation: password leaked in audit row: {s}"
        );
        assert!(
            !s.contains("WRONG"),
            "S6 violation: failed-login password leaked: {s}"
        );
    }
}

#[tokio::test]
async fn authed_request_carries_auth_kind() {
    ensure_global_audit_writer();
    let (app, tid, svc, _anon, _dir) =
        helpers::spin_up_dual_role_self_register("t-aud3").await;
    // service token request → audit row should have auth_kind=service
    let _ = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/t/{tid}/collections"))
                .header(header::AUTHORIZATION, format!("Bearer {svc}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    flush_audit().await;
    let rows = read_audit_rows_for_tenant(&tid);
    assert!(
        rows.iter().any(|l| l["op"].as_str().unwrap_or("").contains("/collections")
            && l["auth_kind"] == "service"),
        "audit row must carry auth_kind=service: rows={rows:?}"
    );
}

// ---------- T2/T3: auth_kind + auth_method on password flows ----------

#[tokio::test]
async fn register_success_carries_auth_kind_user_and_auth_method_password() {
    ensure_global_audit_writer();
    let (app, tid, _svc, _anon, _dir) =
        helpers::spin_up_dual_role_self_register("t-aud5").await;
    let _ = app
        .oneshot(post_json(
            &tid,
            "/auth/register",
            json!({"email": "reg5@x.com", "password": "longpassword"}),
        ))
        .await
        .unwrap();
    flush_audit().await;
    let rows = read_audit_rows_for_tenant(&tid);
    let row = rows
        .iter()
        .find(|l| l["op"].as_str().unwrap_or("").contains("/auth/register"))
        .expect("audit must record /auth/register");
    assert_eq!(
        row["auth_kind"].as_str().unwrap_or(""),
        "user",
        "register row must carry auth_kind=user: {row}"
    );
    assert_eq!(
        row["auth_method"].as_str().unwrap_or(""),
        "password",
        "register row must carry auth_method=password: {row}"
    );
}

#[tokio::test]
async fn login_failure_carries_auth_kind_user_and_auth_method_password() {
    ensure_global_audit_writer();
    let (app, tid, _svc, _anon, _dir) =
        helpers::spin_up_dual_role_self_register("t-aud6").await;
    // Register first so we get a real user row, then fail with wrong pw.
    let _ = app
        .clone()
        .oneshot(post_json(
            &tid,
            "/auth/register",
            json!({"email": "fail6@x.com", "password": "longpassword"}),
        ))
        .await
        .unwrap();
    let _ = app
        .oneshot(post_json(
            &tid,
            "/auth/login",
            json!({"email": "fail6@x.com", "password": "WRONG-PASSWORD"}),
        ))
        .await
        .unwrap();
    flush_audit().await;
    let rows = read_audit_rows_for_tenant(&tid);
    let row = rows
        .iter()
        .find(|l| {
            l["op"].as_str().unwrap_or("").contains("/auth/login")
                && l["status"] == "error"
        })
        .expect("audit must record a failed /auth/login");
    assert_eq!(
        row["auth_kind"].as_str().unwrap_or(""),
        "user",
        "login failure row must carry auth_kind=user: {row}"
    );
    assert_eq!(
        row["auth_method"].as_str().unwrap_or(""),
        "password",
        "login failure row must carry auth_method=password: {row}"
    );
}

#[tokio::test]
async fn user_request_carries_auth_user_id() {
    ensure_global_audit_writer();
    let (app, tid, _svc, _anon, _dir) =
        helpers::spin_up_dual_role_self_register("t-aud4").await;
    let tok =
        helpers::register_and_login_via_app(&app, &tid, "u@x.com", "longpassword").await;
    let _ = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/t/{tid}/me"))
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    flush_audit().await;
    let rows = read_audit_rows_for_tenant(&tid);
    let me = rows
        .iter()
        .find(|l| l["op"].as_str().unwrap_or("").contains("/me"))
        .expect("audit must record /me");
    assert_eq!(me["auth_kind"], "user");
    assert!(
        me["auth_user_id"].as_str().unwrap_or("").starts_with("u-"),
        "user request must carry auth_user_id: {me}"
    );
}
