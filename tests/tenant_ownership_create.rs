//! v1.50 Task 3 — tenant creation stamps the creating admin as owner
//! (`tenants.owner_admin_id`), including the soft-delete → same-id recycle
//! branch where the NEW creator must win.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::mgmt::routes::MgmtState;
use drust::storage::meta::{bootstrap_admin, open_meta};
use rusqlite::params;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::Mutex;
use tower::ServiceExt;

fn build_state(conn: rusqlite::Connection, data_dir: PathBuf, log_dir: PathBuf) -> MgmtState {
    let tenants = Arc::new(drust::storage::pool::TenantRegistry::new(
        data_dir.clone(),
        2,
    ));
    let bus = drust::tenant::events::EventBus::new();
    let mcp = Arc::new(drust::mcp::http_registry::McpHttpRegistry::new(Arc::new(
        drust::mcp::server::McpRegistry::new(tenants.clone()),
    )));
    let mut state = MgmtState::test_default(
        Arc::new(Mutex::new(conn)),
        data_dir,
        tenants,
        mcp,
        bus,
        drust::tenant::rooms::RoomBus::new(),
    );
    state.log_dir = log_dir;
    state
}

/// Mgmt router with one bootstrapped owner admin ("root"/"hunter2", id 1).
async fn spin_up() -> (axum::Router, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let log_dir = data_dir.join("audit");
    std::fs::create_dir_all(&log_dir).unwrap();
    let mut conn = open_meta(&data_dir.join("meta.sqlite")).unwrap();
    bootstrap_admin(&mut conn, "root", "hunter2").unwrap();
    drust::db::migrations::run_migrations(&conn, &data_dir).unwrap();
    let state = build_state(conn, data_dir.clone(), log_dir);
    let router = state.with_data_dir(data_dir);
    (router, dir)
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

/// Insert a second admin directly (OAuth-only sentinel, no password) and mint
/// a session for them — same pattern as tests/admin_team_crud.rs.
fn insert_admin(dir: &tempfile::TempDir, email: &str, role: &str) -> (i64, String) {
    let meta_path = dir.path().join("meta.sqlite");
    let conn = rusqlite::Connection::open(&meta_path).unwrap();
    let username = email.split('@').next().unwrap_or("admin").to_string();
    conn.execute(
        "INSERT INTO admins (username, password_hash, email, role) \
         VALUES (?1, '$oauth-only$', ?2, ?3)",
        params![username, email, role],
    )
    .unwrap();
    let admin_id = conn.last_insert_rowid();
    let session_token = {
        use base64::Engine;
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    };
    let expires_at = chrono::Utc::now() + chrono::Duration::days(7);
    conn.execute(
        "INSERT INTO sessions (token, admin_id, expires_at) VALUES (?1, ?2, ?3)",
        params![session_token, admin_id, expires_at.to_rfc3339()],
    )
    .unwrap();
    (admin_id, format!("drust_session={session_token}"))
}

/// Direct meta read of `tenants.owner_admin_id` for `tenant_id`.
fn owner_of(dir: &tempfile::TempDir, tenant_id: &str) -> Option<i64> {
    let conn = rusqlite::Connection::open(dir.path().join("meta.sqlite")).unwrap();
    conn.query_row(
        "SELECT owner_admin_id FROM tenants WHERE id = ?1",
        params![tenant_id],
        |r| r.get(0),
    )
    .unwrap()
}

async fn create_tenant_json(app: &axum::Router, cookie: &str, id: &str, name: &str) -> StatusCode {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/api/tenants")
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({"id": id, "name": name}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    resp.status()
}

#[tokio::test]
async fn create_json_sets_creator_as_owner() {
    let (app, dir) = spin_up().await;
    let cookie = login(&app, "root", "hunter2").await;
    let status = create_tenant_json(&app, &cookie, "t-owned", "Acme").await;
    assert_eq!(status, StatusCode::CREATED);
    // bootstrap admin is id 1
    assert_eq!(
        owner_of(&dir, "t-owned"),
        Some(1),
        "JSON create must stamp the creating admin as owner_admin_id"
    );
}

#[tokio::test]
async fn create_form_sets_creator_as_owner() {
    let (app, dir) = spin_up().await;
    let cookie = login(&app, "root", "hunter2").await;
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/tenants/new")
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("name=FormTenant"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "form create failed");
    // The form path mints a uuid id — find the row by name.
    let owner: Option<i64> = {
        let conn = rusqlite::Connection::open(dir.path().join("meta.sqlite")).unwrap();
        conn.query_row(
            "SELECT owner_admin_id FROM tenants WHERE name = 'FormTenant'",
            [],
            |r| r.get(0),
        )
        .unwrap()
    };
    assert_eq!(
        owner,
        Some(1),
        "form create must stamp the creating admin as owner_admin_id"
    );
}

#[tokio::test]
async fn recycled_id_gets_new_creator_as_owner() {
    let (app, dir) = spin_up().await;
    let root_cookie = login(&app, "root", "hunter2").await;

    // root creates the tenant …
    let status = create_tenant_json(&app, &root_cookie, "t-recycle", "First").await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(owner_of(&dir, "t-recycle"), Some(1));

    // … then soft-deletes it.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/admin/api/tenants/t-recycle")
                .header(header::COOKIE, &root_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        resp.status().is_success() || resp.status().is_redirection(),
        "soft delete failed: {}",
        resp.status()
    );

    // A DIFFERENT admin recreates the same id — the recycle branch must
    // stamp the NEW creator, not resurrect the old owner.
    //
    // v1.58: the second creator is an `admin`, not a `member`. Recycling
    // hard-DELETEs the old row and tokens, so it now asks `tenant_access_for`
    // first (CLAUDE.md invariant #7) — and `admin` is in `sees_all_tenants`,
    // so root's soft-deleted tenant is visible to them and the recycle is
    // theirs to make. A `member`, who cannot see it, is refused; that is the
    // sibling test below. The property under test here — "the NEW creator
    // wins, the old owner is not resurrected" — is unchanged.
    let (admin_id, admin_cookie) = insert_admin(&dir, "alice@example.com", "admin");
    let status = create_tenant_json(&app, &admin_cookie, "t-recycle", "Second").await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        owner_of(&dir, "t-recycle"),
        Some(admin_id),
        "recycled id must belong to the new creator"
    );
}

/// v1.58 — the same branch, from a caller who cannot see the tenant.
///
/// `POST /admin/api/tenants` has no `{id}`, so `tenant_ownership_layer` passes
/// it through with nothing checked; the gate has to live in the handler. A
/// member who learns a foreign tenant id (they are public — they appear in
/// `/public/<tenant-id>/<key>` URLs) must not be able to hard-DELETE that
/// tenant's row and tokens mid-recovery-window and stamp themselves as owner.
#[tokio::test]
async fn a_member_cannot_recycle_a_tenant_id_they_cannot_see() {
    let (app, dir) = spin_up().await;
    let root_cookie = login(&app, "root", "hunter2").await;

    assert_eq!(
        create_tenant_json(&app, &root_cookie, "t-victim", "First").await,
        StatusCode::CREATED
    );
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/admin/api/tenants/t-victim")
                .header(header::COOKIE, &root_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(resp.status().is_success() || resp.status().is_redirection());

    let (_mallory_id, mallory_cookie) = insert_admin(&dir, "mallory@example.com", "member");
    let status = create_tenant_json(&app, &mallory_cookie, "t-victim", "Mine Now").await;
    assert_ne!(
        status,
        StatusCode::CREATED,
        "a member must not recycle a tenant id they cannot see"
    );
    // And the victim's row survives intact — same owner, still soft-deleted,
    // tokens not cascaded away, so it can still be recovered.
    assert_eq!(owner_of(&dir, "t-victim"), Some(1));
    let (deleted_at, tokens): (Option<String>, i64) = {
        let conn = rusqlite::Connection::open(dir.path().join("meta.sqlite")).unwrap();
        let d = conn
            .query_row(
                "SELECT deleted_at FROM tenants WHERE id='t-victim'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let t = conn
            .query_row(
                "SELECT COUNT(*) FROM tokens WHERE tenant_id='t-victim'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        (d, t)
    };
    assert!(
        deleted_at.is_some(),
        "the row must still exist, soft-deleted"
    );
    assert_eq!(tokens, 2, "the victim's tokens must not be cascaded away");
}
