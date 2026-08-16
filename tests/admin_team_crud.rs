//! End-to-end CRUD tests for /admin/team — list, invite, promote, demote, remove.
//!
//! v1.29.0 — Task 6.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::mgmt::routes::MgmtState;
use drust::storage::meta::{bootstrap_admin, open_meta};
use drust::tenant::rooms::RoomBus;
use rusqlite::params;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering::SeqCst;
use tempfile::tempdir;
use tokio::sync::Mutex;
use tower::ServiceExt;

// ─── helpers ─────────────────────────────────────────────────────────────────

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

/// Spin up a mgmt router with one bootstrapped owner admin (username "root",
/// pw "hunter2"). Returns `(router, dir)`.
async fn spin_up() -> (axum::Router, tempfile::TempDir) {
    let (router, dir, _bus) = spin_up_with_bus().await;
    (router, dir)
}

/// #975 — same router, plus the SHARED `RoomBus` the team handlers evict
/// through, so a test can observe a tenant's eviction epoch across a REST call.
async fn spin_up_with_bus() -> (axum::Router, tempfile::TempDir, RoomBus) {
    let dir = tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let log_dir = data_dir.join("audit");
    std::fs::create_dir_all(&log_dir).unwrap();
    let mut conn = open_meta(&data_dir.join("meta.sqlite")).unwrap();
    bootstrap_admin(&mut conn, "root", "hunter2").unwrap();
    // run_migrations ensures role column exists and backfills existing admin to owner
    drust::db::migrations::run_migrations(&conn, &data_dir).unwrap();
    let state = build_state(conn, data_dir.clone(), log_dir);
    let bus_rooms = state.bus_rooms.clone();
    let router = state.with_data_dir(data_dir);
    (router, dir, bus_rooms)
}

/// PATCH `/admin/team/{id}/role` as `cookie`. Returns the status.
async fn patch_role(
    app: &axum::Router,
    cookie: &str,
    target_id: i64,
    role: &str,
) -> axum::http::StatusCode {
    app.clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/admin/team/{target_id}/role"))
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::json!({ "role": role }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

/// Insert an additional admin with a given email and role directly into the DB.
/// The admin has no password (OAuth-only sentinel) — they log in via a session
/// we create directly with `create_session`.
fn insert_admin(dir: &tempfile::TempDir, email: &str, role: &str) -> (i64, String) {
    let meta_path = dir.path().join("meta.sqlite");
    let conn = rusqlite::Connection::open(&meta_path).unwrap();
    let username = email.split('@').next().unwrap_or("admin").to_string();
    conn.execute(
        "INSERT INTO admins (username, password_hash, email, role) VALUES (?1, '$oauth-only$', ?2, ?3)",
        params![username, email, role],
    ).unwrap();
    let admin_id = conn.last_insert_rowid();
    // Create a session token for this admin directly.
    let session_token = {
        use base64::Engine;
        let mut bytes = [0u8; 32];
        use rand::RngCore;
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

/// Log in via the form endpoint and return the session cookie value string.
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
    // Extract just "drust_session=<token>" (first attribute before ';')
    sc.split(';').next().unwrap().to_string()
}

async fn body_json(resp: axum::http::Response<Body>) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 65_536)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

// ─── CRUD tests ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn owner_can_invite_admin() {
    let (app, _dir) = spin_up().await;
    let cookie = login(&app, "root", "hunter2").await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/team")
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({ "email": "alice@example.com", "role": "member" })
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "invite should return 201"
    );
    let body = body_json(resp).await;
    assert!(
        body["id"].as_i64().is_some(),
        "response should include new admin id"
    );
    assert_eq!(body["email"], "alice@example.com");
    assert_eq!(body["role"], "member");
}

#[tokio::test]
async fn owner_can_list_admins() {
    let (app, dir) = spin_up().await;
    let cookie = login(&app, "root", "hunter2").await;
    // Insert a second admin directly
    let _ = insert_admin(&dir, "bob@example.com", "member");

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/admin/team")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let admins = body["admins"].as_array().expect("should have admins array");
    assert_eq!(admins.len(), 2, "should list both admins");
}

#[tokio::test]
async fn owner_can_promote_member_to_owner() {
    let (app, dir) = spin_up().await;
    let owner_cookie = login(&app, "root", "hunter2").await;
    let (alice_id, _) = insert_admin(&dir, "alice@example.com", "member");

    let resp = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/admin/team/{alice_id}/role"))
                .header(header::COOKIE, &owner_cookie)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({ "role": "owner" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "promote should return 200");
    let body = body_json(resp).await;
    assert_eq!(body["role"], "owner");
}

#[tokio::test]
async fn owner_can_demote_owner_when_another_exists() {
    let (app, dir) = spin_up().await;
    let owner_cookie = login(&app, "root", "hunter2").await;
    let (alice_id, _) = insert_admin(&dir, "alice@example.com", "owner");

    let resp = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/admin/team/{alice_id}/role"))
                .header(header::COOKIE, &owner_cookie)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({ "role": "member" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "demote with another owner should succeed"
    );
}

#[tokio::test]
async fn owner_can_remove_member() {
    let (app, dir) = spin_up().await;
    let owner_cookie = login(&app, "root", "hunter2").await;
    let (alice_id, _) = insert_admin(&dir, "alice@example.com", "member");

    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/admin/team/{alice_id}"))
                .header(header::COOKIE, &owner_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "remove should return 200");
    let body = body_json(resp).await;
    assert_eq!(body["removed"], true);
}

// ─── #975 — role flips / removal close live rooms sockets ────────────────────

/// #975 — a reach-NARROWING role flip (`admin` → `member`, i.e. leaving the
/// sees-all-tenants set) strands the demoted admin's PAT sockets on tenants
/// they can no longer see. Those must close host-wide.
#[tokio::test]
async fn role_demotion_evicts_live_rooms_sockets_host_wide() {
    let (app, dir, bus) = spin_up_with_bus().await;
    let owner_cookie = login(&app, "root", "hunter2").await;
    let (alice_id, _) = insert_admin(&dir, "alice-demote@example.com", "admin");
    let ha = bus.tenant_epoch_handle("t-a");
    let hb = bus.tenant_epoch_handle("t-b");

    assert_eq!(
        patch_role(&app, &owner_cookie, alice_id, "member").await,
        StatusCode::OK,
        "admin → member demotion must succeed"
    );

    assert_eq!(ha.load(SeqCst), 1, "demotion must evict (tenant t-a)");
    assert_eq!(hb.load(SeqCst), 1, "evict must be host-wide (tenant t-b)");
}

/// #975, the other direction — a PROMOTION (`member` → `admin`) only WIDENS
/// reach, so there is no stranded socket to close and no reason to spend the
/// tenant's reconnect budget. Same "real change only" rule as the #955
/// publish-policy faces.
#[tokio::test]
async fn role_promotion_does_not_evict_rooms_sockets() {
    let (app, dir, bus) = spin_up_with_bus().await;
    let owner_cookie = login(&app, "root", "hunter2").await;
    let (alice_id, _) = insert_admin(&dir, "alice-promote@example.com", "member");
    let ha = bus.tenant_epoch_handle("t-a");

    assert_eq!(
        patch_role(&app, &owner_cookie, alice_id, "admin").await,
        StatusCode::OK,
        "member → admin promotion must succeed"
    );

    assert_eq!(
        ha.load(SeqCst),
        0,
        "a promotion widens reach — it must not kick anyone's sockets"
    );
}

/// #975, third direction — a LATERAL flip inside the sees-all set
/// (`owner` → `admin`) narrows nothing, so it must not evict either. This is
/// the case a hand-written `new_role == "member"` string check would get
/// right by accident and a `old_role == "owner"` one would get wrong; the
/// predicate goes through `tenant_authz::sees_all_tenants` (invariant 7).
#[tokio::test]
async fn lateral_role_move_inside_sees_all_does_not_evict() {
    let (app, dir, bus) = spin_up_with_bus().await;
    let owner_cookie = login(&app, "root", "hunter2").await;
    // A second owner so the last-owner guard lets the flip through.
    let (alice_id, _) = insert_admin(&dir, "alice-lateral@example.com", "owner");
    let ha = bus.tenant_epoch_handle("t-a");

    assert_eq!(
        patch_role(&app, &owner_cookie, alice_id, "admin").await,
        StatusCode::OK,
        "owner → admin must succeed while another owner exists"
    );

    assert_eq!(
        ha.load(SeqCst),
        0,
        "owner → admin keeps sees-all reach — no evict"
    );
}

/// #975 — `remove_admin` cascade-DELETEs the removed admin's `_admin_tokens`,
/// so every socket those PATs opened is now credential-less. Unconditional
/// host-wide evict.
#[tokio::test]
async fn remove_admin_evicts_live_rooms_sockets_host_wide() {
    let (app, dir, bus) = spin_up_with_bus().await;
    let owner_cookie = login(&app, "root", "hunter2").await;
    let (alice_id, _) = insert_admin(&dir, "alice-remove@example.com", "member");
    let ha = bus.tenant_epoch_handle("t-a");
    let hb = bus.tenant_epoch_handle("t-b");

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/admin/team/{alice_id}"))
                .header(header::COOKIE, &owner_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "remove should return 200");

    assert_eq!(ha.load(SeqCst), 1, "removal must evict (tenant t-a)");
    assert_eq!(hb.load(SeqCst), 1, "evict must be host-wide (tenant t-b)");
}

#[tokio::test]
async fn member_cannot_invite() {
    let (app, dir) = spin_up().await;
    let (_, member_cookie) = insert_admin(&dir, "alice@example.com", "member");

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/team")
                .header(header::COOKIE, &member_cookie)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({ "email": "bob@example.com", "role": "member" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "member must get 403");
    let body = body_json(resp).await;
    // v1.57 3-tier roles: a `member` caller is not a team manager. The invite
    // gate is now `require_manage_members` (owner|admin) → `NOT_A_MANAGER`,
    // replacing the former owner-only `NOT_OWNER`. Still a hard 403.
    assert_eq!(body["error_code"], "NOT_A_MANAGER");
}

#[tokio::test]
async fn member_cannot_remove() {
    let (app, dir) = spin_up().await;
    let (owner_id, _) = {
        // get the root owner's id
        let meta_path = dir.path().join("meta.sqlite");
        let conn = rusqlite::Connection::open(&meta_path).unwrap();
        let id: i64 = conn
            .query_row("SELECT id FROM admins WHERE username = 'root'", [], |r| {
                r.get(0)
            })
            .unwrap();
        (id, ())
    };
    let (_, member_cookie) = insert_admin(&dir, "alice@example.com", "member");

    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/admin/team/{owner_id}"))
                .header(header::COOKIE, &member_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "member must get 403");
    let body = body_json(resp).await;
    // v1.57 — a member hits `require_manage_members` first, so the code is now
    // NOT_A_MANAGER (replacing the former owner-only NOT_OWNER). Still a hard 403.
    assert_eq!(body["error_code"], "NOT_A_MANAGER");
}

#[tokio::test]
async fn invite_atomically_creates_pat_for_new_admin() {
    let (app, dir) = spin_up().await;
    let cookie = login(&app, "root", "hunter2").await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/team")
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({ "email": "newbie@example.com", "role": "member" })
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "invite should return 201"
    );

    let body = body_json(resp).await;
    let new_id = body["id"]
        .as_i64()
        .expect("invite response should carry new admin id");

    // Verify PAT row exists directly in meta.sqlite.
    let meta_path = dir.path().join("meta.sqlite");
    let conn = rusqlite::Connection::open(&meta_path).unwrap();
    let row: (String, Option<String>) = conn
        .query_row(
            "SELECT token_hash, plaintext FROM _admin_tokens \
             WHERE admin_id = ?1 AND revoked_at IS NULL",
            params![new_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("new admin must have an active PAT row");

    let plaintext = row.1.expect("PAT row must carry plaintext after v1.29.3");
    assert!(
        plaintext.starts_with("drust_pat_"),
        "plaintext prefix wrong: {}",
        plaintext
    );
}
