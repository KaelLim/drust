//! Authority-matrix tests for the 3-tier admin role model (owner > admin >
//! member). Task 5 covers `change_role`: owner manages every role (with the
//! last-owner guard), admin may manage MEMBER rows only (never touch an
//! owner/admin row, never promote to owner/admin), member manages nothing.
//!
//! v1.57 — 3-tier roles.
//!
//! Helpers mirror `tests/admin_team_invariants.rs` verbatim — each integration
//! test is its own crate, so sharing requires re-inlining the scaffold.

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

// ─── helpers (mirrored from admin_team_invariants.rs) ─────────────────────────

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

fn insert_admin(dir: &tempfile::TempDir, email: &str, role: &str) -> (i64, String) {
    let meta_path = dir.path().join("meta.sqlite");
    let conn = rusqlite::Connection::open(&meta_path).unwrap();
    let username = email.split('@').next().unwrap_or("admin").to_string();
    conn.execute(
        "INSERT INTO admins (username, password_hash, email, role) VALUES (?1, '$oauth-only$', ?2, ?3)",
        params![username, email, role],
    ).unwrap();
    let admin_id = conn.last_insert_rowid();
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
        .expect("no Set-Cookie")
        .to_str()
        .unwrap();
    sc.split(';').next().unwrap().to_string()
}

async fn body_json(resp: axum::http::Response<Body>) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 65_536)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

async fn patch_role(
    app: axum::Router,
    cookie: &str,
    target_id: i64,
    new_role: &str,
) -> axum::http::Response<Body> {
    app.oneshot(
        Request::builder()
            .method("PATCH")
            .uri(format!("/admin/team/{target_id}/role"))
            .header(header::COOKIE, cookie)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::json!({ "role": new_role }).to_string(),
            ))
            .unwrap(),
    )
    .await
    .unwrap()
}

async fn invite(
    app: axum::Router,
    cookie: &str,
    email: &str,
    role: &str,
) -> axum::http::Response<Body> {
    app.oneshot(
        Request::builder()
            .method("POST")
            .uri("/admin/team")
            .header(header::COOKIE, cookie)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::json!({ "email": email, "role": role }).to_string(),
            ))
            .unwrap(),
    )
    .await
    .unwrap()
}

async fn batch_invite(
    app: axum::Router,
    cookie: &str,
    emails: serde_json::Value,
    role: &str,
) -> axum::http::Response<Body> {
    app.oneshot(
        Request::builder()
            .method("POST")
            .uri("/admin/team/batch")
            .header(header::COOKIE, cookie)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::json!({ "emails": emails, "role": role }).to_string(),
            ))
            .unwrap(),
    )
    .await
    .unwrap()
}

async fn remove(app: axum::Router, cookie: &str, target_id: i64) -> axum::http::Response<Body> {
    app.oneshot(
        Request::builder()
            .method("DELETE")
            .uri(format!("/admin/team/{target_id}"))
            .header(header::COOKIE, cookie)
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap()
}

fn root_id(dir: &tempfile::TempDir) -> i64 {
    let meta_path = dir.path().join("meta.sqlite");
    let conn = rusqlite::Connection::open(&meta_path).unwrap();
    conn.query_row("SELECT id FROM admins WHERE username = 'root'", [], |r| {
        r.get(0)
    })
    .unwrap()
}

// ─── change_role authority matrix ────────────────────────────────────────────

/// The matrix the plan enumerates:
///   owner can promote member→admin;
///   admin CANNOT promote member→admin (403 PRIVILEGED_ROLE_REQUIRED);
///   admin cannot demote owner (403);
///   admin cannot promote member→owner (403);
///   member cannot change any role (403 NOT_A_MANAGER).
/// Table-driven: (caller_role, target_role, new_role) → (status, error_code?).
#[tokio::test]
async fn change_role_authority_matrix() {
    let cases: [(&str, &str, &str, StatusCode, Option<&str>); 5] = [
        // owner promotes member→admin — the sole positive: role becomes admin.
        ("owner", "member", "admin", StatusCode::OK, None),
        // admin may NOT create an admin/owner or touch an owner/admin row.
        (
            "admin",
            "member",
            "admin",
            StatusCode::FORBIDDEN,
            Some("PRIVILEGED_ROLE_REQUIRED"),
        ),
        (
            "admin",
            "owner",
            "member",
            StatusCode::FORBIDDEN,
            Some("PRIVILEGED_ROLE_REQUIRED"),
        ),
        (
            "admin",
            "member",
            "owner",
            StatusCode::FORBIDDEN,
            Some("PRIVILEGED_ROLE_REQUIRED"),
        ),
        // member manages nothing.
        (
            "member",
            "member",
            "admin",
            StatusCode::FORBIDDEN,
            Some("NOT_A_MANAGER"),
        ),
    ];

    for (caller_role, target_role, new_role, expected_status, expected_code) in cases {
        let (app, dir) = spin_up().await;
        let caller_cookie = if caller_role == "owner" {
            login(&app, "root", "hunter2").await
        } else {
            insert_admin(
                &dir,
                &format!("caller-{caller_role}@example.com"),
                caller_role,
            )
            .1
        };
        let (target_id, _) = insert_admin(&dir, "target@example.com", target_role);

        let resp = patch_role(app, &caller_cookie, target_id, new_role).await;
        let status = resp.status();
        let body = body_json(resp).await;

        assert_eq!(
            status, expected_status,
            "caller={caller_role} target={target_role} new={new_role}: body={body}"
        );
        match expected_code {
            Some(code) => assert_eq!(
                body["error_code"], code,
                "caller={caller_role} target={target_role} new={new_role}"
            ),
            None => assert_eq!(
                body["role"], new_role,
                "positive case must report the new role"
            ),
        }
    }
}

/// Owner retains full authority: may demote an admin back to member.
#[tokio::test]
async fn owner_can_demote_admin_to_member() {
    let (app, dir) = spin_up().await;
    let owner_cookie = login(&app, "root", "hunter2").await;
    let (admin_id, _) = insert_admin(&dir, "adm@example.com", "admin");

    let resp = patch_role(app, &owner_cookie, admin_id, "member").await;
    let status = resp.status();
    let body = body_json(resp).await;
    assert_eq!(status, StatusCode::OK, "owner demote admin→member: {body}");
    assert_eq!(body["role"], "member");
}

/// Regression (adversarial-review finding): demoting the LAST owner to the new
/// `admin` tier must be rejected. Pre-fix the last-owner guard only fired on
/// owner→member, so owner→admin escaped it and could reach ZERO owners — a
/// lockout, since only an owner can mint owners/admins or read backups.
#[tokio::test]
async fn change_role_last_owner_to_admin_rejected() {
    let (app, dir) = spin_up().await;
    let owner_cookie = login(&app, "root", "hunter2").await;
    let sole_owner = root_id(&dir); // bootstrap root is the only owner
    let resp = patch_role(app, &owner_cookie, sole_owner, "admin").await;
    let status = resp.status();
    let body = body_json(resp).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "owner→admin on last owner: {body}"
    );
    assert_eq!(body["error_code"], "LAST_OWNER");
}

// ─── invite authority matrix (single) ─────────────────────────────────────────

/// The matrix the plan enumerates for `invite_admin`:
///   owner may invite any role (member/admin);
///   admin may invite a `member` ONLY (inviting an admin/owner →
///     403 PRIVILEGED_ROLE_REQUIRED);
///   member invites nothing (403 NOT_A_MANAGER).
/// Table-driven: (caller_role, invited_role) → (status, error_code?). A
/// successful invite returns 201 CREATED echoing the invited role (mirrors the
/// existing `owner_can_invite_admin` scaffold in tests/admin_team_crud.rs).
#[tokio::test]
async fn invite_authority_matrix() {
    let cases: [(&str, &str, StatusCode, Option<&str>); 6] = [
        // owner may invite any role.
        ("owner", "member", StatusCode::CREATED, None),
        ("owner", "admin", StatusCode::CREATED, None),
        // admin may invite a member.
        ("admin", "member", StatusCode::CREATED, None),
        // admin may NOT mint an admin or an owner.
        (
            "admin",
            "admin",
            StatusCode::FORBIDDEN,
            Some("PRIVILEGED_ROLE_REQUIRED"),
        ),
        (
            "admin",
            "owner",
            StatusCode::FORBIDDEN,
            Some("PRIVILEGED_ROLE_REQUIRED"),
        ),
        // member manages nothing.
        (
            "member",
            "member",
            StatusCode::FORBIDDEN,
            Some("NOT_A_MANAGER"),
        ),
    ];

    for (caller_role, invited_role, expected_status, expected_code) in cases {
        let (app, dir) = spin_up().await;
        let caller_cookie = if caller_role == "owner" {
            login(&app, "root", "hunter2").await
        } else {
            insert_admin(
                &dir,
                &format!("caller-{caller_role}@example.com"),
                caller_role,
            )
            .1
        };

        let resp = invite(app, &caller_cookie, "invitee@example.com", invited_role).await;
        let status = resp.status();
        let body = body_json(resp).await;

        assert_eq!(
            status, expected_status,
            "caller={caller_role} invited={invited_role}: body={body}"
        );
        match expected_code {
            Some(code) => assert_eq!(
                body["error_code"], code,
                "caller={caller_role} invited={invited_role}"
            ),
            None => assert_eq!(
                body["role"], invited_role,
                "positive invite must echo the invited role: body={body}"
            ),
        }
    }
}

// ─── batch invite authority matrix ────────────────────────────────────────────

/// Same authority matrix over `POST /admin/team/batch` — the up-front authority
/// check is identical to the single-invite path. A successful batch returns 201
/// CREATED with exactly one `created` entry.
#[tokio::test]
async fn batch_invite_authority_matrix() {
    let cases: [(&str, &str, StatusCode, Option<&str>); 6] = [
        ("owner", "member", StatusCode::CREATED, None),
        ("owner", "admin", StatusCode::CREATED, None),
        ("admin", "member", StatusCode::CREATED, None),
        (
            "admin",
            "admin",
            StatusCode::FORBIDDEN,
            Some("PRIVILEGED_ROLE_REQUIRED"),
        ),
        (
            "admin",
            "owner",
            StatusCode::FORBIDDEN,
            Some("PRIVILEGED_ROLE_REQUIRED"),
        ),
        (
            "member",
            "member",
            StatusCode::FORBIDDEN,
            Some("NOT_A_MANAGER"),
        ),
    ];

    for (caller_role, invited_role, expected_status, expected_code) in cases {
        let (app, dir) = spin_up().await;
        let caller_cookie = if caller_role == "owner" {
            login(&app, "root", "hunter2").await
        } else {
            insert_admin(
                &dir,
                &format!("caller-{caller_role}@example.com"),
                caller_role,
            )
            .1
        };

        let resp = batch_invite(
            app,
            &caller_cookie,
            serde_json::json!(["invitee@example.com"]),
            invited_role,
        )
        .await;
        let status = resp.status();
        let body = body_json(resp).await;

        assert_eq!(
            status, expected_status,
            "caller={caller_role} invited={invited_role}: body={body}"
        );
        match expected_code {
            Some(code) => assert_eq!(
                body["error_code"], code,
                "caller={caller_role} invited={invited_role}"
            ),
            None => assert_eq!(
                body["created"].as_array().map(|a| a.len()),
                Some(1),
                "positive batch must create exactly one admin: body={body}"
            ),
        }
    }
}

// ─── remove authority matrix ──────────────────────────────────────────────────

/// The matrix the plan enumerates for `remove_admin` (DELETE /admin/team/{id}):
///   owner may remove any admin (except the last owner — the LAST_OWNER guard);
///   admin may remove a `member` ONLY (removing an admin/owner →
///     403 PRIVILEGED_ROLE_REQUIRED);
///   member removes nothing (403 NOT_A_MANAGER).
/// Table-driven: (caller_role, target_role) → (status, error_code?). A
/// successful remove returns 200 OK with `{ "removed": true }`.
#[tokio::test]
async fn remove_authority_matrix() {
    let cases: [(&str, &str, StatusCode, Option<&str>); 5] = [
        // owner may remove an admin.
        ("owner", "admin", StatusCode::OK, None),
        // admin may remove a member.
        ("admin", "member", StatusCode::OK, None),
        // admin may NOT remove an admin or an owner.
        (
            "admin",
            "admin",
            StatusCode::FORBIDDEN,
            Some("PRIVILEGED_ROLE_REQUIRED"),
        ),
        (
            "admin",
            "owner",
            StatusCode::FORBIDDEN,
            Some("PRIVILEGED_ROLE_REQUIRED"),
        ),
        // member manages nothing.
        (
            "member",
            "member",
            StatusCode::FORBIDDEN,
            Some("NOT_A_MANAGER"),
        ),
    ];

    for (caller_role, target_role, expected_status, expected_code) in cases {
        let (app, dir) = spin_up().await;
        let caller_cookie = if caller_role == "owner" {
            login(&app, "root", "hunter2").await
        } else {
            insert_admin(
                &dir,
                &format!("caller-{caller_role}@example.com"),
                caller_role,
            )
            .1
        };
        let (target_id, _) = insert_admin(&dir, "target@example.com", target_role);

        let resp = remove(app, &caller_cookie, target_id).await;
        let status = resp.status();
        let body = body_json(resp).await;

        assert_eq!(
            status, expected_status,
            "caller={caller_role} target={target_role}: body={body}"
        );
        match expected_code {
            Some(code) => assert_eq!(
                body["error_code"], code,
                "caller={caller_role} target={target_role}"
            ),
            None => assert_eq!(
                body["removed"], true,
                "positive remove must report removed=true: body={body}"
            ),
        }
    }
}

/// Owner removing the LAST owner is still rejected with 409 LAST_OWNER — the
/// v1.50 immutability guard is untouched by the 3-tier authority matrix.
#[tokio::test]
async fn remove_last_owner_still_rejected() {
    let (app, dir) = spin_up().await;
    let owner_id = root_id(&dir);
    let owner_cookie = login(&app, "root", "hunter2").await;

    let resp = remove(app, &owner_cookie, owner_id).await;
    let status = resp.status();
    let body = body_json(resp).await;
    assert_eq!(status, StatusCode::CONFLICT, "remove last owner: {body}");
    assert_eq!(body["error_code"], "LAST_OWNER");
}
