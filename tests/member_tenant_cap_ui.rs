//! v1.57 — role separation on the `/admin/tenants` stat cards.
//!
//! Two things are proved here. (1) The FEATURE: a member sees tenant-scoped
//! cards — owned/cap, their own tenants' usage against their own summed
//! allowance, remaining slots — and the request affordance appears on the
//! remaining card when it hits zero. (2) The LEAK FIX: `list_page_axum` used to
//! call `build_disk_view()` unconditionally, so a member saw the host's
//! physical disk figures and the "Free up /var/lib/garage" banner — host
//! infrastructure state shown to an admin who should only see their own
//! tenants, the same family as the `/admin/_metrics` finding the 2026-07-29
//! audit put behind `require_owner_layer`. An owner still sees the host cards.
//!
//! Router harness mirrors tests/member_tenant_cap_requests.rs (each integration
//! test is its own crate, so sharing the scaffold means re-inlining it).

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::mgmt::i18n::{Locale, Translator};
use drust::mgmt::routes::MgmtState;
use drust::mgmt::tenant_cap;
use drust::storage::meta::{bootstrap_admin, open_meta};
use rusqlite::params;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::{TempDir, tempdir};
use tokio::sync::Mutex;
use tower::ServiceExt;

// ─── router harness ───────────────────────────────────────────────────────────

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

async fn spin_up() -> (axum::Router, TempDir) {
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

/// Log the bootstrap admin in and return its session cookie. `root` is admin
/// id 1 and `run_migrations` promotes it to `owner`, so this is the owner cookie.
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

/// Insert an admin of `role` (OAuth-only sentinel) + a live session.
fn insert_admin_role(dir: &TempDir, email: &str, role: &str) -> (i64, String) {
    let conn = rusqlite::Connection::open(dir.path().join("meta.sqlite")).unwrap();
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

fn insert_member(dir: &TempDir, email: &str) -> (i64, String) {
    insert_admin_role(dir, email, "member")
}

/// A live tenant row owned by `owner_admin_id`. Inserted straight into meta —
/// the list page reads only denormalized meta columns (the v1.15 property), so
/// no on-disk tenant directory is needed to render it.
fn add_tenant(dir: &TempDir, id: &str, owner_admin_id: i64) {
    let conn = rusqlite::Connection::open(dir.path().join("meta.sqlite")).unwrap();
    conn.execute(
        "INSERT INTO tenants (id, name, owner_admin_id) VALUES (?1, ?2, ?3)",
        params![id, format!("Tenant {id}"), owner_admin_id],
    )
    .unwrap();
}

fn add_pending_request(dir: &TempDir, admin_id: i64, requested_cap: i64) {
    let conn = rusqlite::Connection::open(dir.path().join("meta.sqlite")).unwrap();
    conn.execute(
        "INSERT INTO tenant_cap_requests (requester_admin_id, requested_cap) VALUES (?1, ?2)",
        params![admin_id, requested_cap],
    )
    .unwrap();
}

/// The rendered English string for a bundle key. Asserting against the bundle
/// rather than a hardcoded literal keeps these tests honest if the copy changes.
fn en(key: &str) -> String {
    Translator::new(Locale::En).s(key).to_string()
}

/// `GET` an admin page as `cookie`. `Accept: text/html` is what a browser sends
/// and is what the session layer branches on.
async fn get_html(app: &axum::Router, uri: &str, cookie: &str) -> (StatusCode, String) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(uri)
                .header(header::COOKIE, cookie)
                .header(header::ACCEPT, "text/html")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 8_388_608)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

/// Markers that only ever appear on the host-disk card set.
const HOST_DISK_KEYS: &[&str] = &[
    "tenants_list.pulse.disk_free",
    "tenants_list.pulse.well_above_threshold",
    "tenants_list.pulse.tagline",
];

// ─── the leak fix ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn member_sees_tenant_scoped_cards_and_no_host_disk() {
    let (app, dir) = spin_up().await;
    let (mid, member) = insert_member(&dir, "alice@example.com");
    add_tenant(&dir, "t-owned", mid);
    let cap = tenant_cap::configured_default();

    let (st, html) = get_html(&app, "/admin/tenants", &member).await;
    assert_eq!(st, StatusCode::OK, "a member may list their own tenants");

    // The leak first: these assertions are the ones that failed before the fix.
    for key in HOST_DISK_KEYS {
        assert!(
            !html.contains(&en(key)),
            "a member must not see the host card rendered from `{key}`"
        );
    }
    assert!(
        !html.contains("/var/lib/garage"),
        "a member must never see the host disk banner naming /var/lib/garage"
    );
    assert!(
        html.contains(&format!("id=\"cap-figure\">1 / {cap}")),
        "the member card must render owned/cap as `1 / {cap}`"
    );
}

#[tokio::test]
async fn owner_still_sees_host_disk_cards() {
    let (app, _dir) = spin_up().await;
    let owner = login(&app, "root", "hunter2").await;

    let (st, html) = get_html(&app, "/admin/tenants", &owner).await;
    assert_eq!(st, StatusCode::OK);
    assert!(
        html.contains(&en("tenants_list.pulse.disk_free")),
        "an owner legitimately needs host disk state and keeps the card"
    );
    assert!(
        !html.contains("id=\"cap-figure\""),
        "an owner is never capped, so the owned/cap card is not rendered for them"
    );
}

// ─── the request affordance ───────────────────────────────────────────────────

#[tokio::test]
async fn member_at_the_cap_sees_the_request_affordance() {
    let (app, dir) = spin_up().await;
    let (mid, member) = insert_member(&dir, "alice@example.com");
    let cap = tenant_cap::configured_default();
    for i in 0..cap {
        add_tenant(&dir, &format!("t{i}"), mid);
    }

    let (st, html) = get_html(&app, "/admin/tenants", &member).await;
    assert_eq!(st, StatusCode::OK);
    assert!(
        html.contains(&format!("id=\"cap-figure\">{cap} / {cap}")),
        "a member at the cap sees `{cap} / {cap}`"
    );
    assert!(
        html.contains("id=\"cap-request-btn\""),
        "at zero remaining the card must carry the request control — the dead \
         end has to name its own exit"
    );
    assert!(
        !html.contains(&en("tenants_list.cap.pending_note")),
        "no request is pending yet, so the pending note must not render"
    );
}

#[tokio::test]
async fn member_with_a_pending_request_sees_pending_state_not_the_button() {
    let (app, dir) = spin_up().await;
    let (mid, member) = insert_member(&dir, "alice@example.com");
    let cap = tenant_cap::configured_default();
    for i in 0..cap {
        add_tenant(&dir, &format!("t{i}"), mid);
    }
    add_pending_request(&dir, mid, cap + 1);

    let (st, html) = get_html(&app, "/admin/tenants", &member).await;
    assert_eq!(st, StatusCode::OK);
    assert!(
        html.contains(&en("tenants_list.cap.pending_note")),
        "a pending request must be shown as such"
    );
    assert!(
        !html.contains("id=\"cap-request-btn\""),
        "a member with a pending request must not be offered a second one"
    );
}

#[tokio::test]
async fn member_below_the_cap_sees_neither_the_button_nor_the_pending_note() {
    let (app, dir) = spin_up().await;
    let (mid, member) = insert_member(&dir, "alice@example.com");
    let cap = tenant_cap::configured_default();
    assert!(
        cap >= 2,
        "this test needs headroom under the cap, got {cap}"
    );
    add_tenant(&dir, "t-owned", mid);

    let (st, html) = get_html(&app, "/admin/tenants", &member).await;
    assert_eq!(st, StatusCode::OK);
    assert!(
        !html.contains("id=\"cap-request-btn\""),
        "with slots left there is nothing to request"
    );
    assert!(!html.contains(&en("tenants_list.cap.pending_note")));
}

// ─── the team roster cap column ───────────────────────────────────────────────

#[tokio::test]
async fn roster_shows_each_admin_cap_and_owner_only_controls() {
    let (app, dir) = spin_up().await;
    let owner = login(&app, "root", "hunter2").await;
    let (mid, _member) = insert_member(&dir, "alice@example.com");
    let (_aid, other_admin) = insert_admin_role(&dir, "boss2@example.com", "admin");
    let cap = tenant_cap::configured_default();

    // Owner: sees the figure AND the direct-set control.
    let (st, html) = get_html(&app, "/admin/team", &owner).await;
    assert_eq!(st, StatusCode::OK, "an owner may read the roster");
    assert!(
        html.contains(&format!("data-cap-figure=\"{cap}\"")),
        "the member row must render its effective cap ({cap})"
    );
    assert!(
        html.contains("data-set-cap="),
        "an owner gets the direct-set control on the roster"
    );

    // A custom adjustment must read as custom, not inherited.
    {
        let conn = rusqlite::Connection::open(dir.path().join("meta.sqlite")).unwrap();
        conn.execute(
            "UPDATE admins SET tenant_cap_bonus = 2 WHERE id = ?1",
            params![mid],
        )
        .unwrap();
    }
    let (st, html) = get_html(&app, "/admin/team", &owner).await;
    assert_eq!(st, StatusCode::OK);
    assert!(
        html.contains(&format!("data-cap-figure=\"{}\"", cap + 2)),
        "a +2 bonus must show as {} on the roster",
        cap + 2
    );
    assert!(
        html.contains(&en("admin_team.cap.custom")),
        "an adjusted row must be labelled custom, not inherited"
    );

    // An `admin` (middle tier) sees the figure but may not change a host
    // allowance — the control must not be rendered for them at all.
    let (st, html) = get_html(&app, "/admin/team", &other_admin).await;
    assert_eq!(st, StatusCode::OK, "an admin may read the roster");
    assert!(
        html.contains("data-cap-figure="),
        "an admin still sees each member's cap"
    );
    assert!(
        !html.contains("data-set-cap="),
        "only an owner may set a tenant cap, so the control must be absent"
    );
}

// ─── owner-gated nav for BOTH review queues ───────────────────────────────────

#[tokio::test]
async fn owner_sidebar_links_both_review_queues() {
    let (app, dir) = spin_up().await;
    let owner = login(&app, "root", "hunter2").await;
    let (_mid, member) = insert_member(&dir, "alice@example.com");

    let (st, html) = get_html(&app, "/admin/tenants", &owner).await;
    assert_eq!(st, StatusCode::OK);
    assert!(
        html.contains("/admin/tenant-cap-requests\""),
        "the owner sidebar must link the tenant-cap review queue"
    );
    assert!(
        html.contains("/admin/quota-requests\""),
        "the owner sidebar must link the quota review queue — it had ZERO \
         inbound links anywhere before v1.57 (2026-07-29 audit finding)"
    );
    // The highlight script matches nav `data-section` against the page's
    // `<body data-section=…>`; both queue pages already set theirs, so the nav
    // entries must use the same values or the active state silently never fires.
    assert!(
        html.contains("data-section=\"tenant-cap-requests\""),
        "nav data-section must match tenant_cap_review.html's body value"
    );
    assert!(
        html.contains("data-section=\"quota-requests\""),
        "nav data-section must match quota_review.html's body value"
    );

    let (st, html) = get_html(&app, "/admin/tenants", &member).await;
    assert_eq!(st, StatusCode::OK);
    assert!(
        !html.contains("/admin/tenant-cap-requests"),
        "a member gets 403 on the queue, so the link must not be shown"
    );
    assert!(
        !html.contains("/admin/quota-requests"),
        "a member gets 403 on the quota queue, so the link must not be shown"
    );
}
