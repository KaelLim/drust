//! v1.50 Task 4 — admin tenant listings are ownership-scoped: an owner admin
//! sees every tenant (incl. NULL-owner orphans); a member admin sees only the
//! tenants they own, across all three list surfaces (`/admin/api/tenants`,
//! the `/admin/tenants` HTML page, and the cmd-K palette JSON).

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
/// a session for them — same pattern as tests/tenant_ownership_create.rs.
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

async fn create_tenant_json(app: &axum::Router, cookie: &str, id: &str, name: &str) {
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
    assert_eq!(resp.status(), StatusCode::CREATED, "create {id} failed");
}

/// Seed: owner root (id 1) owns t-owner-a; member (id 2) owns t-member-b;
/// t-orphan-c has owner_admin_id NULL (direct meta insert). Returns
/// (app, dir, owner_cookie, member_cookie).
async fn seed_three_tenants() -> (axum::Router, tempfile::TempDir, String, String) {
    let (app, dir) = spin_up().await;
    let owner_cookie = login(&app, "root", "hunter2").await;
    let (_member_id, member_cookie) = insert_admin(&dir, "alice@example.com", "member");
    create_tenant_json(&app, &owner_cookie, "t-owner-a", "AlphaCorp").await;
    create_tenant_json(&app, &member_cookie, "t-member-b", "BetaCorp").await;
    // Orphan tenant: no owner. Direct meta insert (listing reads meta only).
    {
        let conn = rusqlite::Connection::open(dir.path().join("meta.sqlite")).unwrap();
        conn.execute(
            "INSERT INTO tenants (id, name) VALUES ('t-orphan-c', 'GammaCorp')",
            [],
        )
        .unwrap();
    }
    (app, dir, owner_cookie, member_cookie)
}

async fn get_body(app: &axum::Router, cookie: &str, uri: &str) -> (StatusCode, String) {
    // Browsers always send `Accept: text/html` on a page GET; the content-negotiated
    // `/admin/team` route (team_page_or_json) renders HTML for that Accept and JSON
    // otherwise. Send it so the page-render assertions exercise the real HTML path.
    // Dedicated JSON routes (`/admin/api/*`) ignore Accept and stay JSON.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header(header::COOKIE, cookie)
                .header(header::ACCEPT, "text/html")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1_048_576)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

fn json_ids(body: &str) -> Vec<String> {
    let v: serde_json::Value = serde_json::from_str(body).unwrap();
    v.as_array()
        .expect("array")
        .iter()
        .map(|row| row["id"].as_str().unwrap().to_string())
        .collect()
}

// ─── /admin/api/tenants (tenants_json) ───────────────────────────────────────

#[tokio::test]
async fn owner_api_json_lists_all_tenants() {
    let (app, _dir, owner_cookie, _member_cookie) = seed_three_tenants().await;
    let (status, body) = get_body(&app, &owner_cookie, "/admin/api/tenants").await;
    assert_eq!(status, StatusCode::OK);
    let ids = json_ids(&body);
    assert_eq!(
        ids,
        vec!["t-member-b", "t-orphan-c", "t-owner-a"],
        "owner must see owned, foreign, and orphan tenants"
    );
}

#[tokio::test]
async fn member_api_json_lists_only_owned() {
    let (app, _dir, _owner_cookie, member_cookie) = seed_three_tenants().await;
    let (status, body) = get_body(&app, &member_cookie, "/admin/api/tenants").await;
    assert_eq!(status, StatusCode::OK);
    let ids = json_ids(&body);
    assert_eq!(
        ids,
        vec!["t-member-b"],
        "member must see only the tenants they own"
    );
}

// v1.57 — an `admin`-role admin (sees_all_tenants = owner|admin) sees EVERY
// tenant on the management plane, exactly like an owner.
#[tokio::test]
async fn admin_api_json_lists_all_tenants_like_owner() {
    let (app, dir, _owner, _member) = seed_three_tenants().await;
    let (_id, admin_cookie) = insert_admin(&dir, "adm@example.com", "admin");
    let (status, body) = get_body(&app, &admin_cookie, "/admin/api/tenants").await;
    assert_eq!(status, StatusCode::OK);
    let ids = json_ids(&body);
    assert_eq!(ids, vec!["t-member-b", "t-orphan-c", "t-owner-a"]);
}

// ─── /admin/tenants (list_page_axum HTML) ────────────────────────────────────

#[tokio::test]
async fn owner_list_page_shows_all_tenants() {
    let (app, _dir, owner_cookie, _member_cookie) = seed_three_tenants().await;
    let (status, html) = get_body(&app, &owner_cookie, "/admin/tenants").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("t-owner-a"), "owner page must list t-owner-a");
    assert!(
        html.contains("t-member-b"),
        "owner page must list t-member-b"
    );
    assert!(
        html.contains("t-orphan-c"),
        "owner page must list t-orphan-c"
    );
}

#[tokio::test]
async fn member_list_page_hides_foreign_tenants() {
    let (app, _dir, _owner_cookie, member_cookie) = seed_three_tenants().await;
    let (status, html) = get_body(&app, &member_cookie, "/admin/tenants").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains("t-member-b"),
        "member page must list their own tenant"
    );
    assert!(
        !html.contains("t-owner-a"),
        "member page must not leak a foreign tenant id"
    );
    assert!(
        !html.contains("t-orphan-c"),
        "member page must not leak an orphan tenant id"
    );
}

// ─── /admin/api/cmdk/tenants (cmdk_tenants_json) ─────────────────────────────

#[tokio::test]
async fn owner_cmdk_lists_all_tenants() {
    let (app, _dir, owner_cookie, _member_cookie) = seed_three_tenants().await;
    let (status, body) = get_body(&app, &owner_cookie, "/admin/api/cmdk/tenants").await;
    assert_eq!(status, StatusCode::OK);
    let ids = json_ids(&body);
    // cmdk sorts by name COLLATE NOCASE: Alpha, Beta, Gamma.
    assert_eq!(ids, vec!["t-owner-a", "t-member-b", "t-orphan-c"]);
}

#[tokio::test]
async fn member_cmdk_lists_only_owned() {
    let (app, _dir, _owner_cookie, member_cookie) = seed_three_tenants().await;
    let (status, body) = get_body(&app, &member_cookie, "/admin/api/cmdk/tenants").await;
    assert_eq!(status, StatusCode::OK);
    let ids = json_ids(&body);
    assert_eq!(
        ids,
        vec!["t-member-b"],
        "cmdk must be ownership-scoped for member admins"
    );
}

// ─── Task 5: ensure_tenant_visible choke point ───────────────────────────────
// The 12 admin POST handlers that used to call `ensure_tenant_exists` now go
// through the ownership-aware `ensure_tenant_visible`: a member hitting a
// tenant they do not own gets 404 "no such tenant" (no existence leak) BEFORE
// the handler opens the tenant pool; owned tenants behave as before. One
// representative route per caller family (oauth / webhooks / cron / functions).

async fn post_status(app: &axum::Router, cookie: &str, uri: &str) -> (StatusCode, String) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1_048_576)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

#[tokio::test]
async fn member_choke_point_denies_foreign_tenant_admin_actions() {
    let (app, _dir, _owner_cookie, member_cookie) = seed_three_tenants().await;
    // Foreign (owner-owned) tenant AND the NULL-owner orphan: both invisible.
    for tenant in ["t-owner-a", "t-orphan-c"] {
        for uri in [
            format!("/admin/tenants/{tenant}/_oauth_providers/google/delete"),
            format!("/admin/tenants/{tenant}/_webhooks/1/delete"),
            format!("/admin/tenants/{tenant}/_cron/nojob/toggle"),
            format!("/admin/tenants/{tenant}/_functions/nofn/toggle"),
        ] {
            let (status, body) = post_status(&app, &member_cookie, &uri).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "member POST {uri} must 404");
            assert!(
                body.contains("no such tenant"),
                "deny must be indistinguishable from a missing tenant on {uri}, got: {body}"
            );
        }
    }
}

#[tokio::test]
async fn member_choke_point_allows_owned_tenant_admin_actions() {
    let (app, _dir, _owner_cookie, member_cookie) = seed_three_tenants().await;
    // Idempotent deletes on the member's own tenant pass the visibility gate
    // and 303 back to the page (both swallow downstream errors by design).
    let (status, _) = post_status(
        &app,
        &member_cookie,
        "/admin/tenants/t-member-b/_oauth_providers/google/delete",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "own-tenant oauth delete");
    let (status, _) = post_status(
        &app,
        &member_cookie,
        "/admin/tenants/t-member-b/_webhooks/1/delete",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "own-tenant webhook delete");
}

#[tokio::test]
async fn owner_choke_point_keeps_cross_tenant_access() {
    let (app, _dir, owner_cookie, _member_cookie) = seed_three_tenants().await;
    // Owner reach is unchanged: foreign-owned and orphan tenants both pass.
    for tenant in ["t-member-b", "t-orphan-c"] {
        let uri = format!("/admin/tenants/{tenant}/_oauth_providers/google/delete");
        let (status, _) = post_status(&app, &owner_cookie, &uri).await;
        assert_eq!(status, StatusCode::SEE_OTHER, "owner POST {uri} must pass");
    }
}

#[tokio::test]
async fn choke_point_still_404s_missing_tenant() {
    let (app, _dir, owner_cookie, _member_cookie) = seed_three_tenants().await;
    let (status, body) = post_status(
        &app,
        &owner_cookie,
        "/admin/tenants/t-nope/_oauth_providers/google/delete",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body.contains("no such tenant"));
}

// ─── Task 9: admin UI — owner column + transfer control ──────────────────────
// The tenants list grows an "Owner" column (owner-view only: members already
// only see their own tenants, so the column is noise AND would leak admin
// emails). The `⚙ _settings` page grows an owner-only ownership-transfer
// dropdown wired to `PATCH /admin/tenants/{id}/owner` (Task 7).

#[tokio::test]
async fn owner_list_page_shows_owner_column_with_emails() {
    let (app, _dir, owner_cookie, _member_cookie) = seed_three_tenants().await;
    let (status, html) = get_body(&app, &owner_cookie, "/admin/tenants").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains("data-col=\"owner\""),
        "owner view must render the Owner column"
    );
    assert!(
        html.contains("alice@example.com"),
        "owner view must show each tenant's owner email"
    );
}

#[tokio::test]
async fn member_list_page_has_no_owner_column() {
    let (app, _dir, _owner_cookie, member_cookie) = seed_three_tenants().await;
    let (status, html) = get_body(&app, &member_cookie, "/admin/tenants").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !html.contains("data-col=\"owner\""),
        "member view must not render the Owner column"
    );
}

#[tokio::test]
async fn owner_settings_page_shows_transfer_control() {
    let (app, _dir, owner_cookie, _member_cookie) = seed_three_tenants().await;
    let (status, html) = get_body(&app, &owner_cookie, "/admin/tenants/t-member-b/_settings").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains("owner-transfer-form"),
        "owner view must render the ownership-transfer control"
    );
    assert!(
        html.contains("alice@example.com"),
        "transfer dropdown must list admins (email or username)"
    );
}

#[tokio::test]
async fn member_settings_page_hides_transfer_control() {
    let (app, _dir, _owner_cookie, member_cookie) = seed_three_tenants().await;
    let (status, html) =
        get_body(&app, &member_cookie, "/admin/tenants/t-member-b/_settings").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "member must reach the settings page of their own tenant"
    );
    assert!(
        !html.contains("owner-transfer-form"),
        "member view must not render the ownership-transfer control"
    );
}

// ─── sidebar owner-only nav (audit + backups) — #904 ─────────────────────────
// `data-section="…"` is the sidebar nav-item marker (see _admin_sidebar.html),
// so asserting on it isolates the nav from the cmdk palette / other surfaces.

#[tokio::test]
async fn owner_sidebar_shows_audit_and_backups() {
    let (app, _dir, owner_cookie, _member_cookie) = seed_three_tenants().await;
    let (status, html) = get_body(&app, &owner_cookie, "/admin/tenants").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains(r#"data-section="audit""#),
        "owner sidebar must show the audit-log nav item"
    );
    assert!(
        html.contains(r#"data-section="backups""#),
        "owner sidebar must show the backups nav item"
    );
}

#[tokio::test]
async fn member_sidebar_hides_audit_and_backups_but_keeps_the_rest() {
    let (app, _dir, _owner_cookie, member_cookie) = seed_three_tenants().await;
    let (status, html) = get_body(&app, &member_cookie, "/admin/tenants").await;
    assert_eq!(status, StatusCode::OK);
    // Owner-only host surfaces (member gets 403 on both) — no dead nav links.
    assert!(
        !html.contains(r#"data-section="audit""#),
        "member must NOT see the audit-log nav item"
    );
    assert!(
        !html.contains(r#"data-section="backups""#),
        "member must NOT see the backups nav item"
    );
    // The sidebar still renders; member-accessible entries stay.
    assert!(
        html.contains(r#"data-section="tenants""#),
        "member keeps the tenants nav item"
    );
    assert!(
        html.contains(r#"data-section="files""#),
        "member keeps the host-files nav item (not owner-gated)"
    );
    // v1.57 — member is locked out of the team page entirely (owner|admin only),
    // so the nav item is hidden too — no dead link that would 403.
    assert!(
        !html.contains(r#"data-section="team""#),
        "member must NOT see the team nav item (owner|admin only)"
    );
}

// ─── Task 8 (v1.57) — team page + nav are owner|admin only ───────────────────
// The team page (read AND mutations) was member-viewable read-only until v1.57;
// the 3-tier model locks `member` out entirely — 403 at the route AND the nav
// entry hidden (DiD ≥ 2). owner|admin (sees_team) keep both.

#[tokio::test]
async fn member_team_page_forbidden() {
    let (app, _dir, _owner, member_cookie) = seed_three_tenants().await;
    let (status, body) = get_body(&app, &member_cookie, "/admin/team").await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "member must be locked out of /admin/team"
    );
    assert!(
        body.contains("TEAM_REQUIRES_MANAGEMENT"),
        "member team-page deny code, got: {body}"
    );
}

#[tokio::test]
async fn owner_team_page_ok() {
    let (app, _dir, owner_cookie, _member) = seed_three_tenants().await;
    let (status, _body) = get_body(&app, &owner_cookie, "/admin/team").await;
    assert_eq!(status, StatusCode::OK, "owner reaches the team page");
}

#[tokio::test]
async fn admin_team_page_ok() {
    let (app, dir, _owner, _member) = seed_three_tenants().await;
    let (_id, admin_cookie) = insert_admin(&dir, "adm@example.com", "admin");
    let (status, _body) = get_body(&app, &admin_cookie, "/admin/team").await;
    assert_eq!(status, StatusCode::OK, "admin reaches the team page");
}

#[tokio::test]
async fn owner_sidebar_shows_team() {
    let (app, _dir, owner_cookie, _member) = seed_three_tenants().await;
    let (status, html) = get_body(&app, &owner_cookie, "/admin/tenants").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains(r#"data-section="team""#),
        "owner sidebar must show the team nav item"
    );
}

#[tokio::test]
async fn admin_sidebar_shows_team() {
    let (app, dir, _owner, _member) = seed_three_tenants().await;
    let (_id, admin_cookie) = insert_admin(&dir, "adm@example.com", "admin");
    let (status, html) = get_body(&app, &admin_cookie, "/admin/tenants").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains(r#"data-section="team""#),
        "admin sidebar must show the team nav item"
    );
}

// ─── Task 9 (v1.57) — team UI role-management controls adapt to caller ────────
// owner is offered the full invite role picker (owner/admin/member) + can
// edit/remove any row; admin is offered member-only invite and cannot see the
// admin/owner options at all.

#[tokio::test]
async fn team_ui_role_controls_adapt_to_caller() {
    let (app, dir, owner_cookie, _member) = seed_three_tenants().await;
    let (_aid, admin_cookie) = insert_admin(&dir, "adm@example.com", "admin");
    // owner: invite picker offers the admin option.
    let (s, owner_html) = get_body(&app, &owner_cookie, "/admin/team").await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        owner_html.contains("role_admin") || owner_html.to_lowercase().contains("admin —"),
        "owner invite picker must offer the admin role option"
    );
    // admin: invite picker must NOT offer the admin/owner options.
    let (s2, admin_html) = get_body(&app, &admin_cookie, "/admin/team").await;
    assert_eq!(s2, StatusCode::OK);
    assert!(
        !admin_html.to_lowercase().contains("admin — sees all")
            && !admin_html
                .to_lowercase()
                .contains("full access to every tenant"),
        "admin caller must NOT be offered the admin/owner invite options"
    );
}
