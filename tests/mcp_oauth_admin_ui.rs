//! The admin-plane faces of MCP OAuth grants: the settings card's
//! per-row revoke and revoke-all, and the team page's
//! `DELETE /admin/team/{id}/mcp-grants`. Every request goes through the
//! production router at ROOT paths; only outbound strings (`Location`) carry
//! `/drust`.
//!
//! Sessions are minted with `create_session` (no `/login`, no login budget).
//! Audit rows are not asserted (the process-global audit writer is
//! first-write-wins across g_admin members). Every DB touch takes `fx.meta` in
//! its own block and drops it before the next HTTP request (the handlers lock
//! the same mutex). File-private helpers carry a `ui_` prefix so they never
//! collide with `common::mcp_oauth`.

use axum::body::Body;
use axum::http::{Request, Response, StatusCode, header};
use drust::mgmt::mcp_oauth::store;
use drust::mgmt::mcp_oauth::tokens::{self, TokenKind};
use rusqlite::params;

use crate::common::mcp_oauth::{self as mo, SeedGrant};

/// Markup that only the MCP connections card / team button emit. The settings
/// page still carries `key-mcp-pat` as an element id, so the disabled-mode
/// guard looks for these instead.
const NEW_MARKERS: &[&str] = &["mcp-grants", "revoke-mcp", "data-mcp-grant"];
/// en `settings.mcp_grants.card_title`.
const CARD_TITLE_EN: &str = "MCP connections";

// ─── file-private helpers ────────────────────────────────────────────────────

/// `"drust_session=<t>"` for `admin_id`, minted directly.
async fn ui_session(fx: &mo::McpOauthFixture, admin_id: i64) -> String {
    let mut c = fx.meta.lock().await;
    let t = drust::auth::session::create_session(&mut c, admin_id, 3600).unwrap();
    format!("drust_session={t}")
}

/// Revokes `admin_id`'s live UI PAT and inserts one with a known plaintext.
async fn ui_pat(fx: &mo::McpOauthFixture, admin_id: i64) -> String {
    let c = fx.meta.lock().await;
    c.execute(
        "UPDATE _admin_tokens SET revoked_at = datetime('now') \
         WHERE admin_id = ?1 AND revoked_at IS NULL AND label IS NULL",
        params![admin_id],
    )
    .unwrap();
    let pat = drust::auth::admin_token::generate_token();
    c.execute(
        "INSERT INTO _admin_tokens (admin_id, token_hash) VALUES (?1, ?2)",
        params![admin_id, drust::auth::admin_token::hash_token(&pat)],
    )
    .unwrap();
    pat
}

async fn ui_send(
    app: &axum::Router,
    method: &str,
    uri: &str,
    cookie: Option<&str>,
    bearer: Option<&str>,
    accept: Option<&str>,
) -> Response<Body> {
    let mut b = Request::builder().method(method).uri(uri);
    if let Some(c) = cookie {
        b = b.header(header::COOKIE, c);
    }
    if let Some(t) = bearer {
        b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    if let Some(a) = accept {
        b = b.header(header::ACCEPT, a);
    }
    mo::send(app, b.body(Body::empty()).unwrap()).await
}

async fn ui_body(resp: Response<Body>) -> String {
    let b = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    String::from_utf8(b.to_vec()).unwrap()
}

async fn ui_json(resp: Response<Body>) -> serde_json::Value {
    serde_json::from_str(&ui_body(resp).await).unwrap()
}

fn ui_location(resp: &Response<Body>) -> Option<&str> {
    resp.headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
}

fn ui_live(conn: &rusqlite::Connection, grant_id: i64) -> bool {
    conn.query_row(
        "SELECT revoked_at IS NULL FROM _mcp_oauth_grants WHERE id = ?1",
        params![grant_id],
        |r| r.get::<_, bool>(0),
    )
    .unwrap()
}

fn ui_reason(conn: &rusqlite::Connection, grant_id: i64) -> Option<String> {
    conn.query_row(
        "SELECT revoke_reason FROM _mcp_oauth_grants WHERE id = ?1",
        params![grant_id],
        |r| r.get(0),
    )
    .unwrap()
}

fn ui_live_count(conn: &rusqlite::Connection, admin_id: i64) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM _mcp_oauth_grants WHERE admin_id = ?1 AND revoked_at IS NULL",
        params![admin_id],
        |r| r.get(0),
    )
    .unwrap()
}

/// Neither token resolves any more and the unredeemed code row is gone.
fn ui_fully_dead(conn: &rusqlite::Connection, tok: &mo::SeededTokens, code: &str) -> bool {
    let access = store::find_grant_by_access(conn, &tok.access).unwrap();
    let refresh = store::find_grant_by_refresh(conn, &tok.refresh).unwrap();
    let codes: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM _mcp_oauth_codes WHERE code_hash = ?1",
            params![tokens::hash(TokenKind::Code, code)],
            |r| r.get(0),
        )
        .unwrap();
    access.is_none() && refresh.is_none() && codes == 0
}

fn ui_grant(conn: &rusqlite::Connection, admin_id: i64) -> i64 {
    mo::seed_grant(
        conn,
        &SeedGrant {
            admin_id,
            idle: "+30 days",
            absolute: "+90 days",
            revoked: false,
        },
    )
}

/// A live grant with one token pair and one unredeemed code.
fn ui_grant_full(conn: &rusqlite::Connection, admin_id: i64) -> (i64, mo::SeededTokens, String) {
    let g = ui_grant(conn, admin_id);
    let t = mo::seed_tokens(conn, g);
    let c = mo::seed_code(
        conn,
        g,
        "http://localhost:4567/callback",
        mo::FIXED_CHALLENGE,
        None,
    );
    (g, t, c)
}

fn settings_revoke_uri(g: i64) -> String {
    format!("/admin/settings/mcp-grants/{g}/revoke")
}

const REVOKE_ALL_URI: &str = "/admin/settings/mcp-grants/revoke-all";

fn team_uri(admin_id: i64) -> String {
    format!("/admin/team/{admin_id}/mcp-grants")
}

const JSON: Option<&str> = Some("application/json");
const HTML: Option<&str> = Some("text/html");

// ─── A. disabled: nothing new is reachable or rendered ───────────────────────

#[tokio::test]
async fn disabled_settings_page_has_no_mcp_card() {
    let fx = mo::fixture(false).await;
    {
        let c = fx.meta.lock().await;
        ui_grant(&c, fx.owner_id);
    }
    let s = ui_session(&fx, fx.owner_id).await;
    let resp = ui_send(&fx.app, "GET", "/admin/settings", Some(&s), None, HTML).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = ui_body(resp).await;
    for m in NEW_MARKERS {
        assert!(!body.contains(m), "disabled settings page contains {m:?}");
    }
    assert!(!body.contains(CARD_TITLE_EN));
}

#[tokio::test]
async fn disabled_team_page_has_no_revoke_button() {
    let fx = mo::fixture(false).await;
    let s = ui_session(&fx, fx.owner_id).await;
    let resp = ui_send(&fx.app, "GET", "/admin/team", Some(&s), None, HTML).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = ui_body(resp).await;
    for m in NEW_MARKERS {
        assert!(!body.contains(m), "disabled team page contains {m:?}");
    }
}

#[tokio::test]
async fn disabled_routes_are_unmounted() {
    let fx = mo::fixture(false).await;
    let g = {
        let c = fx.meta.lock().await;
        ui_grant(&c, fx.owner_id)
    };
    let s = ui_session(&fx, fx.owner_id).await;
    let owner = fx.owner_id;
    let cases = [
        (
            "POST",
            settings_revoke_uri(g),
            "/admin/settings/mcp-grants-x".to_string(),
        ),
        (
            "POST",
            REVOKE_ALL_URI.to_string(),
            "/admin/settings/mcp-grants-x".to_string(),
        ),
        ("DELETE", team_uri(owner), format!("/admin/team/{owner}/x")),
    ];
    for (method, uri, control) in cases {
        for accept in [None, JSON] {
            let a = ui_send(&fx.app, method, &uri, Some(&s), None, accept).await;
            let b = ui_send(&fx.app, method, &control, Some(&s), None, accept).await;
            assert_eq!(a.status(), b.status(), "{method} {uri} vs {control}");
            assert_eq!(a.status(), StatusCode::NOT_FOUND, "{method} {uri}");
            assert_eq!(ui_body(a).await, ui_body(b).await, "{method} {uri}");
        }
    }
    let c = fx.meta.lock().await;
    assert!(ui_live(&c, g));
}

// ─── B. settings page (enabled) ──────────────────────────────────────────────

#[tokio::test]
async fn settings_revoke_own_grant() {
    let fx = mo::fixture(true).await;
    let ((g1, t1, code1), g2) = {
        let c = fx.meta.lock().await;
        (ui_grant_full(&c, fx.owner_id), ui_grant(&c, fx.owner_id))
    };
    let s = ui_session(&fx, fx.owner_id).await;
    let resp = ui_send(
        &fx.app,
        "POST",
        &settings_revoke_uri(g1),
        Some(&s),
        None,
        None,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(ui_location(&resp), Some("/drust/admin/settings"));
    let c = fx.meta.lock().await;
    assert!(!ui_live(&c, g1));
    assert_eq!(ui_reason(&c, g1).as_deref(), Some("user"));
    for table in ["_mcp_oauth_refresh", "_mcp_oauth_access"] {
        let live: i64 = c
            .query_row(
                &format!("SELECT COUNT(*) FROM {table} WHERE grant_id = ?1 AND revoked_at IS NULL"),
                params![g1],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(live, 0, "{table} rows of the revoked grant stay live");
    }
    assert!(ui_fully_dead(&c, &t1, &code1));
    assert!(ui_live(&c, g2), "the other grant is untouched");
}

#[tokio::test]
async fn settings_revoke_twice_is_404() {
    let fx = mo::fixture(true).await;
    let g = {
        let c = fx.meta.lock().await;
        ui_grant(&c, fx.owner_id)
    };
    let s = ui_session(&fx, fx.owner_id).await;
    let first = ui_send(
        &fx.app,
        "POST",
        &settings_revoke_uri(g),
        Some(&s),
        None,
        None,
    )
    .await;
    assert_eq!(first.status(), StatusCode::SEE_OTHER);
    let again = ui_send(
        &fx.app,
        "POST",
        &settings_revoke_uri(g),
        Some(&s),
        None,
        None,
    )
    .await;
    assert_eq!(again.status(), StatusCode::NOT_FOUND);
    assert_eq!(ui_json(again).await["error_code"], "MCP_GRANT_NOT_FOUND");
    let c = fx.meta.lock().await;
    assert_eq!(ui_reason(&c, g).as_deref(), Some("user"));
}

#[tokio::test]
async fn settings_revoke_foreign_grant_is_indistinguishable_404() {
    let fx = mo::fixture(true).await;
    let a = mo::add_admin(&fx, "alice", "", "admin").await;
    let (ga, ta) = {
        let c = fx.meta.lock().await;
        let g = ui_grant(&c, a);
        (g, mo::seed_tokens(&c, g))
    };
    // The owner sees every tenant — and still cannot revoke another admin's grant here.
    let s = ui_session(&fx, fx.owner_id).await;
    let foreign = ui_send(
        &fx.app,
        "POST",
        &settings_revoke_uri(ga),
        Some(&s),
        None,
        None,
    )
    .await;
    let foreign_status = foreign.status();
    let foreign_body = ui_body(foreign).await;
    assert_eq!(foreign_status, StatusCode::NOT_FOUND);
    let v: serde_json::Value = serde_json::from_str(&foreign_body).unwrap();
    assert_eq!(v["error_code"], "MCP_GRANT_NOT_FOUND");
    {
        let c = fx.meta.lock().await;
        assert!(ui_live(&c, ga));
        assert!(
            store::find_grant_by_access(&c, &ta.access)
                .unwrap()
                .is_some()
        );
    }
    let unknown = ui_send(
        &fx.app,
        "POST",
        &settings_revoke_uri(999_999),
        Some(&s),
        None,
        None,
    )
    .await;
    assert_eq!(unknown.status(), foreign_status);
    assert_eq!(ui_body(unknown).await, foreign_body, "no existence oracle");
}

#[tokio::test]
async fn settings_revoke_all_only_own() {
    let fx = mo::fixture(true).await;
    let a = mo::add_admin(&fx, "alice", "", "admin").await;
    let (mine1, mine2, old, (ga, ta)) = {
        let c = fx.meta.lock().await;
        let m1 = ui_grant_full(&c, fx.owner_id);
        let m2 = ui_grant_full(&c, fx.owner_id);
        let old = mo::seed_grant(
            &c,
            &SeedGrant {
                admin_id: fx.owner_id,
                idle: "+30 days",
                absolute: "+90 days",
                revoked: true,
            },
        );
        let ga = ui_grant(&c, a);
        let ta = mo::seed_tokens(&c, ga);
        (m1, m2, old, (ga, ta))
    };
    let s = ui_session(&fx, fx.owner_id).await;
    let resp = ui_send(&fx.app, "POST", REVOKE_ALL_URI, Some(&s), None, None).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(ui_location(&resp), Some("/drust/admin/settings"));
    let c = fx.meta.lock().await;
    for (g, t, code) in [&mine1, &mine2] {
        assert_eq!(ui_reason(&c, *g).as_deref(), Some("user_all"));
        assert!(ui_fully_dead(&c, t, code));
    }
    assert_eq!(
        ui_reason(&c, old).as_deref(),
        Some("user"),
        "an already-revoked grant keeps its first reason"
    );
    assert!(ui_live(&c, ga), "another admin's grant is untouched");
    assert!(
        store::find_grant_by_access(&c, &ta.access)
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn settings_revoke_all_with_nothing_is_303() {
    let fx = mo::fixture(true).await;
    let s = ui_session(&fx, fx.owner_id).await;
    let resp = ui_send(&fx.app, "POST", REVOKE_ALL_URI, Some(&s), None, None).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(ui_location(&resp), Some("/drust/admin/settings"));
}

#[tokio::test]
async fn settings_revoke_requires_session_not_mcp_token() {
    let fx = mo::fixture(true).await;
    let (g, t) = {
        let c = fx.meta.lock().await;
        let g = ui_grant(&c, fx.owner_id);
        (g, mo::seed_tokens(&c, g))
    };
    // (a) No credential: the browser is sent to /login, a JSON client gets 401.
    let r = ui_send(&fx.app, "POST", &settings_revoke_uri(g), None, None, None).await;
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    assert_eq!(ui_location(&r), Some("/drust/login"));
    let r = ui_send(&fx.app, "POST", &settings_revoke_uri(g), None, None, JSON).await;
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    // (b) An MCP access token never authenticates the management plane.
    let owner = fx.owner_id;
    for (method, uri) in [
        ("GET", "/admin/settings".to_string()),
        ("POST", settings_revoke_uri(g)),
        ("POST", REVOKE_ALL_URI.to_string()),
        ("DELETE", team_uri(owner)),
    ] {
        let r = ui_send(&fx.app, method, &uri, None, Some(&t.access), JSON).await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "{method} {uri}");
        assert_eq!(
            ui_json(r).await["error_code"],
            "ADMIN_PAT_INVALID",
            "{method} {uri}"
        );
    }
    let c = fx.meta.lock().await;
    assert!(ui_live(&c, g));
    assert!(
        store::find_grant_by_access(&c, &t.access)
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn member_can_use_settings_revoke() {
    let fx = mo::fixture(true).await;
    let m = mo::add_admin(&fx, "mia", "", "member").await;
    let g = {
        let c = fx.meta.lock().await;
        ui_grant(&c, m)
    };
    let s = ui_session(&fx, m).await;
    let r = ui_send(
        &fx.app,
        "POST",
        &settings_revoke_uri(g),
        Some(&s),
        None,
        None,
    )
    .await;
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    let c = fx.meta.lock().await;
    assert_eq!(ui_reason(&c, g).as_deref(), Some("user"));
}

#[tokio::test]
async fn ui_pat_is_still_accepted() {
    let fx = mo::fixture(true).await;
    let a = mo::add_admin(&fx, "alice", "", "admin").await;
    let (g, ga) = {
        let c = fx.meta.lock().await;
        (ui_grant(&c, fx.owner_id), ui_grant(&c, a))
    };
    let pat = ui_pat(&fx, fx.owner_id).await;
    let r = ui_send(
        &fx.app,
        "POST",
        &settings_revoke_uri(g),
        None,
        Some(&pat),
        None,
    )
    .await;
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    let r = ui_send(&fx.app, "DELETE", &team_uri(a), None, Some(&pat), JSON).await;
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(ui_json(r).await, serde_json::json!({ "revoked": 1 }));
    let c = fx.meta.lock().await;
    assert_eq!(ui_reason(&c, g).as_deref(), Some("user"));
    assert_eq!(ui_reason(&c, ga).as_deref(), Some("team_admin"));
}

/// Revoked means revoked over HTTP: a real pair from the real flow, revoked
/// from the settings page and from the team page, then refreshed.
#[tokio::test]
async fn revoked_grant_refresh_is_invalid_grant_over_http() {
    let fx = mo::fixture(true).await;
    let m = mo::add_admin(&fx, "mia", "", "member").await;
    let owner_s = ui_session(&fx, fx.owner_id).await;
    let member_s = ui_session(&fx, m).await;
    let mine = mo::obtain_tokens(&fx, &owner_s).await;
    let theirs = mo::obtain_tokens(&fx, &member_s).await;

    let r = ui_send(
        &fx.app,
        "POST",
        &settings_revoke_uri(mine.grant_id),
        Some(&owner_s),
        None,
        None,
    )
    .await;
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    let r = ui_send(&fx.app, "DELETE", &team_uri(m), Some(&owner_s), None, JSON).await;
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(ui_json(r).await, serde_json::json!({ "revoked": 1 }));

    for (who, t) in [("settings", &mine), ("team", &theirs)] {
        let resp = mo::refresh(&fx.app, &t.refresh).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{who}");
        assert_eq!(
            resp.headers()
                .get(header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()),
            Some("no-store"),
            "{who}"
        );
        assert_eq!(
            ui_json(resp).await,
            serde_json::json!({ "error": "invalid_grant" }),
            "{who}"
        );
        let c = fx.meta.lock().await;
        assert!(
            store::find_grant_by_access(&c, &t.access)
                .unwrap()
                .is_none(),
            "{who}"
        );
    }
}

// ─── C. team page route (enabled) ────────────────────────────────────────────

#[tokio::test]
async fn team_revoke_matrix() {
    let fx = mo::fixture(true).await;
    let owner = fx.owner_id;
    let o2 = mo::add_admin(&fx, "olga", "", "owner").await;
    let a = mo::add_admin(&fx, "alice", "", "admin").await;
    let a2 = mo::add_admin(&fx, "amir", "", "admin").await;
    let m = mo::add_admin(&fx, "mia", "", "member").await;
    let m2 = mo::add_admin(&fx, "max", "", "member").await;
    {
        let c = fx.meta.lock().await;
        for id in [owner, o2, a, a2, m, m2] {
            ui_grant(&c, id);
        }
        ui_grant(&c, a);
        ui_grant(&c, m);
    }
    let s_owner = ui_session(&fx, owner).await;
    let s_a = ui_session(&fx, a).await;
    let s_m = ui_session(&fx, m).await;

    // Refusals first, so every target still holds live grants when probed.
    let refusals = [
        (&s_m, m2, "NOT_A_MANAGER", "member -> member"),
        (&s_m, m, "NOT_A_MANAGER", "member -> self"),
        (&s_m, a, "NOT_A_MANAGER", "member -> admin"),
        (&s_a, a2, "PRIVILEGED_ROLE_REQUIRED", "admin -> admin"),
        (&s_a, o2, "PRIVILEGED_ROLE_REQUIRED", "admin -> owner"),
        (&s_a, a, "PRIVILEGED_ROLE_REQUIRED", "admin -> self"),
    ];
    for (session, target, code, ctx) in refusals {
        let before = {
            let c = fx.meta.lock().await;
            ui_live_count(&c, target)
        };
        assert!(before > 0, "{ctx}: fixture");
        let r = ui_send(
            &fx.app,
            "DELETE",
            &team_uri(target),
            Some(session),
            None,
            JSON,
        )
        .await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN, "{ctx}");
        assert_eq!(ui_json(r).await["error_code"], code, "{ctx}");
        let c = fx.meta.lock().await;
        assert_eq!(ui_live_count(&c, target), before, "{ctx}: grants changed");
    }

    let allowed = [
        (&s_a, m, "admin -> member"),
        (&s_owner, a, "owner -> admin"),
        (&s_owner, m2, "owner -> member"),
        (&s_owner, o2, "owner -> owner"),
        (&s_owner, owner, "owner -> self"),
    ];
    for (session, target, ctx) in allowed {
        let live: Vec<i64> = {
            let c = fx.meta.lock().await;
            let mut st = c
                .prepare(
                    "SELECT id FROM _mcp_oauth_grants WHERE admin_id = ?1 AND revoked_at IS NULL",
                )
                .unwrap();
            st.query_map(params![target], |r| r.get(0))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap()
        };
        assert!(!live.is_empty(), "{ctx}: fixture");
        let r = ui_send(
            &fx.app,
            "DELETE",
            &team_uri(target),
            Some(session),
            None,
            JSON,
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK, "{ctx}");
        assert_eq!(
            ui_json(r).await,
            serde_json::json!({ "revoked": live.len() }),
            "{ctx}"
        );
        let c = fx.meta.lock().await;
        for g in live {
            assert_eq!(ui_reason(&c, g).as_deref(), Some("team_admin"), "{ctx}");
        }
    }
}

#[tokio::test]
async fn team_revoke_missing_target() {
    let fx = mo::fixture(true).await;
    let m = mo::add_admin(&fx, "mia", "", "member").await;
    let s_owner = ui_session(&fx, fx.owner_id).await;
    let s_m = ui_session(&fx, m).await;
    let r = ui_send(
        &fx.app,
        "DELETE",
        &team_uri(999_999),
        Some(&s_owner),
        None,
        JSON,
    )
    .await;
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    assert_eq!(ui_json(r).await["error_code"], "ADMIN_NOT_FOUND");
    // A member learns nothing about whether the id exists.
    let r = ui_send(
        &fx.app,
        "DELETE",
        &team_uri(999_999),
        Some(&s_m),
        None,
        JSON,
    )
    .await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    assert_eq!(ui_json(r).await["error_code"], "NOT_A_MANAGER");
}

#[tokio::test]
async fn team_revoke_scope_and_account_kept() {
    let fx = mo::fixture(true).await;
    let a = mo::add_admin(&fx, "alice", "", "admin").await;
    let m = mo::add_admin(&fx, "mia", "", "member").await;
    let s_a = ui_session(&fx, a).await;
    let _pat_a = ui_pat(&fx, a).await;
    let (a_grants, owner_g, m_g) = {
        let c = fx.meta.lock().await;
        let ag = vec![ui_grant_full(&c, a), ui_grant_full(&c, a)];
        (ag, ui_grant(&c, fx.owner_id), ui_grant(&c, m))
    };
    let account_rows = |c: &rusqlite::Connection| -> (i64, i64, i64) {
        let n = |sql: &str| -> i64 { c.query_row(sql, params![a], |r| r.get(0)).unwrap() };
        (
            n("SELECT COUNT(*) FROM admins WHERE id = ?1"),
            n("SELECT COUNT(*) FROM sessions WHERE admin_id = ?1"),
            n("SELECT COUNT(*) FROM _admin_tokens WHERE admin_id = ?1"),
        )
    };
    let before = {
        let c = fx.meta.lock().await;
        account_rows(&c)
    };
    assert_eq!(before.0, 1);
    assert!(before.1 >= 1 && before.2 >= 1, "fixture: {before:?}");

    let s_owner = ui_session(&fx, fx.owner_id).await;
    let r = ui_send(&fx.app, "DELETE", &team_uri(a), Some(&s_owner), None, JSON).await;
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(
        ui_json(r).await,
        serde_json::json!({ "revoked": a_grants.len() })
    );
    {
        let c = fx.meta.lock().await;
        for (g, t, code) in &a_grants {
            assert_eq!(ui_reason(&c, *g).as_deref(), Some("team_admin"));
            assert!(ui_fully_dead(&c, t, code));
        }
        assert!(ui_live(&c, owner_g), "the caller's own grant is untouched");
        assert!(ui_live(&c, m_g), "a third admin's grant is untouched");
        assert_eq!(
            account_rows(&c),
            before,
            "account, sessions and PATs are kept"
        );
    }
    let r = ui_send(&fx.app, "GET", "/admin/settings", Some(&s_a), None, HTML).await;
    assert_eq!(r.status(), StatusCode::OK, "the account still signs in");
    let r = ui_send(&fx.app, "DELETE", &team_uri(a), Some(&s_owner), None, JSON).await;
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(ui_json(r).await, serde_json::json!({ "revoked": 0 }));
}

// ─── D. rendered pages (enabled) ─────────────────────────────────────────────

/// Each `<tr data-admin-id="…"` segment of the team table, up to its `</tr>`.
fn ui_rows(body: &str) -> Vec<(i64, &str)> {
    const OPEN: &str = "<tr data-admin-id=\"";
    let mut out = Vec::new();
    for (at, _) in body.match_indices(OPEN) {
        let rest = &body[at + OPEN.len()..];
        let id: i64 = rest[..rest.find('"').unwrap()].parse().unwrap();
        let end = rest.find("</tr>").expect("row closes");
        out.push((id, &rest[..end]));
    }
    out
}

#[tokio::test]
async fn team_button_visible_only_where_remove_is() {
    let fx = mo::fixture(true).await;
    let a = mo::add_admin(&fx, "alice", "", "admin").await;
    let m = mo::add_admin(&fx, "mia", "", "member").await;
    for (viewer, with_button) in [(fx.owner_id, vec![fx.owner_id, a, m]), (a, vec![m])] {
        let s = ui_session(&fx, viewer).await;
        let resp = ui_send(&fx.app, "GET", "/admin/team", Some(&s), None, HTML).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = ui_body(resp).await;
        let rows = ui_rows(&body);
        assert_eq!(rows.len(), 3, "viewer {viewer}: three admins listed");
        for (id, row) in rows {
            let buttons = row.matches("data-action=\"revoke-mcp\"").count();
            let removes = row.matches("btn-remove").count();
            let want = usize::from(with_button.contains(&id));
            assert_eq!(
                buttons, want,
                "viewer {viewer}, row {id}: revoke-mcp buttons"
            );
            assert_eq!(
                buttons, removes,
                "viewer {viewer}, row {id}: button without Remove"
            );
        }
        assert!(body.contains("/mcp-grants'"), "viewer {viewer}: script");
        assert!(
            body.contains("encodeURIComponent(id)"),
            "viewer {viewer}: script"
        );
    }
}

#[test]
fn mcp_ui_locale_sections_match_and_are_js_safe() {
    fn flatten(
        prefix: &str,
        v: &toml::Value,
        out: &mut std::collections::BTreeMap<String, String>,
    ) {
        match v {
            toml::Value::Table(t) => {
                for (k, child) in t {
                    let key = if prefix.is_empty() {
                        k.clone()
                    } else {
                        format!("{prefix}.{k}")
                    };
                    flatten(&key, child, out);
                }
            }
            toml::Value::String(s) => {
                out.insert(prefix.to_string(), s.clone());
            }
            other => {
                out.insert(prefix.to_string(), other.to_string());
            }
        }
    }
    let load = |file: &str| {
        let path = format!("{}/locales/{file}", env!("CARGO_MANIFEST_DIR"));
        let v: toml::Value = toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let mut all = std::collections::BTreeMap::new();
        flatten("", &v, &mut all);
        all.into_iter()
            .filter(|(k, _)| {
                k.starts_with("settings.mcp_grants.")
                    || k.starts_with("admin_team.mcp.")
                    || k.starts_with("mcp_connect.")
                    || k.starts_with("mcp_diag.")
            })
            .collect::<std::collections::BTreeMap<_, _>>()
    };
    let en = load("en.toml");
    let zh = load("zh-TW.toml");
    assert!(!en.is_empty(), "the MCP UI sections exist");
    assert_eq!(
        en.keys().collect::<Vec<_>>(),
        zh.keys().collect::<Vec<_>>(),
        "en and zh-TW disagree"
    );
    // These values reach single-quoted JS strings and attributes through `|safe`.
    for (lang, map) in [("en", &en), ("zh-TW", &zh)] {
        for (k, v) in map {
            for bad in ["'", "\\", "\n", "\r", "</"] {
                assert!(!v.contains(bad), "{lang} `{k}` contains {bad:?}");
            }
        }
        assert!(
            map["admin_team.mcp.revoke_body"].contains("{email}"),
            "{lang}"
        );
        assert!(map["admin_team.mcp.revoked_n"].contains("{n}"), "{lang}");
    }
}

/// The card: from its root `id` to the first `<script` after it (the card is
/// the last thing in the content block; only `extra_scripts` follows).
fn ui_card(body: &str) -> &str {
    let start = body
        .find("id=\"mcp-grants\"")
        .expect("the MCP connections card");
    let rest = &body[start..];
    &rest[..rest.find("<script").expect("scripts follow the card")]
}

#[tokio::test]
async fn settings_card_lists_own_grants_with_flags() {
    let fx = mo::fixture(true).await;
    let a = mo::add_admin(&fx, "alice", "", "admin").await;
    let (g1, g2, g3, ga, host) = {
        let c = fx.meta.lock().await;
        let g1 = ui_grant(&c, fx.owner_id);
        c.execute(
            "UPDATE _mcp_oauth_grants SET sibling_rejected_at = '2026-01-02 03:04:05', \
             last_used_at = datetime('now') WHERE id = ?1",
            params![g1],
        )
        .unwrap();
        let g2 = mo::seed_grant(
            &c,
            &SeedGrant {
                admin_id: fx.owner_id,
                idle: "-1 hour",
                absolute: "+90 days",
                revoked: false,
            },
        );
        let g3 = mo::seed_grant(
            &c,
            &SeedGrant {
                admin_id: fx.owner_id,
                idle: "+30 days",
                absolute: "+90 days",
                revoked: true,
            },
        );
        let ga = ui_grant(&c, a);
        let host: String = c
            .query_row(
                "SELECT redirect_host FROM _mcp_oauth_grants WHERE id = ?1",
                params![g1],
                |r| r.get(0),
            )
            .unwrap();
        (g1, g2, g3, ga, host)
    };
    let displays: Vec<String> = {
        let c = fx.meta.lock().await;
        drust::mgmt::mcp_oauth::ui::list_grants_for_settings(&c, fx.owner_id)
            .unwrap()
            .into_iter()
            .map(|g| g.client_display)
            .collect()
    };
    assert_eq!(displays.len(), 2, "g1 and g2 listed");
    let s = ui_session(&fx, fx.owner_id).await;
    let resp = ui_send(&fx.app, "GET", "/admin/settings", Some(&s), None, HTML).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = ui_body(resp).await;
    let card = ui_card(&body);
    let action = |g: i64| format!("/admin/settings/mcp-grants/{g}/revoke\"");
    assert!(card.contains(&action(g1)), "own live grant listed");
    assert!(card.contains(&action(g2)), "own expired grant listed");
    assert!(!card.contains(&action(g3)), "revoked grant not listed");
    assert!(
        !card.contains(&action(ga)),
        "another admin's grant not listed"
    );
    assert_eq!(
        card.matches("<span class=\"pill muted\">expired</span>")
            .count(),
        1
    );
    assert_eq!(card.matches("<span class=\"pill warn\"").count(), 1);
    assert!(card.contains("<code data-mcp-sibling-at>2026-01-02 03:04:05</code>"));
    assert!(card.contains(&format!("<code>{host}</code>")));
    // Anchored on the row's name cell: the card description also mentions
    // the client by name, so a bare `contains` could not fail.
    for display in &displays {
        let cell = format!("<div class=\"key-name\">{display}");
        let want = displays.iter().filter(|d| *d == display).count();
        assert_eq!(
            card.matches(&cell).count(),
            want,
            "client_display rendered per row"
        );
    }
    assert!(card.contains("data-mcp-grant-revoke-all"));
}

const EMPTY_EN: &str = "No MCP connections.";
const LOAD_FAILED_EN: &str = "Could not load your MCP connections.";

#[tokio::test]
async fn settings_card_empty_state() {
    let fx = mo::fixture(true).await;
    let s = ui_session(&fx, fx.owner_id).await;
    let resp = ui_send(&fx.app, "GET", "/admin/settings", Some(&s), None, HTML).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = ui_body(resp).await;
    // The card slice, not the body: the revoke-all script names the same
    // attribute in its selector.
    let card = ui_card(&body);
    assert!(card.contains(EMPTY_EN));
    assert!(!card.contains("data-mcp-grant-revoke-all"));
    assert!(!card.contains(LOAD_FAILED_EN));
}

#[tokio::test]
async fn settings_card_zh_tw() {
    let fx = mo::fixture(true).await;
    {
        let c = fx.meta.lock().await;
        ui_grant(&c, fx.owner_id);
    }
    let s = ui_session(&fx, fx.owner_id).await;
    let cookie = format!("{s}; drust_locale=zh-TW");
    let resp = ui_send(&fx.app, "GET", "/admin/settings", Some(&cookie), None, HTML).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = ui_body(resp).await;
    let card = ui_card(&body);
    assert!(card.contains("MCP 連線"));
    assert!(card.contains("全部撤銷"));
}

#[tokio::test]
async fn settings_card_list_failure_still_offers_revoke_all() {
    let fx = mo::fixture(true).await;
    let g1 = {
        let c = fx.meta.lock().await;
        let g = ui_grant(&c, fx.owner_id);
        mo::seed_tokens(&c, g);
        c.execute_batch("ALTER TABLE _mcp_oauth_grants RENAME TO _mcp_oauth_grants_t19")
            .unwrap();
        g
    };
    let s = ui_session(&fx, fx.owner_id).await;
    let resp = ui_send(&fx.app, "GET", "/admin/settings", Some(&s), None, HTML).await;
    let status = resp.status();
    let body = ui_body(resp).await;
    {
        let c = fx.meta.lock().await;
        c.execute_batch("ALTER TABLE _mcp_oauth_grants_t19 RENAME TO _mcp_oauth_grants")
            .unwrap();
        assert!(ui_live(&c, g1));
    }
    assert_eq!(status, StatusCode::OK);
    let card = ui_card(&body);
    assert!(
        card.contains(LOAD_FAILED_EN),
        "the card says the list failed"
    );
    assert!(
        card.contains("data-mcp-grant-revoke-all"),
        "revoke-all is still offered"
    );
    assert!(
        !card.contains(EMPTY_EN),
        "an unreadable list never reads as empty"
    );
}
