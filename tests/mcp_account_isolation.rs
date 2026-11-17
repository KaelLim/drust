//! Isolation between the account-level MCP endpoint and every other plane.
//!
//! An MCP access token is refused everywhere else, with two deliberate
//! exceptions that are not "the other plane accepting it": POST /oauth/revoke
//! answers 200 to it (RFC 7009; it revokes the token's own grant), and
//! /oauth/token answers invalid_grant to it presented as a refresh token.
mod helpers;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use drust::mgmt::mcp_oauth::tokens::{TokenKind, new_token};
use helpers::mcp_init as init;
use serde_json::Value;
use tower::ServiceExt;

async fn harness() -> helpers::AccountMcpHarness {
    helpers::spin_up_account_mcp_with(helpers::AccountMcpOpts {
        admins: vec![("mcp-owner", "owner")],
        tenants: vec![("t1", Some(0))],
        files: true,
        mcp_enabled: true,
    })
    .await
}

/// The backfilled unlabeled UI PAT run_migrations minted for this admin.
fn ui_pat(conn: &rusqlite::Connection, admin_id: i64) -> String {
    conn.query_row(
        "SELECT plaintext FROM _admin_tokens WHERE admin_id = ?1 AND label IS NULL AND revoked_at IS NULL",
        [admin_id],
        |r| r.get(0),
    )
    .unwrap()
}

/// Every other plane's credential, each valid where it belongs.
async fn foreign_credentials(h: &helpers::AccountMcpHarness) -> Vec<(&'static str, String)> {
    let (ui, cli, refresh) = {
        let m = h.meta.lock().await;
        m.execute(
            "UPDATE tenants SET allow_self_register = 1 WHERE id = ?1",
            [&h.tid],
        )
        .unwrap();
        let ui = ui_pat(&m, h.admin_id);
        let cli = drust::auth::admin_token::mint_cli_token(&m, h.admin_id, "test", 3600)
            .unwrap()
            .1;
        let refresh = drust::mgmt::mcp_oauth::store::seed_access_for_tests(&m, h.admin_id)
            .unwrap()
            .refresh;
        (ui, cli, refresh)
    }; // guard dropped before the app runs: its handlers lock meta too
    let user = helpers::register_and_login_via_app(
        &h.app,
        &h.tid,
        "u@example.test",
        "a-long-test-password-1",
    )
    .await;
    vec![
        ("service", h.svc.clone()),
        ("anon", h.anon.clone()),
        ("user", user),
        ("ui_pat", ui),
        ("cli_pat", cli),
        ("refresh", refresh),
        ("code", new_token(TokenKind::Code)),
        ("upload_ticket", new_token(TokenKind::UploadTicket)),
    ]
}

/// POST a form body with no Authorization header.
async fn post_form(app: &axum::Router, uri: &str, form: String) -> StatusCode {
    let r = Request::builder()
        .method("POST")
        .uri(uri)
        .header("host", "127.0.0.1")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(form))
        .unwrap();
    app.clone().oneshot(r).await.unwrap().status()
}

async fn live(h: &helpers::AccountMcpHarness, token: &str) -> bool {
    helpers::mcp_rpc(&h.app, Some(token), init("2025-06-18"))
        .await
        .0
        == StatusCode::OK
}

async fn dead(h: &helpers::AccountMcpHarness, token: &str) -> bool {
    let (s, hd, _) = helpers::mcp_rpc(&h.app, Some(token), init("2025-06-18")).await;
    s == StatusCode::UNAUTHORIZED
        && hd["www-authenticate"]
            .to_str()
            .unwrap()
            .ends_with(r#"error="invalid_token""#)
}

#[tokio::test]
async fn other_plane_credentials_are_refused_on_mcp() {
    let h = harness().await;
    for (kind, tok) in foreign_credentials(&h).await {
        let (s, hd, b) = helpers::mcp_raw(
            &h.app,
            "POST",
            &[("authorization", &format!("Bearer {tok}"))],
            Some(init("2025-06-18")),
        )
        .await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{kind}");
        assert!(
            hd["www-authenticate"]
                .to_str()
                .unwrap()
                .ends_with(r#"error="invalid_token""#),
            "{kind}"
        );
        assert_eq!(
            b,
            br#"{"message":"OAuth only: remove Authorization header from this server's config, then /mcp -> Authenticate","error_code":"MCP_OAUTH_REQUIRED"}"#,
            "{kind}"
        );
    }
}

#[tokio::test]
async fn an_admin_session_cookie_is_not_a_credential() {
    let h = harness().await;
    let cookie = {
        let mut m = h.meta.lock().await;
        format!(
            "drust_session={}",
            drust::auth::session::create_session(&mut m, h.admin_id, 3600).unwrap()
        )
    };
    let (s, hd, b) = helpers::mcp_raw(
        &h.app,
        "POST",
        &[("cookie", &cookie)],
        Some(init("2025-06-18")),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let challenge = hd["www-authenticate"].to_str().unwrap();
    assert!(
        !challenge.contains("error="),
        "no Authorization header at all is the plain challenge, not invalid_token"
    );
    assert!(hd.get("set-cookie").is_none());
    assert_eq!(
        b,
        br#"{"message":"OAuth required: in Claude Code run /mcp, then Authenticate","error_code":"MCP_OAUTH_REQUIRED"}"#
    );
}

#[tokio::test]
async fn mcp_access_is_refused_on_every_other_plane() {
    let h = harness().await;
    let a = format!("Bearer {}", h.access);
    let grant_revoke = format!("/admin/settings/mcp-grants/{}/revoke", h.grant_id);
    for (m, uri, want, code) in [
        ("GET", "/t/t1/records/notes", 401, "UNAUTHENTICATED"),
        (
            "GET",
            "/t/t1/records/notes/subscribe",
            401,
            "UNAUTHENTICATED",
        ),
        ("GET", "/t/t1/realtime", 401, "UNAUTHENTICATED"),
        ("GET", "/t/t1/files", 401, "UNAUTHENTICATED"),
        ("POST", "/t/t1/uploads", 401, "UNAUTHENTICATED"),
        ("POST", "/t/t1/mcp", 401, "UNAUTHENTICATED"),
        ("POST", "/t/t1/query", 401, "UNAUTHENTICATED"),
        (
            "GET",
            "/t/no-such-tenant/records/notes",
            404,
            "TENANT_NOT_FOUND",
        ),
        ("GET", "/admin/tenants", 401, "ADMIN_PAT_INVALID"),
        ("POST", grant_revoke.as_str(), 401, "ADMIN_PAT_INVALID"),
        ("GET", "/oauth/consent?req=x", 401, "ADMIN_PAT_INVALID"),
        ("GET", "/auth/cli/whoami", 401, "CLI_AUTH_REQUIRED"),
    ] {
        let (s, _, b) = helpers::http_raw(
            &h.app,
            m,
            uri,
            &[("authorization", &a), ("accept", ""), ("content-type", "")],
            None,
        )
        .await;
        assert_eq!(s.as_u16(), want, "{m} {uri}");
        assert!(!s.is_success() && !s.is_server_error(), "{m} {uri}");
        let v: Value =
            serde_json::from_slice(&b).unwrap_or_else(|_| panic!("{m} {uri}: body is not JSON"));
        assert_eq!(v["error_code"], code, "{m} {uri}");
    }
    assert!(
        live(&h, &h.access).await,
        "refused requests revoked nothing"
    );
}

#[tokio::test]
async fn a_foreign_host_is_421_before_auth() {
    let h = harness().await;
    for auth in [Some(format!("Bearer {}", h.access)), None] {
        let mut hs = vec![("host", "evil.example")];
        if let Some(a) = &auth {
            hs.push(("authorization", a));
        }
        let (s, _, _) = helpers::mcp_raw(&h.app, "POST", &hs, Some(init("2025-06-18"))).await;
        assert_eq!(s, StatusCode::MISDIRECTED_REQUEST);
    }
}

#[tokio::test]
async fn unknown_access_shaped_tokens_are_always_401() {
    let h = harness().await;
    // A second grant, revoked in SQL: its access row still exists.
    let revoked = {
        let m = h.meta.lock().await;
        let s = drust::mgmt::mcp_oauth::store::seed_access_for_tests(&m, h.admin_id).unwrap();
        m.execute(
            "UPDATE _mcp_oauth_grants SET revoked_at = datetime('now') WHERE id = ?1",
            [s.grant_id],
        )
        .unwrap();
        s.access
    };
    // No per-IP bucket is read: a dead or unknown token is always the 401 that sends the client to refresh.
    let budget = drust::mgmt::mcp_oauth::rl::RS_MISS_IP_BUDGET as usize;
    for i in 0..=budget {
        let (s, hd, _) = helpers::mcp_rpc(
            &h.app,
            Some(&new_token(TokenKind::Access)),
            init("2025-06-18"),
        )
        .await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "miss #{i}");
        assert!(
            hd["www-authenticate"]
                .to_str()
                .unwrap()
                .ends_with(r#"error="invalid_token""#),
            "miss #{i}"
        );
        assert!(hd.get("retry-after").is_none(), "miss #{i}");
    }
    let (s, _, m) = helpers::mcp_rpc(&h.app, Some(&h.access), init("2025-06-18")).await;
    assert_eq!(
        s,
        StatusCode::OK,
        "a flood of unknown tokens never blocks a valid one"
    );
    assert_eq!(m[0]["result"]["protocolVersion"], "2025-06-18");
    assert!(
        dead(&h, &revoked).await,
        "a revoked token stays 401 invalid_token after the flood"
    );
}

#[tokio::test]
async fn revocation_takes_effect_on_the_next_call() {
    let h = harness().await;
    let (pat, a, b) = {
        let m = h.meta.lock().await;
        let a = drust::mgmt::mcp_oauth::store::seed_access_for_tests(&m, h.admin_id).unwrap();
        let b = drust::mgmt::mcp_oauth::store::seed_access_for_tests(&m, h.admin_id).unwrap();
        (ui_pat(&m, h.admin_id), a.access, (b.grant_id, b.access))
    };
    let pat_auth = format!("Bearer {pat}");
    for t in [&h.access, &a, &b.1] {
        assert!(live(&h, t).await);
    }
    // 1. RFC 7009 revoke with the token itself: its grant only.
    assert_eq!(
        post_form(&h.app, "/oauth/revoke", format!("token={a}")).await,
        StatusCode::OK
    );
    assert!(dead(&h, &a).await, "oauth/revoke");
    assert!(
        live(&h, &b.1).await && live(&h, &h.access).await,
        "sibling grants untouched"
    );
    // 2. Settings page, one grant.
    let uri = format!("/admin/settings/mcp-grants/{}/revoke", b.0);
    let (s, _, _) = helpers::http_raw(
        &h.app,
        "POST",
        &uri,
        &[
            ("authorization", &pat_auth),
            ("accept", ""),
            ("content-type", ""),
        ],
        None,
    )
    .await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    assert!(dead(&h, &b.1).await, "settings revoke");
    assert!(live(&h, &h.access).await, "sibling grant untouched");
    // 3. Settings page, revoke all.
    let (s, _, _) = helpers::http_raw(
        &h.app,
        "POST",
        "/admin/settings/mcp-grants/revoke-all",
        &[
            ("authorization", &pat_auth),
            ("accept", ""),
            ("content-type", ""),
        ],
        None,
    )
    .await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    assert!(dead(&h, &h.access).await, "settings revoke-all");
}
