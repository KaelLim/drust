//! MA0-7 — `POST /oauth/token` with `grant_type=authorization_code`: the store
//! layer (`redeem_code`, `issue_token_pair`) called directly on the fixture's
//! meta connection, and the HTTP exchange through the production router at
//! ROOT paths (`/oauth/token`, `/admin/team/{id}`; only outbound strings carry
//! `/drust`).
//!
//! `IssuedTokens` and `RedeemOutcome` have no `Debug` (they hold plaintext
//! credentials), so results are checked with `matches!`, never `unwrap_err`.

use drust::mgmt::mcp_oauth::config::McpOauthConfig;
use drust::mgmt::mcp_oauth::store::{self, CodeRedeemRequest, RedeemOutcome};
use drust::mgmt::mcp_oauth::tokens::{self, TokenKind};
use rusqlite::params;

use crate::common::mcp_oauth::*;

// ─── file-private helpers ────────────────────────────────────────────────────

fn code_hash(code: &str) -> String {
    tokens::hash(TokenKind::Code, code)
}

fn redeemed(conn: &rusqlite::Connection, code: &str) -> bool {
    conn.query_row(
        "SELECT redeemed_at IS NOT NULL FROM _mcp_oauth_codes WHERE code_hash = ?1",
        params![code_hash(code)],
        |r| r.get(0),
    )
    .unwrap()
}

/// Mints an admin session directly (no argon2, no login budget).
async fn session_for(fx: &McpOauthFixture, admin_id: i64) -> String {
    let mut c = fx.meta.lock().await;
    let token = drust::auth::session::create_session(&mut c, admin_id, 3600).unwrap();
    format!("drust_session={token}")
}

/// A code seeded directly (no authorize round-trip).
struct Seeded {
    grant_id: i64,
    code: String,
    verifier: String,
    redirect: String,
}

/// A live grant of the owner (30 / 90 days) plus one code bound to
/// `redirect` and `resource` with a fresh PKCE pair.
async fn seeded_with(fx: &McpOauthFixture, redirect: &str, resource: Option<&str>) -> Seeded {
    let conn = fx.meta.lock().await;
    let grant_id = seed_grant(
        &conn,
        &SeedGrant {
            admin_id: fx.owner_id,
            idle: "+30 days",
            absolute: "+90 days",
            revoked: false,
        },
    );
    let (verifier, challenge) = pkce();
    let code = seed_code(&conn, grant_id, redirect, &challenge, resource);
    Seeded {
        grant_id,
        code,
        verifier,
        redirect: redirect.to_string(),
    }
}

async fn seeded(fx: &McpOauthFixture) -> Seeded {
    seeded_with(fx, &loopback_redirect(5001), Some(RESOURCE)).await
}

fn request<'a>(s: &'a Seeded) -> CodeRedeemRequest<'a> {
    CodeRedeemRequest {
        code: &s.code,
        client_id: CC_CLIENT_ID,
        redirect_uri: Some(&s.redirect),
        verifier: Some(&s.verifier),
        resource: Some(RESOURCE),
    }
}

/// The fixture's own config: `for_tests(PUBLIC_URL)`, default TTLs.
fn cfg() -> McpOauthConfig {
    McpOauthConfig::for_tests(PUBLIC_URL)
}

fn row_count(conn: &rusqlite::Connection, table: &str) -> i64 {
    count(conn, &format!("SELECT COUNT(*) FROM {table}"))
}

// ─── store layer ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_invalid_redemption_writes_nothing() {
    let fx = fixture(true).await;
    let s = seeded(&fx).await;
    let (other_verifier, _) = pkce();
    let other_port = loopback_redirect(5002);
    let cases: Vec<(&str, CodeRedeemRequest)> = vec![
        (
            "wrong verifier",
            CodeRedeemRequest {
                verifier: Some(&other_verifier),
                ..request(&s)
            },
        ),
        (
            "wrong port",
            CodeRedeemRequest {
                redirect_uri: Some(&other_port),
                ..request(&s)
            },
        ),
        (
            "missing redirect",
            CodeRedeemRequest {
                redirect_uri: None,
                ..request(&s)
            },
        ),
        (
            "other resource",
            CodeRedeemRequest {
                resource: Some("https://other.test/drust/mcp"),
                ..request(&s)
            },
        ),
    ];
    let conn = fx.meta.lock().await;
    for (name, req) in &cases {
        let tx = conn.unchecked_transaction().unwrap();
        let before = conn.total_changes();
        let out = store::redeem_code(&tx, &cfg(), req).unwrap();
        assert!(matches!(out, RedeemOutcome::Invalid), "{name}");
        assert_eq!(conn.total_changes(), before, "{name}: wrote something");
        drop(tx);
        assert!(!redeemed(&conn, &s.code), "{name}: code consumed");
    }
}

#[tokio::test]
async fn an_expired_redemption_writes_nothing() {
    let fx = fixture(true).await;
    let s = seeded(&fx).await;
    let conn = fx.meta.lock().await;
    conn.execute(
        "UPDATE _mcp_oauth_codes SET expires_at = datetime('now','-1 second') WHERE code_hash = ?1",
        params![code_hash(&s.code)],
    )
    .unwrap();
    let tx = conn.unchecked_transaction().unwrap();
    let before = conn.total_changes();
    let out = store::redeem_code(&tx, &cfg(), &request(&s)).unwrap();
    assert!(matches!(out, RedeemOutcome::Invalid));
    assert_eq!(conn.total_changes(), before);
    drop(tx);
    assert!(!redeemed(&conn, &s.code));
}

#[tokio::test]
async fn an_unknown_code_is_a_miss() {
    let fx = fixture(true).await;
    let s = seeded(&fx).await;
    let unknown = tokens::new_token(TokenKind::Code);
    let conn = fx.meta.lock().await;
    let tx = conn.unchecked_transaction().unwrap();
    let before = conn.total_changes();
    let req = CodeRedeemRequest {
        code: &unknown,
        ..request(&s)
    };
    let out = store::redeem_code(&tx, &cfg(), &req).unwrap();
    assert!(matches!(out, RedeemOutcome::Miss));
    assert_eq!(conn.total_changes(), before);
}

#[tokio::test]
async fn replay_carries_the_grant_and_writes_nothing_itself() {
    let fx = fixture(true).await;
    let s = seeded(&fx).await;
    let cfg = cfg();
    let conn = fx.meta.lock().await;
    {
        let tx = conn.unchecked_transaction().unwrap();
        match store::redeem_code(&tx, &cfg, &request(&s)).unwrap() {
            RedeemOutcome::Issued { grant, .. } => {
                assert_eq!(grant.grant_id(), s.grant_id);
                assert_eq!(grant.admin_id(), fx.owner_id);
            }
            _ => panic!("first redemption must be Issued"),
        }
        tx.commit().unwrap();
    }
    let tx = conn.unchecked_transaction().unwrap();
    let before = conn.total_changes();
    match store::redeem_code(&tx, &cfg, &request(&s)).unwrap() {
        RedeemOutcome::Replay { grant } => {
            assert_eq!(grant.grant_id(), s.grant_id);
            assert_eq!(grant.admin_id(), fx.owner_id);
        }
        _ => panic!("second fully valid redemption must be Replay"),
    }
    assert_eq!(
        conn.total_changes(),
        before,
        "redeem_code itself revokes nothing"
    );
}

#[tokio::test]
async fn issue_token_pair_links_access_to_the_refresh_it_inserted() {
    let fx = fixture(true).await;
    let s = seeded(&fx).await;
    let g = s.grant_id;
    let conn = fx.meta.lock().await;
    let tx = conn.unchecked_transaction().unwrap();
    let t = store::issue_token_pair(&tx, &cfg(), g, None).unwrap();
    tx.commit().unwrap();
    assert_eq!(t.expires_in, 3600);
    assert_eq!(row_count(&conn, "_mcp_oauth_refresh"), 1);
    let (rid, parent_null, rhash, rexp_ok): (i64, bool, String, bool) = conn
        .query_row(
            "SELECT r.id, r.parent_id IS NULL, r.token_hash, \
                    r.expires_at = (SELECT MIN(idle_expires_at, absolute_expires_at) \
                                      FROM _mcp_oauth_grants WHERE id = ?1) \
               FROM _mcp_oauth_refresh r WHERE r.grant_id = ?1",
            params![g],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap();
    assert_eq!(rid, t.refresh_id);
    assert!(parent_null);
    assert_eq!(rhash, tokens::hash(TokenKind::Refresh, &t.refresh_token));
    assert!(
        rexp_ok,
        "refresh expires_at = the grant's MIN(idle, absolute)"
    );
    assert_eq!(row_count(&conn, "_mcp_oauth_access"), 1);
    let (refresh_id, grant_id, aexp_ok): (i64, i64, bool) = conn
        .query_row(
            "SELECT refresh_id, grant_id, \
                    expires_at >= datetime('now','+3590 seconds') \
                AND expires_at <= datetime('now','+3600 seconds') \
               FROM _mcp_oauth_access WHERE token_hash = ?1",
            params![tokens::hash(TokenKind::Access, &t.access_token)],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(refresh_id, t.refresh_id);
    assert_eq!(grant_id, g);
    assert!(aexp_ok, "access expires_at = now + 3600 s");
    assert_eq!(
        count(
            &conn,
            &format!(
                "SELECT COUNT(*) FROM _mcp_oauth_grants WHERE id = {g} AND last_used_at IS NOT NULL"
            )
        ),
        1
    );
    assert!(t.access_token.starts_with(tokens::ACCESS_PREFIX));
    assert!(t.refresh_token.starts_with(tokens::REFRESH_PREFIX));
}

#[tokio::test]
async fn issue_token_pair_with_a_parent_from_another_grant_inserts_nothing() {
    let fx = fixture(true).await;
    let a = seeded(&fx).await.grant_id;
    let b = seeded(&fx).await.grant_id;
    let cfg = cfg();
    let conn = fx.meta.lock().await;
    let tx = conn.unchecked_transaction().unwrap();
    let rb = store::issue_token_pair(&tx, &cfg, b, None)
        .unwrap()
        .refresh_id;
    tx.commit().unwrap();
    let (refresh, access) = (
        row_count(&conn, "_mcp_oauth_refresh"),
        row_count(&conn, "_mcp_oauth_access"),
    );
    let tx = conn.unchecked_transaction().unwrap();
    let r = store::issue_token_pair(&tx, &cfg, a, Some(rb));
    assert!(matches!(r, Err(rusqlite::Error::QueryReturnedNoRows)));
    drop(tx);
    assert_eq!(row_count(&conn, "_mcp_oauth_refresh"), refresh);
    assert_eq!(row_count(&conn, "_mcp_oauth_access"), access);
}

#[tokio::test]
async fn issue_token_pair_refuses_a_revoked_or_expired_grant() {
    let fx = fixture(true).await;
    let cfg = cfg();
    let conn = fx.meta.lock().await;
    let revoked = seed_grant(
        &conn,
        &SeedGrant {
            admin_id: fx.owner_id,
            idle: "+30 days",
            absolute: "+90 days",
            revoked: true,
        },
    );
    let idle_expired = seed_grant(
        &conn,
        &SeedGrant {
            admin_id: fx.owner_id,
            idle: "-1 hour",
            absolute: "+90 days",
            revoked: false,
        },
    );
    for g in [revoked, idle_expired] {
        let tx = conn.unchecked_transaction().unwrap();
        let r = store::issue_token_pair(&tx, &cfg, g, None);
        assert!(
            matches!(r, Err(rusqlite::Error::QueryReturnedNoRows)),
            "grant {g}"
        );
    }
    assert_eq!(row_count(&conn, "_mcp_oauth_refresh"), 0);
    assert_eq!(row_count(&conn, "_mcp_oauth_access"), 0);
}

#[tokio::test]
async fn a_short_absolute_caps_the_refresh_expiry() {
    let fx = fixture(true).await;
    let cfg = cfg();
    let conn = fx.meta.lock().await;
    let g = seed_grant(
        &conn,
        &SeedGrant {
            admin_id: fx.owner_id,
            idle: "+30 days",
            absolute: "+1 day",
            revoked: false,
        },
    );
    let tx = conn.unchecked_transaction().unwrap();
    store::issue_token_pair(&tx, &cfg, g, None).unwrap();
    tx.commit().unwrap();
    let capped: bool = conn
        .query_row(
            "SELECT r.expires_at = g.absolute_expires_at \
               FROM _mcp_oauth_refresh r JOIN _mcp_oauth_grants g ON g.id = r.grant_id \
              WHERE g.id = ?1",
            params![g],
            |r| r.get(0),
        )
        .unwrap();
    assert!(capped);
}

/// The sweep deletes a grant that is `authorization_code`, never used, and has
/// no code and no refresh left (`SQL_ABANDONED`). An exchange sets
/// `last_used_at` and leaves a refresh, so once its redeemed code has expired
/// and been swept, the grant itself must survive.
#[tokio::test]
async fn an_exchanged_grant_is_not_swept_as_abandoned() {
    let fx = fixture(true).await;
    let s = seeded(&fx).await;
    {
        let conn = fx.meta.lock().await;
        let tx = conn.unchecked_transaction().unwrap();
        let out = store::redeem_code(&tx, &cfg(), &request(&s)).unwrap();
        assert!(matches!(out, RedeemOutcome::Issued { .. }));
        tx.commit().unwrap();
        conn.execute(
            "UPDATE _mcp_oauth_codes SET expires_at = datetime('now','-1 second')",
            [],
        )
        .unwrap();
    }
    let swept = drust::mgmt::mcp_oauth::sweep::sweep_mcp_oauth(&fx.meta).await;
    assert_eq!(swept.codes, 1, "the redeemed code expired and was swept");
    assert_eq!(swept.abandoned, 0);
    let conn = fx.meta.lock().await;
    assert_eq!(
        count(
            &conn,
            &format!(
                "SELECT COUNT(*) FROM _mcp_oauth_grants WHERE id = {} AND revoked_at IS NULL",
                s.grant_id
            )
        ),
        1
    );
}

/// R5: one grant has exactly one code, so revoking the grant on a replay is
/// exactly "revoke every token issued from that code". A protective test: it
/// holds since MA0-6 and pins the shape `code_replay` relies on.
#[tokio::test]
async fn each_grant_has_exactly_one_code() {
    let fx = fixture(true).await;
    let session = session_for(&fx, fx.owner_id).await;
    let _a = obtain_code(&fx, &session, 53_682, None).await;
    let _b = obtain_code(&fx, &session, 53_683, None).await;
    let conn = fx.meta.lock().await;
    assert_eq!(row_count(&conn, "_mcp_oauth_grants"), 2);
    let per_grant: Vec<i64> = conn
        .prepare("SELECT COUNT(*) FROM _mcp_oauth_codes GROUP BY grant_id")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(per_grant, vec![1, 1]);
}
