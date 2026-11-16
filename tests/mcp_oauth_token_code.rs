//! `POST /oauth/token` with `grant_type=authorization_code`: the store
//! layer (`redeem_code`, `issue_token_pair`) called directly on the fixture's
//! meta connection, and the HTTP exchange through the production router at
//! ROOT paths (`/oauth/token`, `/admin/team/{id}`; only outbound strings carry
//! `/drust`).
//!
//! `IssuedTokens` and `RedeemOutcome` have no `Debug` (they hold plaintext
//! credentials), so results are checked with `matches!`, never `unwrap_err`.

use axum::body::Body;
use axum::http::{HeaderMap, Response, StatusCode, header};
use drust::auth::middleware::AdminId;
use drust::mgmt::mcp_oauth::config::{McpOauthConfig, McpOauthEnv};
use drust::mgmt::mcp_oauth::store::{
    self, CodeRedeemRequest, GrantOwner, RedeemOutcome, RevokeReason, RevokedGrant,
};
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
    challenge: String,
    redirect: String,
}

/// A live grant of the owner (30 / 90 days) plus one code bound to
/// `redirect` and `resource` with a fresh PKCE pair.
async fn seeded_with(fx: &McpOauthFixture, redirect: &str, resource: Option<&str>) -> Seeded {
    seeded_for(fx, fx.owner_id, redirect, resource).await
}

/// `seeded_with` for any admin.
async fn seeded_for(
    fx: &McpOauthFixture,
    admin_id: i64,
    redirect: &str,
    resource: Option<&str>,
) -> Seeded {
    let conn = fx.meta.lock().await;
    let grant_id = seed_grant(
        &conn,
        &SeedGrant {
            admin_id,
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
        challenge,
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
        // The abandoned rule spares a grant that still has a code or a refresh
        // row, so take both away: only last_used_at may keep this grant.
        conn.execute_batch(
            "UPDATE _mcp_oauth_codes SET expires_at = datetime('now','-1 second'); \
             UPDATE _mcp_oauth_refresh SET expires_at = datetime('now','-1 second'); \
             UPDATE _mcp_oauth_access SET expires_at = datetime('now','-1 second');",
        )
        .unwrap();
        let last_used: Option<String> = conn
            .query_row(
                "SELECT last_used_at FROM _mcp_oauth_grants WHERE id = ?1",
                params![s.grant_id],
                |r| r.get(0),
            )
            .unwrap();
        assert!(last_used.is_some(), "the exchange set last_used_at");
    }
    let swept = drust::mgmt::mcp_oauth::sweep::sweep_mcp_oauth(&fx.meta).await;
    assert_eq!(swept.codes, 1, "the redeemed code expired and was swept");
    assert_eq!(swept.refresh, 1, "its refresh expired and was swept");
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
/// holds since consent approval was written and pins the shape `code_replay` relies on.
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

// ─── HTTP helpers ────────────────────────────────────────────────────────────

/// `POST /oauth/token` — a root path; the production router has no `/drust`.
async fn post_token(
    app: &axum::Router,
    pairs: &[(&str, &str)],
    headers: &[(&str, &str)],
) -> Response<Body> {
    post_form(app, "/oauth/token", pairs, &[], headers).await
}

/// The SDK-shaped token form for a seeded code (`token_form_for` needs a
/// `CodeGrant`, which only the authorize round-trip yields, and always sends
/// `RESOURCE`).
fn form<'a>(
    code: &'a str,
    verifier: &'a str,
    redirect: Option<&'a str>,
    resource: Option<&'a str>,
) -> Vec<(&'a str, &'a str)> {
    let mut f = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("code_verifier", verifier),
    ];
    if let Some(r) = redirect {
        f.push(("redirect_uri", r));
    }
    f.push(("client_id", CC_CLIENT_ID));
    if let Some(r) = resource {
        f.push(("resource", r));
    }
    f
}

/// The full form for `s`, with `resource = RESOURCE`.
fn seeded_form(s: &Seeded) -> Vec<(&str, &str)> {
    form(&s.code, &s.verifier, Some(&s.redirect), Some(RESOURCE))
}

/// `f` with `key` removed, then set to `v` when `Some`.
fn set<'a>(
    mut f: Vec<(&'a str, &'a str)>,
    key: &'a str,
    v: Option<&'a str>,
) -> Vec<(&'a str, &'a str)> {
    f.retain(|(k, _)| *k != key);
    if let Some(v) = v {
        f.push((key, v));
    }
    f
}

/// Exactly one `Cache-Control` value, and it is `no-store`.
fn assert_single_no_store(h: &HeaderMap, ctx: &str) {
    let cc: Vec<_> = h.get_all(header::CACHE_CONTROL).iter().collect();
    assert_eq!(cc.len(), 1, "{ctx}: one cache-control value, got {cc:?}");
    assert_eq!(cc[0], "no-store", "{ctx}: cache-control");
}

/// The OAuth error contract; returns the headers.
async fn assert_oauth_error(
    resp: Response<Body>,
    status: StatusCode,
    code: &str,
    ctx: &str,
) -> HeaderMap {
    assert_eq!(resp.status(), status, "{ctx}: status");
    let h = resp.headers().clone();
    let ct = h
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert_eq!(
        ct.split(';').next().unwrap().trim(),
        "application/json",
        "{ctx}: content-type"
    );
    assert_single_no_store(&h, ctx);
    assert!(h.get(header::LOCATION).is_none(), "{ctx}: location");
    assert!(h.get(header::SET_COOKIE).is_none(), "{ctx}: set-cookie");
    let v = body_json(resp).await;
    assert_eq!(v["error"], code, "{ctx}: error code");
    if let Some(d) = v.get("error_description") {
        for b in d.as_str().unwrap().bytes() {
            assert!(
                matches!(b, 0x20..=0x21 | 0x23..=0x5B | 0x5D..=0x7E),
                "{ctx}: error_description byte {b:#x}"
            );
        }
    }
    h
}

async fn assert_invalid_grant(resp: Response<Body>, ctx: &str) {
    assert_oauth_error(resp, StatusCode::BAD_REQUEST, "invalid_grant", ctx).await;
}

/// A 429 `temporarily_unavailable` with an integer `Retry-After` in 1..=max.
async fn assert_throttled(resp: Response<Body>, max: u64, ctx: &str) {
    let h = assert_oauth_error(
        resp,
        StatusCode::TOO_MANY_REQUESTS,
        "temporarily_unavailable",
        ctx,
    )
    .await;
    let ra: u64 = h
        .get(header::RETRY_AFTER)
        .unwrap_or_else(|| panic!("{ctx}: Retry-After"))
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!((1..=max).contains(&ra), "{ctx}: Retry-After {ra}");
}

/// 200 with a token pair; returns (access, refresh).
async fn assert_issued(resp: Response<Body>, ctx: &str) -> (String, String) {
    assert_eq!(resp.status(), StatusCode::OK, "{ctx}: status");
    let v = body_json(resp).await;
    (
        v["access_token"].as_str().unwrap().to_string(),
        v["refresh_token"].as_str().unwrap().to_string(),
    )
}

async fn redeemed_now(fx: &McpOauthFixture, code: &str) -> bool {
    redeemed(&*fx.meta.lock().await, code)
}

/// (revoked_at, revoke_reason) of a grant.
async fn grant_revocation(fx: &McpOauthFixture, g: i64) -> (Option<String>, Option<String>) {
    fx.meta
        .lock()
        .await
        .query_row(
            "SELECT revoked_at, revoke_reason FROM _mcp_oauth_grants WHERE id = ?1",
            params![g],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap()
}

async fn grant_of_code(fx: &McpOauthFixture, code: &str) -> i64 {
    fx.meta
        .lock()
        .await
        .query_row(
            "SELECT grant_id FROM _mcp_oauth_codes WHERE code_hash = ?1",
            params![code_hash(code)],
            |r| r.get(0),
        )
        .unwrap()
}

/// Every (table, column) of the WHOLE database whose text contains `needle`.
fn plaintext_anywhere(conn: &rusqlite::Connection, needle: &str) -> Vec<(String, String)> {
    let tables: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    let mut hits = Vec::new();
    for t in tables {
        let cols: Vec<String> = conn
            .prepare("SELECT name FROM pragma_table_info(?1)")
            .unwrap()
            .query_map(params![t], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        for c in cols {
            let n: i64 = conn
                .query_row(
                    &format!(
                        "SELECT COUNT(*) FROM \"{t}\" WHERE instr(CAST(\"{c}\" AS TEXT), ?1) > 0"
                    ),
                    params![needle],
                    |r| r.get(0),
                )
                .unwrap();
            if n > 0 {
                hits.push((t.clone(), c));
            }
        }
    }
    hits
}

type Snapshot = (StatusCode, Vec<(String, String)>, Vec<u8>);

/// Status, every header sorted by name, and the body.
async fn snapshot(resp: Response<Body>) -> Snapshot {
    let status = resp.status();
    let mut headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_string(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect();
    headers.sort_by(|a, b| a.0.cmp(&b.0));
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap()
        .to_vec();
    (status, headers, body)
}

fn random_code() -> String {
    tokens::new_token(TokenKind::Code)
}

// ─── A. success ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn sdk_shaped_exchange_issues_a_bearer_pair() {
    let fx = fixture(true).await;
    let cookie = login(&fx.app, OWNER_USER, OWNER_PASS).await;
    let cg = obtain_code(&fx, &cookie, 53_682, Some("st")).await;
    let resp = exchange(&fx.app, &cg).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let h = resp.headers().clone();
    let ct = h.get(header::CONTENT_TYPE).unwrap().to_str().unwrap();
    assert_eq!(ct.split(';').next().unwrap().trim(), "application/json");
    assert_single_no_store(&h, "success");
    assert!(h.get(header::LOCATION).is_none());
    assert!(h.get(header::SET_COOKIE).is_none());
    let v = body_json(resp).await;
    let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "access_token",
            "expires_in",
            "refresh_token",
            "scope",
            "token_type"
        ]
    );
    let access = v["access_token"].as_str().unwrap();
    let refresh = v["refresh_token"].as_str().unwrap();
    assert!(access.starts_with("drust_mcpat_"));
    assert_eq!(access.len(), 55);
    assert!(refresh.starts_with("drust_mcprt_"));
    assert_eq!(refresh.len(), 55);
    assert_eq!(v["token_type"], "Bearer");
    assert!(v["expires_in"].is_number(), "expires_in is a number");
    assert_eq!(v["expires_in"], 3600);
    assert_eq!(v["scope"], "mcp");
}

#[tokio::test]
async fn exchange_rows_are_linked_in_the_same_response() {
    let fx = fixture(true).await;
    let session = session_for(&fx, fx.owner_id).await;
    let cg = obtain_code(&fx, &session, 53_682, None).await;
    let g = grant_of_code(&fx, &cg.code).await;
    let (access, refresh) = assert_issued(exchange(&fx.app, &cg).await, "exchange").await;
    let conn = fx.meta.lock().await;
    assert_eq!(row_count(&conn, "_mcp_oauth_access"), 1);
    assert_eq!(row_count(&conn, "_mcp_oauth_refresh"), 1);
    let (rid, parent_null, rgrant): (i64, bool, i64) = conn
        .query_row(
            "SELECT id, parent_id IS NULL, grant_id FROM _mcp_oauth_refresh WHERE token_hash = ?1",
            params![tokens::hash(TokenKind::Refresh, &refresh)],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    let (arid, agrant): (i64, i64) = conn
        .query_row(
            "SELECT refresh_id, grant_id FROM _mcp_oauth_access WHERE token_hash = ?1",
            params![tokens::hash(TokenKind::Access, &access)],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert!(parent_null);
    assert_eq!(arid, rid);
    assert_eq!((rgrant, agrant), (g, g));
    let by_access = store::find_grant_by_access(&conn, &access)
        .unwrap()
        .unwrap();
    let by_refresh = store::find_grant_by_refresh(&conn, &refresh)
        .unwrap()
        .unwrap();
    assert_eq!(by_access.grant_id(), g);
    assert_eq!(by_refresh.grant_id(), g);
    assert!(redeemed(&conn, &cg.code));
}

#[tokio::test]
async fn no_plaintext_token_or_code_is_stored_anywhere_in_meta() {
    let fx = fixture(true).await;
    let session = session_for(&fx, fx.owner_id).await;
    let cg = obtain_code(&fx, &session, 53_682, None).await;
    let (access, refresh) = assert_issued(exchange(&fx.app, &cg).await, "exchange").await;
    let conn = fx.meta.lock().await;
    // Anti-vacuous: the scan does find what IS stored.
    assert_eq!(
        plaintext_anywhere(&conn, &code_hash(&cg.code)),
        vec![("_mcp_oauth_codes".to_string(), "code_hash".to_string())]
    );
    for (name, needle) in [
        ("access", &access),
        ("refresh", &refresh),
        ("code", &cg.code),
        ("verifier", &cg.verifier),
    ] {
        assert_eq!(plaintext_anywhere(&conn, needle), Vec::new(), "{name}");
    }
}

#[tokio::test]
async fn without_resource_and_with_127_0_0_1_both_succeed() {
    let fx = fixture(true).await;
    let a = seeded_with(&fx, &loopback_redirect(5001), None).await;
    let b = seeded_with(&fx, &loopback_redirect(5001), None).await;
    let c = seeded_with(&fx, "http://127.0.0.1:5001/callback", Some(RESOURCE)).await;
    for (name, f) in [
        (
            "no resource anywhere",
            form(&a.code, &a.verifier, Some(&a.redirect), None),
        ),
        (
            "resource only on the request",
            form(&b.code, &b.verifier, Some(&b.redirect), Some(RESOURCE)),
        ),
        ("127.0.0.1", seeded_form(&c)),
    ] {
        assert_issued(post_token(&fx.app, &f, &[]).await, name).await;
    }
}

#[tokio::test]
async fn expires_in_follows_the_configured_access_ttl() {
    let fx =
        fixture_with(McpOauthConfig::for_tests(PUBLIC_URL).with_ttls_for_tests(900, 60, 30, 90))
            .await;
    let s = seeded(&fx).await;
    let resp = post_token(&fx.app, &seeded_form(&s), &[]).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert_eq!(v["expires_in"], 900);
    let access = v["access_token"].as_str().unwrap();
    let ok: bool = fx
        .meta
        .lock()
        .await
        .query_row(
            "SELECT expires_at >= datetime('now','+890 seconds') \
                AND expires_at <= datetime('now','+900 seconds') \
               FROM _mcp_oauth_access WHERE token_hash = ?1",
            params![tokens::hash(TokenKind::Access, access)],
            |r| r.get(0),
        )
        .unwrap();
    assert!(ok, "access expires_at = now + 900 s");
}

// ─── B. a wrong verifier does not consume the code ───────────────────────────

#[tokio::test]
async fn a_wrong_verifier_does_not_consume_the_code() {
    let fx = fixture(true).await;
    let session = session_for(&fx, fx.owner_id).await;
    let cg = obtain_code(&fx, &session, 53_682, None).await;
    let (wrong, _) = pkce();
    let f = token_form_for(&cg);
    let pairs: Vec<(&str, &str)> = f.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let pairs = set(pairs, "code_verifier", Some(&wrong));
    assert_invalid_grant(post_token(&fx.app, &pairs, &[]).await, "wrong verifier").await;
    {
        let conn = fx.meta.lock().await;
        assert!(!redeemed(&conn, &cg.code));
        assert_eq!(row_count(&conn, "_mcp_oauth_access"), 0);
        assert_eq!(row_count(&conn, "_mcp_oauth_refresh"), 0);
    }
    assert_issued(exchange(&fx.app, &cg).await, "right verifier").await;
}

#[tokio::test]
async fn malformed_or_missing_verifiers_are_refused_without_consuming() {
    let fx = fixture(true).await;
    let s = seeded(&fx).await;
    let v42 = "a".repeat(42);
    let v129 = "a".repeat(129);
    let plus = format!("{}+", "a".repeat(42));
    let eq = format!("{}=", "a".repeat(42));
    let cases: Vec<(&str, Option<&str>)> = vec![
        ("42 chars", Some(&v42)),
        ("129 chars", Some(&v129)),
        ("contains +", Some(&plus)),
        ("contains =", Some(&eq)),
        ("missing", None),
        ("empty", Some("")),
        ("the challenge itself", Some(&s.challenge)),
    ];
    for (name, v) in cases {
        let f = set(seeded_form(&s), "code_verifier", v);
        assert_invalid_grant(post_token(&fx.app, &f, &[]).await, name).await;
        assert!(!redeemed_now(&fx, &s.code).await, "{name}: consumed");
    }
    assert_issued(
        post_token(&fx.app, &seeded_form(&s), &[]).await,
        "right verifier",
    )
    .await;
}

// ─── C. binding mismatches (none consumes the code) ──────────────────────────

#[tokio::test]
async fn binding_mismatches_are_refused_without_consuming() {
    let fx = fixture(true).await;
    let s = seeded(&fx).await; // http://localhost:5001/callback, resource = RESOURCE
    let resource_slash = format!("{RESOURCE}/");
    let redirect_slash = format!("{}/", s.redirect);
    let cases: Vec<(&str, &str, Option<&str>)> = vec![
        (
            "T-B1 other port",
            "redirect_uri",
            Some("http://localhost:5002/callback"),
        ),
        (
            "T-B2 other host",
            "redirect_uri",
            Some("http://127.0.0.1:5001/callback"),
        ),
        ("T-B3 trailing slash", "redirect_uri", Some(&redirect_slash)),
        ("T-B4 missing redirect_uri", "redirect_uri", None),
        (
            "T-B5 foreign resource",
            "resource",
            Some("https://other.test/drust/mcp"),
        ),
        ("T-B6 resource + slash", "resource", Some(&resource_slash)),
        // No case normalisation and no percent-decoding normalisation at the
        // token endpoint. %63 goes through post_form's encoder, so the decoded
        // value really is the literal "%63".
        (
            "T-B10 upper-case host",
            "redirect_uri",
            Some("http://LOCALHOST:5001/callback"),
        ),
        (
            "T-B11 percent-encoded path",
            "redirect_uri",
            Some("http://localhost:5001/%63allback"),
        ),
    ];
    for (name, key, v) in cases {
        let f = set(seeded_form(&s), key, v);
        assert_invalid_grant(post_token(&fx.app, &f, &[]).await, name).await;
        assert!(!redeemed_now(&fx, &s.code).await, "{name}: consumed");
    }
    // T-B7 / T-B8: the code row says something else than the request.
    for (name, column, value) in [
        (
            "T-B7 stored resource differs",
            "resource",
            "https://drust.test/drust/mcp-old",
        ),
        (
            "T-B8 issued to another client",
            "client_id",
            "https://other.example/cimd",
        ),
    ] {
        let original: String = {
            let conn = fx.meta.lock().await;
            let original = conn
                .query_row(
                    &format!("SELECT {column} FROM _mcp_oauth_codes WHERE code_hash = ?1"),
                    params![code_hash(&s.code)],
                    |r| r.get(0),
                )
                .unwrap();
            conn.execute(
                &format!("UPDATE _mcp_oauth_codes SET {column} = ?1 WHERE code_hash = ?2"),
                params![value, code_hash(&s.code)],
            )
            .unwrap();
            original
        };
        assert_invalid_grant(post_token(&fx.app, &seeded_form(&s), &[]).await, name).await;
        let conn = fx.meta.lock().await;
        assert!(!redeemed(&conn, &s.code), "{name}: consumed");
        conn.execute(
            &format!("UPDATE _mcp_oauth_codes SET {column} = ?1 WHERE code_hash = ?2"),
            params![original, code_hash(&s.code)],
        )
        .unwrap();
    }
    // T-B9: no resource on the request, one on the code row: inherited (RFC 8707 §2.2).
    // Ten failures above are exactly the per-code budget; a valid request reads no bucket.
    let f = set(seeded_form(&s), "resource", None);
    assert_issued(post_token(&fx.app, &f, &[]).await, "T-B9").await;
}

// ─── D. parameter errors (no lookup, nothing consumed) ───────────────────────

#[tokio::test]
async fn unknown_client_id_is_invalid_client() {
    let fx = fixture(true).await;
    let s = seeded(&fx).await;
    let f = set(
        seeded_form(&s),
        "client_id",
        Some("https://evil.example/cimd"),
    );
    let h = assert_oauth_error(
        post_token(&fx.app, &f, &[]).await,
        StatusCode::BAD_REQUEST,
        "invalid_client",
        "evil",
    )
    .await;
    assert!(h.get(header::WWW_AUTHENTICATE).is_none());
    assert!(!redeemed_now(&fx, &s.code).await);
}

#[tokio::test]
async fn missing_client_id_or_code_is_invalid_request() {
    let fx = fixture(true).await;
    let s = seeded(&fx).await;
    for (name, key, v) in [
        ("missing client_id", "client_id", None),
        ("empty client_id", "client_id", Some("")),
        ("missing code", "code", None),
    ] {
        let f = set(seeded_form(&s), key, v);
        assert_oauth_error(
            post_token(&fx.app, &f, &[]).await,
            StatusCode::BAD_REQUEST,
            "invalid_request",
            name,
        )
        .await;
    }
    assert!(!redeemed_now(&fx, &s.code).await);
}

#[tokio::test]
async fn a_code_of_the_wrong_length_is_invalid_grant() {
    let fx = fixture(true).await;
    let s = seeded(&fx).await;
    let c42 = &s.code[..42];
    let c44 = format!("{}A", s.code);
    for (name, c) in [("42 chars", c42), ("44 chars", c44.as_str())] {
        let f = set(seeded_form(&s), "code", Some(c));
        assert_invalid_grant(post_token(&fx.app, &f, &[]).await, name).await;
    }
    assert!(!redeemed_now(&fx, &s.code).await);
}

#[tokio::test]
async fn unknown_extra_parameters_are_ignored() {
    let fx = fixture(true).await;
    let s = seeded(&fx).await;
    let mut f = seeded_form(&s);
    f.extend([("scope", "mcp"), ("foo", "bar"), ("refresh_token", "x")]);
    assert_issued(post_token(&fx.app, &f, &[]).await, "extras").await;
}

// ─── E. code and grant state ─────────────────────────────────────────────────

#[tokio::test]
async fn an_expired_code_is_invalid_grant() {
    let fx = fixture(true).await;
    let s = seeded(&fx).await;
    fx.meta
        .lock()
        .await
        .execute(
            "UPDATE _mcp_oauth_codes SET expires_at = datetime('now','-1 second') WHERE code_hash = ?1",
            params![code_hash(&s.code)],
        )
        .unwrap();
    assert_invalid_grant(post_token(&fx.app, &seeded_form(&s), &[]).await, "expired").await;
    assert_eq!(grant_revocation(&fx, s.grant_id).await, (None, None));
}

#[tokio::test]
async fn a_code_of_a_revoked_grant_is_gone() {
    let fx = fixture(true).await;
    let s = seeded(&fx).await;
    {
        let conn = fx.meta.lock().await;
        let tx = conn.unchecked_transaction().unwrap();
        let r = store::revoke_mcp_grant(
            &tx,
            &GrantOwner::caller(&AdminId(fx.owner_id)),
            s.grant_id,
            RevokeReason::User,
        )
        .unwrap();
        assert_eq!(r, RevokedGrant::Revoked);
        tx.commit().unwrap();
        assert_eq!(
            count(
                &conn,
                &format!(
                    "SELECT COUNT(*) FROM _mcp_oauth_codes WHERE grant_id = {}",
                    s.grant_id
                )
            ),
            0,
            "an unredeemed code is deleted with its grant"
        );
    }
    assert_invalid_grant(post_token(&fx.app, &seeded_form(&s), &[]).await, "revoked").await;
}

#[tokio::test]
async fn a_revoked_grant_whose_code_survived_is_still_refused() {
    let fx = fixture(true).await;
    let s = seeded(&fx).await;
    fx.meta
        .lock()
        .await
        .execute(
            "UPDATE _mcp_oauth_grants SET revoked_at = datetime('now'), revoke_reason = 'user' WHERE id = ?1",
            params![s.grant_id],
        )
        .unwrap();
    assert_invalid_grant(
        post_token(&fx.app, &seeded_form(&s), &[]).await,
        "revoked, code kept",
    )
    .await;
    assert!(!redeemed_now(&fx, &s.code).await);
}

#[tokio::test]
async fn an_idle_or_absolute_expired_grant_is_refused() {
    let fx = fixture(true).await;
    for column in ["idle_expires_at", "absolute_expires_at"] {
        let s = seeded(&fx).await;
        fx.meta
            .lock()
            .await
            .execute(
                &format!("UPDATE _mcp_oauth_grants SET {column} = datetime('now','-1 second') WHERE id = ?1"),
                params![s.grant_id],
            )
            .unwrap();
        assert_invalid_grant(post_token(&fx.app, &seeded_form(&s), &[]).await, column).await;
        assert!(!redeemed_now(&fx, &s.code).await, "{column}");
    }
}

#[tokio::test]
async fn a_removed_admin_cannot_redeem() {
    let fx = fixture(true).await;
    let m1 = add_admin(&fx, "m1", "", "member").await;
    let s = seeded_for(&fx, m1, &loopback_redirect(5001), Some(RESOURCE)).await;
    let owner = session_for(&fx, fx.owner_id).await;
    let req = axum::http::Request::builder()
        .method("DELETE")
        .uri(format!("/admin/team/{m1}"))
        .header(header::COOKIE, &owner)
        .body(Body::empty())
        .unwrap();
    let resp = send(&fx.app, req).await;
    assert!(
        resp.status().is_success(),
        "remove_admin: {}",
        resp.status()
    );
    assert_eq!(
        count(
            &*fx.meta.lock().await,
            &format!(
                "SELECT COUNT(*) FROM _mcp_oauth_codes WHERE grant_id = {}",
                s.grant_id
            )
        ),
        0,
        "remove_admin deletes the grant and its code"
    );
    assert_invalid_grant(
        post_token(&fx.app, &seeded_form(&s), &[]).await,
        "removed admin",
    )
    .await;
}

#[tokio::test]
async fn a_removed_admin_without_cascade_cannot_redeem() {
    let fx = fixture(true).await;
    let m1 = add_admin(&fx, "m1", "", "member").await;
    let s = seeded_for(&fx, m1, &loopback_redirect(5001), Some(RESOURCE)).await;
    {
        let conn = fx.meta.lock().await;
        conn.execute_batch(&format!(
            "PRAGMA foreign_keys = OFF; DELETE FROM admins WHERE id = {m1}; PRAGMA foreign_keys = ON;"
        ))
        .unwrap();
        assert_eq!(
            count(
                &conn,
                &format!(
                    "SELECT COUNT(*) FROM _mcp_oauth_codes WHERE grant_id = {}",
                    s.grant_id
                )
            ),
            1,
            "the code row survives without the cascade"
        );
    }
    assert_invalid_grant(
        post_token(&fx.app, &seeded_form(&s), &[]).await,
        "admin gone",
    )
    .await;
    assert!(!redeemed_now(&fx, &s.code).await);
}

#[tokio::test]
async fn an_admin_created_at_mismatch_cannot_redeem() {
    let fx = fixture(true).await;
    let s = seeded(&fx).await;
    fx.meta
        .lock()
        .await
        .execute(
            "UPDATE _mcp_oauth_grants SET admin_created_at = '1999-01-01 00:00:00' WHERE id = ?1",
            params![s.grant_id],
        )
        .unwrap();
    assert_invalid_grant(
        post_token(&fx.app, &seeded_form(&s), &[]).await,
        "created_at",
    )
    .await;
    assert!(!redeemed_now(&fx, &s.code).await);
}

/// A child row never vouches for itself: a code whose grant row was deleted
/// on a connection without foreign keys is refused.
#[tokio::test]
async fn a_code_left_behind_by_a_deleted_grant_is_refused() {
    let fx = fixture(true).await;
    let session = session_for(&fx, fx.owner_id).await;
    let cg = obtain_code(&fx, &session, 53_682, None).await;
    let g = grant_of_code(&fx, &cg.code).await;
    fx.meta
        .lock()
        .await
        .execute_batch(&format!(
            "PRAGMA foreign_keys = OFF; DELETE FROM _mcp_oauth_grants WHERE id = {g}; PRAGMA foreign_keys = ON;"
        ))
        .unwrap();
    assert_invalid_grant(exchange(&fx.app, &cg).await, "orphan code").await;
    let conn = fx.meta.lock().await;
    assert!(
        !redeemed(&conn, &cg.code),
        "the orphan row is left as it was"
    );
    assert_eq!(row_count(&conn, "_mcp_oauth_access"), 0);
    assert_eq!(row_count(&conn, "_mcp_oauth_refresh"), 0);
}

// ─── F. replay ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_fully_valid_second_redemption_revokes_the_grant() {
    let fx = fixture(true).await;
    let session = session_for(&fx, fx.owner_id).await;
    let cg = obtain_code(&fx, &session, 53_682, None).await;
    let g = grant_of_code(&fx, &cg.code).await;
    let (access, refresh) = assert_issued(exchange(&fx.app, &cg).await, "first").await;
    assert_invalid_grant(exchange(&fx.app, &cg).await, "replay").await;
    let (revoked_at, reason) = grant_revocation(&fx, g).await;
    assert!(revoked_at.is_some());
    assert_eq!(reason.as_deref(), Some("code_replay"));
    let conn = fx.meta.lock().await;
    for t in ["_mcp_oauth_refresh", "_mcp_oauth_access"] {
        assert_eq!(
            count(
                &conn,
                &format!("SELECT COUNT(*) FROM {t} WHERE grant_id = {g} AND revoked_at IS NULL")
            ),
            0,
            "{t}"
        );
    }
    assert!(
        store::find_grant_by_access(&conn, &access)
            .unwrap()
            .is_none()
    );
    assert!(
        store::find_grant_by_refresh(&conn, &refresh)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        row_count(&conn, "_mcp_oauth_access"),
        1,
        "nothing issued for the replay"
    );
}

#[tokio::test]
async fn a_failed_second_redemption_does_not_revoke() {
    let fx = fixture(true).await;
    let session = session_for(&fx, fx.owner_id).await;
    let cg = obtain_code(&fx, &session, 53_682, None).await;
    let g = grant_of_code(&fx, &cg.code).await;
    let (access, _) = assert_issued(exchange(&fx.app, &cg).await, "first").await;
    let (wrong, _) = pkce();
    let f = token_form_for(&cg);
    let pairs: Vec<(&str, &str)> = f.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let pairs = set(pairs, "code_verifier", Some(&wrong));
    assert_invalid_grant(
        post_token(&fx.app, &pairs, &[]).await,
        "second, wrong verifier",
    )
    .await;
    assert_eq!(grant_revocation(&fx, g).await, (None, None));
    assert!(
        store::find_grant_by_access(&*fx.meta.lock().await, &access)
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn a_second_redemption_with_another_port_does_not_revoke() {
    let fx = fixture(true).await;
    let session = session_for(&fx, fx.owner_id).await;
    let cg = obtain_code(&fx, &session, 53_682, None).await;
    let g = grant_of_code(&fx, &cg.code).await;
    assert_issued(exchange(&fx.app, &cg).await, "first").await;
    let f = token_form_for(&cg);
    let pairs: Vec<(&str, &str)> = f.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let other = loopback_redirect(53_683);
    let pairs = set(pairs, "redirect_uri", Some(&other));
    assert_invalid_grant(post_token(&fx.app, &pairs, &[]).await, "second, other port").await;
    assert_eq!(grant_revocation(&fx, g).await, (None, None));
}

#[tokio::test]
async fn a_third_redemption_after_replay_changes_nothing() {
    let fx = fixture(true).await;
    let session = session_for(&fx, fx.owner_id).await;
    let cg = obtain_code(&fx, &session, 53_682, None).await;
    let g = grant_of_code(&fx, &cg.code).await;
    assert_issued(exchange(&fx.app, &cg).await, "first").await;
    assert_invalid_grant(exchange(&fx.app, &cg).await, "replay").await;
    let after_replay = grant_revocation(&fx, g).await;
    assert_eq!(after_replay.1.as_deref(), Some("code_replay"));
    assert_invalid_grant(exchange(&fx.app, &cg).await, "third").await;
    assert_eq!(grant_revocation(&fx, g).await, after_replay);
}

/// Replay detection lasts the code's life (300 s); after that a replayer gets
/// nothing, so the grant is left alone.
#[tokio::test]
async fn a_replay_after_the_code_expired_is_refused_but_does_not_revoke() {
    let fx = fixture(true).await;
    let session = session_for(&fx, fx.owner_id).await;
    let cg = obtain_code(&fx, &session, 53_682, None).await;
    let g = grant_of_code(&fx, &cg.code).await;
    assert_issued(exchange(&fx.app, &cg).await, "first").await;
    fx.meta
        .lock()
        .await
        .execute(
            "UPDATE _mcp_oauth_codes SET expires_at = datetime('now','-1 second') WHERE code_hash = ?1",
            params![code_hash(&cg.code)],
        )
        .unwrap();
    assert_invalid_grant(exchange(&fx.app, &cg).await, "late replay").await;
    assert_eq!(grant_revocation(&fx, g).await, (None, None));
}

/// Single use is a tested property, not a side effect of the meta mutex. Each
/// request runs in its own task on a multi-thread runtime, released together,
/// so they really contend on the meta mutex.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_valid_exchanges_issue_at_most_once() {
    let fx = fixture(true).await;
    let session = session_for(&fx, fx.owner_id).await;
    let cg = std::sync::Arc::new(obtain_code(&fx, &session, 53_682, None).await);
    let g = grant_of_code(&fx, &cg.code).await;
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(8));
    let tasks: Vec<_> = (0..8)
        .map(|_| {
            let app = fx.app.clone();
            let cg = cg.clone();
            let b = barrier.clone();
            tokio::spawn(async move {
                b.wait().await;
                exchange(&app, &cg).await
            })
        })
        .collect();
    let mut issued = Vec::new();
    for task in tasks {
        let r = task.await.unwrap();
        if r.status() == StatusCode::OK {
            issued.push(
                body_json(r).await["access_token"]
                    .as_str()
                    .unwrap()
                    .to_string(),
            );
        } else {
            assert_invalid_grant(r, "a concurrent loser").await;
        }
    }
    assert_eq!(issued.len(), 1, "exactly one exchange succeeds");
    let conn = fx.meta.lock().await;
    assert_eq!(row_count(&conn, "_mcp_oauth_access"), 1);
    assert_eq!(row_count(&conn, "_mcp_oauth_refresh"), 1);
    let reason: Option<String> = conn
        .query_row(
            "SELECT revoke_reason FROM _mcp_oauth_grants WHERE id = ?1 AND revoked_at IS NOT NULL",
            params![g],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        reason.as_deref(),
        Some("code_replay"),
        "the second valid request revoked"
    );
    assert!(
        store::find_grant_by_access(&conn, &issued[0])
            .unwrap()
            .is_none()
    );
}

// ─── G. rate limits (each test has its own fixture, so its own buckets) ──────

#[tokio::test]
async fn eleven_wrong_verifiers_on_one_code_reach_the_per_code_budget() {
    let fx = fixture(true).await;
    let s = seeded(&fx).await;
    for i in 1..=10 {
        let (wrong, _) = pkce();
        let f = set(seeded_form(&s), "code_verifier", Some(&wrong));
        assert_invalid_grant(post_token(&fx.app, &f, &[]).await, &format!("attempt {i}")).await;
    }
    let (wrong, _) = pkce();
    let f = set(seeded_form(&s), "code_verifier", Some(&wrong));
    assert_throttled(post_token(&fx.app, &f, &[]).await, 300, "attempt 11").await;
    assert!(!redeemed_now(&fx, &s.code).await);
    // Failures only: the right verifier never reads the per-code bucket.
    assert_issued(
        post_token(&fx.app, &seeded_form(&s), &[]).await,
        "right verifier",
    )
    .await;
}

#[tokio::test]
async fn the_per_code_budget_is_per_code() {
    let fx = fixture(true).await;
    let a = seeded(&fx).await;
    let b = seeded(&fx).await;
    for _ in 0..11 {
        let (wrong, _) = pkce();
        let f = set(seeded_form(&a), "code_verifier", Some(&wrong));
        let _ = post_token(&fx.app, &f, &[]).await;
    }
    let (wrong, _) = pkce();
    let f = set(seeded_form(&b), "code_verifier", Some(&wrong));
    assert_invalid_grant(post_token(&fx.app, &f, &[]).await, "B wrong").await;
    assert_issued(post_token(&fx.app, &seeded_form(&b), &[]).await, "B right").await;
}

fn miss_form(code: &str) -> Vec<(&str, &str)> {
    vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        (
            "code_verifier",
            "a-well-formed-verifier-that-is-43-characters",
        ),
        ("redirect_uri", "http://localhost:5001/callback"),
        ("client_id", CC_CLIENT_ID),
    ]
}

#[tokio::test]
async fn misses_reach_the_ip_budget_but_a_valid_code_from_the_same_ip_still_succeeds() {
    let fx = fixture(true).await;
    let s = seeded(&fx).await;
    // No X-Forwarded-For and no connect-info: every request is 127.0.0.1.
    for i in 1..=30 {
        let c = if i % 6 == 0 {
            random_code()[..42].to_string()
        } else {
            random_code()
        };
        assert_invalid_grant(
            post_token(&fx.app, &miss_form(&c), &[]).await,
            &format!("miss {i}"),
        )
        .await;
    }
    assert_throttled(
        post_token(&fx.app, &miss_form(&random_code()), &[]).await,
        60,
        "miss 31",
    )
    .await;
    assert_issued(
        post_token(&fx.app, &seeded_form(&s), &[]).await,
        "valid code, same IP",
    )
    .await;
    assert_throttled(
        post_token(&fx.app, &miss_form(&random_code()), &[]).await,
        60,
        "miss 32",
    )
    .await;
}

#[tokio::test]
async fn found_but_invalid_codes_never_charge_the_ip_budget() {
    let fx = fixture(true).await;
    for _ in 0..3 {
        let s = seeded(&fx).await;
        for i in 1..=10 {
            let (wrong, _) = pkce();
            let f = set(seeded_form(&s), "code_verifier", Some(&wrong));
            assert_invalid_grant(post_token(&fx.app, &f, &[]).await, &format!("found {i}")).await;
        }
    }
    for i in 1..=30 {
        assert_invalid_grant(
            post_token(&fx.app, &miss_form(&random_code()), &[]).await,
            &format!("miss {i}"),
        )
        .await;
    }
    assert_throttled(
        post_token(&fx.app, &miss_form(&random_code()), &[]).await,
        60,
        "miss 31",
    )
    .await;
}

#[tokio::test]
async fn the_miss_budget_is_per_client_ip() {
    let fx = fixture(true).await;
    // DRUST_TRUSTED_PROXIES defaults to 2: the client is XFF[len - 2].
    let a = [("x-forwarded-for", "203.0.113.9, 10.0.0.1")];
    for i in 1..=30 {
        assert_invalid_grant(
            post_token(&fx.app, &miss_form(&random_code()), &a).await,
            &format!("A miss {i}"),
        )
        .await;
    }
    assert_throttled(
        post_token(&fx.app, &miss_form(&random_code()), &a).await,
        60,
        "A miss 31",
    )
    .await;
    let b = [("x-forwarded-for", "198.51.100.7, 10.0.0.1")];
    assert_invalid_grant(
        post_token(&fx.app, &miss_form(&random_code()), &b).await,
        "B miss 1",
    )
    .await;
}

// ─── H. disabled ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn token_exchange_is_unmounted_when_disabled() {
    let auto = McpOauthConfig::from_parts(
        &McpOauthEnv {
            mode: Some("auto"),
            public_url: Some(PUBLIC_URL),
            ..Default::default()
        },
        "/drust",
        [1; 32],
        [2; 32],
    );
    assert!(!auto.enabled());
    for (name, fx) in [
        ("unset", fixture(false).await),
        ("auto", fixture_with(auto).await),
    ] {
        let s = seeded(&fx).await;
        let f = seeded_form(&s);
        let token = snapshot(post_form(&fx.app, "/oauth/token", &f, &[], &[]).await).await;
        let never = snapshot(post_form(&fx.app, "/oauth/nonexistent", &f, &[], &[]).await).await;
        assert_eq!(token.0, StatusCode::NOT_FOUND, "{name}");
        assert_eq!(
            token, never,
            "{name}: /oauth/token must look like a path that never existed"
        );
        assert!(!redeemed_now(&fx, &s.code).await, "{name}");
    }
    // Control: the same request IS the token route when enabled, so the
    // comparison above was against the right path.
    let fx = fixture(true).await;
    let s = seeded(&fx).await;
    let resp = post_form(&fx.app, "/oauth/token", &seeded_form(&s), &[], &[]).await;
    assert_ne!(resp.status(), StatusCode::NOT_FOUND);
}

// ─── the whole flow, from signed out ─────────────────────────────────────────

/// Not signed in → authorize → consent sends to login →
/// password login with the resume cookie → back to consent → approve → code →
/// token. The consent flow test stops at the code and `obtain_tokens` starts
/// signed in; this is the one test that walks the whole chain.
#[tokio::test]
async fn signed_out_authorize_to_token_end_to_end() {
    let fx = fixture(true).await;
    let (verifier, challenge) = pkce();
    let redirect = loopback_redirect(53_682);
    let q = authorize_query(&challenge, &redirect, Some("st-flow"), Some(RESOURCE));
    let resp = get(&fx.app, &format!("/oauth/authorize?{q}"), &[]).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "authorize");
    let consent_uri = router_path(&location(&resp));
    let resume = cookie_kv(
        &set_cookie(&resp, drust::mgmt::mcp_oauth::envelope::RESUME_COOKIE).expect("resume cookie"),
    );
    let resp = get(&fx.app, &consent_uri, &[&resume]).await;
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "consent while signed out"
    );
    assert_eq!(location(&resp), "/drust/login");
    let resp = post_form(
        &fx.app,
        "/login",
        &[("username", OWNER_USER), ("password", OWNER_PASS)],
        &[&resume],
        &[],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "login");
    assert_eq!(location(&resp), "/drust/oauth/consent");
    let session = cookie_kv(&set_cookie(&resp, "drust_session").expect("session cookie"));
    let resp = get(&fx.app, "/oauth/consent", &[&session, &resume]).await;
    assert_eq!(resp.status(), StatusCode::OK, "consent page");
    let csrf_cookie = cookie_kv(
        &set_cookie(&resp, drust::mgmt::mcp_oauth::consent::CSRF_COOKIE).expect("csrf cookie"),
    );
    let html = body_text(resp).await;
    let req = hidden_field(&html, "req").unwrap();
    let csrf = hidden_field(&html, "csrf").unwrap();
    let resp = post_form(
        &fx.app,
        "/oauth/consent/approve",
        &[("req", &req), ("csrf", &csrf)],
        &[&session, &resume, &csrf_cookie],
        &[],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "approve");
    let loc = location(&resp);
    let cg = CodeGrant {
        code: query_param(&loc, "code").expect("code"),
        verifier,
        redirect_uri: redirect,
        state: query_param(&loc, "state"),
        iss: query_param(&loc, "iss").expect("iss"),
    };
    assert_eq!(cg.state.as_deref(), Some("st-flow"));
    assert_eq!(cg.iss, ISSUER);
    let resp = exchange(&fx.app, &cg).await;
    assert_eq!(resp.status(), StatusCode::OK, "token");
    let access = body_json(resp).await["access_token"]
        .as_str()
        .unwrap()
        .to_string();
    let conn = fx.meta.lock().await;
    let grant = store::find_grant_by_access(&conn, &access)
        .unwrap()
        .expect("live access");
    assert_eq!(grant.admin_id(), fx.owner_id);
}

/// `obtain_tokens` (the refresh tests start from it): signed in → tokens, grant id
/// resolved through the access token.
#[tokio::test]
async fn obtain_tokens_yields_a_live_pair() {
    let fx = fixture(true).await;
    let session = session_for(&fx, fx.owner_id).await;
    let t = obtain_tokens(&fx, &session).await;
    let conn = fx.meta.lock().await;
    let by_refresh = store::find_grant_by_refresh(&conn, &t.refresh)
        .unwrap()
        .unwrap();
    assert_eq!(by_refresh.grant_id(), t.grant_id);
    assert_eq!(
        store::find_grant_by_access(&conn, &t.access)
            .unwrap()
            .unwrap()
            .grant_id(),
        t.grant_id
    );
}
