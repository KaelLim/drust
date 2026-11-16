//! MA0-8 — `POST /oauth/token` with `grant_type=refresh_token`: rotation, the
//! in-grace sibling, the superseded-sibling branch cut, reuse detection past the
//! grace, and the per-grant budget. Every request goes through the production
//! router at ROOT paths (`/oauth/token`, `/oauth/revoke`, `/admin/team/{id}`);
//! only outbound strings (`RESOURCE`) carry `/drust`.
//!
//! Time never passes for real: a rotation is aged by rewriting `rotated_at`
//! in SQL. Audit rows are not asserted (the process-global audit writer is
//! first-write-wins across g_admin members). Every DB touch takes `fx.meta` in
//! its own block and drops it before the next HTTP request (the handler locks
//! the same mutex).

use axum::body::Body;
use axum::http::{Response, StatusCode, header};
use drust::mgmt::mcp_oauth::config::McpOauthConfig;
use drust::mgmt::mcp_oauth::store;
use drust::mgmt::mcp_oauth::tokens::{self, TokenKind};
use rusqlite::params;

use crate::common::mcp_oauth::*;

// ─── file-private helpers ────────────────────────────────────────────────────

/// `POST /oauth/token` with exactly `pairs` (cases that change the SDK shape).
async fn post_refresh(fx: &McpOauthFixture, pairs: &[(&str, &str)]) -> Response<Body> {
    post_form(&fx.app, "/oauth/token", pairs, &[], &[]).await
}

/// The SDK refresh form with one field replaced (or added).
fn form_with<'a>(token: &'a str, key: &'a str, value: &'a str) -> Vec<(&'a str, &'a str)> {
    let mut f = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", token),
        ("client_id", CC_CLIENT_ID),
        ("resource", RESOURCE),
    ];
    match f.iter_mut().find(|(k, _)| *k == key) {
        Some(slot) => slot.1 = value,
        None => f.push((key, value)),
    }
    f
}

fn hdr(r: &Response<Body>, h: header::HeaderName) -> Option<&str> {
    r.headers().get(h).and_then(|v| v.to_str().ok())
}

/// 200 with the SDK token fields; returns `(access, refresh)`.
async fn issued(resp: Response<Body>, ctx: &str) -> (String, String) {
    assert_eq!(resp.status(), StatusCode::OK, "{ctx}: status");
    assert_eq!(
        hdr(&resp, header::CACHE_CONTROL),
        Some("no-store"),
        "{ctx}: cache-control"
    );
    let v = body_json(resp).await;
    tokens_of(&v, ctx)
}

fn tokens_of(v: &serde_json::Value, ctx: &str) -> (String, String) {
    let a = v["access_token"]
        .as_str()
        .unwrap_or_else(|| panic!("{ctx}: {v}"));
    let r = v["refresh_token"]
        .as_str()
        .unwrap_or_else(|| panic!("{ctx}: {v}"));
    (a.to_string(), r.to_string())
}

/// Exactly `400 {"error":"<code>"}` with `Cache-Control: no-store`.
async fn assert_oauth(resp: Response<Body>, code: &str, ctx: &str) {
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{ctx}: status");
    assert_eq!(
        hdr(&resp, header::CACHE_CONTROL),
        Some("no-store"),
        "{ctx}: cache-control"
    );
    assert_eq!(
        body_json(resp).await,
        serde_json::json!({ "error": code }),
        "{ctx}: body"
    );
}

async fn assert_invalid_grant(resp: Response<Body>, ctx: &str) {
    assert_oauth(resp, "invalid_grant", ctx).await;
}

/// 429 `temporarily_unavailable`, JSON, `Retry-After` in `1..=max`.
async fn assert_throttled(resp: Response<Body>, max: u64, ctx: &str) {
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "{ctx}: status"
    );
    assert_eq!(
        hdr(&resp, header::CONTENT_TYPE),
        Some("application/json"),
        "{ctx}: content-type"
    );
    let ra: u64 = hdr(&resp, header::RETRY_AFTER)
        .unwrap_or_else(|| panic!("{ctx}: no Retry-After"))
        .parse()
        .unwrap_or_else(|e| panic!("{ctx}: Retry-After: {e}"));
    assert!((1..=max).contains(&ra), "{ctx}: Retry-After {ra}");
    assert_eq!(
        body_json(resp).await,
        serde_json::json!({ "error": "temporarily_unavailable" }),
        "{ctx}: body"
    );
}

/// What a rejection exposes: status, Content-Type, Cache-Control, "carries a
/// Set-Cookie or a Location", and the body bytes.
type Shape = (u16, Option<String>, Option<String>, bool, Vec<u8>);

async fn reject_shape(resp: Response<Body>) -> Shape {
    let status = resp.status().as_u16();
    let ct = hdr(&resp, header::CONTENT_TYPE).map(str::to_string);
    let cc = hdr(&resp, header::CACHE_CONTROL).map(str::to_string);
    let side = resp.headers().contains_key(header::SET_COOKIE)
        || resp.headers().contains_key(header::LOCATION);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap()
        .to_vec();
    (status, ct, cc, side, body)
}

fn rid(conn: &rusqlite::Connection, token: &str) -> i64 {
    conn.query_row(
        "SELECT id FROM _mcp_oauth_refresh WHERE token_hash = ?1",
        params![tokens::hash(TokenKind::Refresh, token)],
        |r| r.get(0),
    )
    .unwrap()
}

#[derive(Debug)]
struct RRow {
    grant: i64,
    parent: Option<i64>,
    rotated: Option<String>,
    superseded: Option<String>,
    revoked: Option<String>,
    reason: Option<String>,
    expires: String,
}

fn rrow(conn: &rusqlite::Connection, id: i64) -> RRow {
    conn.query_row(
        "SELECT grant_id, parent_id, rotated_at, superseded_at, revoked_at, revoke_reason, \
                expires_at FROM _mcp_oauth_refresh WHERE id = ?1",
        params![id],
        |r| {
            Ok(RRow {
                grant: r.get(0)?,
                parent: r.get(1)?,
                rotated: r.get(2)?,
                superseded: r.get(3)?,
                revoked: r.get(4)?,
                reason: r.get(5)?,
                expires: r.get(6)?,
            })
        },
    )
    .unwrap()
}

/// Authorization strength: the access token would authorize an MCP call now.
fn access_live(conn: &rusqlite::Connection, token: &str) -> bool {
    store::find_grant_by_access(conn, token).unwrap().is_some()
}

/// The refresh row the access was issued with (`_mcp_oauth_access.refresh_id`).
fn access_refresh_id(conn: &rusqlite::Connection, token: &str) -> i64 {
    conn.query_row(
        "SELECT refresh_id FROM _mcp_oauth_access WHERE token_hash = ?1",
        params![tokens::hash(TokenKind::Access, token)],
        |r| r.get(0),
    )
    .unwrap()
}

#[derive(Debug)]
struct GRow {
    idle: String,
    absolute: String,
    last_used: Option<String>,
    sibling_rejected: Option<String>,
    revoked: Option<String>,
    reason: Option<String>,
}

fn grow(conn: &rusqlite::Connection, gid: i64) -> GRow {
    conn.query_row(
        "SELECT idle_expires_at, absolute_expires_at, last_used_at, sibling_rejected_at, \
                revoked_at, revoke_reason FROM _mcp_oauth_grants WHERE id = ?1",
        params![gid],
        |r| {
            Ok(GRow {
                idle: r.get(0)?,
                absolute: r.get(1)?,
                last_used: r.get(2)?,
                sibling_rejected: r.get(3)?,
                revoked: r.get(4)?,
                reason: r.get(5)?,
            })
        },
    )
    .unwrap()
}

/// Every column of every row of the grant, refresh, access and code tables,
/// in primary-key order: "nothing was written" is `dump` before == after.
fn dump(conn: &rusqlite::Connection) -> String {
    let mut out = String::new();
    for (table, order) in [
        ("_mcp_oauth_grants", "id"),
        ("_mcp_oauth_refresh", "id"),
        ("_mcp_oauth_access", "token_hash"),
        ("_mcp_oauth_codes", "code_hash"),
    ] {
        let mut st = conn
            .prepare(&format!("SELECT * FROM {table} ORDER BY {order}"))
            .unwrap();
        let n = st.column_count();
        let mut rows = st.query([]).unwrap();
        while let Some(r) = rows.next().unwrap() {
            out.push_str(table);
            for i in 0..n {
                let v: rusqlite::types::Value = r.get(i).unwrap();
                out.push_str(&format!("|{v:?}"));
            }
            out.push('\n');
        }
    }
    out
}

async fn dump_now(fx: &McpOauthFixture) -> String {
    dump(&*fx.meta.lock().await)
}

/// Moves a refresh's `rotated_at` `secs` seconds into the past.
async fn age_rotation(fx: &McpOauthFixture, refresh_id: i64, secs: i64) {
    let n = fx
        .meta
        .lock()
        .await
        .execute(
            "UPDATE _mcp_oauth_refresh SET rotated_at = datetime('now', ?2) WHERE id = ?1",
            params![refresh_id, format!("-{secs} seconds")],
        )
        .unwrap();
    assert_eq!(n, 1, "age_rotation: refresh {refresh_id}");
}

async fn sql(fx: &McpOauthFixture, statement: &str) {
    fx.meta.lock().await.execute_batch(statement).unwrap();
}

/// A live grant (30 / 90 days) of `admin_id` with one root refresh + access.
async fn seeded_for(fx: &McpOauthFixture, admin_id: i64) -> (i64, SeededTokens) {
    seeded_with(fx, admin_id, "+30 days", "+90 days").await
}

async fn seeded_with(
    fx: &McpOauthFixture,
    admin_id: i64,
    idle: &'static str,
    absolute: &'static str,
) -> (i64, SeededTokens) {
    let conn = fx.meta.lock().await;
    let gid = seed_grant(
        &conn,
        &SeedGrant {
            admin_id,
            idle,
            absolute,
            revoked: false,
        },
    );
    let t = seed_tokens(&conn, gid);
    (gid, t)
}

async fn seeded(fx: &McpOauthFixture) -> (i64, SeededTokens) {
    seeded_for(fx, fx.owner_id).await
}

/// Mints an admin session directly (no argon2, no login budget).
async fn session_for(fx: &McpOauthFixture, admin_id: i64) -> String {
    let mut c = fx.meta.lock().await;
    let token = drust::auth::session::create_session(&mut c, admin_id, 3600).unwrap();
    format!("drust_session={token}")
}

/// T3's state: R1 -> (A2, R2) by first use, then R1 again inside the grace ->
/// the sibling (A2b, R2b).
struct Race {
    gid: i64,
    r1: String,
    r1_id: i64,
    a2: String,
    r2: String,
    a2b: String,
    r2b: String,
}

async fn race(fx: &McpOauthFixture) -> Race {
    let (gid, t) = seeded(fx).await;
    let (a2, r2) = issued(refresh(&fx.app, &t.refresh).await, "R1 first use").await;
    let (a2b, r2b) = issued(refresh(&fx.app, &t.refresh).await, "R1 in grace").await;
    Race {
        gid,
        r1: t.refresh.clone(),
        r1_id: t.refresh_id,
        a2,
        r2,
        a2b,
        r2b,
    }
}

// ─── rotation ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn rotation_issues_a_new_pair_and_marks_the_old_rotated() {
    let fx = fixture(true).await;
    let (gid, t) = seeded(&fx).await;
    sql(
        &fx,
        &format!(
            "UPDATE _mcp_oauth_grants SET idle_expires_at = datetime('now','+1 day'), \
             last_used_at = NULL WHERE id = {gid}"
        ),
    )
    .await;
    let resp = refresh(&fx.app, &t.refresh).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(hdr(&resp, header::CACHE_CONTROL), Some("no-store"));
    let v = body_json(resp).await;
    let (a2, r2) = tokens_of(&v, "rotation");
    assert!(a2.starts_with(tokens::ACCESS_PREFIX), "{a2:.12}");
    assert!(r2.starts_with(tokens::REFRESH_PREFIX), "{r2:.12}");
    assert_eq!(v["token_type"], "Bearer");
    assert_eq!(v["expires_in"], 3600);
    assert_eq!(v["scope"], "mcp");

    let conn = fx.meta.lock().await;
    let r1 = rrow(&conn, t.refresh_id);
    assert!(r1.rotated.is_some(), "R1 rotated");
    assert!(r1.superseded.is_none() && r1.revoked.is_none(), "{r1:?}");
    let r2_id = rid(&conn, &r2);
    let r2row = rrow(&conn, r2_id);
    assert_eq!(r2row.parent, Some(t.refresh_id), "R2.parent = R1");
    assert_eq!(r2row.grant, gid, "same grant");
    assert_eq!(access_refresh_id(&conn, &a2), r2_id, "A2.refresh_id = R2");
    let g = grow(&conn, gid);
    let (slid, capped): (bool, bool) = conn
        .query_row(
            "SELECT idle_expires_at >= datetime('now','+29 days'), \
                    idle_expires_at <= absolute_expires_at \
               FROM _mcp_oauth_grants WHERE id = ?1",
            params![gid],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert!(slid && capped, "idle slid, never past absolute: {g:?}");
    assert!(g.last_used.is_some(), "last_used_at set");
    let min = std::cmp::min(g.idle.clone(), g.absolute.clone());
    assert_eq!(r2row.expires, min, "R2 expires at MIN(idle, absolute)");
    let all = dump(&conn);
    assert!(
        !all.contains(&a2) && !all.contains(&r2),
        "no plaintext stored"
    );
}

#[tokio::test]
async fn the_idle_slide_never_passes_the_absolute_deadline() {
    let fx = fixture(true).await;
    let (gid, t) = seeded_with(&fx, fx.owner_id, "+1 day", "+2 days").await;
    issued(refresh(&fx.app, &t.refresh).await, "refresh").await;
    let g = grow(&*fx.meta.lock().await, gid);
    assert_eq!(g.idle, g.absolute);
}

// ─── grace and siblings ──────────────────────────────────────────────────────

#[tokio::test]
async fn a_retry_inside_the_grace_issues_a_sibling_and_keeps_the_first_pair() {
    let fx = fixture(true).await;
    let (_gid, t) = seeded(&fx).await;
    let (a2, r2) = issued(refresh(&fx.app, &t.refresh).await, "first").await;
    let rotated_before = rrow(&*fx.meta.lock().await, t.refresh_id).rotated;
    assert!(rotated_before.is_some());
    let (_a2b, r2b) = issued(refresh(&fx.app, &t.refresh).await, "retry").await;
    let conn = fx.meta.lock().await;
    assert_eq!(rrow(&conn, rid(&conn, &r2b)).parent, Some(t.refresh_id));
    assert_eq!(
        rrow(&conn, t.refresh_id).rotated,
        rotated_before,
        "the grace is never re-armed"
    );
    assert!(access_live(&conn, &a2), "A2 still live");
    let r2row = rrow(&conn, rid(&conn, &r2));
    assert!(
        r2row.rotated.is_none() && r2row.superseded.is_none() && r2row.revoked.is_none(),
        "{r2row:?}"
    );
}

/// Pins "b before c": a superseded row has `rotated_at IS NULL`, so with c
/// first R2b would never be cut (`reason` would stay NULL).
#[tokio::test]
async fn the_first_sibling_used_wins_and_the_loser_is_cut_alone() {
    let fx = fixture(true).await;
    let x = race(&fx).await;
    let (a3, r3) = issued(refresh(&fx.app, &x.r2).await, "R2 wins").await;
    {
        let conn = fx.meta.lock().await;
        let loser = rrow(&conn, rid(&conn, &x.r2b));
        assert!(loser.superseded.is_some(), "R2b superseded");
        assert!(
            loser.revoked.is_none(),
            "not revoked before it is presented"
        );
        assert!(access_live(&conn, &x.a2b), "A2b is not cut early");
    }
    assert_invalid_grant(refresh(&fx.app, &x.r2b).await, "loser").await;
    {
        let conn = fx.meta.lock().await;
        let loser = rrow(&conn, rid(&conn, &x.r2b));
        assert!(loser.revoked.is_some(), "R2b revoked");
        assert_eq!(loser.reason.as_deref(), Some("sibling_superseded"));
        assert!(!access_live(&conn, &x.a2b), "A2b revoked with its branch");
        let g = grow(&conn, x.gid);
        assert!(g.sibling_rejected.is_some(), "sibling_rejected_at stamped");
        assert!(g.revoked.is_none(), "the grant stays live");
    }
    issued(refresh(&fx.app, &r3).await, "the winning branch").await;
    assert!(access_live(&*fx.meta.lock().await, &a3));
}

#[tokio::test]
async fn the_older_sibling_can_win_too() {
    let fx = fixture(true).await;
    let x = race(&fx).await;
    let (_a3b, r3b) = issued(refresh(&fx.app, &x.r2b).await, "R2b wins").await;
    assert_invalid_grant(refresh(&fx.app, &x.r2).await, "R2 loses").await;
    {
        let conn = fx.meta.lock().await;
        let loser = rrow(&conn, rid(&conn, &x.r2));
        assert_eq!(loser.reason.as_deref(), Some("sibling_superseded"));
        assert!(!access_live(&conn, &x.a2));
    }
    issued(refresh(&fx.app, &r3b).await, "the winning branch").await;
}

/// d-1: a child of R1 already rotated; R1 again inside the grace is refused
/// and revokes nothing.
#[tokio::test]
async fn presenting_the_parent_after_the_race_is_decided_rejects_only_that_request() {
    let fx = fixture(true).await;
    let (gid, t) = seeded(&fx).await;
    let (_a2, r2) = issued(refresh(&fx.app, &t.refresh).await, "R1").await;
    let (_a3, r3) = issued(refresh(&fx.app, &r2).await, "R2").await;
    let counts = |conn: &rusqlite::Connection| {
        (
            count(conn, "SELECT COUNT(*) FROM _mcp_oauth_refresh"),
            count(conn, "SELECT COUNT(*) FROM _mcp_oauth_access"),
            count(
                conn,
                "SELECT COUNT(*) FROM _mcp_oauth_refresh WHERE revoked_at IS NOT NULL",
            ),
            count(
                conn,
                "SELECT COUNT(*) FROM _mcp_oauth_access WHERE revoked_at IS NOT NULL",
            ),
        )
    };
    let before = counts(&*fx.meta.lock().await);
    assert_invalid_grant(refresh(&fx.app, &t.refresh).await, "parent again").await;
    {
        let conn = fx.meta.lock().await;
        assert_eq!(counts(&conn), before, "nothing issued, nothing revoked");
        let g = grow(&conn, gid);
        assert!(g.revoked.is_none(), "grant live");
        assert!(g.sibling_rejected.is_some(), "sibling_rejected_at stamped");
    }
    issued(refresh(&fx.app, &r3).await, "R3").await;
}

// ─── reuse past the grace ────────────────────────────────────────────────────

#[tokio::test]
async fn reuse_past_the_grace_revokes_the_whole_grant() {
    let fx = fixture(true).await;
    let (g1, t1) = seeded(&fx).await;
    let (g2, q1) = seeded(&fx).await;
    {
        let conn = fx.meta.lock().await;
        let (_, ch) = pkce();
        seed_code(&conn, g1, &loopback_redirect(1), &ch, None);
    }
    let (a2, r2) = issued(refresh(&fx.app, &t1.refresh).await, "R1").await;
    age_rotation(&fx, t1.refresh_id, 61).await;
    assert_invalid_grant(refresh(&fx.app, &t1.refresh).await, "reuse").await;
    {
        let conn = fx.meta.lock().await;
        let g = grow(&conn, g1);
        assert!(g.revoked.is_some(), "G1 revoked");
        assert_eq!(g.reason.as_deref(), Some("refresh_reuse"));
        for (table, sql) in [
            (
                "refresh",
                "SELECT COUNT(*) FROM _mcp_oauth_refresh WHERE grant_id = ?1 AND revoked_at IS NULL",
            ),
            (
                "access",
                "SELECT COUNT(*) FROM _mcp_oauth_access WHERE grant_id = ?1 AND revoked_at IS NULL",
            ),
            (
                "unredeemed code",
                "SELECT COUNT(*) FROM _mcp_oauth_codes WHERE grant_id = ?1",
            ),
        ] {
            let n: i64 = conn.query_row(sql, params![g1], |r| r.get(0)).unwrap();
            assert_eq!(n, 0, "G1 {table}");
        }
    }
    assert_invalid_grant(refresh(&fx.app, &r2).await, "R2 after reuse").await;
    assert!(!access_live(&*fx.meta.lock().await, &a2));
    // Only that grant: the same admin's other connection is untouched.
    issued(refresh(&fx.app, &q1.refresh).await, "G2").await;
    assert!(grow(&*fx.meta.lock().await, g2).revoked.is_none());
}

#[tokio::test]
async fn a_zero_grace_treats_the_second_presentation_as_reuse() {
    let fx =
        fixture_with(McpOauthConfig::for_tests(PUBLIC_URL).with_ttls_for_tests(3600, 0, 30, 90))
            .await;
    let (gid, t) = seeded(&fx).await;
    issued(refresh(&fx.app, &t.refresh).await, "R1").await;
    assert_invalid_grant(refresh(&fx.app, &t.refresh).await, "R1 again").await;
    assert_eq!(
        grow(&*fx.meta.lock().await, gid).reason.as_deref(),
        Some("refresh_reuse")
    );
}

/// A losing sibling's answer depends on its own row only, never on how long
/// ago its ancestors rotated.
#[tokio::test]
async fn a_superseded_sibling_presented_long_after_still_cuts_only_its_branch() {
    let fx = fixture(true).await;
    let x = race(&fx).await;
    let (_a3, r3) = issued(refresh(&fx.app, &x.r2).await, "R2 wins").await;
    let r2_id = rid(&*fx.meta.lock().await, &x.r2);
    age_rotation(&fx, x.r1_id, 7200).await;
    age_rotation(&fx, r2_id, 7200).await;
    assert_invalid_grant(refresh(&fx.app, &x.r2b).await, "old loser").await;
    {
        let conn = fx.meta.lock().await;
        assert_eq!(
            rrow(&conn, rid(&conn, &x.r2b)).reason.as_deref(),
            Some("sibling_superseded")
        );
        assert!(grow(&conn, x.gid).revoked.is_none(), "grant live");
    }
    issued(refresh(&fx.app, &r3).await, "R3").await;
}

// ─── branch a): dead or mismatched ───────────────────────────────────────────

/// (label, SQL applied first, the SDK form field to replace).
type DeadCase = (
    &'static str,
    &'static str,
    Option<(&'static str, &'static str)>,
);

#[tokio::test]
async fn dead_or_mismatched_refresh_is_invalid_grant_and_writes_nothing() {
    // In the SQL, {g} = grant id, {r} = refresh id, {a} = owner id.
    let cases: [DeadCase; 9] = [
        (
            "idle passed",
            "UPDATE _mcp_oauth_grants SET idle_expires_at = datetime('now','-1 minute') WHERE id = {g}",
            None,
        ),
        (
            "absolute passed",
            "UPDATE _mcp_oauth_grants SET absolute_expires_at = datetime('now','-1 minute') WHERE id = {g}",
            None,
        ),
        (
            "grant revoked",
            "UPDATE _mcp_oauth_grants SET revoked_at = datetime('now') WHERE id = {g}",
            None,
        ),
        (
            "refresh revoked",
            "UPDATE _mcp_oauth_refresh SET revoked_at = datetime('now') WHERE id = {r}",
            None,
        ),
        (
            "refresh expired",
            "UPDATE _mcp_oauth_refresh SET expires_at = datetime('now','-1 minute') WHERE id = {r}",
            None,
        ),
        (
            "admin created_at mismatch",
            "UPDATE admins SET created_at = '2000-01-01 00:00:00' WHERE id = {a}",
            None,
        ),
        (
            "foreign client_id",
            "",
            Some(("client_id", "https://evil.example/client.json")),
        ),
        (
            "resource with a trailing slash",
            "",
            Some(("resource", "https://drust.test/drust/mcp/")),
        ),
        (
            "another server's resource",
            "",
            Some(("resource", "https://other.test/drust/mcp")),
        ),
    ];
    for (label, pre, field) in cases {
        let fx = fixture(true).await;
        let (gid, t) = seeded(&fx).await;
        if !pre.is_empty() {
            sql(
                &fx,
                &pre.replace("{g}", &gid.to_string())
                    .replace("{r}", &t.refresh_id.to_string())
                    .replace("{a}", &fx.owner_id.to_string()),
            )
            .await;
        }
        let before = dump_now(&fx).await;
        let resp = match field {
            None => refresh(&fx.app, &t.refresh).await,
            Some((k, v)) => post_refresh(&fx, &form_with(&t.refresh, k, v)).await,
        };
        assert_invalid_grant(resp, label).await;
        assert_eq!(dump_now(&fx).await, before, "{label}: nothing written");
    }
}

#[tokio::test]
async fn a_removed_admin_cannot_refresh() {
    let fx = fixture(true).await;
    let m1 = add_admin(&fx, "m1", "", "member").await;
    let (_gid, t) = seeded_for(&fx, m1).await;
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
            &format!("SELECT COUNT(*) FROM admins WHERE id = {m1}")
        ),
        0,
        "the admin really is gone"
    );
    assert_invalid_grant(refresh(&fx.app, &t.refresh).await, "removed admin").await;
}

#[tokio::test]
async fn oauth_revoke_then_refresh_is_invalid_grant() {
    let fx = fixture(true).await;
    let (_gid, t) = seeded(&fx).await;
    let resp = post_form(&fx.app, "/oauth/revoke", &[("token", &t.access)], &[], &[]).await;
    assert_eq!(resp.status(), StatusCode::OK, "revoke");
    assert_invalid_grant(refresh(&fx.app, &t.refresh).await, "after revoke").await;
}

// ─── request shape ───────────────────────────────────────────────────────────

#[tokio::test]
async fn missing_client_id_is_accepted() {
    let fx = fixture(true).await;
    let (_gid, t) = seeded(&fx).await;
    let resp = post_refresh(
        &fx,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", &t.refresh),
            ("resource", RESOURCE),
        ],
    )
    .await;
    issued(resp, "no client_id").await;
}

#[tokio::test]
async fn scope_on_refresh() {
    let fx = fixture(true).await;
    let (_g, t1) = seeded(&fx).await;
    let resp = post_refresh(&fx, &form_with(&t1.refresh, "scope", "mcp offline_access")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["scope"], "mcp");

    let (_g, t2) = seeded(&fx).await;
    issued(
        post_refresh(&fx, &form_with(&t2.refresh, "scope", "")).await,
        "empty scope = not sent",
    )
    .await;

    let (_g, t3) = seeded(&fx).await;
    let before = dump_now(&fx).await;
    assert_oauth(
        post_refresh(&fx, &form_with(&t3.refresh, "scope", "admin")).await,
        "invalid_scope",
        "scope=admin",
    )
    .await;
    assert_eq!(dump_now(&fx).await, before, "scope=admin writes nothing");
}

#[tokio::test]
async fn request_shape_errors() {
    let fx = fixture(true).await;
    let (_gid, t) = seeded(&fx).await;
    assert_oauth(
        post_refresh(&fx, &[("grant_type", "refresh_token")]).await,
        "invalid_request",
        "missing refresh_token",
    )
    .await;
    let wrong_prefix = format!("drust_pat_{}", "a".repeat(43));
    for bad in [wrong_prefix.as_str(), "drust_mcprt_short"] {
        assert_invalid_grant(refresh(&fx.app, bad).await, bad).await;
    }
    // An access token presented as a refresh: wrong prefix, refused before any
    // lookup — it writes nothing and spends no miss budget.
    let before = dump_now(&fx).await;
    assert_invalid_grant(refresh(&fx.app, &t.access).await, "access as refresh").await;
    assert_eq!(
        dump_now(&fx).await,
        before,
        "access as refresh: nothing written"
    );
    for i in 1..=30 {
        let rnd = tokens::new_token(TokenKind::Refresh);
        assert_invalid_grant(refresh(&fx.app, &rnd).await, &format!("miss {i}")).await;
    }
    let rnd = tokens::new_token(TokenKind::Refresh);
    assert_throttled(refresh(&fx.app, &rnd).await, 60, "miss 31").await;
}

#[tokio::test]
async fn disabled_server_answers_404_for_refresh() {
    let form = [
        ("grant_type", "refresh_token"),
        ("refresh_token", "drust_mcprt_x"),
        ("client_id", CC_CLIENT_ID),
        ("resource", RESOURCE),
    ];
    let off = fixture(false).await;
    let token = reject_shape(post_form(&off.app, "/oauth/token", &form, &[], &[]).await).await;
    let never =
        reject_shape(post_form(&off.app, "/oauth/nonexistent", &form, &[], &[]).await).await;
    assert_eq!(token.0, 404, "disabled /oauth/token");
    assert_eq!(token, never, "disabled = a path that never existed");
    // The same form reaches the handler when enabled, so the comparison above
    // is not between two unmatched paths.
    let on = fixture(true).await;
    let resp = post_form(&on.app, "/oauth/token", &form, &[], &[]).await;
    assert_ne!(resp.status(), StatusCode::NOT_FOUND, "enabled /oauth/token");
}

// ─── rate limits ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn the_per_grant_bucket_rejects_the_11th_in_a_minute_and_only_for_that_grant() {
    let fx = fixture(true).await;
    let (_g1, t1) = seeded(&fx).await;
    let (_g2, t2) = seeded(&fx).await;
    let mut current = t1.refresh;
    for i in 1..=10 {
        let (_, next) = issued(refresh(&fx.app, &current).await, &format!("refresh {i}")).await;
        current = next;
    }
    assert_throttled(refresh(&fx.app, &current).await, 60, "refresh 11").await;
    {
        let conn = fx.meta.lock().await;
        assert!(
            rrow(&conn, rid(&conn, &current)).rotated.is_none(),
            "the 11th (branch c, charged) wrote nothing"
        );
    }
    issued(refresh(&fx.app, &t2.refresh).await, "another grant").await;
}

/// Presents `token` (a known token of the grant whose answer does not change
/// the state machine: branch a or d-1) until the grant's bucket answers 429.
/// The per-grant budget is 10 per 60 s, so at most 11 presentations.
async fn fill_grant_bucket(fx: &McpOauthFixture, token: &str, ctx: &str) {
    for i in 1..=11 {
        let resp = refresh(&fx.app, token).await;
        if resp.status() == StatusCode::TOO_MANY_REQUESTS {
            assert_throttled(resp, 60, &format!("{ctx}: fill {i}")).await;
            return;
        }
        assert_invalid_grant(resp, &format!("{ctx}: fill {i}")).await;
    }
    panic!("{ctx}: the grant's bucket never filled");
}

/// A thief who rotated a stolen refresh first can make a dead token of the
/// grant on demand (an in-grace sibling, cut once as the losing branch) and
/// flood it. Reuse detection must not depend on that budget: the legitimate
/// client's past-grace presentation of the rotated parent still revokes the
/// grant, so the client re-authorizes and the thief's chain dies.
#[tokio::test]
async fn a_dead_siblings_flood_cannot_suppress_reuse_detection() {
    let fx = fixture(true).await;
    let (gid, t) = seeded(&fx).await;
    // The thief: R1 -> R2 (first use), R1 again in grace -> R2b (sibling),
    // R2 -> R3 (supersedes R2b), R2b once (its branch is cut: now dead).
    let (_a2, r2) = issued(refresh(&fx.app, &t.refresh).await, "thief R1").await;
    let (_a2b, r2b) = issued(refresh(&fx.app, &t.refresh).await, "thief R1 again").await;
    let (a3, r3) = issued(refresh(&fx.app, &r2).await, "thief R2").await;
    assert_invalid_grant(refresh(&fx.app, &r2b).await, "thief cuts R2b").await;
    fill_grant_bucket(&fx, &r2b, "dead sibling flood").await;
    // The legitimate client wakes up past the grace with R1.
    age_rotation(&fx, t.refresh_id, 61).await;
    assert_invalid_grant(refresh(&fx.app, &t.refresh).await, "legitimate R1").await;
    {
        let conn = fx.meta.lock().await;
        let g = grow(&conn, gid);
        assert!(g.revoked.is_some(), "grant revoked: {g:?}");
        assert_eq!(g.reason.as_deref(), Some("refresh_reuse"));
        assert!(!access_live(&conn, &a3), "the thief's access is dead");
    }
    // The thief's live chain is gone too (a dead token: charged, so it may be
    // 429 while the bucket is still full; never a 200).
    let resp = refresh(&fx.app, &r3).await;
    assert_ne!(resp.status(), StatusCode::OK, "the thief's R3 is dead");
}

/// Branch b is terminal and runs at most once per token, so it reads no
/// budget: a full bucket still cuts a superseded sibling's branch.
#[tokio::test]
async fn a_full_bucket_still_cuts_a_superseded_sibling() {
    let fx = fixture(true).await;
    let x = race(&fx).await;
    issued(refresh(&fx.app, &x.r2).await, "R2 wins").await;
    // R1 again inside the grace with its child rotated: d-1, charged.
    fill_grant_bucket(&fx, &x.r1, "d-1 flood").await;
    assert_invalid_grant(refresh(&fx.app, &x.r2b).await, "loser").await;
    let conn = fx.meta.lock().await;
    let loser = rrow(&conn, rid(&conn, &x.r2b));
    assert!(loser.revoked.is_some(), "R2b revoked: {loser:?}");
    assert_eq!(loser.reason.as_deref(), Some("sibling_superseded"));
    assert!(!access_live(&conn, &x.a2b), "A2b revoked with its branch");
}

/// The issuing branches are charged: with the bucket full, a current token
/// gets 429 and the transaction writes nothing.
#[tokio::test]
async fn a_full_bucket_refuses_a_current_token_and_writes_nothing() {
    let fx = fixture(true).await;
    let x = race(&fx).await;
    let (_a3, r3) = issued(refresh(&fx.app, &x.r2).await, "R2 wins").await;
    fill_grant_bucket(&fx, &x.r1, "d-1 flood").await;
    let before = dump_now(&fx).await;
    assert_throttled(refresh(&fx.app, &r3).await, 60, "R3 (branch c)").await;
    assert_eq!(dump_now(&fx).await, before, "a refused c writes nothing");
}

#[tokio::test]
async fn random_refresh_tokens_spend_only_the_miss_budget() {
    let fx = fixture(true).await;
    let (_gid, t) = seeded(&fx).await;
    for i in 1..=40 {
        let bad = format!("drust_pat_{}", tokens::new_token(TokenKind::Code));
        assert_invalid_grant(refresh(&fx.app, &bad).await, &format!("wrong prefix {i}")).await;
    }
    for i in 1..=30 {
        let rnd = tokens::new_token(TokenKind::Refresh);
        assert_invalid_grant(refresh(&fx.app, &rnd).await, &format!("miss {i}")).await;
    }
    let rnd = tokens::new_token(TokenKind::Refresh);
    assert_throttled(refresh(&fx.app, &rnd).await, 60, "miss 31").await;
    // A refresh that exists never reads the miss bucket.
    issued(refresh(&fx.app, &t.refresh).await, "valid after misses").await;
}

// ─── concurrency ─────────────────────────────────────────────────────────────

/// Several Claude Code processes on one machine refreshing the same token at
/// once: every request gets a pair (one first use, the rest in-grace
/// siblings). Each request runs in its own task on a multi-thread runtime,
/// released together, so they really contend on the meta mutex.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_concurrent_refreshes_of_one_token_all_succeed() {
    let fx = fixture(true).await;
    let (_gid, t) = seeded(&fx).await;
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(3));
    let tasks: Vec<_> = (0..3)
        .map(|_| {
            let app = fx.app.clone();
            let token = t.refresh.clone();
            let b = barrier.clone();
            tokio::spawn(async move {
                b.wait().await;
                refresh(&app, &token).await
            })
        })
        .collect();
    let mut children = Vec::new();
    for (i, task) in tasks.into_iter().enumerate() {
        let resp = task.await.unwrap();
        children.push(issued(resp, &format!("request {i}")).await.1);
    }
    {
        let conn = fx.meta.lock().await;
        assert_eq!(
            count(
                &conn,
                &format!(
                    "SELECT COUNT(*) FROM _mcp_oauth_refresh WHERE parent_id = {}",
                    t.refresh_id
                )
            ),
            3,
            "three children of R1"
        );
        assert!(rrow(&conn, t.refresh_id).rotated.is_some());
    }
    issued(refresh(&fx.app, &children[0]).await, "one child is used").await;
    let conn = fx.meta.lock().await;
    for other in &children[1..] {
        assert!(
            rrow(&conn, rid(&conn, other)).superseded.is_some(),
            "the other children are superseded"
        );
    }
}

// ─── end to end and rejection uniformity ─────────────────────────────────────

#[tokio::test]
async fn code_then_refresh_end_to_end() {
    let fx = fixture(true).await;
    let session = login(&fx.app, OWNER_USER, OWNER_PASS).await;
    let tokens = obtain_tokens(&fx, &session).await;
    let resp = refresh(&fx.app, &tokens.refresh).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    for field in [
        "access_token",
        "token_type",
        "expires_in",
        "refresh_token",
        "scope",
    ] {
        assert!(v.get(field).is_some(), "SDK field {field}: {v}");
    }
    let (access, _) = tokens_of(&v, "e2e");
    let conn = fx.meta.lock().await;
    let g = store::find_grant_by_access(&conn, &access)
        .unwrap()
        .expect("the refreshed access token authorizes");
    assert_eq!(g.grant_id(), tokens.grant_id);
}

/// Miss, a), b), d-1) and e) must be indistinguishable to the presenter.
#[tokio::test]
async fn every_refresh_rejection_is_byte_identical() {
    let mut shapes: Vec<(&str, Shape)> = Vec::new();

    let fx = fixture(true).await;
    let rnd = tokens::new_token(TokenKind::Refresh);
    shapes.push(("miss", reject_shape(refresh(&fx.app, &rnd).await).await));

    let fx = fixture(true).await;
    let (_g, t) = seeded(&fx).await;
    sql(
        &fx,
        &format!(
            "UPDATE _mcp_oauth_refresh SET revoked_at = datetime('now') WHERE id = {}",
            t.refresh_id
        ),
    )
    .await;
    shapes.push(("a", reject_shape(refresh(&fx.app, &t.refresh).await).await));

    let fx = fixture(true).await;
    let x = race(&fx).await;
    issued(refresh(&fx.app, &x.r2).await, "b setup").await;
    shapes.push(("b", reject_shape(refresh(&fx.app, &x.r2b).await).await));

    let fx = fixture(true).await;
    let (_g, t) = seeded(&fx).await;
    let (_, r2) = issued(refresh(&fx.app, &t.refresh).await, "d-1 setup").await;
    issued(refresh(&fx.app, &r2).await, "d-1 setup 2").await;
    shapes.push((
        "d-1",
        reject_shape(refresh(&fx.app, &t.refresh).await).await,
    ));

    let fx = fixture(true).await;
    let (_g, t) = seeded(&fx).await;
    issued(refresh(&fx.app, &t.refresh).await, "e setup").await;
    age_rotation(&fx, t.refresh_id, 61).await;
    shapes.push(("e", reject_shape(refresh(&fx.app, &t.refresh).await).await));

    let (_, first) = &shapes[0];
    assert_eq!(first.0, 400);
    assert_eq!(first.2.as_deref(), Some("no-store"));
    assert!(!first.3, "no Set-Cookie, no Location");
    for (label, s) in &shapes {
        assert_eq!(s, first, "{label} differs from a miss");
    }

    // The two 429s: an exhausted miss_ip and an exhausted per_grant (filled
    // through a dead token of the grant, branch a, which is charged). Every
    // header but Retry-After, and the body, are the same.
    let fx = fixture(true).await;
    for i in 1..=30 {
        let rnd = tokens::new_token(TokenKind::Refresh);
        assert_invalid_grant(refresh(&fx.app, &rnd).await, &format!("miss {i}")).await;
    }
    let rnd = tokens::new_token(TokenKind::Refresh);
    let miss_429 = shape_429(refresh(&fx.app, &rnd).await).await;

    let fx = fixture(true).await;
    let (_g, t) = seeded(&fx).await;
    sql(
        &fx,
        &format!(
            "UPDATE _mcp_oauth_refresh SET revoked_at = datetime('now') WHERE id = {}",
            t.refresh_id
        ),
    )
    .await;
    fill_grant_bucket(&fx, &t.refresh, "per_grant").await;
    let grant_429 = shape_429(refresh(&fx.app, &t.refresh).await).await;
    assert_eq!(miss_429.0, 429);
    assert_eq!(
        miss_429, grant_429,
        "miss_ip 429 differs from per_grant 429"
    );
}

/// Status, every header except `Retry-After` (sorted name/value pairs) and
/// the body bytes.
async fn shape_429(resp: Response<Body>) -> (u16, Vec<(String, Vec<u8>)>, Vec<u8>) {
    let status = resp.status().as_u16();
    assert!(
        resp.headers().contains_key(header::RETRY_AFTER),
        "a 429 carries Retry-After"
    );
    let mut headers: Vec<(String, Vec<u8>)> = resp
        .headers()
        .iter()
        .filter(|(k, _)| *k != header::RETRY_AFTER)
        .map(|(k, v)| (k.as_str().to_string(), v.as_bytes().to_vec()))
        .collect();
    headers.sort();
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap()
        .to_vec();
    (status, headers, body)
}

/// d-2 never moves the parent's `rotated_at`: the grace always counts from
/// the FIRST rotation, so holding the parent cannot keep it alive.
#[tokio::test]
async fn a_sibling_issued_in_grace_does_not_extend_the_grace() {
    let fx = fixture(true).await;
    let (gid, t) = seeded(&fx).await;
    issued(refresh(&fx.app, &t.refresh).await, "c").await;
    age_rotation(&fx, t.refresh_id, 50).await;
    issued(refresh(&fx.app, &t.refresh).await, "d-2 at 50 s").await;
    age_rotation(&fx, t.refresh_id, 61).await;
    assert_invalid_grant(refresh(&fx.app, &t.refresh).await, "61 s").await;
    assert_eq!(
        grow(&*fx.meta.lock().await, gid).reason.as_deref(),
        Some("refresh_reuse")
    );
}

/// A wrong `client_id` is branch a): it revokes nothing even with genuine
/// reuse evidence (the Claude Code client_id is public, so a thief always
/// sends the right one; this only affects callers that send a wrong one).
#[tokio::test]
async fn reuse_with_a_wrong_client_id_does_not_revoke() {
    let fx = fixture(true).await;
    let (_gid, t) = seeded(&fx).await;
    let (_, r2) = issued(refresh(&fx.app, &t.refresh).await, "R1").await;
    age_rotation(&fx, t.refresh_id, 61).await;
    let before = dump_now(&fx).await;
    assert_invalid_grant(
        post_refresh(
            &fx,
            &form_with(&t.refresh, "client_id", "https://evil.example/client.json"),
        )
        .await,
        "reuse, wrong client_id",
    )
    .await;
    assert_eq!(dump_now(&fx).await, before, "nothing revoked");
    issued(refresh(&fx.app, &r2).await, "R2").await;
}

/// Demotion does not revoke a grant (visibility is decided per MCP call), the
/// opposite of invariant 5's admin-PAT eviction. The refresh path never reads
/// `role`.
#[tokio::test]
async fn demoting_the_owner_does_not_touch_the_grant() {
    let fx = fixture(true).await;
    let m2 = add_admin(&fx, "m2", "", "admin").await;
    let (gid, t) = seeded_for(&fx, m2).await;
    sql(
        &fx,
        &format!("UPDATE admins SET role = 'member' WHERE id = {m2}"),
    )
    .await;
    issued(refresh(&fx.app, &t.refresh).await, "after demotion").await;
    assert!(grow(&*fx.meta.lock().await, gid).revoked.is_none());
}

/// A child row never vouches for itself: a refresh whose grant row was
/// deleted on a connection without foreign keys is refused.
#[tokio::test]
async fn a_refresh_left_behind_by_a_deleted_grant_is_refused() {
    let fx = fixture(true).await;
    let (gid, t) = seeded(&fx).await;
    sql(
        &fx,
        &format!(
            "PRAGMA foreign_keys = OFF; DELETE FROM _mcp_oauth_grants WHERE id = {gid}; \
             PRAGMA foreign_keys = ON;"
        ),
    )
    .await;
    let before = dump_now(&fx).await;
    assert!(
        before.contains("_mcp_oauth_refresh|"),
        "the orphan refresh survives"
    );
    assert_invalid_grant(refresh(&fx.app, &t.refresh).await, "orphan refresh").await;
    assert_eq!(
        dump_now(&fx).await,
        before,
        "no token issued, nothing rewritten"
    );
}
