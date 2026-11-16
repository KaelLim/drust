//! MCP OAuth grant store — revocation primitives and token-to-grant lookups.
//!
//! Every function here runs on the caller's connection or transaction. None of
//! them locks `meta`, awaits, commits, or writes audit: the handler does
//! `s.meta.lock().await` -> `unchecked_transaction()` -> call -> `commit()` ->
//! drop the guard -> audit (MA0-PLAN §3.3).
//!
//! Revocation is per GRANT and has no post-commit step. That holds only while
//! all three of these hold:
//!   1. MCP OAuth tokens never enter `tenant::auth_cache` (or any other cache);
//!   2. they cannot open SSE or rooms streams;
//!   3. no MCP request holds a connection or session open past a single
//!      request — the account MCP endpoint is stateless (no GET stream, no
//!      rmcp session; design §3.7), and an upload ticket bound to a tus
//!      session is re-checked on every PATCH (MA1b).
//!
//! A phase that breaks any of them gives every caller of `revoke_mcp_grant`
//! and `remove_admin` an eviction duty — CLAUDE.md invariants 4 / 5.
//!
//! Two lookup strengths. `find_grant_by_access` is AUTHORIZATION strength and
//! is the only lookup whose `GrantRef` may authorize an MCP call.
//! `find_grant_for_revocation` is REVOCATION strength (any genuine token of an
//! unrevoked grant); its `GrantRef` — like every `GrantRef` other than
//! `find_grant_by_access`'s — may only feed `GrantOwner::holder`.
//!
//! Every read of a child table (codes, refresh, access, upload tickets) that
//! decides validity INNER JOINs `_mcp_oauth_grants` AND `admins` on id +
//! created_at; a child row's own columns never prove the grant exists.

use rusqlite::{Connection, OptionalExtension, Transaction, params};

use crate::auth::middleware::AdminId;
use crate::mgmt::mcp_oauth::config::McpOauthConfig;
use crate::mgmt::mcp_oauth::envelope::AuthzRequest;
use crate::mgmt::mcp_oauth::redirect::RedirectTarget;
use crate::mgmt::mcp_oauth::tokens::{self, TokenKind};

/// Stored in `revoke_reason` on the grant and on each refresh row it revokes.
/// The strings are a contract with the DDL comment (MA0-PLAN §3.1 #9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevokeReason {
    User,
    UserAll,
    TeamAdmin,
    OauthRevoke,
    RefreshReuse,
    CodeReplay,
}

impl RevokeReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::User => "user",
            Self::UserAll => "user_all",
            Self::TeamAdmin => "team_admin",
            Self::OauthRevoke => "oauth_revoke",
            Self::RefreshReuse => "refresh_reuse",
            Self::CodeReplay => "code_replay",
        }
    }
}

/// Who may revoke. The owner is bound into the grant UPDATE's WHERE
/// (`id = ?1 AND admin_id = ?2`), so a revoke that was not handed an owner
/// does not compile. No `Default`, no public field, no `Clone`.
///
/// The type forces the caller to NAME an owner; it does not prove the owner is
/// the session's admin — `AdminId`'s field is public. `caller` must only ever
/// be fed the request's `Extension<AdminId>`, never an id from a path or form.
#[derive(Debug)]
pub struct GrantOwner {
    admin_id: i64,
    /// `Some` for `holder`: a token proves ONE grant, so any other grant id is
    /// `NotFound` even when it belongs to the same admin.
    pinned_grant: Option<i64>,
}

impl GrantOwner {
    /// Self-service: the session's own admin (settings page, MA0-9). Pass the
    /// request's `Extension<AdminId>` only.
    pub fn caller(caller: &AdminId) -> Self {
        Self {
            admin_id: caller.0,
            pinned_grant: None,
        }
    }

    /// Token-proven: the holder presented a genuine token of THIS grant
    /// (`/oauth/revoke`, refresh reuse, code replay). Pinned to that grant.
    pub fn holder(grant: &GrantRef) -> Self {
        Self {
            admin_id: grant.admin_id,
            pinned_grant: Some(grant.grant_id),
        }
    }
    // `managed(&ui::TeamAuthority)` arrives with MA0-9 (`pinned_grant: None`).
}

/// Only `store.rs` constructs this (private fields). It proves the caller
/// presented a genuine token of this grant; how strong that proof is depends
/// on the lookup that built it. Only a `GrantRef` from `find_grant_by_access`
/// may authorize an MCP call (MA1a). Every other one — `find_grant_for_revocation`,
/// `find_grant_by_refresh`, MA0-7 replay, MA0-8 reuse — may only feed
/// `GrantOwner::holder`.
#[derive(Debug)]
pub struct GrantRef {
    grant_id: i64,
    admin_id: i64,
}

impl GrantRef {
    pub fn grant_id(&self) -> i64 {
        self.grant_id
    }

    pub fn admin_id(&self) -> i64 {
        self.admin_id
    }
}

/// `NotFound` = absent, not yours, or already revoked — one answer, so a
/// management-plane caller cannot tell them apart (one 404).
#[must_use = "a NotFound must become a 404, not a silent success"]
#[derive(Debug, PartialEq, Eq)]
pub enum RevokedGrant {
    Revoked,
    NotFound,
}

// Owner-bound. Hits 0 rows for absent / foreign / already-revoked: nothing else runs.
// An expired-but-unrevoked grant IS revoked (the settings page lists recent ones).
const SQL_REVOKE_GRANT: &str = "\
UPDATE _mcp_oauth_grants SET revoked_at = ?3, revoke_reason = ?4 \
 WHERE id = ?1 AND admin_id = ?2 AND revoked_at IS NULL";

// Children key on grant_id alone: they only run after the owner-bound UPDATE hit.
// `revoked_at IS NULL` keeps an earlier per-branch revoke ('sibling_superseded').
const SQL_REVOKE_REFRESH: &str = "\
UPDATE _mcp_oauth_refresh SET revoked_at = ?2, revoke_reason = ?3 \
 WHERE grant_id = ?1 AND revoked_at IS NULL";

const SQL_REVOKE_ACCESS: &str = "\
UPDATE _mcp_oauth_access SET revoked_at = ?2 \
 WHERE grant_id = ?1 AND revoked_at IS NULL";

// codes has no revoked_at (MA0-PLAN §5 #25): a deleted code redeems as a miss.
// Redeemed codes stay until the sweep: the replay check needs them while live.
const SQL_DELETE_UNREDEEMED_CODES: &str = "\
DELETE FROM _mcp_oauth_codes WHERE grant_id = ?1 AND redeemed_at IS NULL";

const SQL_REVOKE_TICKETS: &str = "\
UPDATE _mcp_upload_tickets SET revoked_at = ?2 \
 WHERE grant_id = ?1 AND revoked_at IS NULL";

const SQL_LIVE_GRANT_IDS: &str = "\
SELECT id FROM _mcp_oauth_grants WHERE admin_id = ?1 AND revoked_at IS NULL ORDER BY id";

// AUTHORIZATION strength. Live = token row not revoked and not expired; grant
// not revoked, idle and absolute not passed; admins row matches BOTH id and
// created_at (rowid-recycle layer 3 — second precision, see remove_admin).
// Rotation state is NOT checked on refresh: that decision (with its grace
// window) belongs to refresh::rotate alone (MA0-8); find_grant_by_refresh is a
// validity probe and never decides whether to issue tokens.
const SQL_FIND_BY_ACCESS: &str = "\
SELECT g.id, g.admin_id \
  FROM _mcp_oauth_access a \
  JOIN _mcp_oauth_grants g ON g.id = a.grant_id \
  JOIN admins ad ON ad.id = g.admin_id AND ad.created_at = g.admin_created_at \
 WHERE a.token_hash = ?1 \
   AND a.revoked_at IS NULL AND a.expires_at > datetime('now') \
   AND g.revoked_at IS NULL \
   AND g.idle_expires_at > datetime('now') AND g.absolute_expires_at > datetime('now')";

const SQL_FIND_BY_REFRESH: &str = "\
SELECT g.id, g.admin_id \
  FROM _mcp_oauth_refresh r \
  JOIN _mcp_oauth_grants g ON g.id = r.grant_id \
  JOIN admins ad ON ad.id = g.admin_id AND ad.created_at = g.admin_created_at \
 WHERE r.token_hash = ?1 \
   AND r.revoked_at IS NULL AND r.expires_at > datetime('now') \
   AND g.revoked_at IS NULL \
   AND g.idle_expires_at > datetime('now') AND g.absolute_expires_at > datetime('now')";

// REVOCATION strength (RFC 7009 §2.1 — revoking a token may revoke its grant).
// The token row only has to EXIST — revoked, expired, rotated or superseded all
// count — and its grant must be unrevoked with a matching admin. Grant
// idle/absolute are not checked: revoking an expired grant is harmless.
// Narrowing only; the GrantRef this yields may only feed GrantOwner::holder.
const SQL_FIND_ACCESS_FOR_REVOCATION: &str = "\
SELECT g.id, g.admin_id \
  FROM _mcp_oauth_access a \
  JOIN _mcp_oauth_grants g ON g.id = a.grant_id \
  JOIN admins ad ON ad.id = g.admin_id AND ad.created_at = g.admin_created_at \
 WHERE a.token_hash = ?1 AND g.revoked_at IS NULL";

const SQL_FIND_REFRESH_FOR_REVOCATION: &str = "\
SELECT g.id, g.admin_id \
  FROM _mcp_oauth_refresh r \
  JOIN _mcp_oauth_grants g ON g.id = r.grant_id \
  JOIN admins ad ON ad.id = g.admin_id AND ad.created_at = g.admin_created_at \
 WHERE r.token_hash = ?1 AND g.revoked_at IS NULL";

/// One call = the grant + its refresh + its access + its unredeemed codes
/// (DELETE) + its upload tickets, inside the caller's transaction.
pub fn revoke_mcp_grant(
    tx: &Transaction<'_>,
    owner: &GrantOwner,
    grant_id: i64,
    reason: RevokeReason,
) -> rusqlite::Result<RevokedGrant> {
    // A holder proved ONE grant: any other id is the same NotFound, nothing written.
    if owner.pinned_grant.is_some_and(|p| p != grant_id) {
        return Ok(RevokedGrant::NotFound);
    }
    // One SQLite-generated instant for all five statements (MA0-PLAN §3.2 format).
    let now: String = tx.query_row("SELECT datetime('now')", [], |r| r.get(0))?;
    let hit = tx.execute(
        SQL_REVOKE_GRANT,
        params![grant_id, owner.admin_id, now, reason.as_str()],
    )?;
    if hit == 0 {
        return Ok(RevokedGrant::NotFound);
    }
    tx.execute(SQL_REVOKE_REFRESH, params![grant_id, now, reason.as_str()])?;
    tx.execute(SQL_REVOKE_ACCESS, params![grant_id, now])?;
    tx.execute(SQL_DELETE_UNREDEEMED_CODES, params![grant_id])?;
    tx.execute(SQL_REVOKE_TICKETS, params![grant_id, now])?;
    Ok(RevokedGrant::Revoked)
}

/// Revokes every live grant of `owner`; returns how many were revoked.
/// Loops over `revoke_mcp_grant` so there is exactly one revoke path.
pub fn revoke_all_mcp_grants(
    tx: &Transaction<'_>,
    owner: &GrantOwner,
    reason: RevokeReason,
) -> rusqlite::Result<usize> {
    let ids: Vec<i64> = {
        let mut st = tx.prepare(SQL_LIVE_GRANT_IDS)?;
        let rows = st.query_map(params![owner.admin_id], |r| r.get(0))?;
        rows.collect::<rusqlite::Result<_>>()?
    };
    let mut n = 0;
    for id in ids {
        if revoke_mcp_grant(tx, owner, id, reason)? == RevokedGrant::Revoked {
            n += 1;
        }
    }
    Ok(n)
}

pub fn find_grant_by_access(conn: &Connection, token: &str) -> rusqlite::Result<Option<GrantRef>> {
    find(conn, TokenKind::Access, SQL_FIND_BY_ACCESS, token)
}

pub fn find_grant_by_refresh(conn: &Connection, token: &str) -> rusqlite::Result<Option<GrantRef>> {
    find(conn, TokenKind::Refresh, SQL_FIND_BY_REFRESH, token)
}

/// `/oauth/revoke` only (MA0-4 `lookup_for_revoke`). Accepts an access or a
/// refresh by prefix; any other shape is `None` without touching SQL.
pub fn find_grant_for_revocation(
    conn: &Connection,
    token: &str,
) -> rusqlite::Result<Option<GrantRef>> {
    if tokens::looks_like(TokenKind::Access, token) {
        find(
            conn,
            TokenKind::Access,
            SQL_FIND_ACCESS_FOR_REVOCATION,
            token,
        )
    } else if tokens::looks_like(TokenKind::Refresh, token) {
        find(
            conn,
            TokenKind::Refresh,
            SQL_FIND_REFRESH_FOR_REVOCATION,
            token,
        )
    } else {
        Ok(None)
    }
}

/// `/oauth/revoke` only. A genuine token of an unrevoked grant was presented
/// (REVOCATION strength, `find_grant_for_revocation`), plus the grant's
/// `client_id` for the RFC 7009 §2.1 "was it issued to this client" check.
/// `grant` may only feed `GrantOwner::holder` — never authorize an MCP call.
#[derive(Debug)]
pub struct RevokeTarget {
    pub grant: GrantRef,
    pub client_id: String,
}

const SQL_GRANT_CLIENT_ID: &str = "SELECT client_id FROM _mcp_oauth_grants WHERE id = ?1";

/// Wrong shape (neither access nor refresh) is `None` without touching SQL.
/// Call it on the revoke transaction, so the lookup, this read and the revoke
/// that follows see one state. The revocation predicate lives only in
/// `find_grant_for_revocation`; this adds nothing to it.
pub fn lookup_for_revoke(conn: &Connection, token: &str) -> rusqlite::Result<Option<RevokeTarget>> {
    let Some(grant) = find_grant_for_revocation(conn, token)? else {
        return Ok(None);
    };
    // The JOIN above just proved this row exists; a QueryReturnedNoRows here is
    // a bug and surfaces as Err (the caller answers 500 and revokes nothing).
    let client_id: String =
        conn.query_row(SQL_GRANT_CLIENT_ID, params![grant.grant_id], |r| r.get(0))?;
    Ok(Some(RevokeTarget { grant, client_id }))
}

/// What consent approval created. `code` is the plaintext authorization code:
/// it goes into the 303 `Location` and nowhere else (no log, no audit). No
/// `Debug`, so it cannot be formatted by accident.
pub struct NewCode {
    pub grant_id: i64,
    pub code: String,
}

// `admin_created_at` is copied in SQL, from the same row the INSERT selects:
// an admins row deleted since the consent page means 0 rows, never a grant
// bound to a placeholder. One statement, so `created_at` (column default),
// `idle_expires_at` and `absolute_expires_at` share one 'now'. `MIN(x, y)` with
// two arguments is SQLite's scalar MIN; both are datetime() text.
const SQL_INSERT_GRANT: &str = "\
INSERT INTO _mcp_oauth_grants \
       (admin_id, admin_created_at, client_id, redirect_host, scope, kind, \
        idle_expires_at, absolute_expires_at) \
SELECT a.id, a.created_at, ?2, ?3, 'mcp', 'authorization_code', \
       MIN(datetime('now', ?4), datetime('now', ?5)), datetime('now', ?5) \
  FROM admins a WHERE a.id = ?1";

const SQL_INSERT_CODE: &str = "\
INSERT INTO _mcp_oauth_codes \
       (code_hash, grant_id, client_id, redirect_uri, code_challenge, resource, expires_at) \
VALUES (?1, ?2, ?3, ?4, ?5, ?6, datetime('now', '+300 seconds'))";

/// MA0-6 consent approval: one grant (`kind = 'authorization_code'`, scope
/// `mcp`, absolute = now + max_days, idle = MIN(now + idle_days, absolute))
/// and its one code (hash only, 300 s), in the caller's transaction. The admins
/// row is re-read inside the INSERT; no row => `Err(QueryReturnedNoRows)` and
/// nothing written. `redirect` must be the `RedirectTarget` that
/// `redirect_uri_allowed` returned for `req.redirect_uri`: its `raw` (port
/// included) is what the token endpoint compares, its `host` is the grant's.
pub fn insert_grant_and_code(
    tx: &Transaction<'_>,
    cfg: &McpOauthConfig,
    admin_id: i64,
    req: &AuthzRequest,
    redirect: &RedirectTarget,
) -> rusqlite::Result<NewCode> {
    let idle = format!("+{} days", cfg.idle_days());
    let max = format!("+{} days", cfg.max_days());
    let n = tx.execute(
        SQL_INSERT_GRANT,
        params![admin_id, req.client_id, redirect.host, idle, max],
    )?;
    if n == 0 {
        return Err(rusqlite::Error::QueryReturnedNoRows); // admins row gone
    }
    let grant_id = tx.last_insert_rowid();
    let code = tokens::new_token(TokenKind::Code);
    tx.execute(
        SQL_INSERT_CODE,
        params![
            tokens::hash(TokenKind::Code, &code),
            grant_id,
            req.client_id,
            redirect.raw,
            req.code_challenge,
            req.resource,
        ],
    )?;
    Ok(NewCode { grant_id, code })
}

fn find(
    conn: &Connection,
    kind: TokenKind,
    sql: &str,
    token: &str,
) -> rusqlite::Result<Option<GrantRef>> {
    // Wrong prefix or length: answer without touching SQL (MA0-PLAN §3.5.1).
    if !tokens::looks_like(kind, token) {
        return Ok(None);
    }
    let h = tokens::hash(kind, token);
    conn.query_row(sql, params![h], |r| {
        Ok(GrantRef {
            grant_id: r.get(0)?,
            admin_id: r.get(1)?,
        })
    })
    .optional()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revoke_reason_strings_match_the_ddl_contract() {
        let all = [
            (RevokeReason::User, "user"),
            (RevokeReason::UserAll, "user_all"),
            (RevokeReason::TeamAdmin, "team_admin"),
            (RevokeReason::OauthRevoke, "oauth_revoke"),
            (RevokeReason::RefreshReuse, "refresh_reuse"),
            (RevokeReason::CodeReplay, "code_replay"),
        ];
        for (reason, want) in all {
            assert_eq!(reason.as_str(), want, "{reason:?}");
        }
        let mut seen: Vec<&str> = all.iter().map(|(r, _)| r.as_str()).collect();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(
            seen.len(),
            all.len(),
            "revoke_reason strings must be distinct"
        );
    }
}
