//! MCP OAuth grant store — revocation primitives, token-to-grant lookups,
//! grant/code creation, code redemption, token issuance, and the refresh
//! rotation snapshot and branch revoke (the state machine is `refresh.rs`).
//!
//! Every function here runs on the caller's connection or transaction. None of
//! them locks `meta`, awaits, commits, or writes audit: the handler does
//! `s.meta.lock().await` -> `unchecked_transaction()` -> call -> `commit()` ->
//! drop the guard -> audit.
//!
//! Revocation is per GRANT and has no post-commit step. That holds only while
//! all three of these hold:
//!   1. MCP OAuth tokens never enter `tenant::auth_cache` (or any other cache);
//!   2. they cannot open SSE or rooms streams;
//!   3. no MCP request holds a connection or session open past a single
//!      request.
//!
//! Today nothing accepts a `drust_mcpat_` token, so all three hold trivially.
//! They are conditions the features that will consume these tokens must keep:
//! the account-level MCP endpoint must stay stateless (no GET stream, no rmcp
//! session, every request re-authenticated through `find_grant_by_access`),
//! and an upload bound to a ticket must re-check the ticket and its grant on
//! every tus PATCH. A feature that breaks any of them gives every caller of
//! `revoke_mcp_grant` and `remove_admin` an eviction duty — CLAUDE.md
//! invariants 4 / 5.
//!
//! Two lookup strengths. `find_grant_by_access` is AUTHORIZATION strength and
//! returns an `AccessGrant`, the only value an MCP call may be authorized from.
//! `find_grant_for_revocation` is REVOCATION strength (any genuine token of an
//! unrevoked grant); its `GrantRef` — like every `GrantRef` — may only feed
//! `GrantOwner::holder`.
//!
//! Every read of a child table (codes, refresh, access, upload tickets) that
//! decides validity INNER JOINs `_mcp_oauth_grants` AND `admins` on id +
//! created_at; a child row's own columns never prove the grant exists.

use rusqlite::{Connection, OptionalExtension, Transaction, params};

use crate::auth::middleware::AdminId;
use crate::mgmt::mcp_oauth::config::McpOauthConfig;
use crate::mgmt::mcp_oauth::envelope::AuthzRequest;
use crate::mgmt::mcp_oauth::pkce;
use crate::mgmt::mcp_oauth::redirect::RedirectTarget;
use crate::mgmt::mcp_oauth::tokens::{self, TokenKind};

/// Stored in `revoke_reason` on the grant and on each refresh row it revokes.
/// The strings are a contract with the `revoke_reason` column comments in the
/// `_mcp_*` DDL (`db::migrations`), which name this function: rows already
/// written keep their string, so a variant's string is never changed.
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
    /// Self-service: the session's own admin (settings page). Pass the
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

    /// The team page: an admin acting on another admin's grants. Only
    /// `ui::team_authority` mints the proof, after the `remove_admin` matrix.
    pub fn managed(authority: &super::ui::TeamAuthority) -> Self {
        Self {
            admin_id: authority.target_admin_id(),
            pinned_grant: None,
        }
    }
}

/// Only `store.rs` constructs this (private fields). It proves the caller
/// presented a genuine token of this grant; how strong that proof is depends
/// on the lookup that built it. A `GrantRef` never authorizes an MCP call (that
/// is `AccessGrant`). Every one — from `find_grant_for_revocation`,
/// `find_grant_by_refresh`, a code replay or refresh reuse — may only feed
/// `GrantOwner::holder`. Refresh
/// reuse's (`RefreshState::holder`) exists only for a
/// genuine, unrevoked, already-rotated refresh of a live grant whose admin
/// still matches.
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

/// AUTHORIZATION strength: the only value an MCP call may be authorized from.
/// Built in exactly one place, `find_grant_by_access` (pinned by
/// `access_grant_is_built_only_by_find_grant_by_access`). No `Clone`, no
/// `Default`, no `Debug`: it carries the account's email.
pub struct AccessGrant {
    grant_id: i64,
    admin_id: i64,
    admin_label: String,
}

impl AccessGrant {
    pub fn grant_id(&self) -> i64 {
        self.grant_id
    }

    pub fn admin_id(&self) -> i64 {
        self.admin_id
    }

    /// `COALESCE(email, username)` of the grant's admin.
    pub fn admin_label(&self) -> &str {
        &self.admin_label
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

// codes has no revoked_at: a revoke deletes the unredeemed codes, and a deleted
// code redeems as a miss.
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
// window) belongs to refresh::rotate alone; find_grant_by_refresh is a
// validity probe and never decides whether to issue tokens.
// Also returns the account label (COALESCE(email, username)), the value consent
// and the audit rows use.
const SQL_FIND_BY_ACCESS: &str = "\
SELECT g.id, g.admin_id, COALESCE(ad.email, ad.username) \
  FROM _mcp_oauth_access a \
  JOIN _mcp_oauth_grants g ON g.id = a.grant_id \
  JOIN admins ad ON ad.id = g.admin_id AND ad.created_at = g.admin_created_at \
 WHERE a.token_hash = ?1 \
   AND a.revoked_at IS NULL AND a.expires_at > datetime('now') \
   AND g.revoked_at IS NULL \
   AND g.idle_expires_at > datetime('now') AND g.absolute_expires_at > datetime('now')";

// The same 60 s throttle the admin PAT bump uses (tenant/router.rs). Inside the
// window it matches 0 rows and writes no page.
const TOUCH_GRANT_THROTTLED: &str = "\
UPDATE _mcp_oauth_grants SET last_used_at = datetime('now') \
 WHERE id = ?1 \
   AND (last_used_at IS NULL OR last_used_at < datetime('now', '-60 seconds'))";

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
    // One SQLite-generated instant for all five statements (datetime() text, see
    // the DDL header).
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

pub fn find_grant_by_access(
    conn: &Connection,
    token: &str,
) -> rusqlite::Result<Option<AccessGrant>> {
    // Wrong prefix or length: answer without touching SQL.
    if !tokens::looks_like(TokenKind::Access, token) {
        return Ok(None);
    }
    let h = tokens::hash(TokenKind::Access, token);
    conn.query_row(SQL_FIND_BY_ACCESS, params![h], |r| {
        Ok(AccessGrant {
            grant_id: r.get(0)?,
            admin_id: r.get(1)?,
            admin_label: r.get(2)?,
        })
    })
    .optional()
}

/// Marks the grant as used, at most once per 60 s (the throttle is in the SQL;
/// inside the window it matches 0 rows and writes no page). Takes the
/// `AccessGrant` itself, so only a request that just passed
/// `find_grant_by_access` can make a grant look recently used on the settings
/// card. Called in the same locked block and on the same connection as that
/// lookup, never from a background task. A failure never changes the
/// authorization decision: callers warn and continue.
///
/// Returns rows written: 1 at most once per 60 s per grant, else 0.
pub fn touch_grant_last_used(conn: &Connection, g: &AccessGrant) -> rusqlite::Result<usize> {
    conn.execute(TOUCH_GRANT_THROTTLED, params![g.grant_id()])
}

pub fn find_grant_by_refresh(conn: &Connection, token: &str) -> rusqlite::Result<Option<GrantRef>> {
    find(conn, TokenKind::Refresh, SQL_FIND_BY_REFRESH, token)
}

/// `/oauth/revoke` only (`lookup_for_revoke`). Accepts an access or a
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

/// Consent approval: one grant (`kind = 'authorization_code'`, scope
/// `mcp`, absolute = now + max_days, idle = MIN(now + idle_days, absolute))
/// and its one code (hash only, 300 s), in the caller's transaction. The admins
/// row is re-read inside the INSERT; no row => `Err(QueryReturnedNoRows)` and
/// nothing written. `redirect` must be the `RedirectTarget` that
/// `redirect_uri_allowed` returned for `req.redirect_uri`: its `raw` (port
/// included) is what the token endpoint compares, its `host` is the grant's.
///
/// Every grant has exactly ONE code. A replayed code revokes its whole grant,
/// which equals "revoke every token issued from that code" only because of
/// this; hanging a second code on an existing grant means redesigning the
/// `code_replay` revocation scope first.
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

// ─── Code redemption and token issuance (issue_token_pair also serves refresh) ──

/// One read for the whole decision: the code, its grant, and whether the admin
/// row still matches BOTH id and created_at. The INNER JOIN means a code whose
/// grant row is gone (FK off) is a Miss: a child row never vouches for itself.
/// Booleans are computed in SQL, so every time comparison uses SQLite's
/// `datetime('now')` (datetime() text, see the DDL header).
const REDEEM_SELECT: &str = "\
SELECT c.grant_id,
       g.admin_id,
       c.client_id,
       c.redirect_uri,
       c.code_challenge,
       c.resource,
       c.redeemed_at IS NOT NULL,
       c.expires_at > datetime('now'),
       g.revoked_at IS NULL
         AND g.idle_expires_at > datetime('now')
         AND g.absolute_expires_at > datetime('now'),
       EXISTS (SELECT 1 FROM admins ad
                WHERE ad.id = g.admin_id AND ad.created_at = g.admin_created_at)
  FROM _mcp_oauth_codes c
  JOIN _mcp_oauth_grants g ON g.id = c.grant_id
 WHERE c.code_hash = ?1";

/// Single-use gate. `redeemed_at IS NULL` makes a concurrent second redemption a
/// 0-row update; `expires_at` is re-checked so a code that expired between the
/// two statements cannot be marked.
const REDEEM_MARK: &str = "\
UPDATE _mcp_oauth_codes
   SET redeemed_at = datetime('now')
 WHERE code_hash = ?1
   AND redeemed_at IS NULL
   AND expires_at > datetime('now')";

/// Root or child refresh. expires_at = the grant's MIN(idle, absolute) as it
/// stands NOW (refresh rotation slides idle BEFORE calling issue_token_pair). A parent must
/// belong to the same grant (ids are AUTOINCREMENT but never trusted alone).
/// Parent LIVENESS (revoked / rotated / superseded) is NOT checked here: that is
/// the caller's job (`refresh::rotate`).
const ISSUE_REFRESH: &str = "\
INSERT INTO _mcp_oauth_refresh (grant_id, parent_id, token_hash, expires_at)
SELECT g.id, ?2, ?3, MIN(g.idle_expires_at, g.absolute_expires_at)
  FROM _mcp_oauth_grants g
 WHERE g.id = ?1
   AND g.revoked_at IS NULL
   AND g.idle_expires_at > datetime('now')
   AND g.absolute_expires_at > datetime('now')
   AND (?2 IS NULL OR EXISTS (SELECT 1 FROM _mcp_oauth_refresh p
                               WHERE p.id = ?2 AND p.grant_id = ?1))";

/// refresh_id = the refresh inserted by THIS call (same response), never a parent.
const ISSUE_ACCESS: &str = "\
INSERT INTO _mcp_oauth_access (token_hash, grant_id, refresh_id, expires_at)
VALUES (?1, ?2, ?3, datetime('now', ?4))";

/// The sweep's abandoned-grant rule reads `last_used_at IS NULL`: setting it
/// here is what keeps an exchanged grant out of that rule.
const TOUCH_GRANT: &str = "\
UPDATE _mcp_oauth_grants SET last_used_at = datetime('now') WHERE id = ?1";

/// The code row joined with its grant and admin checks. Holds no plaintext (the
/// code itself is never read back, only its hash is matched), so no pin covers
/// it; it derives nothing because nothing needs it.
struct CodeRow {
    grant_id: i64,
    admin_id: i64,
    client_id: String,
    redirect_uri: String,
    code_challenge: String,
    resource: Option<String>,
    redeemed: bool,
    code_live: bool,
    grant_live: bool,
    admin_ok: bool,
}

/// One refresh and one access, issued in one response. NO `Debug`: the fields
/// are live plaintext credentials (pinned by `credential_types_do_not_derive_debug`).
pub struct IssuedTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub refresh_id: i64,
    pub expires_in: u32,
}

/// Inserts one refresh (`parent_id = parent_refresh_id`) and one access whose
/// `refresh_id` is that refresh, and sets the grant's `last_used_at`.
/// `refresh.expires_at` = the grant's MIN(idle, absolute) after any slide; the
/// access expires `access_ttl_secs` from now and is NOT capped by the grant —
/// `find_grant_by_access` checks the grant's deadlines on every use.
///
/// `Err(QueryReturnedNoRows)` with nothing inserted when the grant is gone,
/// revoked or expired, or the parent belongs to another grant.
pub fn issue_token_pair(
    tx: &Transaction<'_>,
    cfg: &McpOauthConfig,
    grant_id: i64,
    parent_refresh_id: Option<i64>,
) -> rusqlite::Result<IssuedTokens> {
    let refresh_token = tokens::new_token(TokenKind::Refresh);
    let n = tx.execute(
        ISSUE_REFRESH,
        params![
            grant_id,
            parent_refresh_id,
            tokens::hash(TokenKind::Refresh, &refresh_token)
        ],
    )?;
    if n != 1 {
        // Grant gone, revoked, expired, or a foreign parent. Nothing was inserted.
        return Err(rusqlite::Error::QueryReturnedNoRows);
    }
    let refresh_id = tx.last_insert_rowid();
    let access_token = tokens::new_token(TokenKind::Access);
    let ttl = cfg.access_ttl_secs();
    tx.execute(
        ISSUE_ACCESS,
        params![
            tokens::hash(TokenKind::Access, &access_token),
            grant_id,
            refresh_id,
            format!("+{ttl} seconds")
        ],
    )?;
    tx.execute(TOUCH_GRANT, params![grant_id])?;
    Ok(IssuedTokens {
        access_token,
        refresh_token,
        refresh_id,
        expires_in: ttl,
    })
}

/// What the token endpoint received for `grant_type=authorization_code`. NO
/// `Debug`: it holds the plaintext code and verifier.
pub struct CodeRedeemRequest<'a> {
    pub code: &'a str,
    pub client_id: &'a str,
    pub redirect_uri: Option<&'a str>,
    pub verifier: Option<&'a str>,
    pub resource: Option<&'a str>,
}

/// `Issued` / `Replay` carry a `GrantRef` (the audit row names the owner): a
/// request that passed every check presented the code AND its verifier. Like
/// every `GrantRef`, it may only feed
/// `GrantOwner::holder` and audit attribution.
///
/// `Miss` / `Invalid`: the caller MUST NOT commit. Every CHECK fails before any
/// write, but one `Invalid` follows the `redeemed_at` mark (the grant's
/// deadline crossed its second between two statements), and only dropping the
/// transaction rolls that mark back. NO `Debug`: `Issued` holds `IssuedTokens`.
pub enum RedeemOutcome {
    Issued {
        grant: GrantRef,
        tokens: IssuedTokens,
    },
    Miss,
    Invalid,
    Replay {
        grant: GrantRef,
    },
}

/// The code exchange's decision. One read, then every check in a fixed order (code
/// live → grant live and admin id + created_at → client_id → redirect_uri byte
/// for byte → resource → verifier shape → S256 in constant time); ANY failure
/// returns `Invalid` before anything is written, so a wrong verifier never
/// consumes the code. Only then `redeemed_at`: already set → `Replay` (the
/// caller revokes the grant); else mark it and issue the pair.
pub fn redeem_code(
    tx: &Transaction<'_>,
    cfg: &McpOauthConfig,
    req: &CodeRedeemRequest<'_>,
) -> rusqlite::Result<RedeemOutcome> {
    let code_hash = tokens::hash(TokenKind::Code, req.code);
    let row = tx
        .query_row(REDEEM_SELECT, params![code_hash], |r| {
            Ok(CodeRow {
                grant_id: r.get(0)?,
                admin_id: r.get(1)?,
                client_id: r.get(2)?,
                redirect_uri: r.get(3)?,
                code_challenge: r.get(4)?,
                resource: r.get(5)?,
                redeemed: r.get(6)?,
                code_live: r.get(7)?,
                grant_live: r.get(8)?,
                admin_ok: r.get(9)?,
            })
        })
        .optional()?;
    let Some(row) = row else {
        return Ok(RedeemOutcome::Miss);
    };

    // ---- every check, in the order above; any failure returns BEFORE any write ----
    if !row.code_live || !row.grant_live || !row.admin_ok {
        return Ok(RedeemOutcome::Invalid);
    }
    if row.client_id != req.client_id {
        return Ok(RedeemOutcome::Invalid);
    }
    if req.redirect_uri != Some(row.redirect_uri.as_str()) {
        return Ok(RedeemOutcome::Invalid); // missing, or not byte-identical (port included)
    }
    if let Some(r) = req.resource
        && (!cfg.is_our_resource(r) || row.resource.as_deref().is_some_and(|stored| stored != r))
    {
        return Ok(RedeemOutcome::Invalid);
    }
    let Some(v) = req.verifier else {
        return Ok(RedeemOutcome::Invalid);
    };
    if !pkce::verifier_well_formed(v) || !pkce::verify_s256(v, &row.code_challenge) {
        return Ok(RedeemOutcome::Invalid);
    }

    // ---- all checks passed: only from here on may anything be written ----
    let grant = GrantRef {
        grant_id: row.grant_id,
        admin_id: row.admin_id,
    };
    if row.redeemed {
        return Ok(RedeemOutcome::Replay { grant }); // the caller revokes, in this tx
    }
    if tx.execute(REDEEM_MARK, params![code_hash])? != 1 {
        // The SQL gate itself (pinned by `redeem_mark_is_itself_a_single_use_gate`).
        // Not reachable while the handler holds the meta mutex for the whole
        // read-mark-issue sequence.
        return Ok(RedeemOutcome::Invalid);
    }
    let tokens = match issue_token_pair(tx, cfg, row.grant_id, None) {
        Ok(t) => t,
        // The grant's idle/absolute deadline crossed its second between
        // REDEEM_SELECT and ISSUE_REFRESH. The mark above is in this tx; the
        // caller drops it (rollback).
        Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(RedeemOutcome::Invalid),
        Err(e) => return Err(e),
    };
    Ok(RedeemOutcome::Issued { grant, tokens })
}

// ─── Refresh rotation (the state machine is refresh::rotate) ─────────────────

/// Revokes ONE refresh and the access rows whose refresh_id is it; stamps
/// grants.sibling_rejected_at; the grant itself stays live. Returns the number of refresh
/// rows revoked (0 or 1). No GrantOwner: the only caller (refresh::rotate) passes ids read
/// from the presented token's own row in the same transaction — never from request input.
/// pub(crate) on purpose: a handler outside this crate's MCP module must not be able to
/// call it with ids taken from a request.
#[must_use = "0 means the branch was already revoked; the caller reports branch_revoked from it"]
pub(crate) fn revoke_mcp_refresh_branch(
    tx: &rusqlite::Transaction<'_>,
    grant_id: i64,
    refresh_id: i64,
) -> rusqlite::Result<usize> {
    let n = tx.execute(
        "UPDATE _mcp_oauth_refresh \
            SET revoked_at = datetime('now'), revoke_reason = 'sibling_superseded' \
          WHERE id = ?1 AND grant_id = ?2 AND revoked_at IS NULL",
        rusqlite::params![refresh_id, grant_id],
    )?;
    tx.execute(
        "UPDATE _mcp_oauth_access SET revoked_at = datetime('now') \
          WHERE refresh_id = ?1 AND grant_id = ?2 AND revoked_at IS NULL",
        rusqlite::params![refresh_id, grant_id],
    )?;
    // Stamp only a grant that really owns this refresh (a mismatched pair touches nothing).
    tx.execute(
        "UPDATE _mcp_oauth_grants SET sibling_rejected_at = datetime('now') \
          WHERE id = ?1 \
            AND EXISTS (SELECT 1 FROM _mcp_oauth_refresh WHERE id = ?2 AND grant_id = ?1)",
        rusqlite::params![grant_id, refresh_id],
    )?;
    Ok(n)
}

/// One snapshot of everything `refresh::rotate` decides on, read once inside
/// its transaction. Holds no credential (ids, booleans and the grant's public
/// `client_id` only).
pub(crate) struct RefreshState {
    pub(crate) refresh_id: i64,
    pub(crate) grant_id: i64,
    pub(crate) parent_id: Option<i64>,
    pub(crate) rotated: bool,
    pub(crate) superseded: bool,
    /// Not revoked, not expired.
    pub(crate) token_live: bool,
    /// The grant's owner (audit extra, R10); NOT the presenter.
    pub(crate) admin_id: i64,
    /// The grant's.
    pub(crate) client_id: String,
    /// Not revoked, idle and absolute not passed.
    pub(crate) grant_live: bool,
    /// The admins row matches BOTH id and created_at.
    pub(crate) admin_ok: bool,
    /// Rotated AND datetime(rotated_at, grace) > now.
    pub(crate) in_grace: bool,
    pub(crate) child_rotated: bool,
    /// None when not rotated (audit only, R10; never part of a decision).
    pub(crate) rotated_secs_ago: Option<i64>,
    /// S3: Some ONLY when rotated && !superseded && token_live && grant_live && admin_ok —
    /// decided in Rust from the booleans above, no extra SQL. Used only on branch e).
    pub(crate) holder: Option<GrantRef>,
}

/// The INNER JOIN on grants means a refresh whose grant row is gone (FK off)
/// is `None`: a child row never vouches for itself. The admins match is a
/// column (`admin_ok`) because `holder` depends on it; a mismatch is refused
/// by branch a). Booleans are computed in SQL so every time comparison uses
/// SQLite's `datetime('now')` (datetime() text, see the DDL header).
const LOAD_REFRESH_FOR_ROTATE: &str = "\
SELECT r.id,
       r.grant_id,
       r.parent_id,
       r.rotated_at IS NOT NULL,
       r.superseded_at IS NOT NULL,
       (r.revoked_at IS NULL AND r.expires_at > datetime('now')),
       g.admin_id,
       g.client_id,
       (g.revoked_at IS NULL
        AND g.idle_expires_at     > datetime('now')
        AND g.absolute_expires_at > datetime('now')),
       EXISTS (SELECT 1 FROM admins ad
                WHERE ad.id = g.admin_id AND ad.created_at = g.admin_created_at),
       (r.rotated_at IS NOT NULL AND datetime(r.rotated_at, ?2) > datetime('now')),
       EXISTS (SELECT 1 FROM _mcp_oauth_refresh c
                WHERE c.grant_id = r.grant_id AND c.parent_id = r.id
                  AND c.rotated_at IS NOT NULL),
       CAST(strftime('%s','now') AS INTEGER) - CAST(strftime('%s', r.rotated_at) AS INTEGER)
  FROM _mcp_oauth_refresh r
  JOIN _mcp_oauth_grants g ON g.id = r.grant_id
 WHERE r.token_hash = ?1";

/// `presented_hash` = `tokens::hash(TokenKind::Refresh, token)`;
/// `grace_modifier` is a SQLite datetime modifier such as `"+60 seconds"`.
/// `None` when no refresh row with that hash has a grant row.
pub(crate) fn load_refresh_for_rotate(
    conn: &Connection,
    presented_hash: &str,
    grace_modifier: &str,
) -> rusqlite::Result<Option<RefreshState>> {
    let st = conn
        .query_row(
            LOAD_REFRESH_FOR_ROTATE,
            params![presented_hash, grace_modifier],
            |r| {
                Ok(RefreshState {
                    refresh_id: r.get(0)?,
                    grant_id: r.get(1)?,
                    parent_id: r.get(2)?,
                    rotated: r.get(3)?,
                    superseded: r.get(4)?,
                    token_live: r.get(5)?,
                    admin_id: r.get(6)?,
                    client_id: r.get(7)?,
                    grant_live: r.get(8)?,
                    admin_ok: r.get(9)?,
                    in_grace: r.get(10)?,
                    child_rotated: r.get(11)?,
                    rotated_secs_ago: r.get(12)?,
                    holder: None,
                })
            },
        )
        .optional()?;
    Ok(st.map(|mut s| {
        if s.rotated && !s.superseded && s.token_live && s.grant_live && s.admin_ok {
            s.holder = Some(GrantRef {
                grant_id: s.grant_id,
                admin_id: s.admin_id,
            });
        }
        s
    }))
}

fn find(
    conn: &Connection,
    kind: TokenKind,
    sql: &str,
    token: &str,
) -> rusqlite::Result<Option<GrantRef>> {
    // Wrong prefix or length: answer without touching SQL.
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

// ─── test token minting (debug builds and tests only) ───────────────────────
//
// Integration tests are another crate and cannot see cfg(test); a debug build
// can see debug_assertions, so these exist there too. Release builds do not
// have them. No production code in src/ may call them (pinned by
// seed_helpers_have_no_production_caller). Call them before `conn` is wrapped
// in its `Arc<Mutex<_>>`, or while holding that lock.

/// A seeded grant's id and its plaintext tokens. NO `Debug`: the fields are
/// live plaintext credentials (pinned by `credential_types_do_not_derive_debug`).
#[cfg(any(test, debug_assertions))]
pub struct SeededAccess {
    pub grant_id: i64,
    pub access: String,
    pub refresh: String,
    pub refresh_id: i64,
}

/// One live grant for `admin_id` (the first known client, redirect host
/// `localhost`, idle +30 days, absolute +90 days, `last_used_at` NULL) plus
/// [`seed_tokens_for_tests`] on it. A missing admin is
/// `Err(QueryReturnedNoRows)` with nothing written.
#[cfg(any(test, debug_assertions))]
pub fn seed_access_for_tests(conn: &Connection, admin_id: i64) -> rusqlite::Result<SeededAccess> {
    let n = conn.execute(
        "INSERT INTO _mcp_oauth_grants \
           (admin_id, admin_created_at, client_id, redirect_host, \
            idle_expires_at, absolute_expires_at) \
         SELECT a.id, a.created_at, ?2, 'localhost', \
                datetime('now', '+30 days'), datetime('now', '+90 days') \
           FROM admins a WHERE a.id = ?1",
        params![
            admin_id,
            crate::mgmt::mcp_oauth::clients::KNOWN_CLIENTS[0].client_id
        ],
    )?;
    if n == 0 {
        return Err(rusqlite::Error::QueryReturnedNoRows);
    }
    seed_tokens_for_tests(conn, conn.last_insert_rowid())
}

/// One root refresh (`parent_id` NULL, `expires_at` = the grant's
/// MIN(idle, absolute)) and one access pointing at it (+3600 s) for an EXISTING
/// grant, whatever its state: tests mint tokens under revoked and expired
/// grants on purpose. A missing grant is `Err(QueryReturnedNoRows)` with
/// nothing written.
#[cfg(any(test, debug_assertions))]
pub fn seed_tokens_for_tests(conn: &Connection, grant_id: i64) -> rusqlite::Result<SeededAccess> {
    let refresh = tokens::new_token(TokenKind::Refresh);
    let access = tokens::new_token(TokenKind::Access);
    let n = conn.execute(
        "INSERT INTO _mcp_oauth_refresh (grant_id, parent_id, token_hash, expires_at) \
         SELECT id, NULL, ?2, MIN(idle_expires_at, absolute_expires_at) \
           FROM _mcp_oauth_grants WHERE id = ?1",
        params![grant_id, tokens::hash(TokenKind::Refresh, &refresh)],
    )?;
    if n == 0 {
        return Err(rusqlite::Error::QueryReturnedNoRows);
    }
    let refresh_id = conn.last_insert_rowid();
    conn.execute(
        "INSERT INTO _mcp_oauth_access (token_hash, grant_id, refresh_id, expires_at) \
         VALUES (?1, ?2, ?3, datetime('now', '+3600 seconds'))",
        params![
            tokens::hash(TokenKind::Access, &access),
            grant_id,
            refresh_id
        ],
    )?;
    Ok(SeededAccess {
        grant_id,
        access,
        refresh,
        refresh_id,
    })
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

    /// A real meta.sqlite (open_meta creates the MCP OAuth tables) with one
    /// admin and one grant; returns the connection and the grant id.
    fn meta_with_grant(dir: &std::path::Path) -> (Connection, i64) {
        let conn = crate::storage::meta::open_meta(&dir.join("meta.sqlite")).unwrap();
        conn.execute(
            "INSERT INTO admins (username, password_hash) VALUES ('root', '$oauth-only$')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO _mcp_oauth_grants \
               (admin_id, admin_created_at, client_id, redirect_host, \
                idle_expires_at, absolute_expires_at) \
             SELECT id, created_at, 'c', 'localhost', \
                    datetime('now', '+30 days'), datetime('now', '+90 days') FROM admins",
            [],
        )
        .unwrap();
        let g = conn.last_insert_rowid();
        (conn, g)
    }

    fn seed_code_row(conn: &Connection, grant_id: i64, code: &str, expires: &str) -> String {
        let h = tokens::hash(TokenKind::Code, code);
        conn.execute(
            "INSERT INTO _mcp_oauth_codes \
               (code_hash, grant_id, client_id, redirect_uri, code_challenge, expires_at) \
             VALUES (?1, ?2, 'c', 'http://localhost:1/callback', 'x', datetime('now', ?3))",
            params![h, grant_id, expires],
        )
        .unwrap();
        h
    }

    /// Single use does not rest on the handler's meta mutex alone: the MARK
    /// statement itself refuses a second redemption and an expired code.
    #[test]
    fn redeem_mark_is_itself_a_single_use_gate() {
        let dir = tempfile::tempdir().unwrap();
        let (conn, g) = meta_with_grant(dir.path());
        let live = seed_code_row(
            &conn,
            g,
            &tokens::new_token(TokenKind::Code),
            "+300 seconds",
        );
        assert_eq!(conn.execute(REDEEM_MARK, [&live]).unwrap(), 1, "first mark");
        assert_eq!(
            conn.execute(REDEEM_MARK, [&live]).unwrap(),
            0,
            "second mark"
        );
        let expired = seed_code_row(&conn, g, &tokens::new_token(TokenKind::Code), "-1 second");
        assert_eq!(
            conn.execute(REDEEM_MARK, [&expired]).unwrap(),
            0,
            "expired code"
        );
    }

    // ─── branch revoke and the rotate snapshot ───────────────────────────────

    fn cfg() -> McpOauthConfig {
        McpOauthConfig::for_tests("https://drust.test")
    }

    fn issue(conn: &Connection, gid: i64, parent: Option<i64>) -> IssuedTokens {
        let tx = conn.unchecked_transaction().unwrap();
        let t = issue_token_pair(&tx, &cfg(), gid, parent).unwrap();
        tx.commit().unwrap();
        t
    }

    fn second_grant(conn: &Connection) -> i64 {
        conn.execute(
            "INSERT INTO _mcp_oauth_grants \
               (admin_id, admin_created_at, client_id, redirect_host, \
                idle_expires_at, absolute_expires_at) \
             SELECT id, created_at, 'c', 'localhost', \
                    datetime('now', '+30 days'), datetime('now', '+90 days') FROM admins",
            [],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    /// (refresh revoked_at, revoke_reason, access revoked_at) for one pair.
    fn pair_state(
        conn: &Connection,
        t: &IssuedTokens,
    ) -> (Option<String>, Option<String>, Option<String>) {
        let (rr, reason): (Option<String>, Option<String>) = conn
            .query_row(
                "SELECT revoked_at, revoke_reason FROM _mcp_oauth_refresh WHERE id = ?1",
                params![t.refresh_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        let ar: Option<String> = conn
            .query_row(
                "SELECT revoked_at FROM _mcp_oauth_access WHERE token_hash = ?1",
                params![tokens::hash(TokenKind::Access, &t.access_token)],
                |r| r.get(0),
            )
            .unwrap();
        (rr, reason, ar)
    }

    /// (sibling_rejected_at, revoked_at) of a grant.
    fn grant_marks(conn: &Connection, gid: i64) -> (Option<String>, Option<String>) {
        conn.query_row(
            "SELECT sibling_rejected_at, revoked_at FROM _mcp_oauth_grants WHERE id = ?1",
            params![gid],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap()
    }

    fn branch_revoke(conn: &Connection, gid: i64, refresh_id: i64) -> usize {
        let tx = conn.unchecked_transaction().unwrap();
        let n = revoke_mcp_refresh_branch(&tx, gid, refresh_id).unwrap();
        tx.commit().unwrap();
        n
    }

    /// U1. Two siblings, each with its access: one branch revoke cuts exactly
    /// one refresh and the access issued with it.
    #[test]
    fn branch_revoke_touches_one_refresh_and_its_access_only() {
        let dir = tempfile::tempdir().unwrap();
        let (conn, g) = meta_with_grant(dir.path());
        let root = issue(&conn, g, None);
        let s1 = issue(&conn, g, Some(root.refresh_id));
        let s2 = issue(&conn, g, Some(root.refresh_id));
        assert_eq!(branch_revoke(&conn, g, s1.refresh_id), 1);
        let (rr, reason, ar) = pair_state(&conn, &s1);
        assert!(rr.is_some() && ar.is_some(), "S1 and its access revoked");
        assert_eq!(reason.as_deref(), Some("sibling_superseded"));
        assert_eq!(pair_state(&conn, &s2), (None, None, None), "S2 untouched");
        assert_eq!(
            pair_state(&conn, &root),
            (None, None, None),
            "root untouched"
        );
        let (sib, revoked) = grant_marks(&conn, g);
        assert!(sib.is_some(), "sibling_rejected_at stamped");
        assert!(revoked.is_none(), "the grant stays live");
    }

    /// U2.
    #[test]
    fn branch_revoke_twice_returns_zero() {
        let dir = tempfile::tempdir().unwrap();
        let (conn, g) = meta_with_grant(dir.path());
        let root = issue(&conn, g, None);
        let s1 = issue(&conn, g, Some(root.refresh_id));
        assert_eq!(branch_revoke(&conn, g, s1.refresh_id), 1);
        let after_first = pair_state(&conn, &s1);
        assert_eq!(branch_revoke(&conn, g, s1.refresh_id), 0);
        assert_eq!(pair_state(&conn, &s1), after_first, "nothing moves again");
    }

    /// U3. Every UPDATE binds grant_id: another grant's id with S1's refresh
    /// id revokes nothing and stamps nothing.
    #[test]
    fn branch_revoke_with_a_mismatched_grant_is_a_no_op() {
        let dir = tempfile::tempdir().unwrap();
        let (conn, g1) = meta_with_grant(dir.path());
        let g2 = second_grant(&conn);
        let s1 = issue(&conn, g1, None);
        assert_eq!(branch_revoke(&conn, g2, s1.refresh_id), 0);
        assert_eq!(pair_state(&conn, &s1), (None, None, None), "S1 untouched");
        assert_eq!(grant_marks(&conn, g2), (None, None), "G2 not stamped");
        assert_eq!(grant_marks(&conn, g1), (None, None), "G1 not stamped");
    }

    /// S3. The snapshot's `holder` (the only GrantRef refresh rotation can hand to
    /// GrantOwner::holder) exists only for a rotated, unsuperseded, live
    /// refresh of a live grant whose admin still matches.
    #[test]
    fn holder_is_none_unless_rotated_and_live() {
        let cases: [(&str, &str, bool); 6] = [
            ("not rotated", "", false),
            (
                "superseded",
                "UPDATE _mcp_oauth_refresh SET superseded_at = datetime('now')",
                false,
            ),
            (
                "revoked",
                "UPDATE _mcp_oauth_refresh SET rotated_at = datetime('now'), \
                 revoked_at = datetime('now')",
                false,
            ),
            (
                "grant expired",
                "UPDATE _mcp_oauth_refresh SET rotated_at = datetime('now'); \
                 UPDATE _mcp_oauth_grants SET idle_expires_at = datetime('now', '-1 minute')",
                false,
            ),
            (
                "admin mismatch",
                "UPDATE _mcp_oauth_refresh SET rotated_at = datetime('now'); \
                 UPDATE admins SET created_at = '2000-01-01 00:00:00'",
                false,
            ),
            (
                "rotated and live",
                "UPDATE _mcp_oauth_refresh SET rotated_at = datetime('now')",
                true,
            ),
        ];
        for (label, pre, want) in cases {
            let dir = tempfile::tempdir().unwrap();
            let (conn, g) = meta_with_grant(dir.path());
            let t = issue(&conn, g, None);
            if !pre.is_empty() {
                conn.execute_batch(pre).unwrap();
            }
            let st = load_refresh_for_rotate(
                &conn,
                &tokens::hash(TokenKind::Refresh, &t.refresh_token),
                "+60 seconds",
            )
            .unwrap()
            .unwrap_or_else(|| panic!("{label}: row not found"));
            assert_eq!(st.holder.is_some(), want, "{label}");
            if let Some(h) = &st.holder {
                assert_eq!((h.grant_id(), h.admin_id()), (g, st.admin_id), "{label}");
            }
        }
    }

    /// A child row never vouches for itself: no grant row, no snapshot.
    #[test]
    fn load_refresh_for_rotate_needs_the_grant_row() {
        let dir = tempfile::tempdir().unwrap();
        let (conn, g) = meta_with_grant(dir.path());
        let t = issue(&conn, g, None);
        conn.execute_batch(&format!(
            "PRAGMA foreign_keys = OFF; DELETE FROM _mcp_oauth_grants WHERE id = {g}; \
             PRAGMA foreign_keys = ON;"
        ))
        .unwrap();
        let st = load_refresh_for_rotate(
            &conn,
            &tokens::hash(TokenKind::Refresh, &t.refresh_token),
            "+60 seconds",
        )
        .unwrap();
        assert!(st.is_none());
    }

    /// The text between the end of the previous item (`}` or `;`) and `head`:
    /// where a `#[derive(..)]` for that item would have to be.
    fn attrs_before<'a>(prod: &'a str, head: &str) -> &'a str {
        let at = prod
            .find(head)
            .unwrap_or_else(|| panic!("`{head}` not found in store.rs production code"));
        let from = prod[..at].rfind(['}', ';']).map_or(0, |i| i + 1);
        &prod[from..at]
    }

    /// These types hold a plaintext code + verifier or plaintext tokens; a
    /// `Debug` impl is one `{:?}` away from putting a live credential in a log.
    /// Tests use `matches!` (unwrap_err/expect_err need `T: Debug`).
    #[test]
    fn credential_types_do_not_derive_debug() {
        use crate::tenant::rooms::srcpin::{code_only, production_half};
        let stripped = code_only(include_str!("store.rs"));
        let prod = production_half(&stripped);
        for (head, name) in [
            ("pub struct IssuedTokens", "IssuedTokens"),
            ("pub struct CodeRedeemRequest", "CodeRedeemRequest"),
            ("pub enum RedeemOutcome", "RedeemOutcome"),
            ("pub struct SeededAccess", "SeededAccess"),
        ] {
            assert!(
                !attrs_before(prod, head).contains("Debug"),
                "{name} must not derive Debug"
            );
            assert!(
                !prod.contains(&format!("Debug for {name}")),
                "{name} must not implement Debug"
            );
        }
    }

    // ─── authorization strength: AccessGrant ─────────────────────────────────

    /// The label is what consent and the existing audit rows use: email, else username.
    #[test]
    fn find_grant_by_access_carries_the_admin_label() {
        let dir = tempfile::tempdir().unwrap();
        let (conn, g) = meta_with_grant(dir.path());
        let admin: i64 = conn
            .query_row("SELECT id FROM admins WHERE username = 'root'", [], |r| {
                r.get(0)
            })
            .unwrap();
        let t = issue(&conn, g, None);
        let a = find_grant_by_access(&conn, &t.access_token)
            .unwrap()
            .expect("a live access token authorizes");
        assert_eq!((a.grant_id(), a.admin_id()), (g, admin));
        assert_eq!(a.admin_label(), "root", "no email: the username");
        conn.execute(
            "UPDATE admins SET email = 'root@example.test' WHERE id = ?1",
            params![admin],
        )
        .unwrap();
        let a = find_grant_by_access(&conn, &t.access_token)
            .unwrap()
            .unwrap();
        assert_eq!(a.admin_label(), "root@example.test");
    }

    /// No Clone (an authorization proof is not copied around), no Default (no
    /// placeholder grant), no Debug (it carries the account's email).
    #[test]
    fn access_grant_derives_nothing() {
        use crate::tenant::rooms::srcpin::{code_only, production_half};
        let stripped = code_only(include_str!("store.rs"));
        let prod = production_half(&stripped);
        assert!(
            !attrs_before(prod, "pub struct AccessGrant").contains("derive"),
            "AccessGrant must derive nothing"
        );
        for t in ["Clone", "Default", "Debug"] {
            assert!(
                !prod.contains(&format!("impl {t} for AccessGrant")),
                "AccessGrant must not implement {t}"
            );
        }
    }

    /// Field privacy only stops construction OUTSIDE this file; this pin stops
    /// a second construction inside it (a refresh, revocation or code path
    /// handing out an AccessGrant).
    #[test]
    fn access_grant_is_built_only_by_find_grant_by_access() {
        use crate::tenant::rooms::srcpin::{code_only, prod_fn_body, production_half};
        const WHY: &str = "an AccessGrant built outside find_grant_by_access bypasses the \
                           authorization-strength lookup";
        let stripped = code_only(include_str!("store.rs"));
        let prod = production_half(&stripped);
        // The three legitimate occurrences: the struct, its impl, the one literal.
        assert_eq!(
            prod.matches("pub struct AccessGrant {").count(),
            1,
            "anti-vacuous"
        );
        assert_eq!(
            prod.matches("impl AccessGrant {").count(),
            1,
            "anti-vacuous"
        );
        assert_eq!(prod.matches("AccessGrant {").count(), 3, "{WHY}");
        let find = prod_fn_body(&stripped, "pub fn find_grant_by_access(");
        assert_eq!(find.matches("AccessGrant {").count(), 1, "{WHY}");
        let methods = prod_fn_body(&stripped, "impl AccessGrant {");
        assert!(!methods.contains("Self"), "{WHY}");
    }

    #[test]
    fn touch_grant_last_used_is_throttled_to_60_seconds() {
        let dir = tempfile::tempdir().unwrap();
        let (conn, g) = meta_with_grant(dir.path());
        let other = second_grant(&conn);
        let t = issue(&conn, g, None);
        let a = find_grant_by_access(&conn, &t.access_token)
            .unwrap()
            .expect("a live access token authorizes");
        let last = |c: &Connection, id: i64| -> Option<String> {
            c.query_row(
                "SELECT last_used_at FROM _mcp_oauth_grants WHERE id = ?1",
                params![id],
                |r| r.get(0),
            )
            .unwrap()
        };
        let set = |c: &Connection, m: &str| {
            c.execute(
                "UPDATE _mcp_oauth_grants SET last_used_at = datetime('now', ?2) WHERE id = ?1",
                params![g, m],
            )
            .unwrap();
        };
        // issue_token_pair stamps last_used_at; start from a never-used grant.
        conn.execute(
            "UPDATE _mcp_oauth_grants SET last_used_at = NULL WHERE id = ?1",
            params![g],
        )
        .unwrap();
        assert_eq!(last(&conn, g), None);
        assert_eq!(
            touch_grant_last_used(&conn, &a).unwrap(),
            1,
            "first use writes"
        );
        assert!(last(&conn, g).is_some());
        assert_eq!(
            touch_grant_last_used(&conn, &a).unwrap(),
            0,
            "again at once: no write"
        );
        set(&conn, "-59 seconds");
        assert_eq!(
            touch_grant_last_used(&conn, &a).unwrap(),
            0,
            "59 s ago: inside the window"
        );
        set(&conn, "-61 seconds");
        assert_eq!(
            touch_grant_last_used(&conn, &a).unwrap(),
            1,
            "61 s ago: writes again"
        );
        assert_eq!(
            last(&conn, other),
            None,
            "only the authorized grant is touched"
        );
    }

    // ─── test token minting ──────────────────────────────────────────────────

    #[test]
    fn seed_access_for_tests_yields_an_authorizing_token() {
        let dir = tempfile::tempdir().unwrap();
        let (conn, _) = meta_with_grant(dir.path());
        let admin: i64 = conn
            .query_row("SELECT id FROM admins WHERE username = 'root'", [], |r| {
                r.get(0)
            })
            .unwrap();
        let s = seed_access_for_tests(&conn, admin).unwrap();
        let a = find_grant_by_access(&conn, &s.access)
            .unwrap()
            .expect("seeded access authorizes");
        assert_eq!((a.grant_id(), a.admin_id()), (s.grant_id, admin));
        let r = find_grant_by_refresh(&conn, &s.refresh)
            .unwrap()
            .expect("seeded refresh is live");
        assert_eq!(r.grant_id(), s.grant_id);
        let (rid, client, last): (i64, String, Option<String>) = conn
            .query_row(
                "SELECT a.refresh_id, g.client_id, g.last_used_at \
                   FROM _mcp_oauth_access a JOIN _mcp_oauth_grants g ON g.id = a.grant_id \
                  WHERE a.token_hash = ?1",
                params![tokens::hash(TokenKind::Access, &s.access)],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(rid, s.refresh_id);
        assert_eq!(
            client,
            crate::mgmt::mcp_oauth::clients::KNOWN_CLIENTS[0].client_id
        );
        assert_eq!(last, None, "a seeded grant was never used");
    }

    #[test]
    fn seed_access_for_tests_refuses_a_missing_admin() {
        let dir = tempfile::tempdir().unwrap();
        let (conn, _) = meta_with_grant(dir.path());
        let before: i64 = conn
            .query_row("SELECT COUNT(*) FROM _mcp_oauth_grants", [], |r| r.get(0))
            .unwrap();
        assert!(matches!(
            seed_access_for_tests(&conn, 999_999),
            Err(rusqlite::Error::QueryReturnedNoRows)
        ));
        let after: i64 = conn
            .query_row("SELECT COUNT(*) FROM _mcp_oauth_grants", [], |r| r.get(0))
            .unwrap();
        assert_eq!(before, after, "no grant bound to a missing admin");
    }

    /// Tests seed tokens under revoked and expired grants on purpose.
    #[test]
    fn seed_tokens_for_tests_does_not_check_liveness() {
        let dir = tempfile::tempdir().unwrap();
        let (conn, g) = meta_with_grant(dir.path());
        conn.execute(
            "UPDATE _mcp_oauth_grants SET revoked_at = datetime('now'), revoke_reason = 'user'",
            [],
        )
        .unwrap();
        let s = seed_tokens_for_tests(&conn, g).unwrap();
        assert_eq!(s.grant_id, g);
        let minted: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM _mcp_oauth_access WHERE token_hash = ?1 AND grant_id = ?2",
                params![tokens::hash(TokenKind::Access, &s.access), g],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(minted, 1, "minted under a revoked grant");
        assert!(
            find_grant_by_access(&conn, &s.access).unwrap().is_none(),
            "dead grant"
        );
        assert!(matches!(
            seed_tokens_for_tests(&conn, g + 1000),
            Err(rusqlite::Error::QueryReturnedNoRows)
        ));
    }

    /// The seed helpers exist in debug builds too (integration tests are
    /// another crate and cannot see cfg(test)); no production code path, in a
    /// debug build or otherwise, may mint tokens through them.
    #[test]
    fn seed_helpers_have_no_production_caller() {
        use crate::tenant::rooms::srcpin::{code_only, collect_rs_files, production_half};
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        collect_rs_files(&root, &mut files);
        assert!(
            files.len() > 100,
            "the walk found only {} files",
            files.len()
        );
        let mut defining = 0;
        for f in &files {
            let src = std::fs::read_to_string(f).unwrap();
            let stripped = code_only(&src);
            let prod = production_half(&stripped);
            if f.ends_with("mgmt/mcp_oauth/store.rs") {
                defining += 1;
                assert!(
                    prod.contains("pub fn seed_access_for_tests("),
                    "anti-vacuous"
                );
                assert!(
                    prod.contains("pub fn seed_tokens_for_tests("),
                    "anti-vacuous"
                );
                continue;
            }
            for needle in ["seed_access_for_tests", "seed_tokens_for_tests"] {
                assert!(
                    !prod.contains(needle),
                    "{}: {needle} is test-only and must not be called from production code",
                    f.display()
                );
            }
        }
        assert_eq!(defining, 1, "store.rs was not among the walked files");
    }
}
