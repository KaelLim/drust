//! The refresh_token grant's state machine.
//!
//! Five branches, decided in order inside the caller's transaction, under the meta mutex:
//!   a) dead / foreign      -> Err(InvalidGrant), writes nothing
//!   b) superseded sibling  -> revoke THIS branch only (sibling_superseded) -> RejectedSibling
//!   c) first use           -> rotate, supersede the other siblings, slide idle, issue -> Issued
//!   d) rotated, in grace   -> d-1 a child already rotated: stamp sibling_rejected_at -> RejectedSibling
//!                             d-2 otherwise: issue a SIBLING, invalidate nothing      -> Issued
//!   e) rotated, past grace -> reuse: revoke the whole grant (refresh_reuse)          -> RejectedReuse
//!
//! ORDER: b) before c) is load-bearing. A superseded row has rotated_at IS NULL, so checking
//! c) first would send a losing sibling into "first use" (mark_rotated then refuses it and the
//! tx rolls back, but the branch is never cut). b) vs d)/e) is exclusive and order-free.
//!
//! DELIBERATE deviation from the strict reading of OAuth 2.1 §4.3.1: inside the grace window
//! siblings coexist and the loser is cut alone (owner decision, 2026-11-14): several Claude
//! Code processes on one machine share one credential and race refreshes, and a grant revoke
//! would log every one of them out. Reuse past the grace still revokes the grant. Do not
//! "tighten" b) into a grant revoke without re-asking the owner.
//!
//! No cache, no bus, no clear_admin_pat: MCP tokens are read from their own tables on every
//! request and open no SSE or rooms stream (store.rs module doc). Never stringify a rusqlite error into a response,
//! and never put the presented token or its hash into tracing.

use rusqlite::{Connection, OptionalExtension, Transaction, params};

use crate::mgmt::mcp_oauth::config::McpOauthConfig;
use crate::mgmt::mcp_oauth::oauth_error_layer::OAuthError;
use crate::mgmt::mcp_oauth::store::{
    self, GrantOwner, IssuedTokens, RefreshState, RevokeReason, RevokedGrant,
};

/// R3. resource and scope are validated before the transaction (token.rs); only client_id
/// needs the grant row.
pub struct RefreshRequest<'a> {
    pub client_id: Option<&'a str>,
}

/// No Debug (IssuedTokens carries plaintext; pinned by
/// `rotate_outcome_does_not_derive_debug` below): tests use matches!.
pub enum RotateOutcome {
    Issued(IssuedTokens),
    /// R2. branch_revoked = false is d-1 (nothing revoked, only the grant stamped); in d-1
    /// refresh_id is the re-presented PARENT, not a sibling. admin_id = grant owner.
    RejectedSibling {
        grant_id: i64,
        refresh_id: i64,
        admin_id: i64,
        branch_revoked: bool,
    },
    /// R2. rotated_secs_ago lets an operator tell a laptop that slept past the grace
    /// (thousands of seconds) from a race or theft (just past the grace). revoked = false
    /// only if revoke_mcp_grant answered NotFound (unreachable; audit must not claim it).
    RejectedReuse {
        grant_id: i64,
        refresh_id: i64,
        admin_id: i64,
        rotated_secs_ago: Option<i64>,
        revoked: bool,
    },
}

/// The hit/miss probe under the lock: an unknown hash charges the caller's per-IP miss
/// budget, a known one never does. Ignores liveness on purpose — a revoked or rotated row is
/// a HIT. Which branches of a hit charge the grant's per_grant budget is `rotate`'s call:
/// the budget is read only after the snapshot has decided the branch, and the terminal
/// branches b) and e) never read it. Charged here, a known dead token could keep the bucket
/// full and turn the legitimate client's past-grace presentation (reuse, e) into a 429, so a
/// refresh-token thief would never be cut off.
pub(crate) fn lookup_grant_id(
    conn: &Connection,
    presented_hash: &str,
) -> rusqlite::Result<Option<i64>> {
    conn.query_row(
        "SELECT grant_id FROM _mcp_oauth_refresh WHERE token_hash = ?1",
        params![presented_hash],
        |r| r.get(0),
    )
    .optional()
}

/// `charge` reads the grant's per_grant budget; an `Err` (the 429) is returned as is, before
/// the branch writes anything. It is called exactly on the branches that need a bound:
/// a) (a flood of known dead tokens), c) and d-2) (they issue tokens) and d-1) (a stamp).
/// b) and e) never call it: each is terminal and self-limiting (b cuts one row once, e
/// revokes the grant once), and a full bucket must never stop them.
pub(crate) fn rotate(
    tx: &Transaction<'_>,
    cfg: &McpOauthConfig,
    presented_hash: &str,
    req: &RefreshRequest<'_>,
    charge: impl FnOnce() -> Result<(), OAuthError>,
) -> Result<RotateOutcome, OAuthError> {
    let grace = format!("+{} seconds", cfg.refresh_grace_secs());
    // Swept between lookup and tx is impossible under the mutex; fail closed anyway.
    // None is also a refresh whose grant row is gone (store's INNER JOIN): a dead token,
    // charged like a).
    let Some(st) = store::load_refresh_for_rotate(tx, presented_hash, &grace).map_err(db)? else {
        charge()?;
        return Err(OAuthError::InvalidGrant);
    };

    // a)
    if !st.token_live
        || !st.grant_live
        || !st.admin_ok
        || req.client_id.is_some_and(|c| c != st.client_id)
    {
        charge()?;
        return Err(OAuthError::InvalidGrant);
    }
    // b) — MUST stay before c): a superseded row also satisfies !st.rotated. Not charged.
    if st.superseded {
        let n = store::revoke_mcp_refresh_branch(tx, st.grant_id, st.refresh_id).map_err(db)?;
        return Ok(RotateOutcome::RejectedSibling {
            grant_id: st.grant_id,
            refresh_id: st.refresh_id,
            admin_id: st.admin_id,
            branch_revoked: n == 1,
        });
    }
    // c)
    if !st.rotated {
        charge()?;
        mark_rotated(tx, &st)?;
        supersede_siblings(tx, &st)?;
        slide_idle(tx, cfg, st.grant_id)?;
        return Ok(RotateOutcome::Issued(issue(tx, cfg, &st)?));
    }
    // d) — both arms charged.
    if st.in_grace {
        charge()?;
        if st.child_rotated {
            stamp_sibling_rejected(tx, st.grant_id)?;
            return Ok(RotateOutcome::RejectedSibling {
                grant_id: st.grant_id,
                refresh_id: st.refresh_id,
                admin_id: st.admin_id,
                branch_revoked: false,
            });
        }
        slide_idle(tx, cfg, st.grant_id)?;
        return Ok(RotateOutcome::Issued(issue(tx, cfg, &st)?));
    }
    // e) — not charged. holder is Some only for a rotated, live, admin-matching row (S3);
    // None is unreachable here (a) and b) returned already) and fails closed.
    let Some(holder) = st.holder.as_ref() else {
        return Err(OAuthError::InvalidGrant);
    };
    let revoked = match store::revoke_mcp_grant(
        tx,
        &GrantOwner::holder(holder),
        st.grant_id,
        RevokeReason::RefreshReuse,
    )
    .map_err(db)?
    {
        RevokedGrant::Revoked => true,
        // a) already proved the grant live under the same mutex; log, still reject.
        RevokedGrant::NotFound => {
            tracing::warn!(
                grant_id = st.grant_id,
                "mcp_oauth refresh: reuse revoke found no live grant"
            );
            false
        }
    };
    Ok(RotateOutcome::RejectedReuse {
        grant_id: st.grant_id,
        refresh_id: st.refresh_id,
        admin_id: st.admin_id,
        rotated_secs_ago: st.rotated_secs_ago,
        revoked,
    })
}

/// A child of the presented row. `QueryReturnedNoRows` is the grant's idle or
/// absolute deadline crossing its second between the snapshot and the INSERT:
/// `invalid_grant`, and the caller's rollback undoes this branch's writes.
fn issue(
    tx: &Transaction<'_>,
    cfg: &McpOauthConfig,
    st: &RefreshState,
) -> Result<IssuedTokens, OAuthError> {
    match store::issue_token_pair(tx, cfg, st.grant_id, Some(st.refresh_id)) {
        Ok(t) => Ok(t),
        Err(rusqlite::Error::QueryReturnedNoRows) => Err(OAuthError::InvalidGrant),
        Err(e) => Err(db(e)),
    }
}

fn db(e: rusqlite::Error) -> OAuthError {
    // Kind only, never the SQL text: no SQL or internal string reaches a log line or the
    // caller. Same shape as server_error in token.rs: error level, stage,
    // sqlite_error_without_sql.
    tracing::error!(
        stage = "refresh",
        err = %crate::error::sqlite_error_without_sql(&e),
        "mcp oauth token: meta error"
    );
    OAuthError::ServerError
}

fn mark_rotated(tx: &Transaction<'_>, st: &RefreshState) -> Result<(), OAuthError> {
    let n = tx
        .execute(
            "UPDATE _mcp_oauth_refresh SET rotated_at = datetime('now') \
              WHERE id = ?1 AND grant_id = ?2 \
                AND rotated_at IS NULL AND superseded_at IS NULL AND revoked_at IS NULL",
            params![st.refresh_id, st.grant_id],
        )
        .map_err(db)?;
    if n == 1 {
        Ok(())
    } else {
        Err(OAuthError::InvalidGrant) // rollback: state moved underneath
    }
}

fn supersede_siblings(tx: &Transaction<'_>, st: &RefreshState) -> Result<(), OAuthError> {
    tx.execute(
        "UPDATE _mcp_oauth_refresh SET superseded_at = datetime('now') \
          WHERE grant_id = ?1 AND parent_id IS ?2 AND id != ?3 \
            AND rotated_at IS NULL AND superseded_at IS NULL AND revoked_at IS NULL",
        params![st.grant_id, st.parent_id, st.refresh_id],
    )
    .map_err(db)?;
    Ok(()) // 0 rows is the normal case (no sibling was ever issued)
}

fn slide_idle(tx: &Transaction<'_>, cfg: &McpOauthConfig, grant_id: i64) -> Result<(), OAuthError> {
    let n = tx
        .execute(
            "UPDATE _mcp_oauth_grants \
                SET idle_expires_at = MIN(datetime('now', ?2), absolute_expires_at) \
              WHERE id = ?1 AND revoked_at IS NULL",
            params![grant_id, format!("+{} days", cfg.idle_days())],
        )
        .map_err(db)?;
    if n == 1 {
        Ok(())
    } else {
        Err(OAuthError::InvalidGrant)
    }
}

fn stamp_sibling_rejected(tx: &Transaction<'_>, grant_id: i64) -> Result<(), OAuthError> {
    tx.execute(
        "UPDATE _mcp_oauth_grants SET sibling_rejected_at = datetime('now') \
          WHERE id = ?1 AND revoked_at IS NULL",
        params![grant_id],
    )
    .map_err(db)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mgmt::mcp_oauth::tokens::{self, TokenKind};

    const CC: &str = "https://claude.ai/oauth/claude-code-client-metadata";

    fn cfg() -> McpOauthConfig {
        McpOauthConfig::for_tests("https://drust.test")
    }

    /// meta.sqlite with one admin and one live grant (30 / 90 days); returns
    /// the connection, the admin id and the grant id.
    fn setup(dir: &std::path::Path) -> (Connection, i64, i64) {
        let conn = crate::storage::meta::open_meta(&dir.join("meta.sqlite")).unwrap();
        conn.execute(
            "INSERT INTO admins (username, password_hash) VALUES ('u', 'x')",
            [],
        )
        .unwrap();
        let admin = conn.last_insert_rowid();
        let gid = add_grant(&conn, admin);
        (conn, admin, gid)
    }

    fn add_grant(conn: &Connection, admin: i64) -> i64 {
        conn.execute(
            "INSERT INTO _mcp_oauth_grants \
               (admin_id, admin_created_at, client_id, redirect_host, idle_expires_at, absolute_expires_at) \
             SELECT id, created_at, ?2, 'localhost', \
                    datetime('now','+30 days'), datetime('now','+90 days') \
               FROM admins WHERE id = ?1",
            params![admin, CC],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    /// A root refresh (and its access) issued through the production path.
    fn root(conn: &Connection, gid: i64) -> IssuedTokens {
        let tx = conn.unchecked_transaction().unwrap();
        let t = store::issue_token_pair(&tx, &cfg(), gid, None).unwrap();
        tx.commit().unwrap();
        t
    }

    fn h(token: &str) -> String {
        tokens::hash(TokenKind::Refresh, token)
    }

    /// One rotate in its own transaction, committed on Ok (as the handler does).
    fn run(conn: &Connection, token: &str) -> Result<RotateOutcome, OAuthError> {
        run_with(conn, token, None)
    }

    fn run_with(
        conn: &Connection,
        token: &str,
        client_id: Option<&str>,
    ) -> Result<RotateOutcome, OAuthError> {
        let tx = conn.unchecked_transaction().unwrap();
        let r = rotate(
            &tx,
            &cfg(),
            &h(token),
            &RefreshRequest { client_id },
            || Ok(()),
        );
        if r.is_ok() {
            tx.commit().unwrap();
        }
        r
    }

    fn issued(r: Result<RotateOutcome, OAuthError>) -> IssuedTokens {
        match r {
            Ok(RotateOutcome::Issued(t)) => t,
            Ok(_) => panic!("expected Issued, got another outcome"),
            Err(e) => panic!("expected Issued, got {e:?}"),
        }
    }

    fn age_rotation(conn: &Connection, refresh_id: i64, secs: i64) {
        conn.execute(
            "UPDATE _mcp_oauth_refresh SET rotated_at = datetime('now', ?2) WHERE id = ?1",
            params![refresh_id, format!("-{secs} seconds")],
        )
        .unwrap();
    }

    #[test]
    fn branch_a_writes_nothing() {
        let states: [(&str, &str, Option<&str>); 4] = [
            (
                "revoked",
                "UPDATE _mcp_oauth_refresh SET revoked_at = datetime('now')",
                None,
            ),
            (
                "expired",
                "UPDATE _mcp_oauth_refresh SET expires_at = datetime('now','-1 minute')",
                None,
            ),
            (
                "grant expired",
                "UPDATE _mcp_oauth_grants SET idle_expires_at = datetime('now','-1 minute')",
                None,
            ),
            (
                "client_id mismatch",
                "",
                Some("https://evil.example/c.json"),
            ),
        ];
        for (label, pre, client_id) in states {
            let dir = tempfile::tempdir().unwrap();
            let (conn, _admin, gid) = setup(dir.path());
            let t = root(&conn, gid);
            if !pre.is_empty() {
                conn.execute(pre, []).unwrap();
            }
            let tx = conn.unchecked_transaction().unwrap();
            let before = tx.total_changes();
            let r = rotate(
                &tx,
                &cfg(),
                &h(&t.refresh_token),
                &RefreshRequest { client_id },
                || Ok(()),
            );
            assert!(matches!(r, Err(OAuthError::InvalidGrant)), "{label}");
            assert_eq!(tx.total_changes(), before, "{label}: nothing written");
        }
    }

    /// The second layer of "b before c": even if c) ran first, a superseded
    /// row is never rotated.
    #[test]
    fn mark_rotated_refuses_a_superseded_row() {
        let dir = tempfile::tempdir().unwrap();
        let (conn, _admin, gid) = setup(dir.path());
        let t = root(&conn, gid);
        conn.execute(
            "UPDATE _mcp_oauth_refresh SET superseded_at = datetime('now') WHERE id = ?1",
            params![t.refresh_id],
        )
        .unwrap();
        let tx = conn.unchecked_transaction().unwrap();
        let st = store::load_refresh_for_rotate(&tx, &h(&t.refresh_token), "+60 seconds")
            .unwrap()
            .unwrap();
        assert!(st.superseded && !st.rotated);
        let before = tx.total_changes();
        assert!(matches!(
            mark_rotated(&tx, &st),
            Err(OAuthError::InvalidGrant)
        ));
        assert_eq!(tx.total_changes(), before);
    }

    /// c -> d-2 -> d-2 -> a sibling's c -> the loser's b -> d-1: a row is never
    /// both superseded and rotated, and a superseded row never has children.
    #[test]
    fn superseded_and_rotated_are_never_both_set() {
        let dir = tempfile::tempdir().unwrap();
        let (conn, _admin, gid) = setup(dir.path());
        let r1 = root(&conn, gid).refresh_token;
        let r2 = issued(run(&conn, &r1)).refresh_token; // c
        let r2b = issued(run(&conn, &r1)).refresh_token; // d-2
        let _r2c = issued(run(&conn, &r1)).refresh_token; // d-2
        issued(run(&conn, &r2)); // the sibling's c: supersedes r2b, r2c
        assert!(matches!(
            run(&conn, &r2b),
            Ok(RotateOutcome::RejectedSibling {
                branch_revoked: true,
                ..
            })
        ));
        assert!(matches!(
            run(&conn, &r1),
            Ok(RotateOutcome::RejectedSibling {
                branch_revoked: false,
                ..
            })
        ));
        let both: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM _mcp_oauth_refresh \
                  WHERE superseded_at IS NOT NULL AND rotated_at IS NOT NULL",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(both, 0);
        let superseded: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM _mcp_oauth_refresh WHERE superseded_at IS NOT NULL",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(superseded, 2, "the script really superseded two siblings");
        let children_of_losers: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM _mcp_oauth_refresh c \
                   JOIN _mcp_oauth_refresh p ON c.parent_id = p.id \
                  WHERE p.superseded_at IS NOT NULL",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(children_of_losers, 0);
    }

    #[test]
    fn outcome_variants_per_branch() {
        let dir = tempfile::tempdir().unwrap();
        let (conn, admin, gid) = setup(dir.path());

        // a)
        let r1 = root(&conn, gid);
        assert!(matches!(
            run_with(
                &conn,
                &r1.refresh_token,
                Some("https://evil.example/c.json")
            ),
            Err(OAuthError::InvalidGrant)
        ));
        // c)
        let r2 = issued(run(&conn, &r1.refresh_token));
        // d-2)
        let r2b = issued(run(&conn, &r1.refresh_token));
        // c) on R2 supersedes R2b; then b) on R2b
        issued(run(&conn, &r2.refresh_token));
        match run(&conn, &r2b.refresh_token) {
            Ok(RotateOutcome::RejectedSibling {
                grant_id,
                refresh_id,
                admin_id,
                branch_revoked,
            }) => {
                assert_eq!(
                    (grant_id, refresh_id, admin_id, branch_revoked),
                    (gid, r2b.refresh_id, admin, true)
                );
            }
            _ => panic!("b) must be RejectedSibling"),
        }
        // d-1): R1 again inside the grace, its child R2 already rotated
        match run(&conn, &r1.refresh_token) {
            Ok(RotateOutcome::RejectedSibling {
                grant_id,
                refresh_id,
                admin_id,
                branch_revoked,
            }) => {
                assert_eq!(
                    (grant_id, refresh_id, admin_id, branch_revoked),
                    (gid, r1.refresh_id, admin, false),
                    "d-1 names the re-presented parent"
                );
            }
            _ => panic!("d-1) must be RejectedSibling"),
        }
        // e): R1 past the grace
        age_rotation(&conn, r1.refresh_id, 61);
        match run(&conn, &r1.refresh_token) {
            Ok(RotateOutcome::RejectedReuse {
                grant_id,
                refresh_id,
                admin_id,
                rotated_secs_ago,
                revoked,
            }) => {
                assert_eq!(
                    (grant_id, refresh_id, admin_id, revoked),
                    (gid, r1.refresh_id, admin, true)
                );
                assert!(
                    rotated_secs_ago.is_some_and(|n| n >= 61),
                    "{rotated_secs_ago:?}"
                );
            }
            _ => panic!("e) must be RejectedReuse"),
        }
        let reason: Option<String> = conn
            .query_row(
                "SELECT revoke_reason FROM _mcp_oauth_grants WHERE id = ?1",
                params![gid],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(reason.as_deref(), Some("refresh_reuse"));
    }

    /// One rotate whose budget is exhausted: returns the outcome and whether
    /// the budget was read. Commits on Ok, like the handler.
    fn run_full_bucket(
        conn: &Connection,
        token: &str,
    ) -> (Result<RotateOutcome, OAuthError>, bool) {
        let read = std::cell::Cell::new(false);
        let tx = conn.unchecked_transaction().unwrap();
        let before = tx.total_changes();
        let r = rotate(
            &tx,
            &cfg(),
            &h(token),
            &RefreshRequest { client_id: None },
            || {
                read.set(true);
                Err(OAuthError::TemporarilyUnavailable {
                    retry_after_secs: 7,
                })
            },
        );
        if r.is_ok() {
            tx.commit().unwrap();
        } else {
            assert_eq!(
                tx.total_changes(),
                before,
                "a refused branch writes nothing"
            );
        }
        (r, read.get())
    }

    fn throttled(r: &Result<RotateOutcome, OAuthError>) -> bool {
        matches!(
            r,
            Err(OAuthError::TemporarilyUnavailable {
                retry_after_secs: 7
            })
        )
    }

    /// a), c), d-1) and d-2) read the budget and answer its 429 with nothing
    /// written; b) and e) never read it and still decide.
    #[test]
    fn only_the_bounded_branches_read_the_budget() {
        let dir = tempfile::tempdir().unwrap();
        let (conn, _admin, gid) = setup(dir.path());
        let r1 = root(&conn, gid);
        // c) refused, then really taken.
        let (r, read) = run_full_bucket(&conn, &r1.refresh_token);
        assert!(read && throttled(&r), "c) is charged");
        let r2 = issued(run(&conn, &r1.refresh_token));
        // d-2) refused, then really taken.
        let (r, read) = run_full_bucket(&conn, &r1.refresh_token);
        assert!(read && throttled(&r), "d-2) is charged");
        let r2b = issued(run(&conn, &r1.refresh_token));
        issued(run(&conn, &r2.refresh_token)); // c) on R2 supersedes R2b
        // d-1) refused.
        let (r, read) = run_full_bucket(&conn, &r1.refresh_token);
        assert!(read && throttled(&r), "d-1) is charged");
        // b) decides without reading.
        let (r, read) = run_full_bucket(&conn, &r2b.refresh_token);
        assert!(!read, "b) never reads the budget");
        assert!(matches!(
            r,
            Ok(RotateOutcome::RejectedSibling {
                branch_revoked: true,
                ..
            })
        ));
        // a) (the cut branch is dead now) refused.
        let (r, read) = run_full_bucket(&conn, &r2b.refresh_token);
        assert!(read && throttled(&r), "a) is charged");
        // e) decides without reading.
        age_rotation(&conn, r1.refresh_id, 61);
        let (r, read) = run_full_bucket(&conn, &r1.refresh_token);
        assert!(!read, "e) never reads the budget");
        assert!(matches!(
            r,
            Ok(RotateOutcome::RejectedReuse { revoked: true, .. })
        ));
    }

    #[test]
    fn lookup_grant_id_ignores_liveness() {
        let dir = tempfile::tempdir().unwrap();
        let (conn, _admin, gid) = setup(dir.path());
        let t = root(&conn, gid);
        conn.execute(
            "UPDATE _mcp_oauth_refresh SET revoked_at = datetime('now')",
            [],
        )
        .unwrap();
        assert_eq!(
            lookup_grant_id(&conn, &h(&t.refresh_token)).unwrap(),
            Some(gid),
            "a revoked row is a hit"
        );
        assert_eq!(
            lookup_grant_id(&conn, &h(&tokens::new_token(TokenKind::Refresh))).unwrap(),
            None
        );
    }

    /// RotateOutcome holds IssuedTokens (plaintext credentials).
    #[test]
    fn rotate_outcome_does_not_derive_debug() {
        use crate::tenant::rooms::srcpin::{code_only, production_half};
        let stripped = code_only(include_str!("refresh.rs"));
        let prod = production_half(&stripped);
        let at = prod.find("pub enum RotateOutcome").expect("RotateOutcome");
        let from = prod[..at].rfind(['}', ';']).map_or(0, |i| i + 1);
        assert!(
            !prod[from..at].contains("Debug"),
            "RotateOutcome must not derive Debug"
        );
        assert!(!prod.contains("Debug for RotateOutcome"));
    }
}
