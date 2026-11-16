//! MA0-3 — MCP OAuth revocation primitives, token lookups, the hourly sweep
//! and `remove_admin`'s explicit grant DELETE. Every test runs on
//! `fixture(false)` (DRUST_MCP off) unless it says otherwise: none of this is
//! gated on the switch.

use drust::auth::middleware::AdminId;
use drust::mgmt::mcp_oauth::store::{self, GrantOwner, GrantRef, RevokeReason, RevokedGrant};
use drust::mgmt::mcp_oauth::sweep::{SweepCounts, sweep_mcp_oauth};
use drust::mgmt::mcp_oauth::tokens::{self, TokenKind};
use rusqlite::params;

use crate::common::mcp_oauth::*;

const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const REDIRECT: &str = "http://localhost:4567/callback";

type Find = fn(&rusqlite::Connection, &str) -> rusqlite::Result<Option<GrantRef>>;

// ─── file-private helpers ────────────────────────────────────────────────────

/// A grant inside both deadlines.
fn live_grant(conn: &rusqlite::Connection, admin_id: i64) -> i64 {
    seed_grant(
        conn,
        &SeedGrant {
            admin_id,
            idle: "+30 days",
            absolute: "+90 days",
            revoked: false,
        },
    )
}

/// An upload ticket row (MA1b is the real writer; DDL frozen in MA0-2).
/// `expires` is a datetime modifier.
fn seed_ticket(conn: &rusqlite::Connection, grant_id: i64, expires: &str) -> String {
    let ticket = tokens::new_token(TokenKind::UploadTicket);
    let n = conn
        .execute(
            "INSERT INTO _mcp_upload_tickets (ticket_hash, grant_id, admin_id, tenant_id, \
               max_bytes, path, visibility, create_by, expires_at) \
             SELECT ?1, g.id, g.admin_id, 'blog', 1024, NULL, 'private', \
                    datetime('now', '+15 minutes'), datetime('now', ?2) \
               FROM _mcp_oauth_grants g WHERE g.id = ?3",
            params![
                tokens::hash(TokenKind::UploadTicket, &ticket),
                expires,
                grant_id
            ],
        )
        .unwrap();
    assert_eq!(n, 1, "seed_ticket: grant {grant_id} does not exist");
    ticket
}

/// lock -> unchecked_transaction -> f -> commit.
async fn with_tx<T>(fx: &McpOauthFixture, f: impl FnOnce(&rusqlite::Transaction<'_>) -> T) -> T {
    let conn = fx.meta.lock().await;
    let tx = conn.unchecked_transaction().unwrap();
    let out = f(&tx);
    tx.commit().unwrap();
    out
}

/// `UPDATE <table> SET <col> = datetime('now', ?1) WHERE <key_col> = ?2`;
/// the identifiers are test literals. Exactly one row must match.
fn age(
    conn: &rusqlite::Connection,
    table: &str,
    col: &str,
    key_col: &str,
    key: i64,
    modifier: &str,
) {
    let n = conn
        .execute(
            &format!("UPDATE {table} SET {col} = datetime('now', ?1) WHERE {key_col} = ?2"),
            params![modifier, key],
        )
        .unwrap();
    assert_eq!(n, 1, "age: {table}.{key_col} = {key} matched {n} rows");
}

fn revoke(
    tx: &rusqlite::Transaction<'_>,
    owner: &GrantOwner,
    grant_id: i64,
    reason: RevokeReason,
) -> RevokedGrant {
    store::revoke_mcp_grant(tx, owner, grant_id, reason).unwrap()
}

fn grant_reason(conn: &rusqlite::Connection, g: i64) -> Option<String> {
    conn.query_row(
        "SELECT revoke_reason FROM _mcp_oauth_grants WHERE id = ?1",
        params![g],
        |r| r.get(0),
    )
    .unwrap()
}

fn grant_revoked_at(conn: &rusqlite::Connection, g: i64) -> Option<String> {
    conn.query_row(
        "SELECT revoked_at FROM _mcp_oauth_grants WHERE id = ?1",
        params![g],
        |r| r.get(0),
    )
    .unwrap()
}

/// The grant and every refresh / access / ticket row under it are unrevoked,
/// and it still has at least one refresh and one access row.
fn assert_live_tree(conn: &rusqlite::Connection, g: i64) {
    assert_eq!(
        count(
            conn,
            &format!(
                "SELECT COUNT(*) FROM _mcp_oauth_grants WHERE id = {g} AND revoked_at IS NULL"
            )
        ),
        1,
        "grant {g} must be unrevoked"
    );
    for t in [
        "_mcp_oauth_refresh",
        "_mcp_oauth_access",
        "_mcp_upload_tickets",
    ] {
        assert_eq!(
            count(
                conn,
                &format!(
                    "SELECT COUNT(*) FROM {t} WHERE grant_id = {g} AND revoked_at IS NOT NULL"
                )
            ),
            0,
            "{t} rows of grant {g} must be unrevoked"
        );
    }
    for t in ["_mcp_oauth_refresh", "_mcp_oauth_access"] {
        assert!(
            count(
                conn,
                &format!("SELECT COUNT(*) FROM {t} WHERE grant_id = {g}")
            ) > 0,
            "{t} rows of grant {g} must still exist"
        );
    }
}

/// The grant and every refresh / access / ticket row under it are revoked.
fn assert_revoked_tree(conn: &rusqlite::Connection, g: i64) {
    assert!(
        grant_revoked_at(conn, g).is_some(),
        "grant {g} must be revoked"
    );
    for t in [
        "_mcp_oauth_refresh",
        "_mcp_oauth_access",
        "_mcp_upload_tickets",
    ] {
        assert_eq!(
            count(
                conn,
                &format!("SELECT COUNT(*) FROM {t} WHERE grant_id = {g} AND revoked_at IS NULL")
            ),
            0,
            "{t} rows of grant {g} must be revoked"
        );
    }
    assert_eq!(
        count(
            conn,
            &format!(
                "SELECT COUNT(*) FROM _mcp_oauth_codes WHERE grant_id = {g} AND redeemed_at IS NULL"
            )
        ),
        0,
        "unredeemed codes of grant {g} must be deleted"
    );
}

// ─── A. revoke_mcp_grant / revoke_all_mcp_grants ─────────────────────────────

#[tokio::test]
async fn revoke_with_another_admins_owner_is_not_found_and_changes_nothing() {
    let fx = fixture(false).await;
    let bob = add_admin(&fx, "bob", "", "member").await;
    let g = {
        let c = fx.meta.lock().await;
        let g = live_grant(&c, fx.owner_id);
        seed_tokens(&c, g);
        seed_code(&c, g, REDIRECT, CHALLENGE, None);
        seed_ticket(&c, g, "+1 hour");
        g
    };
    let out = with_tx(&fx, |tx| {
        revoke(
            tx,
            &GrantOwner::caller(&AdminId(bob)),
            g,
            RevokeReason::User,
        )
    })
    .await;
    assert_eq!(out, RevokedGrant::NotFound);
    let c = fx.meta.lock().await;
    assert_live_tree(&c, g);
    assert_eq!(
        count(
            &c,
            &format!("SELECT COUNT(*) FROM _mcp_upload_tickets WHERE grant_id = {g}")
        ),
        1
    );
    assert_eq!(
        count(
            &c,
            &format!("SELECT COUNT(*) FROM _mcp_oauth_codes WHERE grant_id = {g}")
        ),
        1,
        "the unredeemed code must still exist"
    );
}

#[tokio::test]
async fn revoke_unknown_grant_is_not_found() {
    let fx = fixture(false).await;
    let bob = add_admin(&fx, "bob", "", "member").await;
    let g = {
        let c = fx.meta.lock().await;
        let g = live_grant(&c, fx.owner_id);
        seed_tokens(&c, g);
        g
    };
    let (foreign, unknown) = with_tx(&fx, |tx| {
        let foreign = revoke(
            tx,
            &GrantOwner::caller(&AdminId(bob)),
            g,
            RevokeReason::User,
        );
        let unknown = revoke(
            tx,
            &GrantOwner::caller(&AdminId(fx.owner_id)),
            g + 1000,
            RevokeReason::User,
        );
        (foreign, unknown)
    })
    .await;
    // Absent and not-yours are ONE answer (one 404 on the management plane).
    assert_eq!(unknown, foreign);
    assert_eq!(unknown, RevokedGrant::NotFound);
    assert_live_tree(&*fx.meta.lock().await, g);
}

#[tokio::test]
async fn revoke_already_revoked_is_not_found_and_keeps_first_reason() {
    let fx = fixture(false).await;
    let g = {
        let c = fx.meta.lock().await;
        let g = live_grant(&c, fx.owner_id);
        seed_tokens(&c, g);
        g
    };
    let owner = GrantOwner::caller(&AdminId(fx.owner_id));
    let first = with_tx(&fx, |tx| revoke(tx, &owner, g, RevokeReason::User)).await;
    assert_eq!(first, RevokedGrant::Revoked);
    // Move the first revocation an hour back, so a rewrite in the same second
    // could not hide behind second-precision timestamps.
    let first_at = {
        let c = fx.meta.lock().await;
        age(&c, "_mcp_oauth_grants", "revoked_at", "id", g, "-1 hour");
        grant_revoked_at(&c, g).unwrap()
    };
    let second = with_tx(&fx, |tx| revoke(tx, &owner, g, RevokeReason::OauthRevoke)).await;
    assert_eq!(second, RevokedGrant::NotFound);
    let c = fx.meta.lock().await;
    assert_eq!(grant_reason(&c, g).as_deref(), Some("user"));
    assert_eq!(grant_revoked_at(&c, g), Some(first_at));
}

#[tokio::test]
async fn revoke_cascades_to_every_child_in_one_statement_time() {
    let fx = fixture(false).await;
    let (g, third_id) = {
        let c = fx.meta.lock().await;
        let g = live_grant(&c, fx.owner_id);
        seed_tokens(&c, g);
        seed_tokens(&c, g);
        let third = seed_tokens(&c, g);
        // An earlier per-branch revoke that a grant revoke must not overwrite.
        c.execute(
            "UPDATE _mcp_oauth_refresh SET revoked_at = datetime('now', '-1 hour'), \
               revoke_reason = 'sibling_superseded' WHERE id = ?1",
            params![third.refresh_id],
        )
        .unwrap();
        seed_code(&c, g, REDIRECT, CHALLENGE, None);
        let redeemed = seed_code(&c, g, REDIRECT, CHALLENGE, None);
        c.execute(
            "UPDATE _mcp_oauth_codes SET redeemed_at = datetime('now') WHERE code_hash = ?1",
            params![tokens::hash(TokenKind::Code, &redeemed)],
        )
        .unwrap();
        seed_ticket(&c, g, "+1 hour");
        (g, third.refresh_id)
    };
    let third_before: String = {
        let c = fx.meta.lock().await;
        c.query_row(
            "SELECT revoked_at FROM _mcp_oauth_refresh WHERE id = ?1",
            params![third_id],
            |r| r.get(0),
        )
        .unwrap()
    };

    let out = with_tx(&fx, |tx| {
        revoke(
            tx,
            &GrantOwner::caller(&AdminId(fx.owner_id)),
            g,
            RevokeReason::User,
        )
    })
    .await;
    assert_eq!(out, RevokedGrant::Revoked);

    let c = fx.meta.lock().await;
    assert_eq!(grant_reason(&c, g).as_deref(), Some("user"));
    assert_revoked_tree(&c, g);
    let (third_at, third_reason): (String, String) = c
        .query_row(
            "SELECT revoked_at, revoke_reason FROM _mcp_oauth_refresh WHERE id = ?1",
            params![third_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(third_reason, "sibling_superseded");
    assert_eq!(third_at, third_before, "the earlier branch revoke is kept");
    assert_eq!(
        count(
            &c,
            &format!(
                "SELECT COUNT(*) FROM _mcp_oauth_refresh WHERE grant_id = {g} \
                   AND id <> {third_id} AND revoke_reason = 'user'"
            )
        ),
        2
    );
    assert_eq!(
        count(
            &c,
            &format!(
                "SELECT COUNT(*) FROM _mcp_oauth_codes WHERE grant_id = {g} \
                   AND redeemed_at IS NOT NULL"
            )
        ),
        1,
        "a redeemed code stays until the sweep"
    );
    // One SQLite-generated instant across all five statements.
    let union = format!(
        "SELECT revoked_at AS t FROM _mcp_oauth_grants WHERE id = {g} \
         UNION ALL SELECT revoked_at FROM _mcp_oauth_refresh \
           WHERE grant_id = {g} AND revoke_reason <> 'sibling_superseded' \
         UNION ALL SELECT revoked_at FROM _mcp_oauth_access WHERE grant_id = {g} \
         UNION ALL SELECT revoked_at FROM _mcp_upload_tickets WHERE grant_id = {g}"
    );
    assert_eq!(
        count(
            &c,
            &format!("SELECT COUNT(*) FROM ({union}) WHERE t IS NULL")
        ),
        0
    );
    assert_eq!(
        count(&c, &format!("SELECT COUNT(*) FROM ({union})")),
        1 + 2 + 3 + 1
    );
    assert_eq!(
        count(&c, &format!("SELECT COUNT(DISTINCT t) FROM ({union})")),
        1,
        "every row of one revoke carries the same revoked_at"
    );
}

#[tokio::test]
async fn revoke_leaves_other_grants_alone() {
    let fx = fixture(false).await;
    let bob = add_admin(&fx, "bob", "", "member").await;
    let (g1, g2, g3) = {
        let c = fx.meta.lock().await;
        let g1 = live_grant(&c, fx.owner_id);
        let g2 = live_grant(&c, fx.owner_id);
        let g3 = live_grant(&c, bob);
        for g in [g1, g2, g3] {
            seed_tokens(&c, g);
            seed_ticket(&c, g, "+1 hour");
        }
        (g1, g2, g3)
    };
    let out = with_tx(&fx, |tx| {
        revoke(
            tx,
            &GrantOwner::caller(&AdminId(fx.owner_id)),
            g1,
            RevokeReason::User,
        )
    })
    .await;
    assert_eq!(out, RevokedGrant::Revoked);
    let c = fx.meta.lock().await;
    assert_revoked_tree(&c, g1);
    assert_live_tree(&c, g2);
    assert_live_tree(&c, g3);
}

#[tokio::test]
async fn revoke_runs_in_the_callers_transaction() {
    let fx = fixture(false).await;
    let g = {
        let c = fx.meta.lock().await;
        let g = live_grant(&c, fx.owner_id);
        seed_tokens(&c, g);
        seed_code(&c, g, REDIRECT, CHALLENGE, None);
        seed_ticket(&c, g, "+1 hour");
        g
    };
    {
        let c = fx.meta.lock().await;
        let tx = c.unchecked_transaction().unwrap();
        let out = revoke(
            &tx,
            &GrantOwner::caller(&AdminId(fx.owner_id)),
            g,
            RevokeReason::User,
        );
        assert_eq!(out, RevokedGrant::Revoked);
        drop(tx); // no commit: the function must not have committed either
    }
    let c = fx.meta.lock().await;
    assert_live_tree(&c, g);
    assert_eq!(
        count(
            &c,
            &format!("SELECT COUNT(*) FROM _mcp_oauth_codes WHERE grant_id = {g}")
        ),
        1
    );
}

#[tokio::test]
async fn revoke_an_expired_grant_still_revokes() {
    let fx = fixture(false).await;
    let g = {
        let c = fx.meta.lock().await;
        seed_grant(
            &c,
            &SeedGrant {
                admin_id: fx.owner_id,
                idle: "-1 hour",
                absolute: "+90 days",
                revoked: false,
            },
        )
    };
    let out = with_tx(&fx, |tx| {
        revoke(
            tx,
            &GrantOwner::caller(&AdminId(fx.owner_id)),
            g,
            RevokeReason::User,
        )
    })
    .await;
    assert_eq!(out, RevokedGrant::Revoked);
    assert_eq!(
        grant_reason(&*fx.meta.lock().await, g).as_deref(),
        Some("user")
    );
}

#[tokio::test]
async fn revoke_by_holder_from_a_token_lookup() {
    let fx = fixture(false).await;
    let (g, t) = {
        let c = fx.meta.lock().await;
        let g = live_grant(&c, fx.owner_id);
        (g, seed_tokens(&c, g))
    };
    let out = with_tx(&fx, |tx| {
        let r = store::find_grant_by_access(tx, &t.access)
            .unwrap()
            .expect("a live access token finds its grant");
        assert_eq!(r.grant_id(), g);
        assert_eq!(r.admin_id(), fx.owner_id);
        revoke(
            tx,
            &GrantOwner::holder(&r),
            r.grant_id(),
            RevokeReason::OauthRevoke,
        )
    })
    .await;
    assert_eq!(out, RevokedGrant::Revoked);
    let c = fx.meta.lock().await;
    assert!(
        store::find_grant_by_access(&c, &t.access)
            .unwrap()
            .is_none()
    );
    assert!(
        store::find_grant_by_refresh(&c, &t.refresh)
            .unwrap()
            .is_none()
    );
    assert_eq!(grant_reason(&c, g).as_deref(), Some("oauth_revoke"));
}

#[tokio::test]
async fn revoke_all_revokes_only_the_owners_live_grants() {
    let fx = fixture(false).await;
    let bob = add_admin(&fx, "bob", "", "member").await;
    let (g1, g2, g3, g4) = {
        let c = fx.meta.lock().await;
        let g1 = live_grant(&c, fx.owner_id);
        let g2 = live_grant(&c, fx.owner_id);
        let g3 = seed_grant(
            &c,
            &SeedGrant {
                admin_id: fx.owner_id,
                idle: "+30 days",
                absolute: "+90 days",
                revoked: true,
            },
        );
        let g4 = live_grant(&c, bob);
        for g in [g1, g2, g3, g4] {
            seed_tokens(&c, g);
        }
        (g1, g2, g3, g4)
    };
    let owner = GrantOwner::caller(&AdminId(fx.owner_id));
    let n = with_tx(&fx, |tx| {
        store::revoke_all_mcp_grants(tx, &owner, RevokeReason::UserAll).unwrap()
    })
    .await;
    assert_eq!(n, 2);
    {
        let c = fx.meta.lock().await;
        for g in [g1, g2] {
            assert_eq!(grant_reason(&c, g).as_deref(), Some("user_all"));
            assert_revoked_tree(&c, g);
        }
        assert_eq!(grant_reason(&c, g3).as_deref(), Some("user"));
        assert_live_tree(&c, g4);
    }
    let again = with_tx(&fx, |tx| {
        store::revoke_all_mcp_grants(tx, &owner, RevokeReason::UserAll).unwrap()
    })
    .await;
    assert_eq!(again, 0);
}

#[tokio::test]
async fn holder_cannot_revoke_a_sibling_grant_of_the_same_admin() {
    let fx = fixture(false).await;
    let (g1, g2, t1) = {
        let c = fx.meta.lock().await;
        let g1 = live_grant(&c, fx.owner_id);
        let g2 = live_grant(&c, fx.owner_id);
        let t1 = seed_tokens(&c, g1);
        seed_tokens(&c, g2);
        (g1, g2, t1)
    };
    with_tx(&fx, |tx| {
        let r = store::find_grant_by_access(tx, &t1.access)
            .unwrap()
            .expect("G1's access token finds G1");
        assert_eq!(r.grant_id(), g1);
        let holder = GrantOwner::holder(&r);
        assert_eq!(
            revoke(tx, &holder, g2, RevokeReason::OauthRevoke),
            RevokedGrant::NotFound,
            "a token of G1 proves G1 only"
        );
        assert_live_tree(tx, g2);
        let n = store::revoke_all_mcp_grants(tx, &holder, RevokeReason::OauthRevoke).unwrap();
        assert_eq!(n, 1, "a pinned holder reaches its own grant only");
        assert_revoked_tree(tx, g1);
        assert_live_tree(tx, g2);
        // Control: the unpinned caller owner does reach G2.
        assert_eq!(
            revoke(
                tx,
                &GrantOwner::caller(&AdminId(fx.owner_id)),
                g2,
                RevokeReason::User
            ),
            RevokedGrant::Revoked
        );
    })
    .await;
}

// ─── B. find_grant_by_access / find_grant_by_refresh / find_grant_for_revocation

#[tokio::test]
async fn find_with_wrong_prefix_or_length_touches_no_sql() {
    // No tables at all: any query that reached SQLite would be an Err.
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    let finds: [(&str, Find); 3] = [
        ("by_access", store::find_grant_by_access),
        ("by_refresh", store::find_grant_by_refresh),
        ("for_revocation", store::find_grant_for_revocation),
    ];
    let bad = [
        drust::auth::admin_token::generate_token(),
        "drust_mcpat_short".to_string(),
        tokens::new_token(TokenKind::Code),
        String::new(),
    ];
    for (name, find) in finds {
        for t in &bad {
            assert!(
                matches!(find(&conn, t), Ok(None)),
                "{name} must answer None for {t:?}-shaped input without SQL"
            );
        }
    }
    assert!(matches!(
        store::find_grant_by_access(&conn, &tokens::new_token(TokenKind::Refresh)),
        Ok(None)
    ));
    assert!(matches!(
        store::find_grant_by_refresh(&conn, &tokens::new_token(TokenKind::Access)),
        Ok(None)
    ));
    // Control: a well-formed token DOES reach SQL (and fails: no such table).
    assert!(store::find_grant_by_access(&conn, &tokens::new_token(TokenKind::Access)).is_err());
    assert!(store::find_grant_by_refresh(&conn, &tokens::new_token(TokenKind::Refresh)).is_err());
    assert!(
        store::find_grant_for_revocation(&conn, &tokens::new_token(TokenKind::Access)).is_err()
    );
    assert!(
        store::find_grant_for_revocation(&conn, &tokens::new_token(TokenKind::Refresh)).is_err()
    );
}

#[tokio::test]
async fn find_live_tokens_return_the_grant() {
    let fx = fixture(false).await;
    let c = fx.meta.lock().await;
    let g = live_grant(&c, fx.owner_id);
    let t = seed_tokens(&c, g);
    for r in [
        store::find_grant_by_access(&c, &t.access).unwrap(),
        store::find_grant_by_refresh(&c, &t.refresh).unwrap(),
    ] {
        let r = r.expect("live token finds its grant");
        assert_eq!(r.grant_id(), g);
        assert_eq!(r.admin_id(), fx.owner_id);
    }
}

#[tokio::test]
async fn find_unknown_token_is_none() {
    let fx = fixture(false).await;
    let c = fx.meta.lock().await;
    let g = live_grant(&c, fx.owner_id);
    seed_tokens(&c, g);
    let access = tokens::new_token(TokenKind::Access);
    let refresh = tokens::new_token(TokenKind::Refresh);
    assert!(store::find_grant_by_access(&c, &access).unwrap().is_none());
    assert!(
        store::find_grant_by_refresh(&c, &refresh)
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn find_revoked_or_expired_token_is_none() {
    let fx = fixture(false).await;
    let c = fx.meta.lock().await;
    let cases = [
        ("_mcp_oauth_access", "revoked_at", "datetime('now')"),
        (
            "_mcp_oauth_access",
            "expires_at",
            "datetime('now', '-1 second')",
        ),
        ("_mcp_oauth_refresh", "revoked_at", "datetime('now')"),
        (
            "_mcp_oauth_refresh",
            "expires_at",
            "datetime('now', '-1 second')",
        ),
    ];
    for (table, col, value) in cases {
        let g = live_grant(&c, fx.owner_id);
        let t = seed_tokens(&c, g);
        c.execute(
            &format!("UPDATE {table} SET {col} = {value} WHERE grant_id = ?1"),
            params![g],
        )
        .unwrap();
        let access = store::find_grant_by_access(&c, &t.access).unwrap();
        let refresh = store::find_grant_by_refresh(&c, &t.refresh).unwrap();
        if table == "_mcp_oauth_access" {
            assert!(access.is_none(), "{table}.{col}: access must be dead");
            assert!(refresh.is_some(), "{table}.{col}: only the access died");
        } else {
            assert!(refresh.is_none(), "{table}.{col}: refresh must be dead");
            assert!(access.is_some(), "{table}.{col}: only the refresh died");
        }
    }
}

#[tokio::test]
async fn find_revoked_grant_is_none() {
    let fx = fixture(false).await;
    let c = fx.meta.lock().await;
    let g = seed_grant(
        &c,
        &SeedGrant {
            admin_id: fx.owner_id,
            idle: "+30 days",
            absolute: "+90 days",
            revoked: true,
        },
    );
    let t = seed_tokens(&c, g);
    assert!(
        store::find_grant_by_access(&c, &t.access)
            .unwrap()
            .is_none()
    );
    assert!(
        store::find_grant_by_refresh(&c, &t.refresh)
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn find_idle_or_absolute_expired_grant_is_none() {
    let fx = fixture(false).await;
    let c = fx.meta.lock().await;
    for (idle, absolute, want_some) in [
        ("-1 hour", "+90 days", false),
        ("+30 days", "-1 hour", false),
        ("+30 days", "+90 days", true),
    ] {
        let g = seed_grant(
            &c,
            &SeedGrant {
                admin_id: fx.owner_id,
                idle,
                absolute,
                revoked: false,
            },
        );
        let t = seed_tokens(&c, g);
        // seed_tokens set the refresh to the grant's MIN(idle, absolute); move it
        // into the future so only the GRANT's deadlines are under test.
        c.execute(
            "UPDATE _mcp_oauth_refresh SET expires_at = datetime('now', '+1 day') \
              WHERE grant_id = ?1",
            params![g],
        )
        .unwrap();
        let access = store::find_grant_by_access(&c, &t.access).unwrap();
        let refresh = store::find_grant_by_refresh(&c, &t.refresh).unwrap();
        assert_eq!(
            access.is_some(),
            want_some,
            "access idle={idle} abs={absolute}"
        );
        assert_eq!(
            refresh.is_some(),
            want_some,
            "refresh idle={idle} abs={absolute}"
        );
    }
}

#[tokio::test]
async fn find_admin_created_at_mismatch_is_none() {
    let fx = fixture(false).await;
    let c = fx.meta.lock().await;
    let g = live_grant(&c, fx.owner_id);
    let t = seed_tokens(&c, g);
    let original: String = c
        .query_row(
            "SELECT admin_created_at FROM _mcp_oauth_grants WHERE id = ?1",
            params![g],
            |r| r.get(0),
        )
        .unwrap();
    let set = |v: &str| {
        c.execute(
            "UPDATE _mcp_oauth_grants SET admin_created_at = ?1 WHERE id = ?2",
            params![v, g],
        )
        .unwrap();
    };
    set("2000-01-01 00:00:00");
    assert!(
        store::find_grant_by_access(&c, &t.access)
            .unwrap()
            .is_none()
    );
    assert!(
        store::find_grant_by_refresh(&c, &t.refresh)
            .unwrap()
            .is_none()
    );
    set(&original);
    assert!(
        store::find_grant_by_access(&c, &t.access)
            .unwrap()
            .is_some()
    );
    assert!(
        store::find_grant_by_refresh(&c, &t.refresh)
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn find_refresh_leaves_rotation_state_to_rotate() {
    let fx = fixture(false).await;
    let c = fx.meta.lock().await;
    let g = live_grant(&c, fx.owner_id);
    let t = seed_tokens(&c, g);
    age(
        &c,
        "_mcp_oauth_refresh",
        "rotated_at",
        "id",
        t.refresh_id,
        "+0 seconds",
    );
    assert!(
        store::find_grant_by_refresh(&c, &t.refresh)
            .unwrap()
            .is_some(),
        "rotated_at is refresh::rotate's decision, not this probe's"
    );
    age(
        &c,
        "_mcp_oauth_refresh",
        "superseded_at",
        "id",
        t.refresh_id,
        "+0 seconds",
    );
    assert!(
        store::find_grant_by_refresh(&c, &t.refresh)
            .unwrap()
            .is_some(),
        "superseded_at is refresh::rotate's decision, not this probe's"
    );
}

#[tokio::test]
async fn find_never_crosses_token_kinds() {
    let fx = fixture(false).await;
    let c = fx.meta.lock().await;
    let g = live_grant(&c, fx.owner_id);
    let t = seed_tokens(&c, g);
    assert!(
        store::find_grant_by_refresh(&c, &t.access)
            .unwrap()
            .is_none()
    );
    assert!(
        store::find_grant_by_access(&c, &t.refresh)
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn revocation_lookup_accepts_any_genuine_token_of_an_unrevoked_grant() {
    let fx = fixture(false).await;
    // (label, which token is presented, UPDATE that makes it dead for authorization)
    let cases: [(&str, TokenKind, &str); 4] = [
        (
            "expired access",
            TokenKind::Access,
            "UPDATE _mcp_oauth_access SET expires_at = datetime('now', '-1 second') \
              WHERE grant_id = ?1",
        ),
        (
            "revoked access",
            TokenKind::Access,
            "UPDATE _mcp_oauth_access SET revoked_at = datetime('now') WHERE grant_id = ?1",
        ),
        (
            "rotated + superseded + branch-revoked refresh",
            TokenKind::Refresh,
            "UPDATE _mcp_oauth_refresh SET rotated_at = datetime('now', '-2 minutes'), \
               superseded_at = datetime('now', '-1 minute'), revoked_at = datetime('now'), \
               revoke_reason = 'sibling_superseded' WHERE grant_id = ?1",
        ),
        (
            "expired refresh",
            TokenKind::Refresh,
            "UPDATE _mcp_oauth_refresh SET expires_at = datetime('now', '-1 second') \
              WHERE grant_id = ?1",
        ),
    ];
    for (label, kind, kill) in cases {
        let (g, token) = {
            let c = fx.meta.lock().await;
            let g = live_grant(&c, fx.owner_id);
            let t = seed_tokens(&c, g);
            c.execute(kill, params![g]).unwrap();
            (
                g,
                if kind == TokenKind::Access {
                    t.access
                } else {
                    t.refresh
                },
            )
        };
        let out = with_tx(&fx, |tx| {
            let authz = if kind == TokenKind::Access {
                store::find_grant_by_access(tx, &token).unwrap()
            } else {
                store::find_grant_by_refresh(tx, &token).unwrap()
            };
            assert!(
                authz.is_none(),
                "{label}: authorization strength stays strict"
            );
            let r = store::find_grant_for_revocation(tx, &token)
                .unwrap()
                .unwrap_or_else(|| panic!("{label}: revocation strength finds the grant"));
            assert_eq!(r.grant_id(), g, "{label}");
            revoke(
                tx,
                &GrantOwner::holder(&r),
                r.grant_id(),
                RevokeReason::OauthRevoke,
            )
        })
        .await;
        assert_eq!(out, RevokedGrant::Revoked, "{label}");
        assert_eq!(
            grant_reason(&*fx.meta.lock().await, g).as_deref(),
            Some("oauth_revoke"),
            "{label}"
        );
    }
}

#[tokio::test]
async fn revocation_lookup_refuses_a_revoked_or_orphan_grant() {
    let fx = fixture(false).await;
    let c = fx.meta.lock().await;
    // (a) revoked grant
    let ga = seed_grant(
        &c,
        &SeedGrant {
            admin_id: fx.owner_id,
            idle: "+30 days",
            absolute: "+90 days",
            revoked: true,
        },
    );
    let ta = seed_tokens(&c, ga);
    // (b) orphan: the admin snapshot no longer matches
    let gb = live_grant(&c, fx.owner_id);
    let tb = seed_tokens(&c, gb);
    c.execute(
        "UPDATE _mcp_oauth_grants SET admin_created_at = '2000-01-01 00:00:00' WHERE id = ?1",
        params![gb],
    )
    .unwrap();
    for (label, t) in [("revoked", &ta), ("orphan", &tb)] {
        assert!(
            store::find_grant_for_revocation(&c, &t.access)
                .unwrap()
                .is_none(),
            "{label} access"
        );
        assert!(
            store::find_grant_for_revocation(&c, &t.refresh)
                .unwrap()
                .is_none(),
            "{label} refresh"
        );
    }
    // (c) control: an expired-but-unrevoked grant can still be revoked.
    let gc = seed_grant(
        &c,
        &SeedGrant {
            admin_id: fx.owner_id,
            idle: "-1 hour",
            absolute: "+90 days",
            revoked: false,
        },
    );
    let tc = seed_tokens(&c, gc);
    for t in [&tc.access, &tc.refresh] {
        let r = store::find_grant_for_revocation(&c, t)
            .unwrap()
            .expect("an expired grant is still revocable");
        assert_eq!(r.grant_id(), gc);
    }
}

// ─── C. sweep_mcp_oauth ──────────────────────────────────────────────────────

/// The C1 shape on one live grant: two access and two refresh rows (one of
/// each expired), three codes (expired-unredeemed, expired-redeemed, live) and
/// two tickets (one expired). A sweep removes exactly 2 codes, 1 access,
/// 1 refresh and 1 ticket.
fn seed_expiring_children(conn: &rusqlite::Connection, admin_id: i64) -> i64 {
    let g = live_grant(conn, admin_id);
    let t1 = seed_tokens(conn, g);
    seed_tokens(conn, g);
    conn.execute(
        "UPDATE _mcp_oauth_access SET expires_at = datetime('now', '-1 second') \
          WHERE token_hash = ?1",
        params![tokens::hash(TokenKind::Access, &t1.access)],
    )
    .unwrap();
    age(
        conn,
        "_mcp_oauth_refresh",
        "expires_at",
        "id",
        t1.refresh_id,
        "-1 second",
    );
    let expired = seed_code(conn, g, REDIRECT, CHALLENGE, None);
    let redeemed = seed_code(conn, g, REDIRECT, CHALLENGE, None);
    seed_code(conn, g, REDIRECT, CHALLENGE, None);
    for (code, redeem) in [(expired, false), (redeemed, true)] {
        conn.execute(
            "UPDATE _mcp_oauth_codes SET expires_at = datetime('now', '-1 second'), \
               redeemed_at = CASE WHEN ?2 THEN datetime('now', '-2 minutes') END \
             WHERE code_hash = ?1",
            params![tokens::hash(TokenKind::Code, &code), redeem],
        )
        .unwrap();
    }
    seed_ticket(conn, g, "-1 second");
    seed_ticket(conn, g, "+1 hour");
    g
}

fn children(conn: &rusqlite::Connection, g: i64) -> [i64; 4] {
    [
        "_mcp_oauth_codes",
        "_mcp_oauth_access",
        "_mcp_oauth_refresh",
        "_mcp_upload_tickets",
    ]
    .map(|t| {
        count(
            conn,
            &format!("SELECT COUNT(*) FROM {t} WHERE grant_id = {g}"),
        )
    })
}

fn grant_exists(conn: &rusqlite::Connection, g: i64) -> bool {
    count(
        conn,
        &format!("SELECT COUNT(*) FROM _mcp_oauth_grants WHERE id = {g}"),
    ) == 1
}

#[tokio::test]
async fn sweep_deletes_expired_children_and_keeps_live_ones() {
    let fx = fixture(false).await;
    let g = seed_expiring_children(&*fx.meta.lock().await, fx.owner_id);
    let counts = sweep_mcp_oauth(&fx.meta).await;
    assert_eq!(
        counts,
        SweepCounts {
            codes: 2,
            access: 1,
            refresh: 1,
            tickets: 1,
            ..SweepCounts::default()
        }
    );
    let c = fx.meta.lock().await;
    assert!(grant_exists(&c, g));
    assert_eq!(children(&c, g), [1, 1, 1, 1], "the live rows stay");
    for t in [
        "_mcp_oauth_codes",
        "_mcp_oauth_access",
        "_mcp_oauth_refresh",
        "_mcp_upload_tickets",
    ] {
        assert_eq!(
            count(
                &c,
                &format!("SELECT COUNT(*) FROM {t} WHERE expires_at < datetime('now')")
            ),
            0,
            "{t}: no expired row survives"
        );
    }
}

#[tokio::test]
async fn sweep_keeps_a_rotated_refresh_until_it_expires() {
    let fx = fixture(false).await;
    let (g, t) = {
        let c = fx.meta.lock().await;
        let g = live_grant(&c, fx.owner_id);
        let t = seed_tokens(&c, g);
        age(
            &c,
            "_mcp_oauth_refresh",
            "rotated_at",
            "id",
            t.refresh_id,
            "-2 days",
        );
        (g, t)
    };
    assert_eq!(sweep_mcp_oauth(&fx.meta).await, SweepCounts::default());
    let c = fx.meta.lock().await;
    assert_eq!(
        count(
            &c,
            &format!(
                "SELECT COUNT(*) FROM _mcp_oauth_refresh WHERE id = {} AND grant_id = {g}",
                t.refresh_id
            )
        ),
        1,
        "refresh-reuse detection needs the rotated row until its own expiry"
    );
}

#[tokio::test]
async fn sweep_grant_retention_is_thirty_days_after_end_of_life() {
    let fx = fixture(false).await;
    // (label, idle, absolute, revoked_at, deleted)
    let rows: [(&str, &str, &str, Option<&str>, bool); 7] = [
        ("a", "+30 days", "+90 days", None, false),
        ("b", "-10 days", "+80 days", None, false),
        ("c", "-31 days", "+59 days", None, true),
        ("d", "+30 days", "-31 days", None, true),
        ("e", "+30 days", "+90 days", Some("-10 days"), false),
        ("f", "+30 days", "+90 days", Some("-31 days"), true),
        ("g", "-40 days", "+50 days", Some("-10 days"), false),
    ];
    let ids: Vec<i64> = {
        let c = fx.meta.lock().await;
        rows.iter()
            .map(|(_, idle, absolute, revoked, _)| {
                // Seed live and give it tokens FIRST (so its refresh/access are
                // unexpired), then age the grant into the row's shape.
                let g = live_grant(&c, fx.owner_id);
                seed_tokens(&c, g);
                age(&c, "_mcp_oauth_grants", "idle_expires_at", "id", g, idle);
                age(
                    &c,
                    "_mcp_oauth_grants",
                    "absolute_expires_at",
                    "id",
                    g,
                    absolute,
                );
                if let Some(r) = revoked {
                    age(&c, "_mcp_oauth_grants", "revoked_at", "id", g, r);
                    c.execute(
                        "UPDATE _mcp_oauth_grants SET revoke_reason = 'user' WHERE id = ?1",
                        params![g],
                    )
                    .unwrap();
                }
                g
            })
            .collect()
    };
    let counts = sweep_mcp_oauth(&fx.meta).await;
    // Child counts 0: the sweep touched no surviving child; a deleted grant's
    // children go by CASCADE, which `changes()` does not count.
    assert_eq!(
        counts,
        SweepCounts {
            grants: 3,
            ..SweepCounts::default()
        }
    );
    let c = fx.meta.lock().await;
    for ((label, .., deleted), g) in rows.iter().zip(ids) {
        assert_eq!(grant_exists(&c, g), !deleted, "row ({label})");
        let [_, access, refresh, _] = children(&c, g);
        if *deleted {
            assert_eq!((access, refresh), (0, 0), "row ({label}) children cascade");
        } else {
            assert_eq!((access, refresh), (1, 1), "row ({label}) children stay");
        }
    }
}

#[tokio::test]
async fn sweep_deletes_orphan_grants_and_their_children() {
    let fx = fixture(false).await;
    let bob = add_admin(&fx, "bob", "", "member").await;
    let (g1, g2) = {
        let c = fx.meta.lock().await;
        // (a) the admin snapshot no longer matches
        let g1 = live_grant(&c, fx.owner_id);
        seed_tokens(&c, g1);
        c.execute(
            "UPDATE _mcp_oauth_grants SET admin_created_at = '2000-01-01 00:00:00' WHERE id = ?1",
            params![g1],
        )
        .unwrap();
        // (b) the admin was deleted by an out-of-process tool without FK enforcement
        let g2 = live_grant(&c, bob);
        seed_tokens(&c, g2);
        c.execute_batch("PRAGMA foreign_keys = OFF").unwrap();
        c.execute("DELETE FROM admins WHERE id = ?1", params![bob])
            .unwrap();
        c.execute_batch("PRAGMA foreign_keys = ON").unwrap();
        (g1, g2)
    };
    assert_eq!(
        sweep_mcp_oauth(&fx.meta).await,
        SweepCounts {
            orphans: 2,
            ..SweepCounts::default()
        }
    );
    let c = fx.meta.lock().await;
    for g in [g1, g2] {
        assert!(!grant_exists(&c, g), "orphan grant {g} is deleted");
        assert_eq!(
            children(&c, g),
            [0, 0, 0, 0],
            "grant {g}'s children cascade"
        );
    }
}

#[tokio::test]
async fn sweep_counts_an_old_orphan_once() {
    let fx = fixture(false).await;
    let g = {
        let c = fx.meta.lock().await;
        let g = live_grant(&c, fx.owner_id);
        seed_tokens(&c, g);
        age(&c, "_mcp_oauth_grants", "revoked_at", "id", g, "-31 days");
        c.execute(
            "UPDATE _mcp_oauth_grants SET revoke_reason = 'user', \
               admin_created_at = '2000-01-01 00:00:00' WHERE id = ?1",
            params![g],
        )
        .unwrap();
        g
    };
    assert_eq!(
        sweep_mcp_oauth(&fx.meta).await,
        SweepCounts {
            grants: 1,
            ..SweepCounts::default()
        },
        "the retention rule runs first; the orphan rule no longer sees the row"
    );
    assert!(!grant_exists(&*fx.meta.lock().await, g));
}

#[tokio::test]
async fn sweep_is_idempotent_and_a_no_op_on_empty_tables() {
    let fx = fixture(false).await;
    assert_eq!(sweep_mcp_oauth(&fx.meta).await.total(), 0, "empty tables");
    seed_expiring_children(&*fx.meta.lock().await, fx.owner_id);
    assert!(sweep_mcp_oauth(&fx.meta).await.total() > 0);
    assert_eq!(sweep_mcp_oauth(&fx.meta).await.total(), 0, "second sweep");
}

#[tokio::test]
async fn sweep_is_all_or_nothing() {
    let fx = fixture(false).await;
    let (g, old) = {
        let c = fx.meta.lock().await;
        let g = seed_expiring_children(&c, fx.owner_id);
        // A grant the retention rule deletes, so the forced failure fires.
        let old = live_grant(&c, fx.owner_id);
        seed_tokens(&c, old);
        age(
            &c,
            "_mcp_oauth_grants",
            "idle_expires_at",
            "id",
            old,
            "-31 days",
        );
        c.execute_batch(
            "CREATE TEMP TRIGGER t_fail BEFORE DELETE ON main._mcp_oauth_grants \
             BEGIN SELECT RAISE(ABORT, 'forced'); END",
        )
        .unwrap();
        (g, old)
    };
    assert_eq!(
        sweep_mcp_oauth(&fx.meta).await,
        SweepCounts::default(),
        "a failed sweep reports nothing"
    );
    {
        let c = fx.meta.lock().await;
        assert_eq!(
            children(&c, g),
            [3, 2, 2, 2],
            "the child DELETEs that ran before the failure rolled back"
        );
        assert!(grant_exists(&c, old));
        c.execute_batch("DROP TRIGGER temp.t_fail").unwrap();
    }
    assert_eq!(
        sweep_mcp_oauth(&fx.meta).await,
        SweepCounts {
            codes: 2,
            access: 1,
            refresh: 1,
            tickets: 1,
            grants: 1,
            ..SweepCounts::default()
        }
    );
}

#[tokio::test]
async fn sweep_deletes_grants_that_can_never_be_redeemed() {
    let fx = fixture(false).await;
    let (g1, g2, g3, g4) = {
        let c = fx.meta.lock().await;
        // G1: its only code has expired, never redeemed.
        let g1 = live_grant(&c, fx.owner_id);
        let code = seed_code(&c, g1, REDIRECT, CHALLENGE, None);
        c.execute(
            "UPDATE _mcp_oauth_codes SET expires_at = datetime('now', '-1 second') \
              WHERE code_hash = ?1",
            params![tokens::hash(TokenKind::Code, &code)],
        )
        .unwrap();
        // G2: a code that can still be redeemed.
        let g2 = live_grant(&c, fx.owner_id);
        seed_code(&c, g2, REDIRECT, CHALLENGE, None);
        // G3: has a refresh.
        let g3 = live_grant(&c, fx.owner_id);
        seed_tokens(&c, g3);
        // G4: nothing at all.
        let g4 = live_grant(&c, fx.owner_id);
        (g1, g2, g3, g4)
    };
    let counts = sweep_mcp_oauth(&fx.meta).await;
    assert_eq!(
        counts,
        SweepCounts {
            codes: 1,
            abandoned: 2,
            ..SweepCounts::default()
        }
    );
    assert_eq!(counts.total(), 3, "total() includes abandoned");
    let c = fx.meta.lock().await;
    assert!(!grant_exists(&c, g1));
    assert!(grant_exists(&c, g2));
    assert!(grant_exists(&c, g3));
    assert!(!grant_exists(&c, g4));
}
