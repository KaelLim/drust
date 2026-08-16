//! #975 — the eviction SET for an admin-PAT revocation, and the one place that
//! decides it.
//!
//! ## Why this is not just `evict_all_tenants()`
//!
//! The four PAT-lifecycle sites in [`crate::mgmt::admin_pat`] — `reroll`,
//! `cli_token_refresh`, `cli_token_logout`, `cli_token_revoke` — are all
//! **self-service**: the caller revokes their OWN key. Two of them sit on
//! `settings_router` (session-authenticated, and that router carries NO
//! `require_owner_layer`) and two on the public router behind their own bearer.
//! So the lowest-privilege admin role, `member`, can reach every one of them on
//! demand, repeatably.
//!
//! Wiring those to a host-wide evict therefore handed a `member` a cross-tenant
//! availability lever: press reroll, every rooms WS socket on EVERY tenant
//! closes. The user approved the blunt *blast radius* of an evict (option (a),
//! spec §設計); nothing approved "an unprivileged role may press it on demand",
//! and spec §隔離與資安不變量 4's own rule — "寧可少踢也不把 evict 變成任何人可
//! 觸發的全站斷線按鈕" — is exactly the property that was violated.
//!
//! ## Why the narrow set is not a weakening
//!
//! It is not a policy choice; it is the PAT's actual reach, read from the same
//! column the data plane reads:
//!
//! - `src/tenant/router.rs`'s bearer CTE resolves an admin PAT to
//!   `AuthCtx::Service` only if `pat_sees_all || tenant_owner_admin_id ==
//!   Some(admin_id)`, else `403 PAT_TENANT_DENIED`.
//! - [`crate::mgmt::tenant_authz::tenant_access_for`] says the same thing on the
//!   management plane.
//!
//! So for a non-sees-all admin the set of tenants where that PAT could ever have
//! opened a socket IS the set of tenants they own — every other tenant's socket
//! belongs to somebody else, and closing it evicts a stranger. For a sees-all
//! admin (`owner` / `admin`) the reach genuinely is the host, and
//! [`RoomBus::evict_all_tenants`](crate::tenant::rooms::RoomBus::evict_all_tenants)
//! stays exactly right. No per-connection credential index is needed for either
//! — that was the deferred option (b), and it is not what this costs.
//!
//! ## Fail direction
//!
//! Every DB failure falls back to the host-wide evict. Under-evicting is the
//! security direction (a revoked PAT keeps a live `AuthCtx::Service` socket),
//! over-evicting is only availability — and the failures that get here (an
//! unreadable `admins` row, an unreadable `tenants` table) are not
//! caller-triggerable, so the fallback does not hand the button back.
//!
//! ## Known residual, stated rather than implied
//!
//! The reach is read live, so a socket opened under a WIDER past role is outside
//! the narrow set. Every in-tree path that narrows a role closes those sockets
//! itself at the moment it narrows them (`admin_team::change_role` evicts
//! host-wide on a sees-all → member flip; `remove_admin` over the pre-image reach it snapshots before its DELETE;
//! `tenant_settings::patch_tenant_owner` for the one tenant that moved), so the
//! gap needs the OUT-OF-PROCESS break-glass `set_admin_role` binary, which
//! evicts nothing at all today and leaves those sockets live regardless of what
//! this module does.

use std::sync::Arc;

use rusqlite::{Connection, params};
use tokio::sync::Mutex;

use crate::mgmt::routes::MgmtState;
use crate::mgmt::tenant_authz::sees_all_tenants;

/// Where an admin's PAT could be holding live rooms sockets right now.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PatReach {
    /// `owner` | `admin` — the bearer CTE's sees-all arm admits this PAT on
    /// every tenant, so a revocation has to close every tenant's sockets.
    HostWide,
    /// Any non-sees-all role (`member` today, and any future role, because
    /// [`sees_all_tenants`] is an allow-list) — the PAT resolves only on
    /// tenants this admin OWNS, so those ids are the whole eviction set. An
    /// empty vector is a real answer: an admin who owns nothing has no socket
    /// anywhere, and the correct action is to evict nothing.
    Owned(Vec<String>),
}

/// Read `admin_id`'s live PAT reach off `meta`.
///
/// Deliberately re-reads `admins.role` from the DB rather than taking the
/// `AdminProfileExt` extension: two of the four callers sit on the PUBLIC
/// router and have no profile extension at all, and the DB column is the same
/// one the data-plane bearer CTE consults, so the eviction set cannot disagree
/// with what the PAT can actually reach.
///
/// Any failure answers [`PatReach::HostWide`] — see the module's fail-direction
/// note.
async fn pat_reach(meta: &Arc<Mutex<Connection>>, admin_id: i64) -> PatReach {
    let conn = meta.lock().await;
    read_pat_reach(&conn, admin_id)
}

/// The synchronous half, split out so it is testable against a plain
/// `Connection` without a router.
pub(crate) fn read_pat_reach(conn: &Connection, admin_id: i64) -> PatReach {
    let read = || -> rusqlite::Result<PatReach> {
        let role: String = conn.query_row(
            "SELECT role FROM admins WHERE id = ?1",
            params![admin_id],
            |r| r.get(0),
        )?;
        if sees_all_tenants(&role) {
            return Ok(PatReach::HostWide);
        }
        // Same predicate as `tenant_ownership_layer` and the bearer CTE's
        // owns-this-tenant arm. A soft-deleted tenant is excluded because
        // `soft_delete_tenant` already evicted it when it was deleted, and no
        // bearer can re-open a socket on it afterwards (the CTE filters
        // `deleted_at IS NULL`, and both auth-cache arms open with
        // `get_if_live`).
        let mut stmt = conn
            .prepare("SELECT id FROM tenants WHERE owner_admin_id = ?1 AND deleted_at IS NULL")?;
        let ids = stmt
            .query_map(params![admin_id], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<String>>>()?;
        Ok(PatReach::Owned(ids))
    };
    read().unwrap_or(PatReach::HostWide)
}

/// #975 — close the rooms WS sockets an admin's just-revoked PAT may still be
/// holding, over exactly the tenants that PAT could reach.
///
/// **Call this AFTER `auth_cache.clear_admin_pat`, never before** (spec
/// §隔離與資安不變量 2, pinned per-site by the test-only `mgmt::pat_evict_pin`
/// module): the kicked client reconnects immediately and must not be
/// re-admitted from a cache entry the clear had not yet removed.
///
/// Must also be called after the handler's own DB work has committed and its
/// `meta` guard has dropped — this takes the `meta` lock itself.
pub(crate) async fn evict_pat_rooms_sockets(s: &MgmtState, admin_id: i64) {
    let reach = pat_reach(&s.meta, admin_id).await;
    evict_reach(s, reach);
}

/// Apply an already-decided [`PatReach`]. Split out for the caller that must
/// read the reach BEFORE destroying the rows it is derived from —
/// `admin_team::remove_admin`: its `DELETE FROM admins` fires the FK
/// `ON DELETE SET NULL` on `tenants.owner_admin_id`, so a post-commit
/// `read_pat_reach` would answer `Owned([])` and evict nothing.
pub(crate) fn evict_reach(s: &MgmtState, reach: PatReach) {
    match reach {
        PatReach::HostWide => s.bus_rooms.evict_all_tenants(),
        PatReach::Owned(ids) => {
            // `evict_tenant` is an INSERTING call on the never-reclaimed
            // `epochs` map, so its doc requires every caller to authorize the
            // id first. These ids come straight out of `tenants`, so the key
            // space stays bounded by the tenant table — no caller-supplied
            // string reaches it.
            //
            // Per-tenant interleaving (tenant A's channel teardown landing
            // before tenant B's epoch bump) is fine HERE even though
            // `evict_all_tenants` refuses that shape for the host-wide set: a
            // WS socket checkpoints only its OWN tenant's epoch, and each
            // `evict_tenant` is internally bump-then-teardown (structurally
            // pinned), so the stale-epoch window never spans tenants.
            for id in &ids {
                s.bus_rooms.evict_tenant(id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `admins` + `tenants` only — this module reads nothing else.
    fn meta() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE admins (id INTEGER PRIMARY KEY, role TEXT NOT NULL DEFAULT 'member');
             CREATE TABLE tenants (id TEXT PRIMARY KEY, owner_admin_id INTEGER, deleted_at TEXT);
             INSERT INTO admins (id, role) VALUES (1, 'owner'), (2, 'admin'), (3, 'member'),
                                                  (4, 'future-role');
             INSERT INTO tenants (id, owner_admin_id, deleted_at) VALUES
               ('t-owned',   3, NULL),
               ('t-owned-2', 3, NULL),
               ('t-foreign', 1, NULL),
               ('t-gone',    3, '2026-08-16T00:00:00Z'),
               ('t-orphan',  NULL, NULL);",
        )
        .unwrap();
        conn
    }

    fn owned(conn: &Connection, admin_id: i64) -> Vec<String> {
        match read_pat_reach(conn, admin_id) {
            PatReach::Owned(mut ids) => {
                ids.sort();
                ids
            }
            PatReach::HostWide => panic!("expected a narrowed reach for admin {admin_id}"),
        }
    }

    #[test]
    fn sees_all_roles_reach_the_whole_host() {
        let conn = meta();
        assert_eq!(read_pat_reach(&conn, 1), PatReach::HostWide, "owner");
        assert_eq!(read_pat_reach(&conn, 2), PatReach::HostWide, "admin");
    }

    /// The finding this module exists for: a `member` reaches only what they
    /// own, so a `member` revocation may close only those tenants' sockets.
    #[test]
    fn a_member_reaches_only_the_tenants_they_own() {
        let conn = meta();
        assert_eq!(owned(&conn, 3), vec!["t-owned", "t-owned-2"]);
    }

    /// `sees_all_tenants` is an allow-list, so an unknown role narrows rather
    /// than widening — the same fail-closed shape as the bearer CTE's
    /// `pat_sees_all`, which would also deny this PAT on a foreign tenant.
    #[test]
    fn an_unknown_role_narrows_like_a_member() {
        let conn = meta();
        assert_eq!(owned(&conn, 4), Vec::<String>::new());
    }

    /// A soft-deleted tenant is out of the set: `soft_delete_tenant` evicted it
    /// already and nothing can reconnect to it.
    #[test]
    fn a_soft_deleted_tenant_is_not_in_the_eviction_set() {
        let conn = meta();
        assert!(!owned(&conn, 3).contains(&"t-gone".to_string()));
    }

    /// Fail direction: an unreadable `admins` row must NOT silently narrow to
    /// "evict nothing" — it falls back to the host-wide set.
    #[test]
    fn an_unknown_admin_falls_back_to_host_wide() {
        let conn = meta();
        assert_eq!(read_pat_reach(&conn, 999), PatReach::HostWide);
    }

    /// Same direction, other table: the role says "narrow", but the tenant
    /// listing cannot be read. Answering `Owned(vec![])` there would evict
    /// nothing at all and silently defeat the revocation.
    #[test]
    fn an_unreadable_tenants_table_falls_back_to_host_wide() {
        let conn = meta();
        conn.execute_batch("DROP TABLE tenants;").unwrap();
        assert_eq!(read_pat_reach(&conn, 3), PatReach::HostWide);
    }
}
