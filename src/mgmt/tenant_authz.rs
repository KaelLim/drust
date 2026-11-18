//! v1.50 — single ownership predicate shared by every enforcement site
//! (list filter, route guard, ensure_tenant_visible, PAT CTE deny).

#[derive(Debug, PartialEq, Eq)]
pub enum TenantAccess {
    Allow,
    Deny,
}

pub fn tenant_access_for(
    sees_all: bool,
    caller_admin_id: i64,
    tenant_owner: Option<i64>,
) -> TenantAccess {
    if sees_all {
        // owner OR admin (sees_all_tenants): global reach, incl. NULL (orphaned) tenants
        return TenantAccess::Allow;
    }
    match tenant_owner {
        Some(o) if o == caller_admin_id => TenantAccess::Allow,
        _ => TenantAccess::Deny, // foreign or NULL → invisible to a member
    }
}

/// SQL fragment appended to a `WHERE deleted_at IS NULL` tenant listing.
/// sees_all (owner OR admin) → no extra clause; member → caller binds their
/// admin id for the `?`.
pub fn visibility_where(sees_all: bool) -> &'static str {
    if sees_all {
        ""
    } else {
        " AND owner_admin_id = ?"
    }
}

// ─── role-capability helpers (v1.57 — 3-tier owner > admin > member) ──────────

/// Global tenant reach — owner AND admin see every tenant; member sees only owned.
pub fn sees_all_tenants(role: &str) -> bool {
    matches!(role, "owner" | "admin")
}
/// May invite/remove MEMBER-role admins (owner + admin).
pub fn can_manage_members(role: &str) -> bool {
    matches!(role, "owner" | "admin")
}
/// May create/demote OWNER or ADMIN roles, and reach owner-only host surfaces.
/// Owner-only — the top tier.
pub fn can_manage_privileged(role: &str) -> bool {
    role == "owner"
}
/// May see the team page (owner + admin; member cannot).
pub fn sees_team_page(role: &str) -> bool {
    matches!(role, "owner" | "admin")
}

// ─── route-layer guard middleware ────────────────────────────────────────────

/// State for `tenant_ownership_layer` — mirrors
/// `admin_profile::AdminProfileLayerState` (meta handle only).
#[derive(Clone)]
pub struct TenantOwnershipLayerState {
    pub meta: std::sync::Arc<tokio::sync::Mutex<rusqlite::Connection>>,
}

/// v1.50 — owner-only gate for HOST-WIDE admin surfaces that expose every
/// tenant's data or roster (backups, host audit, host metrics). These have no
/// `{id}` param, so `tenant_ownership_layer` passes them through; they predate
/// the member role (when every admin was cross-tenant) and would otherwise
/// leak the full tenant roster — and, for a backup download, EVERY tenant's
/// plaintext service/admin tokens — to a member admin. Reads
/// `AdminProfileExt.is_owner` (populated by the outer `admin_profile_layer`);
/// a non-owner (or missing profile → fail-closed) gets `403 OWNER_REQUIRED`.
pub async fn require_owner_layer(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let is_owner = req
        .extensions()
        .get::<crate::mgmt::admin_profile::AdminProfileExt>()
        .map(|p| p.is_owner)
        .unwrap_or(false);
    if !is_owner {
        return crate::error::json_error(
            axum::http::StatusCode::FORBIDDEN,
            "OWNER_REQUIRED",
            "this host-wide admin surface requires the owner role",
        );
    }
    next.run(req).await
}

/// v1.57 — route-layer member block for the team READ surface (`GET /admin/team`).
/// The mutation routes on the same sub-router (invite / batch / role / remove)
/// enforce their own authority matrix in-handler (`NOT_A_MANAGER` /
/// `PRIVILEGED_ROLE_REQUIRED`), so this guard gates ONLY the GET read — the
/// second, independent line of defense next to `team_page`'s `sees_team` handler
/// gate (DiD ≥ 2). Reads `AdminProfileExt.sees_team` (owner|admin); a `member`
/// (or a missing profile → fail-closed) gets `403 TEAM_REQUIRES_MANAGEMENT`.
pub async fn require_sees_team_layer(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if req.method() == axum::http::Method::GET {
        let sees_team = req
            .extensions()
            .get::<crate::mgmt::admin_profile::AdminProfileExt>()
            .map(|p| p.sees_team)
            .unwrap_or(false); // no profile → treat as member, fail-closed
        if !sees_team {
            return crate::error::json_error(
                axum::http::StatusCode::FORBIDDEN,
                "TEAM_REQUIRES_MANAGEMENT",
                "the team page requires the owner or admin role",
            );
        }
    }
    next.run(req).await
}

/// v1.50 — route-level ownership guard for the tenant-scoped admin
/// sub-routers (`tenants_router` + `admin_tenant_files_router`). Reads the
/// `{id}` path param; routes on the same router without one (host-wide
/// listings, `/admin/audit`, …) pass through untouched. Denies — and missing
/// tenants — get the SAME 404 "no such tenant" so a member cannot probe for
/// a foreign tenant's existence. Independent second line of defense next to
/// the `ensure_tenant_visible` handler choke point (DiD ≥ 2).
///
/// Layer order: mounted on the sub-router, so it runs AFTER (inner to)
/// `admin_session_layer` + `admin_profile_layer` — both extensions are
/// already populated. Missing extensions fail closed (treated as member /
/// denied).
pub async fn tenant_ownership_layer(
    axum::extract::State(state): axum::extract::State<TenantOwnershipLayerState>,
    params: axum::extract::RawPathParams,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let tenant_id = params
        .iter()
        .find(|(k, _)| *k == "id")
        .map(|(_, v)| v.to_string());
    let Some(tenant_id) = tenant_id else {
        return next.run(req).await; // non-tenant-scoped route
    };
    let sees_all = req
        .extensions()
        .get::<crate::mgmt::admin_profile::AdminProfileExt>()
        .map(|p| sees_all_tenants(&p.role))
        .unwrap_or(false); // no profile → treat as member, fail-closed
    let caller = req
        .extensions()
        .get::<crate::auth::middleware::AdminId>()
        .map(|a| a.0);
    let Some(caller) = caller else {
        return crate::error::json_error(
            axum::http::StatusCode::NOT_FOUND,
            "TENANT_NOT_FOUND",
            "no such tenant",
        );
    };
    let owner: Result<Option<i64>, _> = {
        let conn = state.meta.lock().await;
        conn.query_row(
            "SELECT owner_admin_id FROM tenants WHERE id = ?1 AND deleted_at IS NULL",
            rusqlite::params![tenant_id],
            |r| r.get(0),
        )
    };
    match owner {
        Ok(o) if tenant_access_for(sees_all, caller, o) == TenantAccess::Allow => {
            next.run(req).await
        }
        // Missing tenant, soft-deleted, or member-not-owned: same 404 JSON
        // envelope (TENANT_NOT_FOUND) — no existence oracle, and matches the
        // canonical error shape the fronted handlers used to return.
        _ => crate::error::json_error(
            axum::http::StatusCode::NOT_FOUND,
            "TENANT_NOT_FOUND",
            "no such tenant",
        ),
    }
}

// ─── MCP OAuth callers (grant-anchored) ──────────────────────────────────────

/// Grant-anchored: re-validates the grant (unrevoked, inside idle and absolute)
/// and the admin (id AND created_at) on every check.
const SQL_TENANT_ACCESS_FOR_ADMIN: &str = "\
SELECT a.role, t.id, t.owner_admin_id, t.created_at
  FROM _mcp_oauth_grants g
  JOIN admins a ON a.id = g.admin_id AND a.created_at = g.admin_created_at
  LEFT JOIN tenants t ON t.id = ?3 AND t.deleted_at IS NULL
 WHERE g.id = ?1 AND g.admin_id = ?2 AND g.revoked_at IS NULL
   AND g.idle_expires_at > datetime('now') AND g.absolute_expires_at > datetime('now')";

const SQL_ROLE_FOR_GRANT: &str = "\
SELECT a.role
  FROM _mcp_oauth_grants g
  JOIN admins a ON a.id = g.admin_id AND a.created_at = g.admin_created_at
 WHERE g.id = ?1 AND g.admin_id = ?2 AND g.revoked_at IS NULL
   AND g.idle_expires_at > datetime('now') AND g.absolute_expires_at > datetime('now')";

/// Which incarnation of a tenant a check admitted: its owner and its
/// `created_at`, so a later check can tell a soft delete or an id recycle by
/// another owner from the tenant it first saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TenantIncarnation {
    pub owner: Option<i64>,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AdminTenantAccess {
    Allow(TenantIncarnation),
    Deny,
}

/// Tenant visibility for an MCP OAuth caller, anchored on its grant: one of
/// the sites of the shared ownership predicate (`tenant_access_for`, CLAUDE.md
/// invariant 7). Fails closed: no live grant/admin row or no live tenant row is
/// `Deny`, and a query error is returned as `Err` for the caller to map to an
/// internal error — never to Allow, and never through `read_pat_reach`, whose
/// failure direction is host-wide.
pub(crate) fn tenant_access_for_admin(
    conn: &rusqlite::Connection,
    grant_id: i64,
    admin_id: i64,
    tenant_id: &str,
) -> rusqlite::Result<AdminTenantAccess> {
    use rusqlite::OptionalExtension;
    let row: Option<(String, Option<String>, Option<i64>, Option<String>)> = conn
        .query_row(
            SQL_TENANT_ACCESS_FOR_ADMIN,
            rusqlite::params![grant_id, admin_id, tenant_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    let Some((role, id, owner, created_at)) = row else {
        return Ok(AdminTenantAccess::Deny); // no live grant/admin
    };
    // Under the LEFT JOIN a missing or soft-deleted tenant and an orphan both
    // carry a NULL owner; only `t.id` tells them apart, and a sees-all role
    // would otherwise be allowed into a tenant that does not exist.
    if id.is_none() {
        return Ok(AdminTenantAccess::Deny);
    }
    match tenant_access_for(sees_all_tenants(&role), admin_id, owner) {
        TenantAccess::Allow => Ok(AdminTenantAccess::Allow(TenantIncarnation {
            owner,
            created_at: created_at.unwrap_or_default(),
        })),
        TenantAccess::Deny => Ok(AdminTenantAccess::Deny),
    }
}

/// One live tenant as an MCP OAuth caller's tenant list shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TenantSummary {
    pub id: String,
    pub name: String,
    pub created_at: String,
}

/// The caller's role and the live tenants it can see, sorted by id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VisibleTenants {
    pub role: String,
    pub tenants: Vec<TenantSummary>,
}

/// The tenant list an MCP OAuth caller can see, with the same predicate and
/// the same grant anchor as `tenant_access_for_admin`. `None` means the grant
/// or its admin is no longer valid.
pub(crate) fn visible_tenants_for_admin(
    conn: &rusqlite::Connection,
    grant_id: i64,
    admin_id: i64,
) -> rusqlite::Result<Option<VisibleTenants>> {
    use rusqlite::OptionalExtension;
    let role: Option<String> = conn
        .query_row(
            SQL_ROLE_FOR_GRANT,
            rusqlite::params![grant_id, admin_id],
            |r| r.get(0),
        )
        .optional()?;
    let Some(role) = role else {
        return Ok(None);
    };
    let sees_all = sees_all_tenants(&role);
    let sql = format!(
        "SELECT id, name, created_at FROM tenants WHERE deleted_at IS NULL{} ORDER BY id",
        visibility_where(sees_all)
    );
    let mut stmt = conn.prepare(&sql)?;
    let map = |r: &rusqlite::Row<'_>| {
        Ok(TenantSummary {
            id: r.get(0)?,
            name: r.get(1)?,
            created_at: r.get(2)?,
        })
    };
    let tenants = if sees_all {
        stmt.query_map([], map)?
            .collect::<rusqlite::Result<Vec<_>>>()?
    } else {
        stmt.query_map([admin_id], map)?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    Ok(Some(VisibleTenants { role, tenants }))
}

/// The grant-and-admin liveness conditions every grant-anchored query must
/// carry, alias-free, in step with `find_grant_by_access` in the MCP OAuth
/// store. Each such query has a test asserting it contains all of them, so a
/// new invalidation condition cannot reach the auth layer without reaching
/// the per-call checks too.
#[cfg(test)]
pub(crate) const GRANT_LIVE_CLAUSES: [&str; 5] = [
    ".id = g.admin_id",
    ".created_at = g.admin_created_at",
    "g.revoked_at IS NULL",
    "g.idle_expires_at > datetime('now')",
    "g.absolute_expires_at > datetime('now')",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_capabilities() {
        for (role, all, mem, priv_, team) in [
            ("owner", true, true, true, true),
            ("admin", true, true, false, true),
            ("member", false, false, false, false),
            ("bogus", false, false, false, false), // unknown → nothing
        ] {
            assert_eq!(sees_all_tenants(role), all, "{role} sees_all");
            assert_eq!(can_manage_members(role), mem, "{role} manage_members");
            assert_eq!(
                can_manage_privileged(role),
                priv_,
                "{role} manage_privileged"
            );
            assert_eq!(sees_team_page(role), team, "{role} sees_team");
        }
    }

    #[test]
    fn admin_sees_all_like_owner() {
        // admin passes sees_all=true → Allow on owned, foreign, and orphan.
        assert_eq!(tenant_access_for(true, 5, Some(2)), TenantAccess::Allow); // foreign
        assert_eq!(tenant_access_for(true, 5, None), TenantAccess::Allow); // orphan
        // member (sees_all=false) unchanged.
        assert_eq!(tenant_access_for(false, 5, Some(2)), TenantAccess::Deny);
    }

    // owner × {owned, foreign, NULL} → Allow ×3
    #[test]
    fn owner_sees_owned_tenant() {
        assert_eq!(tenant_access_for(true, 1, Some(1)), TenantAccess::Allow);
    }

    #[test]
    fn owner_sees_foreign_tenant() {
        assert_eq!(tenant_access_for(true, 1, Some(2)), TenantAccess::Allow);
    }

    #[test]
    fn owner_sees_orphan_tenant() {
        assert_eq!(tenant_access_for(true, 1, None), TenantAccess::Allow);
    }

    // member × owned → Allow
    #[test]
    fn member_sees_owned_tenant() {
        assert_eq!(tenant_access_for(false, 2, Some(2)), TenantAccess::Allow);
    }

    // member × {foreign, NULL} → Deny
    #[test]
    fn member_denied_foreign_tenant() {
        assert_eq!(tenant_access_for(false, 2, Some(1)), TenantAccess::Deny);
    }

    #[test]
    fn member_denied_orphan_tenant() {
        assert_eq!(tenant_access_for(false, 2, None), TenantAccess::Deny);
    }

    // visibility_where two states
    #[test]
    fn visibility_where_owner_is_empty() {
        assert_eq!(visibility_where(true), "");
    }

    #[test]
    fn visibility_where_member_binds_owner() {
        assert_eq!(visibility_where(false), " AND owner_admin_id = ?");
    }
}

#[cfg(test)]
mod admin_access_tests {
    use super::*;
    use rusqlite::{Connection, params};

    struct Ids {
        owner: i64,
        admin: i64,
        member: i64,
        bogus: i64,
        g_owner: i64,
        g_admin: i64,
        g_member: i64,
        g_bogus: i64,
    }

    const ALL: [&str; 6] = [
        "a-foreign",
        "b-orphan",
        "c-mine",
        "d-gone",
        "e-bogus",
        "z-missing",
    ];

    fn grant_for(conn: &Connection, admin_id: i64) -> i64 {
        conn.execute(
            "INSERT INTO _mcp_oauth_grants \
               (admin_id, admin_created_at, client_id, redirect_host, \
                idle_expires_at, absolute_expires_at) \
             SELECT id, created_at, 'c', 'localhost', \
                    datetime('now', '+30 days'), datetime('now', '+90 days') \
               FROM admins WHERE id = ?1",
            params![admin_id],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    /// owner / admin / member / an unknown role "bogus"; tenants:
    /// a-foreign (owner), b-orphan (NULL), c-mine (member),
    /// d-gone (member, soft-deleted), e-bogus (bogus).
    fn fixture(dir: &std::path::Path) -> (Connection, Ids) {
        let conn = crate::storage::meta::open_meta(&dir.join("meta.sqlite")).unwrap();
        crate::db::migrations::run_migrations(&conn, dir).unwrap();
        let id = |u: &str, role: &str| {
            conn.execute(
                "INSERT INTO admins (username, password_hash, role) VALUES (?1, '$oauth-only$', ?2)",
                params![u, role],
            )
            .unwrap();
            conn.last_insert_rowid()
        };
        let (owner, admin, member, bogus) = (
            id("u_owner", "owner"),
            id("u_admin", "admin"),
            id("u_member", "member"),
            id("u_bogus", "bogus"),
        );
        for (t, o, deleted) in [
            ("a-foreign", Some(owner), false),
            ("b-orphan", None, false),
            ("c-mine", Some(member), false),
            ("d-gone", Some(member), true),
            ("e-bogus", Some(bogus), false),
        ] {
            conn.execute(
                "INSERT INTO tenants (id, name, owner_admin_id, deleted_at) \
                 VALUES (?1, ?1, ?2, CASE WHEN ?3 THEN datetime('now') END)",
                params![t, o, deleted],
            )
            .unwrap();
        }
        let ids = Ids {
            owner,
            admin,
            member,
            bogus,
            g_owner: grant_for(&conn, owner),
            g_admin: grant_for(&conn, admin),
            g_member: grant_for(&conn, member),
            g_bogus: grant_for(&conn, bogus),
        };
        (conn, ids)
    }

    fn allowed(conn: &Connection, g: i64, a: i64, t: &str) -> bool {
        matches!(
            tenant_access_for_admin(conn, g, a, t).unwrap(),
            AdminTenantAccess::Allow(_)
        )
    }

    fn roles(i: &Ids) -> [(&'static str, i64, i64); 4] {
        [
            ("owner", i.g_owner, i.owner),
            ("admin", i.g_admin, i.admin),
            ("member", i.g_member, i.member),
            ("bogus", i.g_bogus, i.bogus),
        ]
    }

    #[test]
    fn admin_access_truth_table() {
        let dir = tempfile::tempdir().unwrap();
        let (c, i) = fixture(dir.path());
        let visible: [&[&str]; 4] = [
            &["a-foreign", "b-orphan", "c-mine", "e-bogus"], // owner
            &["a-foreign", "b-orphan", "c-mine", "e-bogus"], // admin
            &["c-mine"],                                     // member
            &["e-bogus"],                                    // unknown role reads as member
        ];
        for ((who, g, a), vis) in roles(&i).into_iter().zip(visible) {
            for t in ALL {
                assert_eq!(allowed(&c, g, a, t), vis.contains(&t), "{who} × {t}");
            }
        }
    }

    #[test]
    fn a_missing_tenant_is_denied_even_for_sees_all() {
        let dir = tempfile::tempdir().unwrap();
        let (c, i) = fixture(dir.path());
        assert_eq!(
            tenant_access_for_admin(&c, i.g_owner, i.owner, "z-missing").unwrap(),
            AdminTenantAccess::Deny
        );
        assert_eq!(
            tenant_access_for_admin(&c, i.g_owner, i.owner, "d-gone").unwrap(),
            AdminTenantAccess::Deny
        );
    }

    #[test]
    fn allow_carries_owner_and_created_at() {
        let dir = tempfile::tempdir().unwrap();
        let (c, i) = fixture(dir.path());
        let ca: String = c
            .query_row(
                "SELECT created_at FROM tenants WHERE id = 'c-mine'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            tenant_access_for_admin(&c, i.g_member, i.member, "c-mine").unwrap(),
            AdminTenantAccess::Allow(TenantIncarnation {
                owner: Some(i.member),
                created_at: ca
            })
        );
        let AdminTenantAccess::Allow(orphan) =
            tenant_access_for_admin(&c, i.g_owner, i.owner, "b-orphan").unwrap()
        else {
            panic!("orphan")
        };
        assert_eq!(orphan.owner, None);
    }

    #[test]
    fn a_revoked_or_expired_grant_denies_every_tenant() {
        for sql in [
            "UPDATE _mcp_oauth_grants SET revoked_at = datetime('now') WHERE id = ?1",
            "UPDATE _mcp_oauth_grants SET idle_expires_at = datetime('now', '-1 second') WHERE id = ?1",
            "UPDATE _mcp_oauth_grants SET absolute_expires_at = datetime('now', '-1 second') WHERE id = ?1",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let (c, i) = fixture(dir.path());
            c.execute(sql, params![i.g_owner]).unwrap();
            for t in ["a-foreign", "b-orphan", "c-mine"] {
                assert!(!allowed(&c, i.g_owner, i.owner, t), "{sql} × {t}");
            }
            assert!(
                visible_tenants_for_admin(&c, i.g_owner, i.owner)
                    .unwrap()
                    .is_none(),
                "{sql}"
            );
        }
    }

    #[test]
    fn a_grant_whose_admin_no_longer_matches_is_denied() {
        let dir = tempfile::tempdir().unwrap();
        let (c, i) = fixture(dir.path());
        // wrong admin id for this grant
        assert!(!allowed(&c, i.g_member, i.owner, "c-mine"));
        // admins rowid recycled: created_at no longer equals the grant's admin_created_at
        c.execute(
            "UPDATE admins SET created_at = '2000-01-01 00:00:00' WHERE id = ?1",
            params![i.member],
        )
        .unwrap();
        assert!(!allowed(&c, i.g_member, i.member, "c-mine"));
        assert!(
            visible_tenants_for_admin(&c, i.g_member, i.member)
                .unwrap()
                .is_none()
        );
        // admin row removed
        c.execute("DELETE FROM admins WHERE id = ?1", params![i.admin])
            .unwrap();
        assert!(!allowed(&c, i.g_admin, i.admin, "a-foreign"));
    }

    #[test]
    fn a_query_failure_is_an_error_not_a_deny() {
        let c = Connection::open_in_memory().unwrap(); // no schema at all
        assert!(tenant_access_for_admin(&c, 1, 1, "c-mine").is_err());
        assert!(visible_tenants_for_admin(&c, 1, 1).is_err());
    }

    /// The list and the single-tenant check must admit exactly the same set for
    /// every role: the list is cross-checked against the check, not against a
    /// second hand-written expectation.
    #[test]
    fn visible_tenants_follow_the_same_predicate() {
        let dir = tempfile::tempdir().unwrap();
        let (c, i) = fixture(dir.path());
        for (who, g, a) in roles(&i) {
            let v = visible_tenants_for_admin(&c, g, a)
                .unwrap()
                .expect("live grant");
            assert_eq!(v.role, who);
            let listed: Vec<String> = v.tenants.iter().map(|t| t.id.clone()).collect();
            let checked: Vec<String> = ALL
                .iter()
                .filter(|t| allowed(&c, g, a, t))
                .map(|t| t.to_string())
                .collect();
            assert_eq!(listed, checked, "{who}: list and check diverge");
        }
        let one = visible_tenants_for_admin(&c, i.g_member, i.member)
            .unwrap()
            .unwrap()
            .tenants
            .remove(0);
        assert_eq!(one.name, "c-mine");
        assert_eq!(
            one.created_at.len(),
            19,
            "datetime('now') text: {}",
            one.created_at
        );
    }

    #[test]
    fn grant_anchored_queries_carry_every_liveness_clause() {
        for (name, sql) in [
            ("tenant access", SQL_TENANT_ACCESS_FOR_ADMIN),
            ("role for grant", SQL_ROLE_FOR_GRANT),
            (
                "store access lookup",
                crate::mgmt::mcp_oauth::store::SQL_FIND_BY_ACCESS,
            ),
        ] {
            for clause in GRANT_LIVE_CLAUSES {
                assert!(sql.contains(clause), "{name} query lacks `{clause}`");
            }
        }
    }
}
