//! v1.50 — single ownership predicate shared by every enforcement site
//! (list filter, route guard, ensure_tenant_visible, PAT CTE deny).

#[derive(Debug, PartialEq, Eq)]
pub enum TenantAccess {
    Allow,
    Deny,
}

pub fn tenant_access_for(
    is_owner: bool,
    caller_admin_id: i64,
    tenant_owner: Option<i64>,
) -> TenantAccess {
    if is_owner {
        return TenantAccess::Allow; // owner: global reach, incl. NULL (orphaned) tenants
    }
    match tenant_owner {
        Some(o) if o == caller_admin_id => TenantAccess::Allow,
        _ => TenantAccess::Deny, // foreign or NULL → invisible to a member
    }
}

/// SQL fragment appended to a `WHERE deleted_at IS NULL` tenant listing.
/// Owner → no extra clause; member → caller binds their admin id for the `?`.
pub fn visibility_where(is_owner: bool) -> &'static str {
    if is_owner {
        ""
    } else {
        " AND owner_admin_id = ?"
    }
}

// ─── route-layer guard middleware ────────────────────────────────────────────

use axum::response::IntoResponse;

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
    let is_owner = req
        .extensions()
        .get::<crate::mgmt::admin_profile::AdminProfileExt>()
        .map(|p| p.is_owner)
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
        Ok(o) if tenant_access_for(is_owner, caller, o) == TenantAccess::Allow => {
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

#[cfg(test)]
mod tests {
    use super::*;

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
