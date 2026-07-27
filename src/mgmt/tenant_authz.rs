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
