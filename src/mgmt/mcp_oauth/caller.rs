//! The caller of one account-level MCP request, carried in its request
//! extensions. AUTHORIZATION strength: its only production constructor is
//! `from_access`, whose argument only `store::find_grant_by_access` can
//! produce (both constructions are pinned). There is no `Default`: a request
//! without one must fail closed, never fall back to a placeholder identity.
//!
//! It carries no role and no tenant reach: visibility is decided on every
//! call by a grant-anchored query, so a demotion, owner transfer, grant
//! revoke or admin removal applies to the next call. Never decide
//! visibility or role from `admin_id()` alone (admin ids are recycled);
//! anchor on `grant_id()`.

use std::sync::Arc;

use crate::mgmt::mcp_oauth::store::AccessGrant;

#[derive(Clone)]
pub struct McpCaller {
    admin_id: i64,
    grant_id: i64,
    admin_label: Arc<str>,
}

impl McpCaller {
    // Allowed until the resource-server layer calls it.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn from_access(g: &AccessGrant) -> Self {
        McpCaller {
            admin_id: g.admin_id(),
            grant_id: g.grant_id(),
            admin_label: Arc::from(g.admin_label()),
        }
    }

    pub fn admin_id(&self) -> i64 {
        self.admin_id
    }

    pub fn grant_id(&self) -> i64 {
        self.grant_id
    }

    /// `COALESCE(email, username)` of the grant's admin.
    pub fn admin_label(&self) -> &str {
        &self.admin_label
    }
}

#[cfg(test)]
impl McpCaller {
    /// Lib tests only. Integration tests get a real token through
    /// `store::seed_access_for_tests` instead.
    pub(crate) fn for_tests(admin_id: i64, grant_id: i64) -> Self {
        McpCaller {
            admin_id,
            grant_id,
            admin_label: Arc::from("admin@example.test"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mgmt::mcp_oauth::store;
    use crate::tenant::rooms::srcpin::{code_only, prod_fn_body, production_half};

    #[test]
    fn from_access_copies_the_proven_identity() {
        let dir = tempfile::tempdir().unwrap();
        let conn = crate::storage::meta::open_meta(&dir.path().join("meta.sqlite")).unwrap();
        conn.execute(
            "INSERT INTO admins (username, password_hash, email) \
             VALUES ('owner', '$oauth-only$', 'owner@example.test')",
            [],
        )
        .unwrap();
        let admin = conn.last_insert_rowid();
        let s = store::seed_access_for_tests(&conn, admin).unwrap();
        let g = store::find_grant_by_access(&conn, &s.access)
            .unwrap()
            .unwrap();
        let c = McpCaller::from_access(&g);
        assert_eq!((c.admin_id(), c.grant_id()), (admin, s.grant_id));
        assert_eq!(c.admin_label(), "owner@example.test");
        let d = c.clone();
        assert_eq!(
            (d.admin_id(), d.grant_id(), d.admin_label()),
            (admin, s.grant_id, "owner@example.test")
        );
    }

    /// `Extensions::insert` itself requires Clone + Send + Sync + 'static, so
    /// this compiles only if McpCaller has them.
    #[test]
    fn fits_in_request_extensions() {
        let mut ext = axum::http::Extensions::new();
        ext.insert(McpCaller::for_tests(5, 9));
        let got = ext.get::<McpCaller>().expect("inserted");
        assert_eq!(
            (got.admin_id(), got.grant_id(), got.admin_label()),
            (5, 9, "admin@example.test")
        );
    }

    /// No Default and no Debug: a missing caller must fail closed, and the label
    /// is an email.
    #[test]
    fn derives_only_clone() {
        let stripped = code_only(include_str!("caller.rs"));
        let prod = production_half(&stripped);
        assert!(prod.contains("#[derive(Clone)]"), "anti-vacuous");
        for t in ["Default", "Debug", "PartialEq"] {
            assert!(!prod.contains(t), "McpCaller must not have {t}");
        }
    }

    /// Field privacy stops construction outside this file; this pin stops a
    /// second constructor inside it.
    #[test]
    fn from_access_is_the_only_constructor() {
        const WHY: &str = "a McpCaller built outside from_access bypasses the \
                           authorization-strength lookup";
        let stripped = code_only(include_str!("caller.rs"));
        let prod = production_half(&stripped);
        // The three legitimate occurrences: the struct, its impl, the one literal.
        assert_eq!(
            prod.matches("pub struct McpCaller {").count(),
            1,
            "anti-vacuous"
        );
        assert_eq!(prod.matches("impl McpCaller {").count(), 1, "anti-vacuous");
        assert_eq!(prod.matches("McpCaller {").count(), 3, "{WHY}");
        let body = prod_fn_body(
            &stripped,
            "pub(crate) fn from_access(g: &AccessGrant) -> Self {",
        );
        assert_eq!(body.matches("McpCaller {").count(), 1, "{WHY}");
        // The one `Self {` is the `-> Self {` that opens from_access itself; a
        // `Self { .. }` literal anywhere would be a second.
        assert_eq!(prod.matches("Self {").count(), 1, "{WHY}");
        assert_eq!(prod.matches("-> Self").count(), 1, "{WHY}");
    }

    /// No role and no tenant reach: visibility is decided on every call by a
    /// grant-anchored query, and admin ids are recycled.
    #[test]
    fn carries_exactly_three_fields() {
        let stripped = code_only(include_str!("caller.rs"));
        let body = prod_fn_body(&stripped, "pub struct McpCaller {");
        let fields: Vec<&str> = body
            .lines()
            .skip(1)
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect();
        assert_eq!(
            fields,
            ["admin_id: i64,", "grant_id: i64,", "admin_label: Arc<str>,"],
            "adding a field (a role, a tenant list) would cache what must be re-decided per call"
        );
    }
}
