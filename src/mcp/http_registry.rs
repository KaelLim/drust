//! The management plane's handle on the MCP state: one `McpRegistry`, shared
//! with the account-level endpoint (which builds a fresh `DrustMcp` per call
//! through `McpRegistry::build_live` and never reads the cache). `evict`
//! retires a tenant's cached entry on soft delete and id recycle.

use crate::mcp::server::McpRegistry;
use std::sync::Arc;

pub struct McpHttpRegistry {
    mcp: Arc<McpRegistry>,
}

impl McpHttpRegistry {
    pub fn new(mcp: Arc<McpRegistry>) -> Self {
        Self { mcp }
    }

    /// The shared inner registry, for the account-level MCP router.
    pub(crate) fn registry(&self) -> &Arc<McpRegistry> {
        &self.mcp
    }

    /// Retire a tenant's cached `DrustMcp` (the inner registry's entry, which
    /// holds the pool). Called on soft delete and id recycle: leaving it kept
    /// the old incarnation's SQLite connections open, after an id recycle it
    /// handed them to the new tenant, and a late close of an old pool unlinks
    /// the `-wal` / `-shm` PATHS that by then belong to the new database.
    pub fn evict(&self, tenant_id: &str) {
        self.mcp.evict(tenant_id);
    }
}

#[cfg(test)]
mod tests {
    //! E5 — eviction must reach the INNER `McpRegistry`, whose `DrustMcp`
    //! holds the `Arc<TenantPool>`. Every `get_or_create` return value is
    //! dropped at once (`let _ =`): binding it would keep the `DrustMcp`
    //! alive past the eviction.
    use super::*;
    use crate::storage::pool::TenantRegistry;

    fn fixture() -> (
        tempfile::TempDir,
        Arc<TenantRegistry>,
        Arc<McpRegistry>,
        McpHttpRegistry,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let tenants = Arc::new(TenantRegistry::new(dir.path().into(), 2));
        let _ = tenants.get_or_create("t1").unwrap();
        let inner = Arc::new(McpRegistry::new(tenants.clone()));
        let http = McpHttpRegistry::new(inner.clone());
        (dir, tenants, inner, http)
    }

    #[tokio::test]
    async fn evict_drops_the_inner_drust_mcp() {
        let (_d, _tenants, inner, http) = fixture();
        let _ = inner.get_or_create("t1").await.unwrap();
        assert_eq!(inner.cached_count(), 1);
        http.evict("t1");
        assert_eq!(inner.cached_count(), 0, "inner DrustMcp not evicted");
    }

    #[tokio::test]
    async fn evict_releases_the_tenant_pool() {
        let (_d, tenants, inner, http) = fixture();
        let weak = Arc::downgrade(&tenants.get_or_create("t1").unwrap());
        let _ = inner.get_or_create("t1").await.unwrap();
        tenants.evict("t1");
        http.evict("t1");
        assert!(
            weak.upgrade().is_none(),
            "the evicted tenant's pool is still held (connections + FDs stay open)"
        );
    }

    #[tokio::test]
    async fn rebuild_after_evict_uses_the_current_pool() {
        let (_d, tenants, inner, http) = fixture();
        let _ = inner.get_or_create("t1").await.unwrap();
        tenants.evict("t1");
        http.evict("t1");
        let p2 = tenants.get_or_create("t1").unwrap();
        let d = inner.get_or_create("t1").await.unwrap();
        assert!(
            Arc::ptr_eq(&d.inner().pool, &p2),
            "the rebuilt DrustMcp must use the registry's CURRENT pool"
        );
    }

    #[tokio::test]
    async fn evict_is_tenant_scoped() {
        let (_d, tenants, inner, http) = fixture();
        let _ = tenants.get_or_create("t2").unwrap();
        let _ = inner.get_or_create("t1").await.unwrap();
        let before = inner.get_or_create("t2").await.unwrap().inner();
        http.evict("t1");
        assert_eq!(inner.cached_count(), 1);
        let after = inner.get_or_create("t2").await.unwrap().inner();
        assert!(
            Arc::ptr_eq(&before, &after),
            "evicting t1 must not touch t2"
        );
    }

    #[test]
    fn registry_is_the_inner_registry() {
        let (_d, _tenants, inner, http) = fixture();
        assert!(Arc::ptr_eq(http.registry(), &inner));
    }

    #[test]
    fn the_registry_holds_no_per_tenant_service_of_its_own() {
        let src = include_str!("http_registry.rs");
        let prod = src.split(&format!("#[cfg({})]", "test")).next().unwrap();
        for needle in [
            concat!("Session", "Manager"),
            concat!("Streamable", "HttpService"),
            concat!("Dash", "Map"),
        ] {
            assert!(!prod.contains(needle), "{needle}");
        }
    }
}
