//! Per-tenant cache of `StreamableHttpService` instances.
//!
//! rmcp's Streamable HTTP transport is stateful per handler instance
//! (session IDs live on `LocalSessionManager`). We must therefore pin
//! one service per tenant — mixing tenants on a single service would
//! cross-contaminate session state and defeat the whole per-tenant
//! isolation model.
//!
//! The factory closure handed to `StreamableHttpService::new` runs
//! once per new MCP session, so it captures the tenant's `DrustMcp`
//! state by clone. The resulting service is itself cheaply cloneable
//! (three `Arc` clones, per rmcp's own impl).

use crate::mcp::handler::DrustMcpService;
use crate::mcp::server::McpRegistry;
use dashmap::DashMap;
use rmcp::transport::streamable_http_server::{
    SessionManager, StreamableHttpService, session::local::LocalSessionManager,
};
use std::sync::Arc;
use std::time::Duration;

/// rmcp's default keep_alive is 5 minutes — way too aggressive for an
/// interactive CC session that may go idle while the user reads code or
/// runs a build. 24h survives a typical workday; CC restarts (1–2/day)
/// give us a natural GC cycle, so zombie sessions don't accumulate.
const SESSION_KEEP_ALIVE: Duration = Duration::from_secs(86_400);

pub type TenantMcpService = StreamableHttpService<DrustMcpService, LocalSessionManager>;

/// One cached tenant service plus the session manager it was built on.
/// The manager is kept so `evict` can END live sessions: each rmcp session
/// task holds its own `Arc` of the manager and its own `DrustMcpService`
/// (→ `DrustMcp` → `Arc<TenantPool>`), so dropping the service alone leaves
/// the old pool open until the 24 h idle timeout.
struct CachedService {
    svc: Arc<TenantMcpService>,
    sessions: Arc<LocalSessionManager>,
}

pub struct McpHttpRegistry {
    mcp: Arc<McpRegistry>,
    services: DashMap<String, CachedService>,
}

impl McpHttpRegistry {
    pub fn new(mcp: Arc<McpRegistry>) -> Self {
        Self {
            mcp,
            services: DashMap::new(),
        }
    }

    /// The shared inner registry, for the account-level MCP router: one
    /// `McpRegistry` serves both endpoints.
    // Allowed until the account-level MCP router calls it.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn registry(&self) -> &Arc<McpRegistry> {
        &self.mcp
    }

    /// Return (or lazily construct) the MCP Streamable HTTP service for
    /// a given tenant. The inner `McpRegistry` owns the authoritative
    /// `DrustMcp` per tenant; this registry holds the rmcp-side wrapper
    /// so repeated sessions for the same tenant hit a hot cache.
    pub async fn get_or_create(&self, tenant_id: &str) -> anyhow::Result<Arc<TenantMcpService>> {
        if let Some(s) = self.services.get(tenant_id) {
            return Ok(s.svc.clone());
        }
        let state = self.mcp.get_or_create(tenant_id).await?;
        let mut mgr = LocalSessionManager::default();
        mgr.session_config.keep_alive = Some(SESSION_KEEP_ALIVE);
        let mgr = Arc::new(mgr);
        let svc = Arc::new(StreamableHttpService::new(
            move || Ok(DrustMcpService::new(state.clone())),
            mgr.clone(),
            Default::default(),
        ));
        self.services.insert(
            tenant_id.to_string(),
            CachedService {
                svc: svc.clone(),
                sessions: mgr,
            },
        );
        Ok(svc)
    }

    /// Retire a tenant's MCP state (soft-delete and id-recycle): the inner
    /// `DrustMcp` that holds the `Arc<TenantPool>`, the outer rmcp service, and
    /// every live session on it. Leaving any of these kept the old incarnation's
    /// SQLite connections open; after an id recycle the inner entry handed them
    /// to the new tenant, and a late close of an old pool unlinks the `-wal` /
    /// `-shm` PATHS that by then belong to the new database.
    ///
    /// Inner first, outer second. That narrows, but does not close, the race
    /// with a concurrent `get_or_create` (read → inner → insert, no lock held):
    /// a request that read the inner entry before this call can still insert a
    /// stale service after it. A soft-deleted tenant is unreachable, and an id
    /// recycle evicts again.
    ///
    /// Sessions are closed on a spawned task so nothing in the eviction sequence
    /// waits on a session worker (`close_session` sends on a bounded channel).
    pub fn evict(&self, tenant_id: &str) {
        self.mcp.evict(tenant_id);
        if let Some((_, cached)) = self.services.remove(tenant_id) {
            close_sessions_in_background(cached.sessions);
        }
    }

    /// How many tenants are currently cached. Test/observability hook.
    pub fn cached_count(&self) -> usize {
        self.services.len()
    }
}

/// End every session currently registered on `mgr`. Each closed session's
/// worker task finishes `serve_server` and drops its `DrustMcpService`, which
/// is what finally releases the evicted tenant's pool.
fn close_sessions_in_background(mgr: Arc<LocalSessionManager>) {
    // No runtime ⇒ no session task can exist either.
    let Ok(rt) = tokio::runtime::Handle::try_current() else {
        return;
    };
    rt.spawn(async move {
        let ids: Vec<_> = mgr.sessions.read().await.keys().cloned().collect();
        for id in ids {
            let _ = mgr.close_session(&id).await;
        }
    });
}

#[cfg(test)]
mod tests {
    //! E5 — eviction must reach the INNER `McpRegistry`, whose `DrustMcp`
    //! holds the `Arc<TenantPool>`. Every `get_or_create` return value is
    //! dropped at once (`let _ =`): binding it would keep the outer factory
    //! closure — and with it the `DrustMcp` — alive past the eviction.
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
    async fn evict_also_drops_the_inner_drust_mcp() {
        let (_d, _tenants, inner, http) = fixture();
        let _ = http.get_or_create("t1").await.unwrap();
        assert_eq!(http.cached_count(), 1);
        assert_eq!(inner.cached_count(), 1);
        http.evict("t1");
        assert_eq!(http.cached_count(), 0, "outer service not evicted");
        assert_eq!(inner.cached_count(), 0, "inner DrustMcp not evicted");
    }

    #[tokio::test]
    async fn evict_releases_the_tenant_pool() {
        let (_d, tenants, _inner, http) = fixture();
        let weak = Arc::downgrade(&tenants.get_or_create("t1").unwrap());
        let _ = http.get_or_create("t1").await.unwrap();
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
        let _ = http.get_or_create("t1").await.unwrap();
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
        let _ = http.get_or_create("t1").await.unwrap();
        let _ = http.get_or_create("t2").await.unwrap();
        let before = inner.get_or_create("t2").await.unwrap().inner();
        http.evict("t1");
        assert_eq!(inner.cached_count(), 1);
        assert_eq!(http.cached_count(), 1);
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
}
