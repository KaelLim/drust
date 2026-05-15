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
    StreamableHttpService, session::local::LocalSessionManager,
};
use std::sync::Arc;
use std::time::Duration;

/// rmcp's default keep_alive is 5 minutes — way too aggressive for an
/// interactive CC session that may go idle while the user reads code or
/// runs a build. 24h survives a typical workday; CC restarts (1–2/day)
/// give us a natural GC cycle, so zombie sessions don't accumulate.
const SESSION_KEEP_ALIVE: Duration = Duration::from_secs(86_400);

pub type TenantMcpService = StreamableHttpService<DrustMcpService, LocalSessionManager>;

pub struct McpHttpRegistry {
    mcp: Arc<McpRegistry>,
    services: DashMap<String, Arc<TenantMcpService>>,
}

impl McpHttpRegistry {
    pub fn new(mcp: Arc<McpRegistry>) -> Self {
        Self {
            mcp,
            services: DashMap::new(),
        }
    }

    /// Return (or lazily construct) the MCP Streamable HTTP service for
    /// a given tenant. The inner `McpRegistry` owns the authoritative
    /// `DrustMcp` per tenant; this registry holds the rmcp-side wrapper
    /// so repeated sessions for the same tenant hit a hot cache.
    pub async fn get_or_create(&self, tenant_id: &str) -> anyhow::Result<Arc<TenantMcpService>> {
        if let Some(s) = self.services.get(tenant_id) {
            return Ok(s.clone());
        }
        let state = self.mcp.get_or_create(tenant_id).await?;
        let mut mgr = LocalSessionManager::default();
        mgr.session_config.keep_alive = Some(SESSION_KEEP_ALIVE);
        let svc = Arc::new(StreamableHttpService::new(
            move || Ok(DrustMcpService::new(state.clone())),
            Arc::new(mgr),
            Default::default(),
        ));
        self.services.insert(tenant_id.to_string(), svc.clone());
        Ok(svc)
    }

    /// Drop a tenant's service (called on soft-delete).
    pub fn evict(&self, tenant_id: &str) {
        self.services.remove(tenant_id);
    }

    /// How many tenants are currently cached. Test/observability hook.
    pub fn cached_count(&self) -> usize {
        self.services.len()
    }
}
