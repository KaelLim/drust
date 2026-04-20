use crate::storage::pool::{SharedTenantPool, TenantRegistry};
use crate::tenant::events::EventBus;
use dashmap::DashMap;
use std::sync::Arc;

/// Per-tenant MCP state bundling the connection pool, the event bus, and the
/// tenant id. Tool handlers receive a reference to this struct.
#[derive(Clone)]
pub struct DrustMcpInner {
    pub tenant_id: String,
    pub pool: SharedTenantPool,
    pub bus: EventBus,
}

/// Newtype so we can hand out `Arc` without exposing the inner struct.
#[derive(Clone)]
pub struct DrustMcp {
    inner: Arc<DrustMcpInner>,
}

impl DrustMcp {
    pub fn new(tenant_id: &str, pool: SharedTenantPool, bus: EventBus) -> Self {
        Self {
            inner: Arc::new(DrustMcpInner {
                tenant_id: tenant_id.to_string(),
                pool,
                bus,
            }),
        }
    }
    pub fn inner(&self) -> Arc<DrustMcpInner> {
        self.inner.clone()
    }
}

/// Lazy cache of per-tenant MCP services. Entries are evicted when a tenant is
/// soft-deleted (call `evict`). The cache shares the global `TenantRegistry`
/// for pool lookup so writer/reader connections stay consistent across
/// REST and MCP paths.
pub struct McpRegistry {
    tenants: Arc<TenantRegistry>,
    bus: EventBus,
    services: DashMap<String, DrustMcp>,
}

impl McpRegistry {
    pub fn new(tenants: Arc<TenantRegistry>) -> Self {
        Self {
            tenants,
            bus: EventBus::new(),
            services: DashMap::new(),
        }
    }
    pub fn with_bus(tenants: Arc<TenantRegistry>, bus: EventBus) -> Self {
        Self {
            tenants,
            bus,
            services: DashMap::new(),
        }
    }
    pub async fn get_or_create(&self, tenant_id: &str) -> anyhow::Result<DrustMcp> {
        if let Some(s) = self.services.get(tenant_id) {
            return Ok(s.clone());
        }
        let pool = self.tenants.get_or_open(tenant_id)?;
        let svc = DrustMcp::new(tenant_id, pool, self.bus.clone());
        self.services.insert(tenant_id.to_string(), svc.clone());
        Ok(svc)
    }
    pub fn evict(&self, tenant_id: &str) {
        self.services.remove(tenant_id);
    }
}
