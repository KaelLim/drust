use crate::storage::garage::GarageClient;
use crate::storage::pool::{SharedTenantPool, TenantRegistry};
use crate::tenant::events::EventBus;
use dashmap::DashMap;
use std::sync::Arc;

/// Per-tenant MCP state bundling the connection pool, the event bus, the
/// tenant id, and (optionally) a Garage client + the public base URL
/// used by the Y-scope file tools. Tool handlers receive a reference
/// to this struct.
#[derive(Clone)]
pub struct DrustMcpInner {
    pub tenant_id: String,
    pub pool: SharedTenantPool,
    pub bus: EventBus,
    pub garage: Option<Arc<GarageClient>>,
    pub public_base_url: String,
    pub url_sign_secret: Arc<[u8; 32]>,
}

/// Newtype so we can hand out `Arc` without exposing the inner struct.
#[derive(Clone)]
pub struct DrustMcp {
    inner: Arc<DrustMcpInner>,
}

impl DrustMcp {
    pub fn new(
        tenant_id: &str,
        pool: SharedTenantPool,
        bus: EventBus,
        garage: Option<Arc<GarageClient>>,
        public_base_url: String,
        url_sign_secret: Arc<[u8; 32]>,
    ) -> Self {
        Self {
            inner: Arc::new(DrustMcpInner {
                tenant_id: tenant_id.to_string(),
                pool,
                bus,
                garage,
                public_base_url,
                url_sign_secret,
            }),
        }
    }
    pub fn inner(&self) -> Arc<DrustMcpInner> {
        self.inner.clone()
    }
    pub fn tenant_id(&self) -> &str {
        &self.inner.tenant_id
    }
    pub fn garage(&self) -> Option<&Arc<GarageClient>> {
        self.inner.garage.as_ref()
    }
    pub fn public_base_url(&self) -> &str {
        &self.inner.public_base_url
    }
    pub fn url_sign_secret(&self) -> &[u8; 32] {
        &self.inner.url_sign_secret
    }
}

/// Lazy cache of per-tenant MCP services. Entries are evicted when a tenant is
/// soft-deleted (call `evict`). The cache shares the global `TenantRegistry`
/// for pool lookup so writer/reader connections stay consistent across
/// REST and MCP paths.
pub struct McpRegistry {
    tenants: Arc<TenantRegistry>,
    bus: EventBus,
    garage: Option<Arc<GarageClient>>,
    public_base_url: String,
    url_sign_secret: Arc<[u8; 32]>,
    services: DashMap<String, DrustMcp>,
}

impl McpRegistry {
    pub fn new(tenants: Arc<TenantRegistry>) -> Self {
        Self {
            tenants,
            bus: EventBus::new(),
            garage: None,
            public_base_url: String::new(),
            url_sign_secret: Arc::new([0u8; 32]),
            services: DashMap::new(),
        }
    }
    pub fn with_bus(tenants: Arc<TenantRegistry>, bus: EventBus) -> Self {
        Self {
            tenants,
            bus,
            garage: None,
            public_base_url: String::new(),
            url_sign_secret: Arc::new([0u8; 32]),
            services: DashMap::new(),
        }
    }
    pub fn with_bus_and_storage(
        tenants: Arc<TenantRegistry>,
        bus: EventBus,
        garage: Option<Arc<GarageClient>>,
        public_base_url: String,
        url_sign_secret: Arc<[u8; 32]>,
    ) -> Self {
        Self {
            tenants,
            bus,
            garage,
            public_base_url,
            url_sign_secret,
            services: DashMap::new(),
        }
    }
    pub async fn get_or_create(&self, tenant_id: &str) -> anyhow::Result<DrustMcp> {
        if let Some(s) = self.services.get(tenant_id) {
            return Ok(s.clone());
        }
        let pool = self.tenants.get_or_open(tenant_id)?;
        let svc = DrustMcp::new(
            tenant_id,
            pool,
            self.bus.clone(),
            self.garage.clone(),
            self.public_base_url.clone(),
            self.url_sign_secret.clone(),
        );
        self.services.insert(tenant_id.to_string(), svc.clone());
        Ok(svc)
    }
    pub fn evict(&self, tenant_id: &str) {
        self.services.remove(tenant_id);
    }
}
