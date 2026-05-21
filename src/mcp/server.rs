use crate::storage::garage::GarageClient;
use crate::storage::pool::{SharedTenantPool, TenantRegistry};
use crate::tenant::events::EventBus;
use crate::tenant::WebhookDispatcher;
use dashmap::DashMap;
use rusqlite::Connection;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Per-tenant MCP state bundling the connection pool, the event bus, the
/// tenant id, and (optionally) a Garage client + the public base URL
/// used by the Y-scope file tools. Tool handlers receive a reference
/// to this struct.
///
/// `meta` is optional because the test-only `McpRegistry::new` /
/// `with_bus` constructors don't have a real meta.sqlite to hand in;
/// tools that need it (currently `whoami`) bail with a clear error
/// when it's absent.
#[derive(Clone)]
pub struct DrustMcpInner {
    pub tenant_id: String,
    pub pool: SharedTenantPool,
    pub bus: EventBus,
    pub webhooks: Arc<WebhookDispatcher>,
    pub garage: Option<Arc<GarageClient>>,
    pub public_base_url: String,
    pub url_sign_secret: Arc<[u8; 32]>,
    pub meta: Option<Arc<Mutex<Connection>>>,
    pub max_upload_bytes: usize,
    /// Row count threshold above which index creation is considered "large
    /// table" and returns `LARGE_TABLE` unless `force=true`. Sourced from
    /// `DRUST_INDEX_LARGE_TABLE_ROWS` (default 1 000 000).
    pub index_large_table_rows: u64,
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
        webhooks: Arc<WebhookDispatcher>,
        garage: Option<Arc<GarageClient>>,
        public_base_url: String,
        url_sign_secret: Arc<[u8; 32]>,
        meta: Option<Arc<Mutex<Connection>>>,
        max_upload_bytes: usize,
        index_large_table_rows: u64,
    ) -> Self {
        Self {
            inner: Arc::new(DrustMcpInner {
                tenant_id: tenant_id.to_string(),
                pool,
                bus,
                webhooks,
                garage,
                public_base_url,
                url_sign_secret,
                meta,
                max_upload_bytes,
                index_large_table_rows,
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
    pub fn meta(&self) -> Option<&Arc<Mutex<Connection>>> {
        self.inner.meta.as_ref()
    }
    pub fn max_upload_bytes(&self) -> usize {
        self.inner.max_upload_bytes
    }
    pub fn index_large_table_rows(&self) -> u64 {
        self.inner.index_large_table_rows
    }
}

/// Lazy cache of per-tenant MCP services. Entries are evicted when a tenant is
/// soft-deleted (call `evict`). The cache shares the global `TenantRegistry`
/// for pool lookup so writer/reader connections stay consistent across
/// REST and MCP paths.
pub struct McpRegistry {
    tenants: Arc<TenantRegistry>,
    bus: EventBus,
    webhooks: Arc<WebhookDispatcher>,
    garage: Option<Arc<GarageClient>>,
    public_base_url: String,
    url_sign_secret: Arc<[u8; 32]>,
    meta: Option<Arc<Mutex<Connection>>>,
    max_upload_bytes: usize,
    /// Row count threshold above which index creation is considered "large
    /// table". Forwarded to each `DrustMcp` instance on creation.
    index_large_table_rows: u64,
    services: DashMap<String, DrustMcp>,
}

impl McpRegistry {
    pub fn new(tenants: Arc<TenantRegistry>) -> Self {
        let webhooks = WebhookDispatcher::new(tenants.clone());
        Self {
            tenants,
            bus: EventBus::new(),
            webhooks,
            garage: None,
            public_base_url: String::new(),
            url_sign_secret: Arc::new([0u8; 32]),
            meta: None,
            max_upload_bytes: 52_428_800,
            index_large_table_rows: 1_000_000,
            services: DashMap::new(),
        }
    }
    pub fn with_bus(tenants: Arc<TenantRegistry>, bus: EventBus) -> Self {
        let webhooks = WebhookDispatcher::new(tenants.clone());
        Self {
            tenants,
            bus,
            webhooks,
            garage: None,
            public_base_url: String::new(),
            url_sign_secret: Arc::new([0u8; 32]),
            meta: None,
            max_upload_bytes: 52_428_800,
            index_large_table_rows: 1_000_000,
            services: DashMap::new(),
        }
    }
    pub fn with_bus_and_storage(
        tenants: Arc<TenantRegistry>,
        bus: EventBus,
        webhooks: Arc<WebhookDispatcher>,
        garage: Option<Arc<GarageClient>>,
        public_base_url: String,
        url_sign_secret: Arc<[u8; 32]>,
        meta: Option<Arc<Mutex<Connection>>>,
        max_upload_bytes: usize,
        index_large_table_rows: u64,
    ) -> Self {
        Self {
            tenants,
            bus,
            webhooks,
            garage,
            public_base_url,
            url_sign_secret,
            meta,
            max_upload_bytes,
            index_large_table_rows,
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
            self.webhooks.clone(),
            self.garage.clone(),
            self.public_base_url.clone(),
            self.url_sign_secret.clone(),
            self.meta.clone(),
            self.max_upload_bytes,
            self.index_large_table_rows,
        );
        self.services.insert(tenant_id.to_string(), svc.clone());
        Ok(svc)
    }
    pub fn evict(&self, tenant_id: &str) {
        self.services.remove(tenant_id);
    }
}
