use crate::storage::garage::GarageClient;
use crate::storage::pool::{SharedTenantPool, TenantRegistry};
use crate::tenant::events::EventBus;
use crate::tenant::rooms::{PublishBucket, RoomBus, RoomsConfig};
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
    /// v1.26 — read-only handle to `meta_logs.sqlite`. Shared with the
    /// admin UI's audit reader; no extra connection is opened. Tools
    /// like `recent_writes` use this to surface recent write-op audit
    /// rows for the bound tenant.
    pub audit_meta_read: Arc<Mutex<Connection>>,
    /// v1.31 — broadcast-room bus shared with REST `/rooms/{room}` and
    /// the `/realtime` WS handler. The `broadcast` MCP tool publishes
    /// into this same bus.
    pub bus_rooms: RoomBus,
    /// v1.31 — per-tenant publish rate limiter, shared across REST /
    /// WS / MCP publish surfaces so all three count toward one bucket.
    pub bucket: Arc<PublishBucket>,
    /// v1.31 — broadcast policy config (payload max, per-conn room cap,
    /// per-room subscriber cap, refill rate). The MCP tool consults
    /// `payload_max_bytes` directly.
    pub rooms_cfg: RoomsConfig,
}

/// Newtype so we can hand out `Arc` without exposing the inner struct.
#[derive(Clone)]
pub struct DrustMcp {
    inner: Arc<DrustMcpInner>,
}

impl DrustMcp {
    #[allow(clippy::too_many_arguments)]
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
        audit_meta_read: Arc<Mutex<Connection>>,
        bus_rooms: RoomBus,
        bucket: Arc<PublishBucket>,
        rooms_cfg: RoomsConfig,
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
                audit_meta_read,
                bus_rooms,
                bucket,
                rooms_cfg,
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
    /// v1.26 — read-only `meta_logs.sqlite` handle threaded into every
    /// `DrustMcp` for the `recent_writes` tool. Real prod path passes
    /// the same Arc that `MgmtState` holds; test-only constructors
    /// (`new`, `with_bus`) allocate an in-memory DB so test fixtures
    /// don't have to.
    audit_meta_read: Arc<Mutex<Connection>>,
    /// v1.31 — broadcast bus / bucket / config threaded into every
    /// `DrustMcp` so the MCP `broadcast` tool shares the exact pipeline
    /// as REST `/rooms/{room}` and the `/realtime` WS handler.
    bus_rooms: RoomBus,
    bucket: Arc<PublishBucket>,
    rooms_cfg: RoomsConfig,
    services: DashMap<String, DrustMcp>,
}

impl McpRegistry {
    pub fn new(tenants: Arc<TenantRegistry>) -> Self {
        let webhooks = WebhookDispatcher::new(tenants.clone(), None);
        let rooms_cfg = RoomsConfig::test_defaults();
        let bucket = rooms_cfg.bucket();
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
            audit_meta_read: test_audit_conn(),
            bus_rooms: RoomBus::new(),
            bucket,
            rooms_cfg,
            services: DashMap::new(),
        }
    }
    pub fn with_bus(tenants: Arc<TenantRegistry>, bus: EventBus) -> Self {
        let webhooks = WebhookDispatcher::new(tenants.clone(), None);
        let rooms_cfg = RoomsConfig::test_defaults();
        let bucket = rooms_cfg.bucket();
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
            audit_meta_read: test_audit_conn(),
            bus_rooms: RoomBus::new(),
            bucket,
            rooms_cfg,
            services: DashMap::new(),
        }
    }
    #[allow(clippy::too_many_arguments)]
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
        audit_meta_read: Arc<Mutex<Connection>>,
        bus_rooms: RoomBus,
        bucket: Arc<PublishBucket>,
        rooms_cfg: RoomsConfig,
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
            audit_meta_read,
            bus_rooms,
            bucket,
            rooms_cfg,
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
            self.audit_meta_read.clone(),
            self.bus_rooms.clone(),
            self.bucket.clone(),
            self.rooms_cfg.clone(),
        );
        self.services.insert(tenant_id.to_string(), svc.clone());
        Ok(svc)
    }
    pub fn evict(&self, tenant_id: &str) {
        self.services.remove(tenant_id);
    }
}

/// v1.26 — used by the test-only `McpRegistry::new` / `with_bus`
/// constructors. Allocates a fresh in-memory `meta_logs.sqlite` so
/// the audit_meta_read field is always populated without forcing
/// every test fixture to pass one in. Gated to test + debug builds —
/// release `main.rs` always calls `with_bus_and_storage` with the
/// real on-disk RO connection.
#[cfg(any(test, debug_assertions))]
fn test_audit_conn() -> Arc<Mutex<Connection>> {
    Arc::new(Mutex::new(
        crate::safety::audit_db::open_audit_db_memory()
            .expect("open in-memory audit DB for test/debug McpRegistry"),
    ))
}

/// Release-build fallback: `new` / `with_bus` are never expected to be
/// called from `main.rs` (it always goes through `with_bus_and_storage`),
/// but a panic-on-call stub keeps the API surface identical so anyone
/// touching the release path gets a loud failure rather than a silent
/// missing-conn at runtime.
#[cfg(not(any(test, debug_assertions)))]
fn test_audit_conn() -> Arc<Mutex<Connection>> {
    panic!("McpRegistry::new / with_bus are test-only constructors; \
            release code must use with_bus_and_storage");
}
