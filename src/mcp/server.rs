use crate::storage::garage::GarageClient;
use crate::storage::pool::{SharedTenantPool, TenantRegistry};
use crate::tenant::WebhookDispatcher;
use crate::tenant::events::EventBus;
use crate::tenant::rooms::{PublishBucket, RoomBus, RoomsConfig};
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
    /// v1.35 — shared auth cache (same `Arc` as `TenantAuthState`). `None` in
    /// the test-only `McpRegistry::new` / `with_bus` ctors. The MCP
    /// user-mutation tool wrappers pass it into `tools::user::delete_user` /
    /// `revoke_user_sessions`, which invalidate the user's cached session
    /// entries (hooks 7-MCP / 8-MCP).
    pub auth_cache: Option<Arc<crate::tenant::auth_cache::AuthCache>>,
    /// v1.36 — function dispatcher for the three MCP record-write emission
    /// sites. `None` in: (a) test-only ctors, (b) the executor-built host
    /// state (`HostStateSeed::build_mcp`) — THAT None is the depth=1
    /// recursion guard (spec §4): a guest-initiated write fires SSE +
    /// webhooks but can never enqueue another function.
    pub functions: Option<Arc<crate::functions::dispatcher::FunctionDispatcher>>,
    /// v1.48 — shared cron state (schedule index + knobs). The MCP cron
    /// tools reload THIS index after every mutation, so prod (`main.rs`)
    /// MUST hand in the SAME `CronState` the minute-tick scheduler
    /// snapshots, via `McpRegistry::with_cron` — a detached default here
    /// means an MCP-created job never fires until the next boot scan.
    /// `DrustMcp::new` defaults to a fresh detached state so test-only
    /// ctors and the executor host state (which exposes no cron tools)
    /// need no wiring.
    pub cron: Arc<crate::cron::CronState>,
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
        auth_cache: Option<Arc<crate::tenant::auth_cache::AuthCache>>,
        functions: Option<Arc<crate::functions::dispatcher::FunctionDispatcher>>,
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
                auth_cache,
                functions,
                cron: fresh_cron_state(),
            }),
        }
    }
    /// v1.48 — swap in the process-shared cron state (see
    /// `DrustMcpInner::cron`). Builder-style so `DrustMcp::new`'s
    /// signature (and its non-cron callers) stay untouched.
    pub fn with_cron(self, cron: Arc<crate::cron::CronState>) -> Self {
        let mut inner = (*self.inner).clone();
        inner.cron = cron;
        Self {
            inner: Arc::new(inner),
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

/// Lazy per-tenant `DrustMcp` cache (tests and the eviction hooks use it; the
/// account-level endpoint builds per call with `build_live`). Entries are evicted through
/// `McpHttpRegistry::evict` (soft-delete and id-recycle, via
/// `mgmt::tenants::crud::evict_tenant_everywhere`); nothing else calls `evict`
/// directly. The cache shares the global `TenantRegistry`
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
    /// v1.35 — shared auth cache forwarded into every `DrustMcp` so the MCP
    /// user-mutation tools can fire invalidation hooks 7-MCP / 8-MCP. `None`
    /// in the test-only `new` / `with_bus` ctors; the prod path
    /// (`with_bus_and_storage`) always carries the `main.rs` instance.
    auth_cache: Option<Arc<crate::tenant::auth_cache::AuthCache>>,
    /// v1.36 — function dispatcher forwarded into every `DrustMcp` so the
    /// three MCP record-write tools dispatch function invocations. `None` in
    /// the test-only `new` / `with_bus` ctors; the prod path
    /// (`with_bus_and_storage`) always carries the `main.rs` instance.
    functions: Option<Arc<crate::functions::dispatcher::FunctionDispatcher>>,
    /// v1.48 — shared cron state threaded into every `DrustMcp` this
    /// registry mints (see `DrustMcpInner::cron`). All ctors default to a
    /// fresh detached state; the prod path in `main.rs` MUST override it
    /// with the scheduler's instance via `with_cron`.
    cron: Arc<crate::cron::CronState>,
    services: DashMap<String, DrustMcp>,
}

impl McpRegistry {
    /// Test-only ctor. **Mints a PRIVATE `RoomBus`** (`test_rooms_defaults`),
    /// so the MCP surface it builds evicts a bus nothing else is on — fine for
    /// a registry used on its own to drive tools, WRONG for one handed to a
    /// `TenantStack`, where `delete_user` / `revoke_user_sessions` must reach
    /// the same sockets the WS handler serves (#955). Stacks use
    /// [`McpRegistry::with_bus`], which requires the bus explicitly.
    pub fn new(tenants: Arc<TenantRegistry>) -> Self {
        let webhooks = WebhookDispatcher::new(tenants.clone(), None);
        let (bus_rooms, bucket, rooms_cfg) = test_rooms_defaults();
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
            bus_rooms,
            bucket,
            rooms_cfg,
            auth_cache: None,
            functions: None,
            cron: fresh_cron_state(),
            services: DashMap::new(),
        }
    }
    /// Test-only ctor for a registry that goes into a `TenantStack`.
    ///
    /// #955 — `bus_rooms` is a REQUIRED parameter, not a default, because the
    /// MCP eviction tools — `delete_user` and `revoke_user_sessions` (evicting
    /// in their `#[tool]` wrappers) and `set_publish_policy` (evicting one
    /// level down, in `mcp::tools::owner_field`, through this same
    /// registry-supplied `bus_rooms`) — all must move the SAME bus the WS
    /// handler's sockets are on. Production threads one instance into all
    /// three (`src/main.rs` → `with_bus_and_storage`). While this ctor
    /// defaulted it from `test_rooms_defaults`, every helper stack in the
    /// suite ran two buses and any "revoke over MCP, assert the socket died"
    /// test would have passed without exercising anything. Tests get the
    /// instance from `helpers::shared_bus_rooms`.
    ///
    /// For the authoritative list of everything that calls `evict_tenant`, read
    /// [`crate::tenant::rooms::RoomBus::evict_tenant`]'s doc and re-derive it
    /// with the recipe there. This doc deliberately states NO count: the one it
    /// used to carry ("2 of the 5") went stale in the very commit that added
    /// `set_publish_policy` as the third MCP site.
    ///
    /// Note this ctor also leaves `meta: None`, so any tool whose body needs
    /// the meta handle (`set_publish_policy` among them) short-circuits in its
    /// wrapper under this registry.
    pub fn with_bus(tenants: Arc<TenantRegistry>, bus: EventBus, bus_rooms: RoomBus) -> Self {
        let webhooks = WebhookDispatcher::new(tenants.clone(), None);
        let (_private_bus_rooms, bucket, rooms_cfg) = test_rooms_defaults();
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
            bus_rooms,
            bucket,
            rooms_cfg,
            auth_cache: None,
            functions: None,
            cron: fresh_cron_state(),
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
        auth_cache: Arc<crate::tenant::auth_cache::AuthCache>,
        functions: Arc<crate::functions::dispatcher::FunctionDispatcher>,
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
            auth_cache: Some(auth_cache),
            functions: Some(functions),
            cron: fresh_cron_state(),
            services: DashMap::new(),
        }
    }
    /// v1.48 — thread the process-shared cron state into every `DrustMcp`
    /// this registry mints. `main.rs` MUST chain this onto
    /// `with_bus_and_storage` with the scheduler's `CronState`; without it
    /// the MCP cron tools reload a detached index and MCP-created jobs
    /// don't fire until restart.
    pub fn with_cron(mut self, cron: Arc<crate::cron::CronState>) -> Self {
        self.cron = cron;
        self
    }
    /// Creates the tenant's database on open: tests and eviction regressions
    /// only, never a request path (a request opens through `build_live`,
    /// which never creates).
    pub async fn get_or_create(&self, tenant_id: &str) -> anyhow::Result<DrustMcp> {
        if let Some(s) = self.services.get(tenant_id) {
            return Ok(s.clone());
        }
        // Never on a request path: `tenants.get_or_create` creates a missing database.
        let pool = self.tenants.get_or_create(tenant_id)?;
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
            self.auth_cache.clone(),
            self.functions.clone(),
        )
        .with_cron(self.cron.clone());
        self.services.insert(tenant_id.to_string(), svc.clone());
        Ok(svc)
    }
    /// The account-level MCP endpoint's per-call builder: a fresh `DrustMcp` for a
    /// LIVE tenant. Never reads or writes `services` (so an id recycle can never be
    /// served from this cache) and never creates files (`get_if_live` only; `None` =
    /// gone, which the caller maps to the same answer as "not visible"). Opening a
    /// pool has side effects (schema catch-up, the pool cache), so callers must
    /// decide visibility BEFORE calling this. `meta` is a required parameter on
    /// purpose: the test-only registries carry `meta: None`, which would silently
    /// skip the meta-backed checks of the tools. `functions` comes from the registry
    /// exactly as in `get_or_create` (CLAUDE.md invariant 13), and the shared cron
    /// state is applied the same way.
    pub(crate) fn build_live(
        &self,
        tenant_id: &str,
        meta: Arc<Mutex<Connection>>,
    ) -> Option<DrustMcp> {
        let pool = self.tenants.get_if_live(tenant_id)?;
        Some(
            DrustMcp::new(
                tenant_id,
                pool,
                self.bus.clone(),
                self.webhooks.clone(),
                self.garage.clone(),
                self.public_base_url.clone(),
                self.url_sign_secret.clone(),
                Some(meta),
                self.max_upload_bytes,
                self.index_large_table_rows,
                self.audit_meta_read.clone(),
                self.bus_rooms.clone(),
                self.bucket.clone(),
                self.rooms_cfg.clone(),
                self.auth_cache.clone(),
                self.functions.clone(),
            )
            .with_cron(self.cron.clone()),
        )
    }
    pub fn evict(&self, tenant_id: &str) {
        self.services.remove(tenant_id);
    }
    /// How many tenants have a cached `DrustMcp`. Test/observability hook —
    /// this layer holds the `Arc<TenantPool>`, so it is what a lifecycle
    /// test must see drop to zero (E5).
    pub fn cached_count(&self) -> usize {
        self.services.len()
    }
}

/// v1.48 — detached default for construction sites that don't thread the
/// process-shared cron state: the test-only registry ctors, the prod
/// registry BEFORE `with_cron` overrides it, and the functions-executor
/// host state (which exposes no cron tools). Valid in every build profile —
/// it is a real, just unshared, `CronState`.
fn fresh_cron_state() -> Arc<crate::cron::CronState> {
    Arc::new(crate::cron::CronState {
        index: Arc::new(crate::cron::index::CronIndex::new()),
        cfg: crate::cron::CronConfig::from_env(),
    })
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
    panic!(
        "McpRegistry::new / with_bus are test-only constructors; \
            release code must use with_bus_and_storage"
    );
}

/// v1.31 — same release/debug split for the broadcast bucket. `new` /
/// `with_bus` are test-only; release path provides its own bucket via
/// `with_bus_and_storage`.
#[cfg(any(test, debug_assertions))]
fn test_rooms_defaults() -> (RoomBus, Arc<PublishBucket>, RoomsConfig) {
    let cfg = RoomsConfig::test_defaults();
    let bucket = cfg.bucket();
    (RoomBus::new(), bucket, cfg)
}

#[cfg(not(any(test, debug_assertions)))]
fn test_rooms_defaults() -> (RoomBus, Arc<PublishBucket>, RoomsConfig) {
    panic!(
        "McpRegistry::new / with_bus are test-only constructors; \
            release code must use with_bus_and_storage"
    );
}

#[cfg(test)]
mod build_live_tests {
    use super::*;

    fn meta() -> Arc<Mutex<Connection>> {
        Arc::new(Mutex::new(Connection::open_in_memory().unwrap()))
    }

    /// Production-shaped registry (functions: Some) plus the cron state it was given.
    fn registry(
        root: &std::path::Path,
    ) -> (
        McpRegistry,
        Arc<TenantRegistry>,
        Arc<crate::cron::CronState>,
    ) {
        let tr = Arc::new(TenantRegistry::new(root.to_path_buf(), 2));
        let cron = fresh_cron_state();
        let (bus_rooms, bucket, rooms_cfg) = test_rooms_defaults();
        let garage = Arc::new(GarageClient::from_store(
            Arc::new(object_store::memory::InMemory::new()),
            "private",
        ));
        let reg = McpRegistry::with_bus_and_storage(
            tr.clone(),
            EventBus::new(),
            WebhookDispatcher::new(tr.clone(), None),
            Some(garage),
            String::new(),
            Arc::new([0u8; 32]),
            None,
            1,
            1,
            test_audit_conn(),
            bus_rooms,
            bucket,
            rooms_cfg,
            Arc::new(crate::tenant::auth_cache::AuthCache::new(
                std::time::Duration::from_secs(10),
                16,
            )),
            crate::functions::dispatcher::FunctionDispatcher::new(
                tr.clone(),
                tokio::sync::mpsc::channel(8).0,
                crate::functions::FnConfig::test_default(),
            ),
        )
        .with_cron(cron.clone());
        (reg, tr, cron)
    }

    #[tokio::test]
    async fn build_live_returns_none_for_a_tenant_without_a_database() {
        let dir = tempfile::tempdir().unwrap();
        let (reg, _tr, _) = registry(dir.path());
        assert!(reg.build_live("ghost", meta()).is_none());
        assert!(
            !crate::storage::tenant_db::tenant_dir(dir.path(), "ghost").exists(),
            "build_live must never create a tenant directory"
        );
        assert_eq!(reg.cached_count(), 0);
    }

    #[tokio::test]
    async fn build_live_wires_the_same_state_as_get_or_create_but_bypasses_the_cache() {
        let dir = tempfile::tempdir().unwrap();
        let (reg, tr, cron) = registry(dir.path());
        tr.get_or_create("blog").unwrap();
        tr.evict("blog"); // force the create-free open path
        let m = meta();
        let live = reg.build_live("blog", m.clone()).expect("live tenant");
        assert_eq!(
            reg.cached_count(),
            0,
            "build_live must not write the services cache"
        );
        assert_eq!(live.tenant_id(), "blog");
        assert!(Arc::ptr_eq(live.meta().expect("meta is always Some"), &m));
        let inner = live.inner();
        assert!(Arc::ptr_eq(&inner.cron, &cron), "with_cron must be applied");
        let cached = reg.get_or_create("blog").await.unwrap();
        let ci = cached.inner();
        assert!(
            Arc::ptr_eq(
                inner.functions.as_ref().expect("functions: Some"),
                ci.functions.as_ref().unwrap()
            ),
            "functions must come from the registry (invariant 13)"
        );
        assert!(
            Arc::ptr_eq(&inner.pool, &ci.pool),
            "same TenantRegistry pool"
        );
        // Every shared handle is the registry's own: a fresh one here would
        // detach the account endpoint's tools from the process state (the
        // auth cache is what the invariant-4 hooks of the MCP tools clear).
        assert!(
            Arc::ptr_eq(
                inner.auth_cache.as_ref().expect("auth_cache: Some"),
                reg.auth_cache.as_ref().unwrap()
            ),
            "auth cache"
        );
        assert!(Arc::ptr_eq(&inner.webhooks, &reg.webhooks), "webhooks");
        assert!(
            Arc::ptr_eq(
                inner.garage.as_ref().expect("garage: Some"),
                reg.garage.as_ref().unwrap()
            ),
            "object-store client"
        );
        assert!(inner.bus.shares_channels_with(&reg.bus), "event bus");
        assert!(
            inner.bus_rooms.shares_channels_with(&reg.bus_rooms),
            "room bus"
        );
        assert!(Arc::ptr_eq(&inner.bucket, &reg.bucket), "publish bucket");
        assert!(
            Arc::ptr_eq(&inner.audit_meta_read, &reg.audit_meta_read),
            "audit reader"
        );
        assert!(
            Arc::ptr_eq(&inner.url_sign_secret, &reg.url_sign_secret),
            "url signing secret"
        );
        // never reads the cache: a second build_live is a fresh DrustMcp, not the cached one
        let again = reg.build_live("blog", m).unwrap();
        assert!(!Arc::ptr_eq(&again.inner(), &cached.inner()));
        assert_eq!(reg.cached_count(), 1);
    }

    /// The names an MCP registry handle is bound to in `prod`, each with
    /// whether its declaration is `pub` (visible outside the file): fields and
    /// parameters typed `Arc<McpRegistry>` / `Arc<McpHttpRegistry>` (or the
    /// bare types), and `let` bindings built from either.
    fn mcp_handle_names(prod: &str) -> Vec<(String, bool)> {
        let ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
        let mut out = Vec::new();
        for ty in ["McpRegistry", "McpHttpRegistry"] {
            for decl in [format!(": Arc<{ty}>"), format!(": {ty}")] {
                for (i, _) in prod.match_indices(decl.as_str()) {
                    let after = prod[i + decl.len()..].chars().next();
                    if after.is_some_and(ident) {
                        continue; // a longer type name
                    }
                    let name: String = prod[..i]
                        .chars()
                        .rev()
                        .take_while(|c| ident(*c))
                        .collect::<Vec<_>>()
                        .into_iter()
                        .rev()
                        .collect();
                    let line = prod[..i - name.len()].rsplit('\n').next().unwrap_or("");
                    out.push((name, line.trim_start().starts_with("pub")));
                }
            }
        }
        for (i, _) in prod.match_indices("let ") {
            let rest = &prod[i + 4..];
            let name: String = rest.chars().take_while(|c| ident(*c)).collect();
            let Some(value) = rest[name.len()..].trim_start().strip_prefix('=') else {
                continue;
            };
            let value: String = value.chars().filter(|c| !c.is_whitespace()).collect();
            if ["Arc::new(McpRegistry::", "Arc::new(McpHttpRegistry::"]
                .iter()
                .any(|p| value.starts_with(p))
            {
                out.push((name, false));
            }
        }
        out
    }

    /// Scans one file's production text: the number of `.get_or_create(`
    /// calls in `prod`, and each one whose receiver chain ends in one of
    /// `handles`, as `<receiver>.get_or_create(`. Whitespace between the
    /// segments of a chain is skipped, so a rustfmt-wrapped chain (each
    /// `.segment` on its own line) has the same receiver as a one-line one.
    fn registry_calls(prod: &str, handles: &[String]) -> (usize, Vec<String>) {
        let receiver_char = |c: char| c.is_ascii_alphanumeric() || "_.()&".contains(c);
        let (mut calls, mut flagged) = (0, Vec::new());
        for (i, _) in prod.match_indices(".get_or_create(") {
            calls += 1;
            let receiver: String = prod[..i]
                .chars()
                .rev()
                .filter(|c| !c.is_whitespace())
                .take_while(|c| receiver_char(*c))
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            let last = receiver.rsplit('.').next().unwrap_or("");
            if handles.iter().any(|h| h == last) {
                flagged.push(format!("{receiver}.get_or_create("));
            }
        }
        (calls, flagged)
    }

    #[test]
    fn registry_calls_see_wrapped_and_single_line_chains() {
        let planted = "struct S { registry: Arc<McpRegistry>, tenants: Arc<TenantRegistry> }\n\
                       fn a(&self) { let _ = self\n    .inner\n    .registry\n    .get_or_create(id); }\n\
                       fn b(&self) { let _ = self.inner.registry.get_or_create(id); }\n\
                       fn c(&self) { let _ = state\n    .tenants\n    .get_or_create(id); }\n";
        let handles: Vec<String> = mcp_handle_names(planted)
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        assert_eq!(handles, ["registry"]);
        let (calls, flagged) = registry_calls(planted, &handles);
        assert_eq!(calls, 3);
        assert_eq!(
            flagged,
            [
                "self.inner.registry.get_or_create(",
                "self.inner.registry.get_or_create("
            ],
            "the wrapped and the single-line chain on the MCP registry are both \
             flagged; the tenant-pool chain is not"
        );
    }

    /// The account endpoint builds every call's `DrustMcp` through
    /// `build_live`, and the per-tenant cache behind `get_or_create` has no
    /// production reader: no `.get_or_create(` call outside this file has an
    /// MCP registry handle as its receiver: a name the same file binds to
    /// one, a `pub` field typed as one, or the `registry()` accessor.
    #[test]
    fn get_or_create_has_no_production_caller_outside_this_file() {
        use crate::tenant::rooms::srcpin::{code_only, collect_rs_files, production_half};
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        collect_rs_files(&root, &mut files);
        let sources: Vec<(std::path::PathBuf, String, Vec<(String, bool)>)> = files
            .into_iter()
            .filter(|f| !f.ends_with("mcp/server.rs"))
            .map(|f| {
                let code = code_only(&std::fs::read_to_string(&f).unwrap());
                let prod = production_half(&code).to_string();
                let handles = mcp_handle_names(&prod);
                (f, prod, handles)
            })
            .collect();
        // Anti-vacuous: the handles held today are found where they live.
        for (file, known) in [
            ("main.rs", "mcp_reg"),
            ("mcp/http_registry.rs", "mcp"),
            ("mcp/account.rs", "registry"),
        ] {
            assert!(
                sources
                    .iter()
                    .any(|(f, _, h)| f.ends_with(file) && h.iter().any(|(n, _)| n == known)),
                "handle `{known}` not found in {file}"
            );
        }
        let mut global: Vec<String> = vec!["registry()".into()];
        for (_, _, h) in &sources {
            global.extend(h.iter().filter(|(_, p)| *p).map(|(n, _)| n.clone()));
        }
        let (mut calls, mut via_mcp) = (0, Vec::new());
        for (f, prod, local) in &sources {
            assert!(
                !prod.contains("McpRegistry::get_or_create"),
                "{}: names McpRegistry::get_or_create",
                f.display()
            );
            let mut handles = global.clone();
            handles.extend(local.iter().map(|(n, _)| n.clone()));
            let (n, flagged) = registry_calls(prod, &handles);
            calls += n;
            via_mcp.extend(flagged.into_iter().map(|c| format!("{}: {c}", f.display())));
        }
        // Anti-vacuous: the tenant pool registry's own get_or_create calls are seen.
        assert!(calls > 50, "only {calls} .get_or_create( calls found");
        assert!(via_mcp.is_empty(), "{via_mcp:#?}");
    }
}
