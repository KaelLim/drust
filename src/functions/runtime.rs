//! wasmtime runtime: global Engine (OnceLock + epoch ticker thread),
//! per-sha InstancePre LRU, per-invocation Store with memory/CPU caps,
//! and the `drust:function/host` import implementation that calls the
//! transport-agnostic tool layer (mcp/tools/{write,read}.rs) directly.

use crate::functions::FnConfig;
use crate::functions::executor::{FunctionRunner, RunOutcome, RunStatus};
use crate::mcp::server::DrustMcp;
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use wasmtime::component::{Component, HasSelf, InstancePre, Linker};
use wasmtime::{Config, Engine, Store};

// Generated bindings for the WIT world. The WIT file is the SDK template's —
// single source of truth (Task 2). wasmtime-45 drift: the `async: true`
// bindgen key became `imports/exports: { default: async }`.
wasmtime::component::bindgen!({
    path: "sdk/edge-function-template/wit",
    world: "edge-function",
    imports: { default: async },
    exports: { default: async },
});

/// Global engine + ticker. Lazy: the ticker thread only exists once the
/// first function executes (or compiles at upload time).
pub fn engine() -> &'static Engine {
    static ENGINE: OnceLock<Engine> = OnceLock::new();
    ENGINE.get_or_init(|| {
        let mut cfg = Config::new();
        // wasmtime 45: async support is always on; `Config::async_support`
        // is deprecated as a no-op, so it is not called here.
        cfg.epoch_interruption(true);
        cfg.wasm_component_model(true);
        let engine = Engine::new(&cfg).expect("construct wasmtime engine");
        let ticker = engine.clone();
        std::thread::Builder::new()
            .name("drust-fn-epoch".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    ticker.increment_epoch();
                }
            })
            .expect("spawn epoch ticker");
        engine
    })
}

/// Upload-time validation: compiles (cheaply discards) the artifact.
/// 422 WASM_COMPILE_FAILED at the route layer on Err.
pub fn validate_component(bytes: &[u8]) -> anyhow::Result<()> {
    Component::new(engine(), bytes)?;
    Ok(())
}

/// Tiny LRU over compiled InstancePre keyed by sha256. cap from
/// DRUST_FN_MODULE_CACHE. Mutex<Vec> is fine at cap ≤ 32.
struct PreCache {
    cap: usize,
    entries: StdMutex<Vec<(String, InstancePre<StoreData>)>>,
}

impl PreCache {
    fn get_or_compile(
        &self,
        sha: &str,
        path: &std::path::Path,
        linker: &Linker<StoreData>,
    ) -> anyhow::Result<InstancePre<StoreData>> {
        {
            let mut v = self.entries.lock().unwrap();
            if let Some(pos) = v.iter().position(|(k, _)| k == sha) {
                let hit = v.remove(pos);
                let pre = hit.1.clone();
                v.push(hit); // move to MRU end
                return Ok(pre);
            }
        }
        let component = Component::from_file(engine(), path)?;
        let pre = linker.instantiate_pre(&component)?;
        let mut v = self.entries.lock().unwrap();
        if v.len() >= self.cap {
            v.remove(0); // evict LRU
        }
        v.push((sha.to_string(), pre.clone()));
        Ok(pre)
    }
}

/// Per-invocation store data: WASI ctx (locked down), the resource limiter,
/// the per-tenant tool state, and the captured guest log buffer.
pub struct StoreData {
    wasi: wasmtime_wasi::WasiCtx,
    table: wasmtime::component::ResourceTable,
    limits: MemLimiter,
    host: HostState,
}

pub struct HostState {
    /// Per-tenant tool state built with `functions: None` — the recursion
    /// guard IS this absence (spec §4).
    mcp: DrustMcp,
    file_read_max: u64,
    /// DRUST_DISK_MIN_FREE_PCT — put-file disk guard (parity with Mode A/B).
    disk_min_free_pct: u8,
    log_buf: String,
}

const LOG_CAP_BYTES: usize = 64 * 1024;

struct MemLimiter {
    cap: usize,
    oom_hit: bool,
}

impl wasmtime::ResourceLimiter for MemLimiter {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        if desired > self.cap {
            self.oom_hit = true;
            return Ok(false);
        }
        Ok(true)
    }
    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        Ok(desired <= 1_000_000)
    }
}

// WASI plumbing — wasmtime-wasi 45 merged the old IoView/WasiView pair into
// one `WasiView` returning a `WasiCtxView { ctx, table }` (Grounding note 1).
impl wasmtime_wasi::WasiView for StoreData {
    fn ctx(&mut self) -> wasmtime_wasi::WasiCtxView<'_> {
        wasmtime_wasi::WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}

fn vis_from_str(visibility: &str) -> crate::storage::files::Visibility {
    match visibility {
        "public" => crate::storage::files::Visibility::Public,
        _ => crate::storage::files::Visibility::Private,
    }
}

/// Cache-control for a guest `put-file`, derived from the object's
/// visibility exactly like Mode A/B (`storage::files::default_cache_control`)
/// rather than hardcoding a public value — a private object must carry a
/// private, non-cacheable directive on both the `_system_files` row and the
/// Garage object.
fn put_file_cache_control(visibility: &str) -> &'static str {
    crate::storage::files::default_cache_control(
        vis_from_str(visibility),
        crate::storage::files::Disposition::Inline,
    )
}

/// The `host` import interface. bindgen generates true async trait methods
/// (`imports: { default: async }`), so the tool layer is awaited directly —
/// no block_on / runtime Handle needed (plan adaptation note: preferred form).
impl host::Host for StoreData {
    async fn query_list(
        &mut self,
        collection: String,
        body_json: String,
    ) -> Result<String, String> {
        let mut v: serde_json::Value =
            serde_json::from_str(&body_json).map_err(|e| format!("bad body-json: {e}"))?;
        v.as_object_mut()
            .ok_or("body-json must be an object")?
            .insert("collection".into(), serde_json::Value::String(collection));
        let args: crate::mcp::tools::read::ListRecordsArgs =
            serde_json::from_value(v).map_err(|e| format!("bad list args: {e}"))?;
        crate::mcp::tools::read::list_records(&self.host.mcp, args)
            .await
            .map(|v| v.to_string())
            .map_err(|e| e.to_string())
    }

    async fn insert_record(
        &mut self,
        collection: String,
        data_json: String,
    ) -> Result<String, String> {
        let data: serde_json::Value =
            serde_json::from_str(&data_json).map_err(|e| format!("bad data-json: {e}"))?;
        crate::mcp::tools::write::insert_record(&self.host.mcp, &collection, data)
            .await
            .map(|v| v.to_string())
            .map_err(|e| e.to_string())
    }

    async fn update_record(
        &mut self,
        collection: String,
        id: i64,
        data_json: String,
    ) -> Result<String, String> {
        let data: serde_json::Value =
            serde_json::from_str(&data_json).map_err(|e| format!("bad data-json: {e}"))?;
        crate::mcp::tools::write::update_record(&self.host.mcp, &collection, id, data)
            .await
            .map(|v| v.to_string())
            .map_err(|e| e.to_string())
    }

    async fn delete_record(&mut self, collection: String, id: i64) -> Result<String, String> {
        crate::mcp::tools::write::delete_record(&self.host.mcp, &collection, id)
            .await
            .map(|v| v.to_string())
            .map_err(|e| e.to_string())
    }

    async fn get_file_bytes(&mut self, key: String) -> Result<Vec<u8>, String> {
        let cap = self.host.file_read_max;
        let inner = self.host.mcp.inner();
        let garage = inner
            .garage
            .as_ref()
            .ok_or("STORAGE_UNAVAILABLE: storage not configured")?;
        // Resolve visibility → bucket from the tenant's _system_files row.
        // Pure single-row SELECT — reader lane, same as get_file_url
        // (mcp/tools/files.rs); never occupy the serialized writer mutex.
        let pool = inner.pool.clone();
        let key2 = key.clone();
        let row: Option<(String, i64)> = pool
            .with_reader(move |c| {
                match c.query_row(
                    "SELECT visibility, size_bytes FROM _system_files WHERE key = ?1",
                    rusqlite::params![key2],
                    |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)),
                ) {
                    Ok(v) => Ok(Some(v)),
                    Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                    Err(e) => Err(e),
                }
            })
            .await
            .map_err(|e| format!("DB_ERROR: {e}"))?;
        let (visibility, size) = row.ok_or("FILE_NOT_FOUND: no such key")?;
        if size as u64 > cap {
            return Err(format!(
                "FN_FILE_TOO_LARGE: {size} bytes exceeds get-file-bytes cap {cap}"
            ));
        }
        let bucket = crate::storage::files::bucket_for(vis_from_str(&visibility));
        let object_key = format!("{}/{}", inner.tenant_id, key);
        garage
            .get_object_bytes_in(bucket, &object_key)
            .await
            .map(|b| b.to_vec())
            .map_err(|e| format!("GARAGE_GET_FAILED: {e:#}"))
    }

    async fn put_file(
        &mut self,
        key: String,
        bytes: Vec<u8>,
        content_type: String,
        visibility: String,
    ) -> Result<String, String> {
        if !matches!(visibility.as_str(), "public" | "private") {
            return Err("INVALID_VISIBILITY: visibility must be public|private".into());
        }
        let inner = self.host.mcp.inner();
        let garage = inner
            .garage
            .as_ref()
            .ok_or("STORAGE_UNAVAILABLE: storage not configured")?;
        // Defense-in-depth parity with every other Garage write surface:
        // Mode A enforces max_upload_bytes + the disk guard
        // (mgmt/tenant_files.rs), Mode B enforces the disk guard
        // (tenant/uploads/mod.rs). The guest host API enforces both too —
        // otherwise a function could loop Garage puts up to the wasm memory
        // cap per call with no disk-full stop.
        if bytes.len() > inner.max_upload_bytes {
            return Err(format!(
                "FN_PUT_TOO_LARGE: {} bytes exceeds upload limit {}",
                bytes.len(),
                inner.max_upload_bytes
            ));
        }
        // Best-effort like Mode A: skip (with a warn) if the path is absent.
        match crate::storage::disk::disk_stats(std::path::Path::new("/var/lib/garage")) {
            Ok(stats) if (stats.free_pct as u8) < self.host.disk_min_free_pct => {
                return Err(format!(
                    "DISK_FULL: {:.1}% free, minimum {}% required",
                    stats.free_pct, self.host.disk_min_free_pct
                ));
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(error = %e, "disk_stats for /var/lib/garage failed — skipping disk check");
            }
        }
        let pool = inner.pool.clone();
        let size = bytes.len() as i64;
        // Cache-control derived from visibility (mirror Mode A/B) — a private
        // object must not advertise a publicly-cacheable directive.
        let cc = put_file_cache_control(&visibility);
        // SQLite-first (Mode A ordering): row, then object, compensate on failure.
        let key_w = key.clone();
        let ct_w = content_type.clone();
        let vis_w = visibility.clone();
        let cc_w = cc.to_string();
        pool.with_writer(move |c| {
            c.execute(
                "INSERT INTO _system_files
                 (key, original_name, content_type, size_bytes, content_disposition,
                  visibility, cache_control, meta_json, uploader)
                 VALUES (?1, ?2, ?3, ?4, 'inline', ?5, ?6, NULL, 'function')",
                rusqlite::params![key_w, key_w, ct_w, size, vis_w, cc_w],
            )
            .map(|_| ())
        })
        .await
        .map_err(|e| format!("DB_INSERT_FAILED: {e}"))?;

        let bucket = crate::storage::files::bucket_for(vis_from_str(&visibility));
        let object_key = format!("{}/{}", inner.tenant_id, key);
        if let Err(e) = garage
            .put_object_in(
                bucket,
                &object_key,
                bytes.into(),
                Some(&content_type),
                "inline",
                &key,
                Some(cc),
                None,
            )
            .await
        {
            let key_c = key.clone();
            let _ = pool
                .with_writer(move |c| {
                    c.execute(
                        "DELETE FROM _system_files WHERE key = ?1",
                        rusqlite::params![key_c],
                    )
                    .map(|_| ())
                })
                .await;
            return Err(format!("GARAGE_PUT_FAILED: {e:#}"));
        }
        Ok(serde_json::json!({"key": key, "size_bytes": size}).to_string())
    }

    async fn log(&mut self, level: String, msg: String) {
        if self.host.log_buf.len() < LOG_CAP_BYTES {
            use std::fmt::Write;
            let _ = writeln!(self.host.log_buf, "[{level}] {msg}");
            if self.host.log_buf.len() > LOG_CAP_BYTES {
                // walk back to a char boundary — String::truncate panics
                // mid-codepoint, and guest log content is arbitrary UTF-8.
                let mut cut = LOG_CAP_BYTES;
                while !self.host.log_buf.is_char_boundary(cut) {
                    cut -= 1;
                }
                self.host.log_buf.truncate(cut);
            }
        }
    }
}

/// Production runner.
pub struct WasmRunner {
    cfg: FnConfig,
    cache: PreCache,
    linker: OnceLock<Linker<StoreData>>,
    /// Builds the per-tenant DrustMcp with functions: None.
    seed: HostStateSeed,
}

/// Everything needed to construct a per-tenant `DrustMcp` for host calls —
/// the same fields main.rs passes to `McpRegistry::with_bus_and_storage`,
/// minus auth_cache (host calls carry no token) and minus functions
/// (recursion guard). Constructed once in main.rs.
#[derive(Clone)]
pub struct HostStateSeed {
    pub tenants: Arc<crate::storage::pool::TenantRegistry>,
    pub bus: crate::tenant::events::EventBus,
    pub webhooks: Arc<crate::tenant::WebhookDispatcher>,
    pub garage: Option<Arc<crate::storage::garage::GarageClient>>,
    pub public_base_url: String,
    pub url_sign_secret: Arc<[u8; 32]>,
    pub meta: Option<Arc<tokio::sync::Mutex<rusqlite::Connection>>>,
    pub max_upload_bytes: usize,
    pub index_large_table_rows: u64,
    pub audit_meta_read: Arc<tokio::sync::Mutex<rusqlite::Connection>>,
    pub bus_rooms: crate::tenant::rooms::RoomBus,
    pub bucket: Arc<crate::tenant::rooms::PublishBucket>,
    pub rooms_cfg: crate::tenant::rooms::RoomsConfig,
    /// DRUST_DISK_MIN_FREE_PCT (same value main.rs threads into MgmtState /
    /// TenantFilesState; default 20) — enforced by the `put-file` host call.
    /// Not a DrustMcp field: consumed by HostState, not build_mcp.
    pub disk_min_free_pct: u8,
}

impl HostStateSeed {
    /// `functions: None` here is the depth=1 recursion guard (spec §4).
    pub fn build_mcp(&self, tenant_id: &str) -> anyhow::Result<DrustMcp> {
        let pool = self.tenants.get_or_open(tenant_id)?;
        Ok(DrustMcp::new(
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
            None, // auth_cache — host calls carry no token
            None, // functions — RECURSION GUARD: a guest write can never re-dispatch
        ))
    }
}

impl WasmRunner {
    pub fn new(cfg: FnConfig, seed: HostStateSeed) -> Arc<Self> {
        Arc::new(Self {
            cache: PreCache {
                cap: cfg.module_cache,
                entries: StdMutex::new(Vec::new()),
            },
            cfg,
            linker: OnceLock::new(),
            seed,
        })
    }

    fn linker(&self) -> anyhow::Result<&Linker<StoreData>> {
        if self.linker.get().is_none() {
            let mut l: Linker<StoreData> = Linker::new(engine());
            wasmtime_wasi::p2::add_to_linker_async(&mut l)?;
            host::add_to_linker::<_, HasSelf<_>>(&mut l, |s: &mut StoreData| s)?;
            let _ = self.linker.set(l);
        }
        Ok(self.linker.get().unwrap())
    }
}

#[async_trait::async_trait]
impl FunctionRunner for WasmRunner {
    async fn run(
        &self,
        tenant_id: &str,
        wasm_path: &std::path::Path,
        event_json: &str,
    ) -> RunOutcome {
        let mcp = match self.seed.build_mcp(tenant_id) {
            Ok(m) => m,
            Err(e) => {
                return RunOutcome {
                    status: RunStatus::Error,
                    result: format!("host state: {e}"),
                    log_text: String::new(),
                };
            }
        };
        let sha = wasm_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_string();
        let linker = match self.linker() {
            Ok(l) => l,
            Err(e) => {
                return RunOutcome {
                    status: RunStatus::Error,
                    result: format!("linker: {e}"),
                    log_text: String::new(),
                };
            }
        };
        let pre = match self.cache.get_or_compile(&sha, wasm_path, linker) {
            Ok(p) => p,
            Err(e) => {
                return RunOutcome {
                    status: RunStatus::Error,
                    result: format!("compile: {e}"),
                    log_text: String::new(),
                };
            }
        };

        // Locked-down WASI: no preopens, no allowed socket addrs, discarded stdio.
        let wasi = wasmtime_wasi::WasiCtxBuilder::new().build();
        let data = StoreData {
            wasi,
            table: wasmtime::component::ResourceTable::new(),
            limits: MemLimiter {
                cap: self.cfg.memory_max_bytes,
                oom_hit: false,
            },
            host: HostState {
                mcp,
                file_read_max: self.cfg.file_read_max_bytes,
                disk_min_free_pct: self.seed.disk_min_free_pct,
                log_buf: String::new(),
            },
        };
        let mut store = Store::new(engine(), data);
        store.limiter(|d| &mut d.limits);
        // 100ms ticks ⇒ deadline = secs * 10 ticks.
        store.set_epoch_deadline(self.cfg.timeout_secs * 10);

        let run = async {
            let bindings = EdgeFunctionPre::new(pre)?
                .instantiate_async(&mut store)
                .await?;
            bindings.call_handle(&mut store, event_json).await
        };
        let outcome = match run.await {
            Ok(Ok(json)) => RunOutcome {
                status: RunStatus::Ok,
                result: json,
                log_text: String::new(),
            },
            Ok(Err(guest_err)) => RunOutcome {
                status: RunStatus::Error,
                result: guest_err,
                log_text: String::new(),
            },
            Err(trap) => {
                let oom = store.data().limits.oom_hit;
                // Epoch-deadline expiry raises wasmtime::Trap::Interrupt
                // (wasmtime-45 vm/libcalls.rs: `UpdateDeadline::Interrupt =>
                // Err(Trap::Interrupt)`). Classify by trap code, NOT wall
                // clock: the deadline fires on the Nth global ticker tick,
                // which lands up to one tick (100ms) BEFORE `timeout_secs`
                // of wall time has elapsed, so an elapsed-time comparison
                // misreports essentially every genuine timeout as a trap.
                let interrupted =
                    trap.downcast_ref::<wasmtime::Trap>() == Some(&wasmtime::Trap::Interrupt);
                let status = if oom {
                    RunStatus::Oom
                } else if interrupted {
                    RunStatus::Timeout
                } else {
                    RunStatus::Trap
                };
                RunOutcome {
                    status,
                    result: format!("{trap:#}"),
                    log_text: String::new(),
                }
            }
        };
        let log_text = store.data().host.log_buf.clone();
        RunOutcome {
            log_text,
            ..outcome
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_initializes_once() {
        let a = engine() as *const Engine;
        let b = engine() as *const Engine;
        assert_eq!(a, b);
    }

    #[test]
    fn validate_rejects_garbage() {
        assert!(validate_component(b"not wasm at all").is_err());
    }

    // Drive the *production* put-file host call (StoreData::put_file) with an
    // in-memory Garage and read back the cache_control the `_system_files`
    // INSERT actually wrote. This exercises the line the Fix-5 change touches
    // (the INSERT's bound `cc`), so hardcoding a public literal back into the
    // INSERT — i.e. reverting the fix — makes this assertion fail. (The earlier
    // helper-only test was tautological: it re-derived the same expression it
    // asserted, and stayed green when the bug was reintroduced.)
    async fn build_store_with_garage(
        tenant_id: &str,
    ) -> (
        StoreData,
        crate::storage::pool::SharedTenantPool,
        tempfile::TempDir,
    ) {
        let tmp = tempfile::tempdir().unwrap();
        let tenants = Arc::new(crate::storage::pool::TenantRegistry::new(
            tmp.path().to_path_buf(),
            2,
        ));
        // get_or_open bootstraps the tenant schema, including `_system_files`.
        let pool = tenants.get_or_open(tenant_id).unwrap();
        let garage = Arc::new(crate::storage::garage::GarageClient::from_store(
            Arc::new(object_store::memory::InMemory::new()),
            "unused",
        ));
        let rooms_cfg = crate::tenant::rooms::RoomsConfig::test_defaults();
        let bucket = rooms_cfg.bucket();
        let seed = HostStateSeed {
            tenants: tenants.clone(),
            bus: crate::tenant::events::EventBus::new(),
            webhooks: crate::tenant::WebhookDispatcher::new(tenants.clone(), None),
            garage: Some(garage),
            public_base_url: String::new(),
            url_sign_secret: Arc::new([0u8; 32]),
            meta: None,
            max_upload_bytes: 52_428_800,
            index_large_table_rows: 1_000_000,
            audit_meta_read: Arc::new(tokio::sync::Mutex::new(
                crate::safety::audit_db::open_audit_db_memory().unwrap(),
            )),
            bus_rooms: crate::tenant::rooms::RoomBus::new(),
            bucket,
            rooms_cfg,
            disk_min_free_pct: 20,
        };
        let mcp = seed.build_mcp(tenant_id).unwrap();
        let store = StoreData {
            wasi: wasmtime_wasi::WasiCtxBuilder::new().build(),
            table: wasmtime::component::ResourceTable::new(),
            limits: MemLimiter {
                cap: 64 * 1024 * 1024,
                oom_hit: false,
            },
            host: HostState {
                mcp,
                file_read_max: 4 * 1024 * 1024,
                disk_min_free_pct: 20,
                log_buf: String::new(),
            },
        };
        (store, pool, tmp)
    }

    async fn put_file_then_read_cc(visibility: &str) -> String {
        let (mut store, pool, _tmp) = build_store_with_garage("t-cc").await;
        let key = format!("fn-{visibility}.bin");
        host::Host::put_file(
            &mut store,
            key.clone(),
            b"hello".to_vec(),
            "application/octet-stream".into(),
            visibility.into(),
        )
        .await
        .expect("put_file host call");
        pool.with_reader(move |c| {
            c.query_row(
                "SELECT cache_control FROM _system_files WHERE key = ?1",
                rusqlite::params![key],
                |r| r.get::<_, String>(0),
            )
        })
        .await
        .expect("read back cache_control")
    }

    // Fix 5: a guest put-file must derive cache_control from the object's
    // visibility (mirror Mode A/B `default_cache_control`), not hardcode a
    // public value — otherwise a private function-written object carries a
    // publicly-cacheable directive on both the `_system_files` row and the
    // Garage object. Asserted against the row the production INSERT wrote.
    #[tokio::test(flavor = "multi_thread")]
    async fn put_file_private_row_carries_private_cache_control() {
        let cc = put_file_then_read_cc("private").await;
        assert_ne!(
            cc, "public, max-age=3600",
            "private put-file row must not carry the hardcoded public cache_control"
        );
        assert_eq!(
            cc,
            crate::storage::files::default_cache_control(
                crate::storage::files::Visibility::Private,
                crate::storage::files::Disposition::Inline,
            ),
            "private _system_files row must carry the Mode A/B private default ('private, no-store')"
        );
    }

    // Public put-file stays publicly cacheable — guards against an over-broad
    // fix that flips everything to private.
    #[tokio::test(flavor = "multi_thread")]
    async fn put_file_public_row_carries_public_cache_control() {
        let cc = put_file_then_read_cc("public").await;
        assert_eq!(
            cc,
            crate::storage::files::default_cache_control(
                crate::storage::files::Visibility::Public,
                crate::storage::files::Disposition::Inline,
            ),
            "public _system_files row must carry the Mode A/B public default"
        );
    }
}
