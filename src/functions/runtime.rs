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
    /// The identity this invocation runs as. The six data-plane host fns branch
    /// on it: `Privileged` → today's god-mode path (byte-for-byte unchanged);
    /// `Anon`/`User` → the capability-gated enforcement core (`functions::enforce`)
    /// with `caller.to_auth_ctx()` / `caller.role()`.
    caller: crate::functions::caller::CallerCtx,
    /// The tenant's file caps (`file_anon_caps_json` / `file_user_caps_json`),
    /// loaded ONCE per invocation from the tenant row (mirroring
    /// `bearer_auth_layer`). Consulted only on the Anon/User file branches; the
    /// Privileged/service path ignores it (service is unrestricted).
    file_caps: crate::tenant::file_caps::TenantFileCaps,
    /// v1.49 — the gated `http-fetch` state: the tenant's egress allowlist
    /// (resolved ONCE at invocation build time so the guest can't race a config
    /// change), the response/timeout caps, the per-tenant rate limiter, and an
    /// optional resolver override (production is `None` → `PinnedPublicResolver`).
    http: HttpFetchState,
}

/// Per-invocation state for the `http-fetch` host import (v1.49). Every field
/// is resolved BEFORE the guest runs so a guest cannot influence the egress
/// decision at call time.
pub struct HttpFetchState {
    /// The tenant's `egress_allowlist_json`. Resolved LAZILY on the first
    /// `http-fetch` call (not at build time) so a function that never fetches
    /// pays no meta read — the common Privileged (event/cron) path. Still
    /// race-free: read once, cached for the invocation, before any dial.
    /// Deny-all `"[]"` when meta is absent (test ctors) or unreadable. Only the
    /// `system=function` entries gate `http-fetch`.
    pub allowlist_json: String,
    /// Meta handle for the lazy allowlist read; `None` in test ctors (which
    /// pre-set `allowlist_json` directly and skip the read).
    pub meta: Option<Arc<tokio::sync::Mutex<rusqlite::Connection>>>,
    /// Tenant id for the lazy allowlist read.
    pub tenant_id: String,
    /// Whether `allowlist_json` has been resolved from meta this invocation.
    pub resolved: bool,
    /// `DRUST_FN_HTTP_TIMEOUT_SECS` — per-request reqwest timeout.
    pub timeout_secs: u64,
    /// `DRUST_FN_HTTP_MAX_RESPONSE_BYTES` — streaming response-body cap.
    pub max_response_bytes: u64,
    /// Per-tenant token-bucket limiter (`DRUST_FN_HTTP_RATE_PER_MIN` / 60 s),
    /// shared across invocations via `WasmRunner`. Keyed by tenant id.
    pub rate_limiter: Arc<crate::safety::rate_limit::RateLimiter>,
    /// Test-only reqwest resolver override. Production leaves this `None`, so
    /// the client is ALWAYS pinned to `PinnedPublicResolver` — the second DiD
    /// gate. Tests inject a loopback-pinning resolver to reach a local server;
    /// there is NO loopback carve-out on the production `http-fetch` path.
    pub resolver_override: Option<Arc<dyn reqwest::dns::Resolve + Send + Sync>>,
}

impl HttpFetchState {
    /// Build the production per-invocation state from the shared limiter + cfg.
    /// The allowlist is resolved lazily (see `allowlist`), so `new` takes the
    /// meta handle + tenant id rather than a pre-read JSON string.
    pub fn new(
        meta: Option<Arc<tokio::sync::Mutex<rusqlite::Connection>>>,
        tenant_id: String,
        timeout_secs: u64,
        max_response_bytes: u64,
        rate_limiter: Arc<crate::safety::rate_limit::RateLimiter>,
    ) -> Self {
        Self {
            allowlist_json: "[]".to_string(),
            meta,
            tenant_id,
            resolved: false,
            timeout_secs,
            max_response_bytes,
            rate_limiter,
            resolver_override: None,
        }
    }

    /// Lazily resolve (and cache) the tenant's egress allowlist. With `meta`
    /// present it reads `egress_allowlist_json` under the meta lock exactly
    /// once per invocation, fail-closed to deny-all. With `meta` absent (test
    /// ctors) it returns the pre-set `allowlist_json` unchanged.
    pub async fn allowlist(&mut self) -> &str {
        if let Some(meta) = &self.meta
            && !self.resolved
        {
            let conn = meta.lock().await;
            self.allowlist_json =
                crate::tenant::egress::read_egress_allowlist(&conn, &self.tenant_id)
                    .unwrap_or_else(|_| "[]".to_string());
            self.resolved = true;
        }
        &self.allowlist_json
    }

    /// Test defaults — deny-all allowlist, no meta (pre-set allowlist wins),
    /// generous caps, a fresh limiter, no resolver override. Callers spread
    /// `..HttpFetchState::test_default()`.
    #[cfg(any(test, debug_assertions))]
    pub fn test_default() -> Self {
        Self {
            allowlist_json: "[]".to_string(),
            meta: None,
            tenant_id: "test".to_string(),
            resolved: false,
            timeout_secs: 10,
            max_response_bytes: 5 * 1024 * 1024,
            rate_limiter: Arc::new(crate::safety::rate_limit::RateLimiter::new(
                60,
                std::time::Duration::from_secs(60),
            )),
            resolver_override: None,
        }
    }
}

/// Hop-by-hop headers (RFC 7230 §6.1) plus `host`/`content-length` — never
/// forwarded from a guest-supplied header list. `host` in particular must not
/// be guest-settable or a function could spoof the SNI/vhost of an allowlisted
/// origin; the length is reqwest's to compute.
fn is_forbidden_fetch_header(name_lower: &str) -> bool {
    matches!(
        name_lower,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "host"
            | "content-length"
    )
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

/// The `host` import interface. bindgen generates true async trait methods
/// (`imports: { default: async }`), so the tool layer is awaited directly —
/// no block_on / runtime Handle needed (plan adaptation note: preferred form).
impl host::Host for StoreData {
    async fn query_list(
        &mut self,
        collection: String,
        body_json: String,
    ) -> Result<String, String> {
        use crate::functions::caller::CallerCtx;
        match &self.host.caller {
            // Privileged: today's god-mode path, byte-for-byte unchanged.
            CallerCtx::Privileged => {
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
            // Anon/User: capability-gated through the enforcement core.
            caller => {
                debug_assert!(
                    !matches!(caller, CallerCtx::Privileged),
                    "non-privileged branch reached with Privileged caller"
                );
                let ctx = caller.to_auth_ctx();
                let req: crate::query::list_builder::ListRequest =
                    serde_json::from_str(&body_json).map_err(|e| format!("bad list args: {e}"))?;
                crate::functions::enforce::enforced_list(&self.host.mcp, &ctx, &collection, req)
                    .await
                    .map(|v| v.to_string())
                    .map_err(|e| e.to_string())
            }
        }
    }

    async fn insert_record(
        &mut self,
        collection: String,
        data_json: String,
    ) -> Result<String, String> {
        use crate::functions::caller::CallerCtx;
        let data: serde_json::Value =
            serde_json::from_str(&data_json).map_err(|e| format!("bad data-json: {e}"))?;
        match &self.host.caller {
            CallerCtx::Privileged => {
                crate::mcp::tools::write::insert_record(&self.host.mcp, &collection, data)
                    .await
                    .map(|v| v.to_string())
                    .map_err(|e| e.to_string())
            }
            caller => {
                debug_assert!(
                    !matches!(caller, CallerCtx::Privileged),
                    "non-privileged branch reached with Privileged caller"
                );
                let ctx = caller.to_auth_ctx();
                crate::functions::enforce::enforced_insert(&self.host.mcp, &ctx, &collection, data)
                    .await
                    .map(|v| v.to_string())
                    .map_err(|e| e.to_string())
            }
        }
    }

    async fn update_record(
        &mut self,
        collection: String,
        id: i64,
        data_json: String,
    ) -> Result<String, String> {
        use crate::functions::caller::CallerCtx;
        let data: serde_json::Value =
            serde_json::from_str(&data_json).map_err(|e| format!("bad data-json: {e}"))?;
        match &self.host.caller {
            CallerCtx::Privileged => {
                crate::mcp::tools::write::update_record(&self.host.mcp, &collection, id, data)
                    .await
                    .map(|v| v.to_string())
                    .map_err(|e| e.to_string())
            }
            caller => {
                debug_assert!(
                    !matches!(caller, CallerCtx::Privileged),
                    "non-privileged branch reached with Privileged caller"
                );
                let ctx = caller.to_auth_ctx();
                crate::functions::enforce::enforced_update(
                    &self.host.mcp,
                    &ctx,
                    &collection,
                    id,
                    data,
                )
                .await
                .map(|v| v.to_string())
                .map_err(|e| e.to_string())
            }
        }
    }

    async fn delete_record(&mut self, collection: String, id: i64) -> Result<String, String> {
        use crate::functions::caller::CallerCtx;
        match &self.host.caller {
            CallerCtx::Privileged => {
                crate::mcp::tools::write::delete_record(&self.host.mcp, &collection, id)
                    .await
                    .map(|v| v.to_string())
                    .map_err(|e| e.to_string())
            }
            caller => {
                debug_assert!(
                    !matches!(caller, CallerCtx::Privileged),
                    "non-privileged branch reached with Privileged caller"
                );
                let ctx = caller.to_auth_ctx();
                crate::functions::enforce::enforced_delete(&self.host.mcp, &ctx, &collection, id)
                    .await
                    .map(|v| v.to_string())
                    .map_err(|e| e.to_string())
            }
        }
    }

    async fn get_file_bytes(&mut self, key: String) -> Result<Vec<u8>, String> {
        use crate::functions::caller::CallerCtx;
        match &self.host.caller {
            // Privileged (event/service/cron): raw path, no cap gate — today's
            // behavior, byte-for-byte.
            CallerCtx::Privileged => {
                crate::functions::enforce::get_file_bytes_raw(
                    &self.host.mcp,
                    &key,
                    self.host.file_read_max,
                )
                .await
            }
            // Anon/User: the `file.read` cap gate (against the tenant's
            // TenantFileCaps) runs before the raw path.
            caller => {
                debug_assert!(
                    !matches!(caller, CallerCtx::Privileged),
                    "non-privileged branch reached with Privileged caller"
                );
                crate::functions::enforce::enforced_get_file_bytes(
                    &self.host.mcp,
                    caller.role(),
                    &self.host.file_caps,
                    &key,
                    self.host.file_read_max,
                )
                .await
            }
        }
    }

    async fn put_file(
        &mut self,
        key: String,
        bytes: Vec<u8>,
        content_type: String,
        visibility: String,
    ) -> Result<String, String> {
        // Shared with the enforcement core (`functions::enforce::put_file_raw`):
        // it carries the same max_upload_bytes + disk guard + SQLite-first
        // ordering + visibility-derived cache_control. Privileged callers use
        // the raw path (no cap); anon/user invoke gates `file.upload` first.
        use crate::functions::caller::CallerCtx;
        match &self.host.caller {
            CallerCtx::Privileged => {
                crate::functions::enforce::put_file_raw(
                    &self.host.mcp,
                    &key,
                    bytes,
                    &content_type,
                    &visibility,
                    self.host.disk_min_free_pct,
                )
                .await
            }
            caller => {
                debug_assert!(
                    !matches!(caller, CallerCtx::Privileged),
                    "non-privileged branch reached with Privileged caller"
                );
                crate::functions::enforce::enforced_put_file(
                    &self.host.mcp,
                    caller.role(),
                    &self.host.file_caps,
                    &key,
                    bytes,
                    &content_type,
                    &visibility,
                    self.host.disk_min_free_pct,
                )
                .await
            }
        }
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

    /// The gated outbound-HTTP host import (v1.49). Enforcement is caller-blind
    /// by design: egress is a HOST-outbound authorization surface, not a
    /// tenant-DATA one, so a `Privileged` (service/event/cron) caller is NOT
    /// exempt — every fetch passes BOTH `check_egress` (the tenant's
    /// `system=function` allowlist) AND `PinnedPublicResolver` (private-IP
    /// block). Each failure returns `Err(String)` to the guest; never panics.
    async fn http_fetch(
        &mut self,
        origin: String,
        path: String,
        method: String,
        body: Vec<u8>,
        headers: Vec<(String, String)>,
    ) -> Result<host::HttpResponse, String> {
        use crate::tenant::egress::{
            EgressSystem, check_egress, normalize_origin, origin_host_is_private_ip,
        };
        use std::time::Duration;

        let started = std::time::Instant::now();
        let tenant = self.host.mcp.tenant_id().to_string();

        // 1. Normalize the requested origin, then the allowlist gate (gate 1/2).
        //    Fail-closed: an un-normalizable origin or an origin absent from the
        //    tenant's `system=function` allowlist denies before any network I/O.
        let origin = normalize_origin(&origin).map_err(|e| format!("bad origin: {e}"))?;
        // DiD gate 2 for IP-LITERAL hosts: `PinnedPublicResolver` (below) only
        // filters resolved DNS names — hyper dials an IP-literal host directly
        // without polling the resolver, so an allowlisted `http://169.254.169.254`
        // / `http://127.0.0.1` would SSRF straight through to cloud metadata / host
        // loopback. Reject private/loopback/link-local IP literals explicitly here;
        // DNS-name hosts fall through to the resolver as before (codex full-scan F2).
        if origin_host_is_private_ip(&origin) {
            return Err("origin host is a private/loopback address".to_string());
        }
        let allowlist = self.host.http.allowlist().await.to_string();
        if !check_egress(&allowlist, EgressSystem::Function, &origin) {
            return Err("origin not allowlisted".to_string());
        }

        // 2. Method allowlist — reject anything outside the safe verb set.
        let method_uc = method.to_ascii_uppercase();
        let reqwest_method = match method_uc.as_str() {
            "GET" => reqwest::Method::GET,
            "POST" => reqwest::Method::POST,
            "PUT" => reqwest::Method::PUT,
            "PATCH" => reqwest::Method::PATCH,
            "DELETE" => reqwest::Method::DELETE,
            "HEAD" => reqwest::Method::HEAD,
            other => return Err(format!("method not allowed: {other}")),
        };

        // 3. Path-shape guard (pure, cheap — BEFORE the rate limit so a
        //    malformed path never burns quota). The guest-supplied `path` must
        //    be empty or rooted (`/...`): a bare `@host`, `.host`, or `//host`
        //    would rewrite the authority and dial a host the allowlist never
        //    checked (SSRF — gate 1 saw only `origin`). Reject non-rooted paths,
        //    then RE-DERIVE the origin the assembled URL actually dials and
        //    require it to equal the gated origin — DiD belt-and-suspenders:
        //    `normalize_origin` rejects userinfo (`@`) and strips the path, so
        //    any residual authority-injection fails closed even if the
        //    leading-`/` check is ever loosened.
        if !path.is_empty() && !path.starts_with('/') {
            return Err("path must be empty or start with '/'".to_string());
        }
        let url = format!("{origin}{path}");
        let dialed = normalize_origin(&url).map_err(|e| format!("bad url: {e}"))?;
        if dialed != origin {
            return Err("path must not alter the request host".to_string());
        }

        // 4. Per-tenant rate limit — BEFORE the dial so a denied call costs no
        //    outbound socket. Over budget → Err.
        if self.host.http.rate_limiter.try_acquire(&tenant).is_err() {
            return Err("rate limited".to_string());
        }

        // 5. Build a per-call client pinned to the resolver (gate 2/2). Production
        //    uses `PinnedPublicResolver` (drops private/loopback/link-local before
        //    the dial); tests inject a loopback-pinning override. No redirect
        //    following — a 3xx is returned to the guest verbatim so a redirect
        //    can never bounce the request out of the allowlist.
        let resolver: Arc<dyn reqwest::dns::Resolve + Send + Sync> = self
            .host
            .http
            .resolver_override
            .clone()
            .unwrap_or_else(|| Arc::new(crate::tenant::webhook_resolver::PinnedPublicResolver));
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(self.host.http.timeout_secs))
            .redirect(reqwest::redirect::Policy::none())
            .pool_max_idle_per_host(0)
            .dns_resolver(Arc::new(crate::tenant::webhook_resolver::ResolverHandle(
                resolver,
            )))
            .build()
            .map_err(|e| format!("client build: {e}"))?;

        // 6. Assemble the request. Guest-supplied headers are filtered: no
        //    hop-by-hop, no `Host`/`Content-Length` spoofing. `url`/`dialed`
        //    were validated in step 3, before the rate limit.
        let mut req = client.request(reqwest_method, &url);
        for (k, v) in &headers {
            if is_forbidden_fetch_header(&k.to_ascii_lowercase()) {
                continue;
            }
            req = req.header(k, v);
        }
        if !body.is_empty() {
            req = req.body(body);
        }

        // 6. Send + read the body with a streaming cap: abort as soon as the
        //    accumulated bytes exceed `max_response_bytes` (OOM guard).
        let mut resp = req
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;
        let status = resp.status().as_u16();
        let resp_headers: Vec<(String, String)> = resp
            .headers()
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_string(),
                    String::from_utf8_lossy(v.as_bytes()).into_owned(),
                )
            })
            .collect();
        let cap = self.host.http.max_response_bytes as usize;
        let mut body_buf: Vec<u8> = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(|e| format!("read body: {e}"))? {
            if body_buf.len().saturating_add(chunk.len()) > cap {
                return Err(format!("response exceeds size cap of {cap} bytes"));
            }
            body_buf.extend_from_slice(&chunk);
        }

        // 7. Audit a completed fetch (op `function.http_fetch`).
        crate::safety::audit_db::try_send(
            &crate::safety::audit::AuditEntry::success(
                &tenant,
                "function",
                "function.http_fetch",
                started.elapsed().as_millis() as u64,
            )
            .with_extra(serde_json::json!({
                "origin": origin,
                "method": method_uc,
                "status": status,
            })),
        );

        Ok(host::HttpResponse {
            status,
            headers: resp_headers,
            body: body_buf,
        })
    }
}

/// Test-gated constructor + wrapper so the integration suite
/// (`tests/egress_http_fetch.rs`) can drive `http_fetch` directly — the
/// `HostState` fields are private, so an external test cannot build a
/// `StoreData` literal.
#[cfg(any(test, debug_assertions))]
impl StoreData {
    /// Build a `StoreData` over a pre-constructed `DrustMcp` + caller + the
    /// `http-fetch` state (allowlist / caps / resolver). File caps default to
    /// all-off; `http-fetch` never consults them.
    pub fn new_for_test(
        mcp: DrustMcp,
        caller: crate::functions::caller::CallerCtx,
        http: HttpFetchState,
    ) -> Self {
        StoreData {
            wasi: wasmtime_wasi::WasiCtxBuilder::new().build(),
            table: wasmtime::component::ResourceTable::new(),
            limits: MemLimiter {
                cap: 64 * 1024 * 1024,
                oom_hit: false,
            },
            host: HostState {
                mcp,
                file_read_max: 4 * 1024 * 1024,
                disk_min_free_pct: 0,
                log_buf: String::new(),
                caller,
                file_caps: crate::tenant::file_caps::TenantFileCaps::default(),
                http,
            },
        }
    }

    /// Call the production `http_fetch` and flatten the generated
    /// `host::HttpResponse` into a plain tuple so the test needn't touch the
    /// bindgen module.
    pub async fn http_fetch_for_test(
        &mut self,
        origin: String,
        path: String,
        method: String,
        body: Vec<u8>,
        headers: Vec<(String, String)>,
    ) -> Result<(u16, Vec<(String, String)>, Vec<u8>), String> {
        host::Host::http_fetch(self, origin, path, method, body, headers)
            .await
            .map(|r| (r.status, r.headers, r.body))
    }
}

/// Production runner.
pub struct WasmRunner {
    cfg: FnConfig,
    cache: PreCache,
    linker: OnceLock<Linker<StoreData>>,
    /// Builds the per-tenant DrustMcp with functions: None.
    seed: HostStateSeed,
    /// v1.49 — per-tenant `http-fetch` rate limiter, shared across every
    /// invocation (keyed by tenant id). Built once here so the budget survives
    /// across the fresh `StoreData` each invocation constructs.
    http_rl: Arc<crate::safety::rate_limit::RateLimiter>,
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
    /// Resolve the tenant's file caps for this invocation from the `tenants`
    /// row (`file_anon_caps_json` / `file_user_caps_json`), mirroring the
    /// `SQL_BEARER_AUTH_CTE` load in `bearer_auth_layer`. Only the Anon/User
    /// file branches consult the result. Fails CLOSED to all-off (`default()`)
    /// when `meta` is absent (test ctors) or the tenant row is missing/unreadable
    /// — the function host carries no bearer, so the cap source is the row alone.
    async fn load_file_caps(&self, tenant_id: &str) -> crate::tenant::file_caps::TenantFileCaps {
        let Some(meta) = self.meta.as_ref() else {
            return crate::tenant::file_caps::TenantFileCaps::default();
        };
        let conn = meta.lock().await;
        let row: Option<(String, String)> = conn
            .query_row(
                "SELECT COALESCE(file_anon_caps_json, '[]'), COALESCE(file_user_caps_json, '[]') \
                 FROM tenants WHERE id = ?1 AND deleted_at IS NULL",
                rusqlite::params![tenant_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .ok();
        match row {
            Some((anon_json, user_json)) => {
                crate::tenant::file_caps::TenantFileCaps::from_json(&anon_json, &user_json)
            }
            None => crate::tenant::file_caps::TenantFileCaps::default(),
        }
    }

    /// `functions: None` here is the depth=1 recursion guard (spec §4).
    pub fn build_mcp(&self, tenant_id: &str) -> anyhow::Result<DrustMcp> {
        // `get_if_live`, NOT `get_or_open`: the runner resolves by tenant-id
        // string after arbitrary queue/lock waits, so a soft-delete landing
        // in that window must fail the build — never re-create the dead
        // tenant's data.sqlite (the create-free open is the atomic guard;
        // completes the executor-side fix, which alone left this re-entry).
        let pool = self
            .tenants
            .get_if_live(tenant_id)
            .ok_or_else(|| anyhow::anyhow!("tenant gone or unopenable: {tenant_id}"))?;
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
        let http_rl = Arc::new(crate::safety::rate_limit::RateLimiter::new(
            cfg.http_rate_per_min,
            std::time::Duration::from_secs(60),
        ));
        Arc::new(Self {
            cache: PreCache {
                cap: cfg.module_cache,
                entries: StdMutex::new(Vec::new()),
            },
            cfg,
            linker: OnceLock::new(),
            seed,
            http_rl,
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
        caller: crate::functions::caller::CallerCtx,
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

        // Load the tenant's file caps ONCE per invocation (mirrors how
        // `bearer_auth_layer` resolves them from the `tenants` row), but ONLY
        // for a non-Privileged caller: the Privileged (service/event/cron) file
        // branches bypass caps entirely, so loading them on the god-mode hot
        // path is a wasted meta query. No `meta` (test ctors) ⇒ default = all-off.
        let file_caps = match &caller {
            crate::functions::caller::CallerCtx::Privileged => {
                crate::tenant::file_caps::TenantFileCaps::default()
            }
            _ => self.seed.load_file_caps(tenant_id).await,
        };

        // The egress allowlist is resolved LAZILY on the first `http-fetch`
        // call (see `HttpFetchState::allowlist`) — a function that never
        // fetches (the common event/cron path) does no meta read here.
        let http = HttpFetchState::new(
            self.seed.meta.clone(),
            tenant_id.to_string(),
            self.cfg.http_timeout_secs,
            self.cfg.http_max_response_bytes,
            self.http_rl.clone(),
        );

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
                caller,
                file_caps,
                http,
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

    /// The runner resolves tenants by id string AFTER arbitrary queue/lock
    /// waits, so `build_mcp` must never take the create-happy `get_or_open`
    /// path: a gone tenant fails the build and leaves no directory behind.
    /// (Reverting `build_mcp` to `get_or_open` makes both assertions fail —
    /// the dir would be re-created with a fresh data.sqlite.)
    #[test]
    fn build_mcp_never_recreates_a_gone_tenant() {
        let tmp = tempfile::tempdir().unwrap();
        let tenants = Arc::new(crate::storage::pool::TenantRegistry::new(
            tmp.path().to_path_buf(),
            2,
        ));
        let rooms_cfg = crate::tenant::rooms::RoomsConfig::test_defaults();
        let bucket = rooms_cfg.bucket();
        let seed = HostStateSeed {
            tenants: tenants.clone(),
            bus: crate::tenant::events::EventBus::new(),
            webhooks: crate::tenant::WebhookDispatcher::new(tenants.clone(), None),
            garage: None,
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
        let err = match seed.build_mcp("ghost") {
            Ok(_) => panic!("build_mcp on a gone tenant must error"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("tenant gone"),
            "unexpected error: {err}"
        );
        let dir = tmp.path().join("tenants").join("ghost");
        assert!(
            !dir.exists(),
            "build_mcp must not re-create a gone tenant's directory"
        );
    }

    /// F14: `HostStateSeed::load_file_caps` is the production source of an
    /// anon/user invocation's file caps, but every other test builds the host
    /// with `meta: None` (default all-off). Cover the real path: parse a
    /// populated `tenants` row, fall back to all-off on a missing tenant, and —
    /// load-bearing — honour the `deleted_at IS NULL` filter so a soft-deleted
    /// tenant never yields caps.
    #[tokio::test]
    async fn load_file_caps_reads_populated_meta_row() {
        use crate::storage::schema::FileVerb;
        let tmp = tempfile::tempdir().unwrap();
        let tenants = Arc::new(crate::storage::pool::TenantRegistry::new(
            tmp.path().to_path_buf(),
            2,
        ));
        let meta = rusqlite::Connection::open_in_memory().unwrap();
        meta.execute_batch(
            "CREATE TABLE tenants (id TEXT PRIMARY KEY, deleted_at TEXT,
                 file_anon_caps_json TEXT, file_user_caps_json TEXT);
             INSERT INTO tenants (id, deleted_at, file_anon_caps_json, file_user_caps_json) VALUES
                 ('t-fc',  NULL,                   '[\"read\",\"list\"]', '[\"upload\"]'),
                 ('t-del', '2026-01-01T00:00:00Z', '[\"read\"]',          '[\"delete\"]');",
        )
        .unwrap();
        let rooms_cfg = crate::tenant::rooms::RoomsConfig::test_defaults();
        let bucket = rooms_cfg.bucket();
        let seed = HostStateSeed {
            tenants: tenants.clone(),
            bus: crate::tenant::events::EventBus::new(),
            webhooks: crate::tenant::WebhookDispatcher::new(tenants.clone(), None),
            garage: None,
            public_base_url: String::new(),
            url_sign_secret: Arc::new([0u8; 32]),
            meta: Some(Arc::new(tokio::sync::Mutex::new(meta))),
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

        // Populated, live row → parsed caps (anon read+list, user upload only).
        let caps = seed.load_file_caps("t-fc").await;
        assert!(caps.anon.contains(&FileVerb::Read) && caps.anon.contains(&FileVerb::List));
        assert!(!caps.anon.contains(&FileVerb::Upload) && !caps.anon.contains(&FileVerb::Delete));
        assert!(caps.user.contains(&FileVerb::Upload));
        assert!(!caps.user.contains(&FileVerb::Read));

        // Missing tenant → default all-off.
        let none = seed.load_file_caps("nope").await;
        assert!(none.anon.is_empty() && none.user.is_empty());

        // Soft-deleted tenant is filtered by `deleted_at IS NULL` → all-off,
        // NOT the row's caps.
        let del = seed.load_file_caps("t-del").await;
        assert!(
            del.anon.is_empty() && del.user.is_empty(),
            "soft-deleted tenant must not yield file caps"
        );
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
                caller: crate::functions::caller::CallerCtx::Privileged,
                file_caps: crate::tenant::file_caps::TenantFileCaps::default(),
                http: HttpFetchState::test_default(),
            },
        };
        (store, pool, tmp)
    }

    // ── Task 3: CallerCtx-branched host imports ─────────────────────────────
    //
    // Drive the production `host::Host` fns directly (as the put_file tests do)
    // with a non-Privileged `caller`, and assert the host op now runs through
    // the capability-gated enforcement core — proving the branch is wired, not
    // that the core itself decides correctly (that is `enforce`'s own suite).
    use crate::functions::caller::CallerCtx;
    use crate::mcp::server::DrustMcp;

    /// Build a fully-wired `DrustMcp` over a fresh tenant pool + in-memory Garage
    /// (no `meta` — the caller is supplied directly, so the per-invocation file-cap
    /// load is bypassed; tests pass `file_caps` explicitly).
    async fn mcp_for(
        tenant_id: &str,
    ) -> (
        DrustMcp,
        crate::storage::pool::SharedTenantPool,
        tempfile::TempDir,
    ) {
        let tmp = tempfile::tempdir().unwrap();
        let tenants = Arc::new(crate::storage::pool::TenantRegistry::new(
            tmp.path().to_path_buf(),
            2,
        ));
        let pool = tenants.get_or_open(tenant_id).unwrap();
        let garage = Arc::new(crate::storage::garage::GarageClient::from_store(
            Arc::new(object_store::memory::InMemory::new()),
            "unused",
        ));
        let rooms_cfg = crate::tenant::rooms::RoomsConfig::test_defaults();
        let bucket = rooms_cfg.bucket();
        let mcp = DrustMcp::new(
            tenant_id,
            pool.clone(),
            crate::tenant::events::EventBus::new(),
            crate::tenant::WebhookDispatcher::new(tenants.clone(), None),
            Some(garage),
            String::new(),
            Arc::new([0u8; 32]),
            None,
            52_428_800,
            1_000_000,
            Arc::new(tokio::sync::Mutex::new(
                crate::safety::audit_db::open_audit_db_memory().unwrap(),
            )),
            crate::tenant::rooms::RoomBus::new(),
            bucket,
            rooms_cfg,
            None,
            None,
        );
        (mcp, pool, tmp)
    }

    fn store_with(
        mcp: DrustMcp,
        caller: CallerCtx,
        file_caps: crate::tenant::file_caps::TenantFileCaps,
    ) -> StoreData {
        StoreData {
            wasi: wasmtime_wasi::WasiCtxBuilder::new().build(),
            table: wasmtime::component::ResourceTable::new(),
            limits: MemLimiter {
                cap: 64 * 1024 * 1024,
                oom_hit: false,
            },
            host: HostState {
                mcp,
                file_read_max: 4 * 1024 * 1024,
                disk_min_free_pct: 0,
                log_buf: String::new(),
                caller,
                file_caps,
                http: HttpFetchState::test_default(),
            },
        }
    }

    async fn make_owner_scoped(
        pool: &crate::storage::pool::SharedTenantPool,
        mcp: &DrustMcp,
        coll: &str,
        read_scope: &str,
    ) {
        let coll_c = coll.to_string();
        let scope_c = read_scope.to_string();
        let coll_q = coll.replace('"', "\"\"");
        pool.with_writer(move |c| {
            c.execute_batch(&format!(
                "PRAGMA foreign_keys = ON;
                 CREATE TABLE \"{coll_q}\" (
                     id         INTEGER PRIMARY KEY AUTOINCREMENT,
                     owner      TEXT REFERENCES _system_users(id) ON DELETE RESTRICT,
                     title      TEXT,
                     created_at TEXT DEFAULT (datetime('now')),
                     updated_at TEXT DEFAULT (datetime('now'))
                 );"
            ))?;
            crate::storage::schema::set_owner_field(c, &coll_c, Some("owner"), Some(&scope_c))
        })
        .await
        .unwrap();
        mcp.inner().pool.schema_cache.invalidate(coll);
    }

    async fn seed_user(pool: &crate::storage::pool::SharedTenantPool, id: &str) {
        let id = id.to_string();
        pool.with_writer(move |c| {
            c.execute(
                "INSERT INTO _system_users (id, email, password_hash, created_at, updated_at) \
                 VALUES (?1, ?1, 'x', datetime('now'), datetime('now'))",
                rusqlite::params![id],
            )
            .map(|_| ())
        })
        .await
        .unwrap();
    }

    /// Anon caller invoking the insert host fn over a collection without the
    /// insert cap is DENIED by the enforcement core (default anon_caps=[select]).
    #[tokio::test(flavor = "multi_thread")]
    async fn anon_insert_host_fn_denied_without_cap() {
        let (mcp, pool, _t) = mcp_for("t-anon").await;
        crate::mcp::tools::schema::create_collection(
            &mcp,
            "notes",
            &[crate::mcp::tools::schema::FieldSpec {
                name: "body".into(),
                sql_type: "text".into(),
                nullable: true,
                ..Default::default()
            }],
        )
        .await
        .unwrap();
        let _ = pool; // keep handle alive
        let mut store = store_with(mcp, CallerCtx::Anon, Default::default());
        let r = host::Host::insert_record(
            &mut store,
            "notes".into(),
            serde_json::json!({"body": "x"}).to_string(),
        )
        .await;
        let e = r.unwrap_err();
        assert!(e.contains("ANON_CAP_DENIED"), "got: {e}");
    }

    /// Granting the insert cap lets the anon host-fn insert succeed.
    #[tokio::test(flavor = "multi_thread")]
    async fn anon_insert_host_fn_allowed_with_cap() {
        let (mcp, _pool, _t) = mcp_for("t-anon2").await;
        crate::mcp::tools::schema::create_collection(
            &mcp,
            "notes",
            &[crate::mcp::tools::schema::FieldSpec {
                name: "body".into(),
                sql_type: "text".into(),
                nullable: true,
                ..Default::default()
            }],
        )
        .await
        .unwrap();
        crate::mcp::tools::schema::set_anon_caps(
            &mcp,
            "notes",
            &[
                crate::storage::schema::DmlVerb::Select,
                crate::storage::schema::DmlVerb::Insert,
            ],
        )
        .await
        .unwrap();
        let mut store = store_with(mcp, CallerCtx::Anon, Default::default());
        let out = host::Host::insert_record(
            &mut store,
            "notes".into(),
            serde_json::json!({"body": "x"}).to_string(),
        )
        .await
        .expect("anon insert with cap");
        assert!(out.contains("\"id\""), "inserted row: {out}");
    }

    /// User caller insert over an owner-scoped collection stamps the owner column
    /// to the caller's user_id (the core overwrites a forged owner).
    #[tokio::test(flavor = "multi_thread")]
    async fn user_insert_host_fn_stamps_owner() {
        let (mcp, pool, _t) = mcp_for("t-user").await;
        make_owner_scoped(&pool, &mcp, "todos", "own").await;
        seed_user(&pool, "u-1").await;
        let mut store = store_with(
            mcp,
            CallerCtx::User {
                user_id: "u-1".into(),
            },
            Default::default(),
        );
        let out = host::Host::insert_record(
            &mut store,
            "todos".into(),
            serde_json::json!({"title": "t", "owner": "u-evil"}).to_string(),
        )
        .await
        .expect("user insert");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["record"]["owner"], "u-1", "owner must be stamped: {v}");
    }

    /// Privileged (service/event) caller keeps god-mode: insert succeeds with NO
    /// cap granted — the cap gate is bypassed, today's behavior unchanged.
    #[tokio::test(flavor = "multi_thread")]
    async fn privileged_insert_host_fn_god_mode() {
        let (mcp, _pool, _t) = mcp_for("t-priv").await;
        crate::mcp::tools::schema::create_collection(
            &mcp,
            "notes",
            &[crate::mcp::tools::schema::FieldSpec {
                name: "body".into(),
                sql_type: "text".into(),
                nullable: true,
                ..Default::default()
            }],
        )
        .await
        .unwrap();
        // no caps granted — Privileged ignores them.
        let mut store = store_with(mcp, CallerCtx::Privileged, Default::default());
        let out = host::Host::insert_record(
            &mut store,
            "notes".into(),
            serde_json::json!({"body": "s"}).to_string(),
        )
        .await
        .expect("privileged god-mode insert");
        assert!(out.contains("\"id\""), "inserted: {out}");
    }

    /// Anon file put without the upload cap is DENIED via the enforcement core.
    #[tokio::test(flavor = "multi_thread")]
    async fn anon_put_file_host_fn_denied_without_cap() {
        let (mcp, _pool, _t) = mcp_for("t-file").await;
        let mut store = store_with(mcp, CallerCtx::Anon, Default::default());
        let r = host::Host::put_file(
            &mut store,
            "f.bin".into(),
            b"hi".to_vec(),
            "application/octet-stream".into(),
            "private".into(),
        )
        .await;
        assert!(
            r.unwrap_err().contains("FILE_UPLOAD_DENIED"),
            "anon put-file must be cap-gated"
        );
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
