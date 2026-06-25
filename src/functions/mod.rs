//! v1.36 — Edge functions: per-tenant user-uploaded wasm components,
//! event-triggered (record CRUD + file upload), executed in in-process
//! wasmtime. Spec: docs/superpowers/specs/2026-06-10-drust-edge-functions-design.md.

pub mod bindings;
pub mod caller;
pub mod dispatcher;
pub mod enforce;
pub mod executor;
pub mod invoke_gate;
pub mod routes;
pub mod runtime;
pub mod schema;

/// Env-driven resource knobs. Parsed once in `main.rs`; cloned everywhere.
#[derive(Clone, Debug)]
pub struct FnConfig {
    /// DRUST_FN_MAX_WASM_BYTES — artifact size ceiling (default 20 MiB).
    pub max_wasm_bytes: usize,
    /// DRUST_FN_MEMORY_MAX_BYTES — per-Store linear-memory cap (default 256 MiB).
    pub memory_max_bytes: usize,
    /// DRUST_FN_TIMEOUT_SECS — wall-clock epoch deadline (default 30).
    pub timeout_secs: u64,
    /// DRUST_FN_MAX_PER_TENANT — `_system_functions` row cap (default 10).
    pub max_per_tenant: u32,
    /// DRUST_FN_QUEUE_DEPTH — queued invocations per tenant (default 100).
    pub queue_depth: usize,
    /// DRUST_FN_CONCURRENCY — global concurrent executions (default 2).
    pub concurrency: usize,
    /// DRUST_FN_FILE_READ_MAX_BYTES — get-file-bytes refusal threshold (default 32 MiB).
    pub file_read_max_bytes: u64,
    /// DRUST_FN_MODULE_CACHE — compiled-component LRU entries (default 32).
    pub module_cache: usize,
}

impl FnConfig {
    pub fn from_env() -> Self {
        fn env_or<T: std::str::FromStr>(key: &str, default: T) -> T {
            std::env::var(key)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(default)
        }
        Self {
            max_wasm_bytes: env_or("DRUST_FN_MAX_WASM_BYTES", 20 * 1024 * 1024),
            memory_max_bytes: env_or("DRUST_FN_MEMORY_MAX_BYTES", 256 * 1024 * 1024),
            timeout_secs: env_or("DRUST_FN_TIMEOUT_SECS", 30),
            max_per_tenant: env_or("DRUST_FN_MAX_PER_TENANT", 10),
            queue_depth: env_or("DRUST_FN_QUEUE_DEPTH", 100),
            concurrency: env_or("DRUST_FN_CONCURRENCY", 2),
            file_read_max_bytes: env_or("DRUST_FN_FILE_READ_MAX_BYTES", 32 * 1024 * 1024),
            module_cache: env_or("DRUST_FN_MODULE_CACHE", 32),
        }
    }

    /// Test defaults — small, fast, deterministic.
    #[cfg(any(test, debug_assertions))]
    pub fn test_default() -> Self {
        Self {
            max_wasm_bytes: 20 * 1024 * 1024,
            memory_max_bytes: 64 * 1024 * 1024,
            timeout_secs: 3,
            max_per_tenant: 10,
            queue_depth: 8,
            concurrency: 2,
            file_read_max_bytes: 4 * 1024 * 1024,
            module_cache: 4,
        }
    }
}

/// Test factory — builds the (dispatcher, executor, cfg) triple a
/// `TenantStack` literal needs, with a no-op runner. Keeps inline struct
/// builds out of test files (v1.35 MgmtState E0063 lesson).
#[cfg(any(test, debug_assertions))]
pub fn test_stack_parts(
    tenants: std::sync::Arc<crate::storage::pool::TenantRegistry>,
) -> (
    std::sync::Arc<dispatcher::FunctionDispatcher>,
    std::sync::Arc<executor::Executor>,
    FnConfig,
) {
    let cfg = FnConfig::test_default();
    let (tx, rx) = tokio::sync::mpsc::channel(64);
    let d = dispatcher::FunctionDispatcher::new(tenants.clone(), tx, cfg.clone());
    struct NoopRunner;
    #[async_trait::async_trait]
    impl executor::FunctionRunner for NoopRunner {
        async fn run(
            &self,
            _t: &str,
            _p: &std::path::Path,
            _e: &str,
            _caller: caller::CallerCtx,
        ) -> executor::RunOutcome {
            executor::RunOutcome {
                status: executor::RunStatus::Ok,
                result: "{}".into(),
                log_text: String::new(),
            }
        }
    }
    let exec = executor::Executor::new(
        std::sync::Arc::new(NoopRunner),
        tenants,
        cfg.clone(),
        std::env::temp_dir(),
        d.depth.clone(),
    );
    exec.spawn_loop(rx);
    (d, exec, cfg)
}
