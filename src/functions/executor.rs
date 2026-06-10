//! Invocation executor: drains the global bounded queue, enforces the global
//! concurrency semaphore + per-tenant serialization (FIFO tokio::sync::Mutex),
//! writes one `_system_function_logs` row + one `function.invoke` audit row
//! per invocation. Failure semantics per spec §8: no retry, loss-on-crash
//! accepted (webhook philosophy).

use crate::functions::FnConfig;
use crate::functions::schema::{self, LogRow};
use crate::storage::pool::TenantRegistry;
use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::{Mutex, Semaphore, mpsc};

/// One queued invocation (built by the dispatcher).
#[derive(Clone, Debug)]
pub struct Invocation {
    pub tenant_id: String,
    pub function_name: String,
    /// "record.created:posts" / "file.uploaded" / "manual"
    pub trigger: String,
    pub event_json: String,
}

/// Terminal status of one run. Maps 1:1 to `_system_function_logs.status`.
#[derive(Clone, Debug, PartialEq)]
pub enum RunStatus {
    Ok,
    Error,
    Trap,
    Timeout,
    Oom,
}

impl RunStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            RunStatus::Ok => "ok",
            RunStatus::Error => "error",
            RunStatus::Trap => "trap",
            RunStatus::Timeout => "timeout",
            RunStatus::Oom => "oom",
        }
    }
}

#[derive(Clone, Debug)]
pub struct RunOutcome {
    pub status: RunStatus,
    /// Ok ⇒ guest's Ok(json); Error/Trap/… ⇒ error string.
    pub result: String,
    /// Captured guest log() lines (cap 64 KiB, enforced by the runner).
    pub log_text: String,
}

/// The runner seam. `WasmRunner` (Task 7) is the production impl; tests
/// inject mocks. `run` receives the tenant + the resolved artifact path so
/// runners stay storage-agnostic.
#[async_trait::async_trait]
pub trait FunctionRunner: Send + Sync {
    async fn run(
        &self,
        tenant_id: &str,
        wasm_path: &std::path::Path,
        event_json: &str,
    ) -> RunOutcome;
}

pub struct Executor {
    runner: Arc<dyn FunctionRunner>,
    tenants: Arc<TenantRegistry>,
    cfg: FnConfig,
    data_root: std::path::PathBuf,
    semaphore: Arc<Semaphore>,
    /// FIFO per-tenant serialization (tokio Mutex is queue-fair).
    tenant_locks: DashMap<String, Arc<Mutex<()>>>,
    /// Per-tenant queued+running count — decremented HERE on completion,
    /// incremented by the dispatcher at enqueue. Shared Arc with dispatcher.
    pub depth: Arc<DashMap<String, Arc<std::sync::atomic::AtomicUsize>>>,
    pub completed_total: AtomicU64,
}

impl Executor {
    pub fn new(
        runner: Arc<dyn FunctionRunner>,
        tenants: Arc<TenantRegistry>,
        cfg: FnConfig,
        data_root: std::path::PathBuf,
        depth: Arc<DashMap<String, Arc<std::sync::atomic::AtomicUsize>>>,
    ) -> Arc<Self> {
        let permits = cfg.concurrency.max(1);
        Arc::new(Self {
            runner,
            tenants,
            cfg,
            data_root,
            semaphore: Arc::new(Semaphore::new(permits)),
            tenant_locks: DashMap::new(),
            depth,
            completed_total: AtomicU64::new(0),
        })
    }

    fn tenant_lock(&self, tenant: &str) -> Arc<Mutex<()>> {
        self.tenant_locks
            .entry(tenant.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    pub fn artifact_path(&self, tenant: &str, sha: &str) -> std::path::PathBuf {
        self.data_root
            .join("tenants")
            .join(tenant)
            .join("_functions")
            .join(format!("{sha}.wasm"))
    }

    /// Spawn the drain loop. Called once from main.rs (and from tests).
    pub fn spawn_loop(self: &Arc<Self>, mut rx: mpsc::Receiver<Invocation>) {
        let me = self.clone();
        tokio::spawn(async move {
            while let Some(inv) = rx.recv().await {
                let me2 = me.clone();
                tokio::spawn(async move {
                    me2.run_one(inv).await;
                });
            }
            tracing::info!("function executor queue closed — loop ends");
        });
    }

    /// Full pipeline for one invocation: tenant lock → semaphore → resolve
    /// row → run → log + audit. Public so the synchronous test-invoke path
    /// (REST /invoke, MCP invoke_function) reuses it and returns the outcome.
    pub async fn run_one(&self, inv: Invocation) -> RunOutcome {
        // Per-tenant FIFO first, then the global permit — no lock cycle
        // (permits are not held while waiting for a tenant lock elsewhere).
        let tlock = self.tenant_lock(&inv.tenant_id);
        let _t = tlock.lock().await;
        let _p = self.semaphore.acquire().await.expect("semaphore closed");

        let started = std::time::Instant::now();
        let outcome = self.resolve_and_run(&inv).await;
        let duration_ms = started.elapsed().as_millis() as i64;

        self.record(&inv, &outcome, duration_ms).await;
        if let Some(d) = self.depth.get(&inv.tenant_id) {
            d.fetch_sub(1, Ordering::Relaxed);
        }
        self.completed_total.fetch_add(1, Ordering::Relaxed);
        outcome
    }

    async fn resolve_and_run(&self, inv: &Invocation) -> RunOutcome {
        let pool = match self.tenants.get_or_open(&inv.tenant_id) {
            Ok(p) => p,
            Err(e) => {
                return RunOutcome {
                    status: RunStatus::Error,
                    result: format!("tenant open failed: {e}"),
                    log_text: String::new(),
                };
            }
        };
        // Fresh row read at execution time: active flag + sha may have
        // changed between enqueue and run.
        let row = match schema::get_function(&pool, &inv.function_name).await {
            Ok(Some(r)) if r.active => r,
            Ok(Some(_)) => {
                return RunOutcome {
                    status: RunStatus::Error,
                    result: "function deactivated before run".into(),
                    log_text: String::new(),
                };
            }
            Ok(None) => {
                return RunOutcome {
                    status: RunStatus::Error,
                    result: "function deleted before run".into(),
                    log_text: String::new(),
                };
            }
            Err(e) => {
                return RunOutcome {
                    status: RunStatus::Error,
                    result: format!("row read failed: {e}"),
                    log_text: String::new(),
                };
            }
        };
        let path = self.artifact_path(&inv.tenant_id, &row.wasm_sha256);
        self.runner.run(&inv.tenant_id, &path, &inv.event_json).await
    }

    async fn record(&self, inv: &Invocation, out: &RunOutcome, duration_ms: i64) {
        let invocation_id = uuid::Uuid::new_v4().to_string();
        if let Ok(pool) = self.tenants.get_or_open(&inv.tenant_id) {
            let _ = schema::insert_log(
                &pool,
                LogRow {
                    invocation_id: invocation_id.clone(),
                    function_name: inv.function_name.clone(),
                    trigger: inv.trigger.clone(),
                    status: out.status.as_str().to_string(),
                    duration_ms,
                    log_text: out.log_text.clone(),
                    result_json: Some(out.result.clone()),
                },
            )
            .await;
        }
        crate::safety::audit_db::try_send(&crate::safety::audit::AuditEntry {
            ts: chrono::Utc::now().to_rfc3339(),
            tenant: inv.tenant_id.clone(),
            token_hint: format!("function:{}", inv.function_name),
            op: "function.invoke".to_string(),
            status: out.status.as_str().to_string(),
            duration_ms: duration_ms.max(0) as u64,
            collection: None,
            sql_hash: None,
            record_id: None,
            error_code: (out.status != RunStatus::Ok)
                .then(|| format!("FN_{}", out.status.as_str().to_uppercase())),
            error_message: (out.status != RunStatus::Ok).then(|| out.result.clone()),
            auth_method: None,
            oauth_email: None,
            oauth_error_code: None,
            actor_admin_id: None,
            actor_email_snapshot: None,
            extra: Default::default(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct OkRunner;
    #[async_trait::async_trait]
    impl FunctionRunner for OkRunner {
        async fn run(&self, _t: &str, _p: &std::path::Path, ev: &str) -> RunOutcome {
            RunOutcome {
                status: RunStatus::Ok,
                result: format!(r#"{{"echo":{ev}}}"#),
                log_text: "ran".into(),
            }
        }
    }

    async fn setup(dir: &std::path::Path) -> (Arc<Executor>, Arc<TenantRegistry>) {
        let reg = Arc::new(TenantRegistry::new(dir.to_path_buf(), 2));
        let pool = reg.get_or_open("t-e").unwrap();
        schema::create_function(
            &pool,
            schema::CreateFunctionParams {
                name: "echo".into(),
                wasm_sha256: "00".repeat(32),
                size_bytes: 1,
                triggers_json: "[]".into(),
                description: String::new(),
            },
            10,
        )
        .await
        .unwrap();
        let exec = Executor::new(
            Arc::new(OkRunner),
            reg.clone(),
            FnConfig::test_default(),
            dir.to_path_buf(),
            Arc::new(DashMap::new()),
        );
        (exec, reg)
    }

    #[tokio::test]
    async fn run_one_logs_and_returns_outcome() {
        let dir = tempfile::tempdir().unwrap();
        let (exec, reg) = setup(dir.path()).await;
        let out = exec
            .run_one(Invocation {
                tenant_id: "t-e".into(),
                function_name: "echo".into(),
                trigger: "manual".into(),
                event_json: r#"{"x":1}"#.into(),
            })
            .await;
        assert_eq!(out.status, RunStatus::Ok);
        let pool = reg.get_or_open("t-e").unwrap();
        let logs = schema::list_logs(&pool, "echo", 10).await.unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].status, "ok");
        assert_eq!(logs[0].trigger, "manual");
    }

    #[tokio::test]
    async fn inactive_function_records_error_not_run() {
        let dir = tempfile::tempdir().unwrap();
        let (exec, reg) = setup(dir.path()).await;
        let pool = reg.get_or_open("t-e").unwrap();
        schema::set_active(&pool, "echo", false).await.unwrap();
        let out = exec
            .run_one(Invocation {
                tenant_id: "t-e".into(),
                function_name: "echo".into(),
                trigger: "manual".into(),
                event_json: "{}".into(),
            })
            .await;
        assert_eq!(out.status, RunStatus::Error);
        assert!(out.result.contains("deactivated"));
    }

    #[tokio::test]
    async fn queue_loop_drains() {
        let dir = tempfile::tempdir().unwrap();
        let (exec, reg) = setup(dir.path()).await;
        let (tx, rx) = mpsc::channel(16);
        exec.spawn_loop(rx);
        for _ in 0..5 {
            tx.send(Invocation {
                tenant_id: "t-e".into(),
                function_name: "echo".into(),
                trigger: "record.created:posts".into(),
                event_json: "{}".into(),
            })
            .await
            .unwrap();
        }
        // poll until drained (condition-based wait, no fixed sleep)
        for _ in 0..100 {
            if exec.completed_total.load(Ordering::Relaxed) == 5 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(exec.completed_total.load(Ordering::Relaxed), 5);
        let pool = reg.get_or_open("t-e").unwrap();
        assert_eq!(schema::list_logs(&pool, "echo", 100).await.unwrap().len(), 5);
    }
}
