//! Invocation executor: drains the global bounded queue into per-tenant FIFO
//! lanes (one unbounded channel + one worker task per tenant), enforces the
//! global concurrency semaphore + per-tenant serialization, writes one
//! `_system_function_logs` row + one `function.invoke` audit row per
//! invocation. Failure semantics per spec §8: no retry, loss-on-crash
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
    data_root: std::path::PathBuf,
    semaphore: Arc<Semaphore>,
    /// Per-tenant mutual exclusion. Both the lane worker (queued path) and
    /// synchronous `run_one` callers (REST /invoke, MCP invoke_function)
    /// take this, so a manual test-invoke never overlaps a queued run.
    /// FIFO *ordering* of queued invocations is NOT this lock's job — the
    /// single lane worker per tenant provides that by construction.
    tenant_locks: DashMap<String, Arc<Mutex<()>>>,
    /// Per-tenant FIFO lanes: the global drain loop forwards each invocation
    /// to its tenant's lane in dequeue order, and the lane's single worker
    /// task drains sequentially — so same-tenant execution order is enqueue
    /// order by construction. Lanes are unbounded channels so the global
    /// loop never awaits a send (one busy tenant cannot head-of-line-block
    /// the others); real capacity is bounded by the dispatcher's per-tenant
    /// depth cap (DRUST_FN_QUEUE_DEPTH) enforced at enqueue.
    tenant_lanes: DashMap<String, mpsc::UnboundedSender<Invocation>>,
    /// Per-tenant queued+running count — incremented by the dispatcher at
    /// enqueue, decremented (saturating, never wraps below zero) by the lane
    /// worker after a queued run completes. Shared Arc with the dispatcher.
    /// Synchronous `run_one` callers neither increment nor decrement.
    pub depth: Arc<DashMap<String, Arc<std::sync::atomic::AtomicUsize>>>,
    /// Total completed runs, queued AND synchronous.
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
            data_root,
            semaphore: Arc::new(Semaphore::new(permits)),
            tenant_locks: DashMap::new(),
            tenant_lanes: DashMap::new(),
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
                me.route_to_lane(inv);
            }
            tracing::info!("function executor queue closed — loop ends");
        });
    }

    /// Forward one invocation onto its tenant's FIFO lane, spawning the lane
    /// worker on first use. Never awaits, so a slow tenant cannot stall the
    /// global drain loop.
    fn route_to_lane(self: &Arc<Self>, inv: Invocation) {
        let tx = self
            .tenant_lanes
            .entry(inv.tenant_id.clone())
            .or_insert_with(|| {
                let (tx, mut lane_rx) = mpsc::unbounded_channel::<Invocation>();
                let me = self.clone();
                tokio::spawn(async move {
                    while let Some(inv) = lane_rx.recv().await {
                        let tenant = inv.tenant_id.clone();
                        me.run_one(inv).await;
                        me.decrement_depth(&tenant);
                    }
                });
                tx
            })
            .clone();
        if let Err(e) = tx.send(inv) {
            // Unreachable while the lane sender lives in the map (the worker
            // exits only once every sender is dropped); guard the accounting
            // anyway so a dropped invocation can't leak a depth slot.
            tracing::warn!(tenant = %e.0.tenant_id, "function lane closed — invocation dropped");
            self.decrement_depth(&e.0.tenant_id);
        }
    }

    /// Saturating decrement of the dispatcher-shared depth counter:
    /// `checked_sub` makes 0 stay 0. An unguarded `fetch_sub` would wrap
    /// 0 → usize::MAX and permanently trip the dispatcher's queue-depth cap
    /// for the tenant.
    fn decrement_depth(&self, tenant: &str) {
        if let Some(d) = self.depth.get(tenant) {
            let _ = d.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
        }
    }

    /// Full pipeline for one invocation: tenant lock → semaphore → resolve
    /// row → run → log + audit. Public so the synchronous test-invoke path
    /// (REST /invoke, MCP invoke_function) reuses it and returns the outcome.
    ///
    /// Depth accounting: `run_one` itself never touches `depth`. Queued
    /// invocations are incremented by the dispatcher at enqueue and
    /// decremented by the lane worker after this returns; synchronous callers
    /// must NOT increment — they bypass the queue cap by design, and keeping
    /// them out of the counter means their completion can never corrupt it.
    pub async fn run_one(&self, inv: Invocation) -> RunOutcome {
        // Per-tenant exclusion first, then the global permit — no lock cycle
        // (permits are never held while waiting for a tenant lock elsewhere).
        let tlock = self.tenant_lock(&inv.tenant_id);
        let _t = tlock.lock().await;
        let _p = self.semaphore.acquire().await.expect("semaphore closed");

        let started = std::time::Instant::now();
        let outcome = self.resolve_and_run(&inv).await;
        let duration_ms = started.elapsed().as_millis() as i64;

        self.record(&inv, &outcome, duration_ms).await;
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
    use std::sync::atomic::{AtomicBool, AtomicUsize};

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

    async fn create_echo_fn(reg: &Arc<TenantRegistry>, tenant: &str) {
        let pool = reg.get_or_open(tenant).unwrap();
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
    }

    async fn setup(dir: &std::path::Path) -> (Arc<Executor>, Arc<TenantRegistry>) {
        let reg = Arc::new(TenantRegistry::new(dir.to_path_buf(), 2));
        create_echo_fn(&reg, "t-e").await;
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

    /// Records (tenant, seq) at run entry and flags any same-tenant overlap.
    struct SeqRunner {
        entries: Arc<std::sync::Mutex<Vec<(String, u64)>>>,
        in_flight: Arc<DashMap<String, AtomicUsize>>,
        overlap: Arc<AtomicBool>,
    }

    #[async_trait::async_trait]
    impl FunctionRunner for SeqRunner {
        async fn run(&self, t: &str, _p: &std::path::Path, ev: &str) -> RunOutcome {
            let seq = serde_json::from_str::<serde_json::Value>(ev).unwrap()["seq"]
                .as_u64()
                .unwrap();
            let prev = self
                .in_flight
                .entry(t.to_string())
                .or_insert_with(|| AtomicUsize::new(0))
                .fetch_add(1, Ordering::SeqCst);
            if prev > 0 {
                self.overlap.store(true, Ordering::SeqCst);
            }
            self.entries.lock().unwrap().push((t.to_string(), seq));
            // widen the race window so an ordering/serialization regression
            // actually manifests instead of passing by luck
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
            self.in_flight.get(t).unwrap().fetch_sub(1, Ordering::SeqCst);
            RunOutcome {
                status: RunStatus::Ok,
                result: "{}".into(),
                log_text: String::new(),
            }
        }
    }

    /// The commit's headline claim: same-tenant invocations run serialized
    /// AND in enqueue order, while two tenants still run in parallel under
    /// the global semaphore (concurrency=2 in test_default). The old
    /// spawn-per-invocation shape could invert same-tenant order via the
    /// multi-thread scheduler's LIFO slot — hence the multi_thread flavor.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn same_tenant_fifo_order_and_serialization() {
        let dir = tempfile::tempdir().unwrap();
        let reg = Arc::new(TenantRegistry::new(dir.path().to_path_buf(), 2));
        for t in ["t-a", "t-b"] {
            create_echo_fn(&reg, t).await;
        }
        let entries = Arc::new(std::sync::Mutex::new(Vec::new()));
        let overlap = Arc::new(AtomicBool::new(false));
        let exec = Executor::new(
            Arc::new(SeqRunner {
                entries: entries.clone(),
                in_flight: Arc::new(DashMap::new()),
                overlap: overlap.clone(),
            }),
            reg.clone(),
            FnConfig::test_default(),
            dir.path().to_path_buf(),
            Arc::new(DashMap::new()),
        );
        let (tx, rx) = mpsc::channel(64);
        exec.spawn_loop(rx);
        // interleaved A/B burst — the shape that used to make inversion likely
        for seq in 0..20u64 {
            for t in ["t-a", "t-b"] {
                tx.send(Invocation {
                    tenant_id: t.into(),
                    function_name: "echo".into(),
                    trigger: "manual".into(),
                    event_json: format!(r#"{{"seq":{seq}}}"#),
                })
                .await
                .unwrap();
            }
        }
        for _ in 0..300 {
            if exec.completed_total.load(Ordering::Relaxed) == 40 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(exec.completed_total.load(Ordering::Relaxed), 40);
        assert!(!overlap.load(Ordering::SeqCst), "same-tenant runs overlapped");
        let entries = entries.lock().unwrap();
        for t in ["t-a", "t-b"] {
            let seqs: Vec<u64> =
                entries.iter().filter(|(tt, _)| tt == t).map(|(_, s)| *s).collect();
            assert_eq!(
                seqs,
                (0..20).collect::<Vec<u64>>(),
                "tenant {t}: execution order != enqueue order"
            );
        }
    }

    /// A synchronous run_one (REST /invoke, MCP invoke_function) must never
    /// touch the dispatcher's depth counter — the old unguarded fetch_sub
    /// wrapped 0 → usize::MAX here and permanently bricked the tenant queue.
    #[tokio::test]
    async fn sync_run_one_never_wraps_depth_counter() {
        let dir = tempfile::tempdir().unwrap();
        let (exec, _reg) = setup(dir.path()).await;
        let d = Arc::new(AtomicUsize::new(0));
        exec.depth.insert("t-e".into(), d.clone());
        let out = exec
            .run_one(Invocation {
                tenant_id: "t-e".into(),
                function_name: "echo".into(),
                trigger: "manual".into(),
                event_json: "{}".into(),
            })
            .await;
        assert_eq!(out.status, RunStatus::Ok);
        assert_eq!(d.load(Ordering::Relaxed), 0, "sync invoke corrupted queue depth");
    }

    /// Queued completions decrement depth; the decrement saturates at zero
    /// even if accounting drifted (here: depth pre-set to 1 but 2 queued).
    #[tokio::test]
    async fn queued_depth_decrement_saturates_at_zero() {
        let dir = tempfile::tempdir().unwrap();
        let (exec, _reg) = setup(dir.path()).await;
        let d = Arc::new(AtomicUsize::new(1));
        exec.depth.insert("t-e".into(), d.clone());
        let (tx, rx) = mpsc::channel(16);
        exec.spawn_loop(rx);
        for _ in 0..2 {
            tx.send(Invocation {
                tenant_id: "t-e".into(),
                function_name: "echo".into(),
                trigger: "record.created:posts".into(),
                event_json: "{}".into(),
            })
            .await
            .unwrap();
        }
        for _ in 0..100 {
            if d.load(Ordering::Relaxed) == 0
                && exec.completed_total.load(Ordering::Relaxed) == 2
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(exec.completed_total.load(Ordering::Relaxed), 2);
        assert_eq!(d.load(Ordering::Relaxed), 0, "decrement wrapped instead of saturating");
    }
}
