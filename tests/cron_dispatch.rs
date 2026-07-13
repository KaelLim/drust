//! v1.48 — cron dispatch integration: `run_due_job` end to end against a real
//! tenant registry, for BOTH target kinds. Function targets go through the
//! synchronous `Executor::run_one` path with an injected mock runner (the
//! `CountRunner` shape from tests/functions_dispatch.rs); RPC targets go
//! through the real read/write executors, so record-history capture is
//! observable exactly as production wires it.

mod helpers;

use drust::cron::index::{CronIndex, IndexedJob};
use drust::cron::scheduler::{CronDeps, run_due_job};
use drust::cron::{CronConfig, store};
use drust::functions::caller::CallerCtx;
use drust::functions::executor::{Executor, FunctionRunner, Invocation, RunOutcome, RunStatus};
use drust::storage::pool::{SharedTenantPool, TenantRegistry};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Counting mock runner — the tests/functions_dispatch.rs shape, with the
/// event assertion adapted to the cron envelope. Also pins the caller
/// identity: a cron fire must run `Privileged`, never capability-gated.
struct CountRunner(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl FunctionRunner for CountRunner {
    async fn run(&self, _t: &str, _p: &std::path::Path, ev: &str, caller: CallerCtx) -> RunOutcome {
        let v: serde_json::Value = serde_json::from_str(ev).expect("cron event_json is JSON");
        assert_eq!(v["trigger"], "cron", "cron event envelope: {v}");
        assert!(
            matches!(caller, CallerCtx::Privileged),
            "cron fires run at Privileged identity, got {caller:?}"
        );
        self.0.fetch_add(1, Ordering::SeqCst);
        RunOutcome {
            status: RunStatus::Ok,
            result: "{}".into(),
            log_text: String::new(),
        }
    }
}

/// Runner that parks inside `run_one` until released — makes the overlap /
/// concurrency windows deterministic: `started` gains one permit per entry
/// (counting, so two entries never coalesce the way a `Notify` would),
/// `release` lets a parked run finish. Also tracks peak concurrency
/// (`current` incremented on entry / decremented on exit, max folded into
/// `peak`) so the DRUST_CRON_CONCURRENCY bound is observable.
struct BlockingRunner {
    started: Arc<tokio::sync::Semaphore>,
    release: Arc<tokio::sync::Notify>,
    hits: Arc<AtomicUsize>,
    current: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl FunctionRunner for BlockingRunner {
    async fn run(
        &self,
        _t: &str,
        _p: &std::path::Path,
        _ev: &str,
        _caller: CallerCtx,
    ) -> RunOutcome {
        self.hits.fetch_add(1, Ordering::SeqCst);
        let now = self.current.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(now, Ordering::SeqCst);
        self.started.add_permits(1);
        self.release.notified().await;
        self.current.fetch_sub(1, Ordering::SeqCst);
        RunOutcome {
            status: RunStatus::Ok,
            result: "{}".into(),
            log_text: String::new(),
        }
    }
}

fn deps(registry: Arc<TenantRegistry>, executor: Arc<Executor>) -> Arc<CronDeps> {
    let cfg = CronConfig::test_default();
    let permits = cfg.concurrency;
    deps_with_permits(registry, executor, cfg, permits)
}

fn deps_with_permits(
    registry: Arc<TenantRegistry>,
    executor: Arc<Executor>,
    cfg: CronConfig,
    permits: usize,
) -> Arc<CronDeps> {
    Arc::new(CronDeps {
        registry,
        index: Arc::new(CronIndex::new()),
        executor,
        in_flight: Arc::new(dashmap::DashMap::new()),
        tenant_gate: dashmap::DashMap::new(),
        permits: Arc::new(tokio::sync::Semaphore::new(permits)),
        cfg,
    })
}

/// The fire minute `collect_due` would have passed — `run_due_job` itself
/// does not re-check the schedule against it, so any minute works.
fn minute_now() -> chrono::DateTime<chrono::Utc> {
    drust::cron::scheduler::next_minute(chrono::Utc::now())
}

/// Stale-index projection of a stored job — what the scheduler snapshot
/// carries into `run_due_job`.
fn indexed(j: &store::CronJob) -> IndexedJob {
    IndexedJob {
        id: j.id,
        name: j.name.clone(),
        schedule: j.schedule.clone(),
        target_kind: j.target_kind.clone(),
        target_name: j.target_name.clone(),
        payload_json: j.payload_json.clone(),
    }
}

async fn runs_for(pool: &SharedTenantPool, name: &str) -> Vec<store::CronRun> {
    let name = name.to_string();
    pool.with_reader(move |c| store::list_runs_reader(c, &name))
        .await
        .unwrap()
}

async fn count_rows(pool: &SharedTenantPool, sql: &'static str) -> i64 {
    pool.with_reader(move |c| c.query_row(sql, [], |r| r.get(0)))
        .await
        .unwrap()
}

/// Create an RPC by writing directly to `_system_rpc` (same shape as
/// tests/record_history_rpc.rs — bypasses config-time guards on purpose,
/// the runtime dispatch path is what's under test).
async fn create_rpc(pool: &SharedTenantPool, name: &str, sql: &str, params_json: &str, mode: &str) {
    let name = name.to_string();
    let sql = sql.to_string();
    let params_json = params_json.to_string();
    let mode = mode.to_string();
    pool.with_writer(move |c| {
        c.execute(
            "INSERT INTO _system_rpc \
             (name, sql, params_json, description, anon_callable, mode, \
              anon_calls, service_calls, last_called_at, created_at, updated_at) \
             VALUES (?1, ?2, ?3, '', 0, ?4, 0, 0, NULL, \
                     datetime('now'), datetime('now'))",
            rusqlite::params![name, sql, params_json, mode],
        )
    })
    .await
    .unwrap();
}

/// Create `items` (one nullable text field `v`) through the CANONICAL
/// create_collection tool — STRICT + `<name>_updated_at` trigger + the
/// default-ON audit meta row, so record-history capture applies to it.
async fn create_items_collection(registry: &Arc<TenantRegistry>, tenant: &str) {
    let svc = drust::mcp::server::McpRegistry::new(registry.clone())
        .get_or_create(tenant)
        .await
        .unwrap();
    drust::mcp::tools::schema::create_collection(
        &svc,
        "items",
        &[drust::mcp::tools::schema::FieldSpec {
            name: "v".into(),
            sql_type: "text".into(),
            nullable: true,
            ..Default::default()
        }],
    )
    .await
    .unwrap();
}

// ── Function target: runs Privileged via run_one, records an ok run. ───────

#[tokio::test]
async fn function_target_runs_privileged_and_records_ok_run() {
    let hits = Arc::new(AtomicUsize::new(0));
    let (registry, executor, _tmp) =
        helpers::cron_test_stack("t-cron1", Arc::new(CountRunner(hits.clone()))).await;
    let pool = registry.get_or_open("t-cron1").unwrap();
    let job = pool
        .with_writer(|c| {
            store::create_job(
                c,
                "tick",
                "* * * * *",
                "function",
                "f1",
                Some(r#"{"n":1}"#),
                true,
            )
        })
        .await
        .unwrap();

    let d = deps(registry.clone(), executor);
    run_due_job(d, "t-cron1".into(), indexed(&job), minute_now()).await;

    assert_eq!(hits.load(Ordering::SeqCst), 1, "runner invoked once");
    let runs = runs_for(&pool, "tick").await;
    assert_eq!(runs.len(), 1, "{runs:?}");
    assert_eq!(runs[0].status, "ok", "{runs:?}");
    assert!(runs[0].duration_ms.is_some(), "duration measured: {runs:?}");
    let j = pool
        .with_reader(|c| store::get_job_reader(c, "tick"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(j.last_status.as_deref(), Some("ok"));
    assert_eq!(j.last_run_at.as_deref(), Some(runs[0].fired_at.as_str()));
}

// ── Fire-time re-assert: a STALE index entry for a job that was disabled or
//    deleted after the snapshot must dispatch nothing and record nothing. ───

#[tokio::test]
async fn reassert_blocks_disabled_and_deleted_jobs() {
    let hits = Arc::new(AtomicUsize::new(0));
    let (registry, executor, _tmp) =
        helpers::cron_test_stack("t-cron2", Arc::new(CountRunner(hits.clone()))).await;
    let pool = registry.get_or_open("t-cron2").unwrap();

    // Disabled under us: the IndexedJob still says active.
    let j_off = pool
        .with_writer(|c| store::create_job(c, "off", "* * * * *", "function", "f1", None, true))
        .await
        .unwrap();
    let stale_off = indexed(&j_off);
    pool.with_writer(|c| store::update_job(c, "off", None, None, Some(false)))
        .await
        .unwrap();

    // Deleted under us: the IndexedJob points at a row that is gone.
    let j_gone = pool
        .with_writer(|c| store::create_job(c, "gone", "* * * * *", "function", "f1", None, true))
        .await
        .unwrap();
    let stale_gone = indexed(&j_gone);
    assert!(
        pool.with_writer(|c| store::delete_job(c, "gone"))
            .await
            .unwrap()
    );

    let d = deps(registry.clone(), executor);
    run_due_job(d.clone(), "t-cron2".into(), stale_off, minute_now()).await;
    run_due_job(d, "t-cron2".into(), stale_gone, minute_now()).await;

    assert_eq!(hits.load(Ordering::SeqCst), 0, "runner never invoked");
    assert!(
        runs_for(&pool, "off").await.is_empty(),
        "no run row for the disabled job"
    );
    assert!(
        runs_for(&pool, "gone").await.is_empty(),
        "no run row for the deleted job"
    );
    assert_eq!(
        count_rows(&pool, "SELECT COUNT(*) FROM _system_cron_runs").await,
        0,
        "silent return — a re-asserted-away fire records NO run row"
    );
}

// ── Fire-time re-assert pins the row ID, not just the name: delete+recreate
//    of the same name (new AUTOINCREMENT id, same schedule) between snapshot
//    and re-assert must NOT let the stale snapshot's target execute — the run
//    would land under the old job_id as an invisible orphan (list_runs joins
//    runs→jobs by id, and the old id no longer resolves). ────────────────────

#[tokio::test]
async fn reassert_blocks_deleted_and_recreated_job_with_same_name() {
    let hits = Arc::new(AtomicUsize::new(0));
    let (registry, executor, _tmp) =
        helpers::cron_test_stack("t-cron7", Arc::new(CountRunner(hits.clone()))).await;
    let pool = registry.get_or_open("t-cron7").unwrap();

    let j_old = pool
        .with_writer(|c| store::create_job(c, "sync", "* * * * *", "function", "f1", None, true))
        .await
        .unwrap();
    let stale = indexed(&j_old);

    // Delete + recreate: same name and schedule, DIFFERENT target, new id.
    assert!(
        pool.with_writer(|c| store::delete_job(c, "sync"))
            .await
            .unwrap()
    );
    let j_new = pool
        .with_writer(|c| store::create_job(c, "sync", "* * * * *", "function", "f2", None, true))
        .await
        .unwrap();
    assert_ne!(j_new.id, j_old.id, "recreate mints a new AUTOINCREMENT id");

    let d = deps(registry.clone(), executor);
    run_due_job(d, "t-cron7".into(), stale, minute_now()).await;

    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "stale snapshot's target must not execute"
    );
    assert!(
        runs_for(&pool, "sync").await.is_empty(),
        "no run row joined to the recreated job"
    );
    assert_eq!(
        count_rows(&pool, "SELECT COUNT(*) FROM _system_cron_runs").await,
        0,
        "no orphan run row under the old (deleted) job_id either"
    );
}

// ── Overlap: a second fire of the SAME still-running job records a
//    skipped_overlap run without dispatching; the first still lands ok. ─────

#[tokio::test]
async fn overlap_second_fire_records_skipped_overlap() {
    let started = Arc::new(tokio::sync::Semaphore::new(0));
    let release = Arc::new(tokio::sync::Notify::new());
    let hits = Arc::new(AtomicUsize::new(0));
    let (registry, executor, _tmp) = helpers::cron_test_stack(
        "t-cron3",
        Arc::new(BlockingRunner {
            started: started.clone(),
            release: release.clone(),
            hits: hits.clone(),
            current: Arc::new(AtomicUsize::new(0)),
            peak: Arc::new(AtomicUsize::new(0)),
        }),
    )
    .await;
    let pool = registry.get_or_open("t-cron3").unwrap();
    let job = pool
        .with_writer(|c| store::create_job(c, "slow", "* * * * *", "function", "f1", None, true))
        .await
        .unwrap();
    let d = deps(registry.clone(), executor);

    // First fire parks inside run_one, holding the in-flight marker.
    let first = tokio::spawn(run_due_job(
        d.clone(),
        "t-cron3".into(),
        indexed(&job),
        minute_now(),
    ));
    started.acquire().await.unwrap().forget();

    // Second fire of the same job returns quickly with skipped_overlap.
    run_due_job(d, "t-cron3".into(), indexed(&job), minute_now()).await;
    let runs = runs_for(&pool, "slow").await;
    assert_eq!(runs.len(), 1, "{runs:?}");
    assert_eq!(runs[0].status, "skipped_overlap", "{runs:?}");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "second fire never dispatched"
    );

    // Release the first fire; it completes and records its ok run.
    release.notify_one();
    first.await.unwrap();

    let runs = runs_for(&pool, "slow").await;
    assert_eq!(runs.len(), 2, "{runs:?}");
    let statuses: std::collections::HashSet<&str> =
        runs.iter().map(|r| r.status.as_str()).collect();
    assert!(
        statuses.contains("ok") && statuses.contains("skipped_overlap"),
        "statuses are exactly {{ok, skipped_overlap}}: {runs:?}"
    );
    let j = pool
        .with_reader(|c| store::get_job_reader(c, "slow"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        j.last_status.as_deref(),
        Some("ok"),
        "the completed run wrote last_* after the skip"
    );
}

// ── Global dispatch bound (DRUST_CRON_CONCURRENCY): with permits=1, two
//    due jobs in two DIFFERENT tenants never dispatch concurrently — the
//    second fire waits for the first's permit instead of running alongside
//    it, and both still complete ok. Cross-tenant on purpose: the executor
//    already serializes same-tenant function runs (tenant lock), so only
//    distinct tenants observe the herd the cron permit bound exists for.
//    (The overlap gate above is a different mechanism: it skips a second
//    fire of the SAME job.) ──────────────────────────────────────────────────

#[tokio::test]
async fn dispatch_concurrency_is_bounded_by_cron_permits() {
    let started = Arc::new(tokio::sync::Semaphore::new(0));
    let release = Arc::new(tokio::sync::Notify::new());
    let hits = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let (registry, executor, _tmp) = helpers::cron_test_stack(
        "t-cron8",
        Arc::new(BlockingRunner {
            started: started.clone(),
            release: release.clone(),
            hits: hits.clone(),
            current: Arc::new(AtomicUsize::new(0)),
            peak: peak.clone(),
        }),
    )
    .await;
    let pool_a = registry.get_or_open("t-cron8").unwrap();
    // Second tenant in the SAME registry/executor, with its own `f1` row.
    let pool_b = registry.get_or_open("t-cron9").unwrap();
    drust::functions::schema::create_function(
        &pool_b,
        drust::functions::schema::CreateFunctionParams {
            name: "f1".into(),
            wasm_sha256: "00".repeat(32),
            size_bytes: 1,
            triggers_json: "[]".into(),
            description: String::new(),
        },
        10,
    )
    .await
    .unwrap();
    let j_a = pool_a
        .with_writer(|c| store::create_job(c, "a", "* * * * *", "function", "f1", None, true))
        .await
        .unwrap();
    let j_b = pool_b
        .with_writer(|c| store::create_job(c, "b", "* * * * *", "function", "f1", None, true))
        .await
        .unwrap();

    let d = deps_with_permits(registry.clone(), executor, CronConfig::test_default(), 1);
    let t_a = tokio::spawn(run_due_job(
        d.clone(),
        "t-cron8".into(),
        indexed(&j_a),
        minute_now(),
    ));
    let t_b = tokio::spawn(run_due_job(
        d.clone(),
        "t-cron9".into(),
        indexed(&j_b),
        minute_now(),
    ));

    // One fire is inside the runner (permit held). While it parks there, the
    // other fire must NOT be able to enter — probe with a bounded wait for a
    // second `started` permit: bounded dispatch can never grant it (timeout),
    // unbounded dispatch grants it almost immediately (the executor's own
    // semaphore is 2 in test_default, so it would not save us).
    started.acquire().await.unwrap().forget();
    let second_entered =
        tokio::time::timeout(std::time::Duration::from_millis(300), started.acquire()).await;
    assert!(
        second_entered.is_err(),
        "second fire entered the runner while the first held the only permit"
    );
    // Release the first; only then can the second acquire the permit, enter,
    // and be released in turn.
    release.notify_one();
    started.acquire().await.unwrap().forget();
    release.notify_one();
    t_a.await.unwrap();
    t_b.await.unwrap();

    assert_eq!(hits.load(Ordering::SeqCst), 2, "both jobs dispatched");
    assert_eq!(
        peak.load(Ordering::SeqCst),
        1,
        "permits=1 serializes fires across tenants"
    );
    for (pool, name) in [(&pool_a, "a"), (&pool_b, "b")] {
        let runs = runs_for(pool, name).await;
        assert_eq!(runs.len(), 1, "{name}: {runs:?}");
        assert_eq!(runs[0].status, "ok", "{name}: {runs:?}");
    }
}

// ── Ordering pin: the overlap in_flight gate sits BEFORE the permit acquire,
//    and the overlap-skip path records its run row WITHOUT taking a permit.
//    With the single permit exhausted by a parked fire of X, a queued fire of
//    Y holds Y's in-flight marker while it waits for the permit, so a SECOND
//    fire of Y must return promptly with a `skipped_overlap` run row — while
//    the permit is still exhausted. Swapping the gate/permit order (Y's first
//    fire would then wait permit-first, marker never set, and the second fire
//    would queue too) or making the skip path take a permit turns the bounded
//    waits below into timeouts. Y lives in a SECOND tenant so its first fire
//    queues on the global permit itself, not on X's tenant mutex. ────────────

#[tokio::test]
async fn overlap_gate_precedes_permit_and_skip_records_without_permit() {
    let started = Arc::new(tokio::sync::Semaphore::new(0));
    let release = Arc::new(tokio::sync::Notify::new());
    let hits = Arc::new(AtomicUsize::new(0));
    let (registry, executor, _tmp) = helpers::cron_test_stack(
        "t-cron14",
        Arc::new(BlockingRunner {
            started: started.clone(),
            release: release.clone(),
            hits: hits.clone(),
            current: Arc::new(AtomicUsize::new(0)),
            peak: Arc::new(AtomicUsize::new(0)),
        }),
    )
    .await;
    let pool_x = registry.get_or_open("t-cron14").unwrap();
    // Tenant B carries job Y as a fast read-RPC — never touches the runner,
    // so once X's permit frees up, Y's queued fire completes on its own.
    let pool_y = registry.get_or_open("t-cron15").unwrap();
    create_rpc(&pool_y, "ping", "SELECT 1 AS x", "[]", "read").await;

    let j_x = pool_x
        .with_writer(|c| store::create_job(c, "x", "* * * * *", "function", "f1", None, true))
        .await
        .unwrap();
    let j_y = pool_y
        .with_writer(|c| store::create_job(c, "y", "* * * * *", "rpc", "ping", None, true))
        .await
        .unwrap();

    let d = deps_with_permits(registry.clone(), executor, CronConfig::test_default(), 1);

    // X parks inside the runner, holding the ONLY permit.
    let t_x = tokio::spawn(run_due_job(
        d.clone(),
        "t-cron14".into(),
        indexed(&j_x),
        minute_now(),
    ));
    started.acquire().await.unwrap().forget();
    assert_eq!(d.permits.available_permits(), 0, "X holds the only permit");

    // Y's first fire queues on the permit. Its in-flight marker is inserted
    // BEFORE the permit wait — exactly the ordering under test — so wait
    // (bounded) until the marker is visible before firing Y again.
    let t_y = tokio::spawn(run_due_job(
        d.clone(),
        "t-cron15".into(),
        indexed(&j_y),
        minute_now(),
    ));
    let key = ("t-cron15".to_string(), j_y.id);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while !d.in_flight.contains_key(&key) {
        assert!(
            std::time::Instant::now() < deadline,
            "queued fire never registered its in-flight marker — is the \
             overlap gate ordered after the permit acquire?"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(
        runs_for(&pool_y, "y").await.is_empty(),
        "Y's first fire is queued on the permit, not yet run"
    );

    // Second fire of Y: must return promptly (skip paths never take a
    // permit) and record skipped_overlap WHILE the permit is exhausted.
    let second = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        run_due_job(d.clone(), "t-cron15".into(), indexed(&j_y), minute_now()),
    )
    .await;
    assert!(
        second.is_ok(),
        "overlap skip waited on the exhausted permit — skip paths must be permit-free"
    );
    assert_eq!(
        d.permits.available_permits(),
        0,
        "the skip was recorded while X still held the only permit"
    );
    let runs = runs_for(&pool_y, "y").await;
    assert_eq!(runs.len(), 1, "{runs:?}");
    assert_eq!(runs[0].status, "skipped_overlap", "{runs:?}");
    assert_eq!(hits.load(Ordering::SeqCst), 1, "only X entered the runner");

    // Release X; Y's queued fire then takes the freed permit and lands ok.
    release.notify_one();
    t_x.await.unwrap();
    t_y.await.unwrap();

    let runs_x = runs_for(&pool_x, "x").await;
    assert_eq!(runs_x.len(), 1, "{runs_x:?}");
    assert_eq!(runs_x[0].status, "ok", "{runs_x:?}");
    let runs_y = runs_for(&pool_y, "y").await;
    assert_eq!(runs_y.len(), 2, "{runs_y:?}");
    let statuses: std::collections::HashSet<&str> =
        runs_y.iter().map(|r| r.status.as_str()).collect();
    assert!(
        statuses.contains("ok") && statuses.contains("skipped_overlap"),
        "Y's statuses are exactly {{ok, skipped_overlap}}: {runs_y:?}"
    );
}

// ── Per-tenant single-flight: one tenant's slow jobs can hold at most ONE
//    global permit, so another tenant's due work still dispatches (no
//    head-of-line starvation). permits=2, tenant A has TWO parked function
//    jobs due, tenant B one fast RPC job. Without the tenant gate, A's first
//    job parks in the runner holding permit 1 while A's second job holds
//    permit 2 (blocked on the executor's same-tenant lock) — B starves. With
//    the gate, A's second job waits on the tenant mutex BEFORE taking a
//    permit, so one permit stays free for B. ────────────────────────────────

#[tokio::test]
async fn tenant_single_flight_prevents_one_tenant_monopolizing_permits() {
    let started = Arc::new(tokio::sync::Semaphore::new(0));
    let release = Arc::new(tokio::sync::Notify::new());
    let hits = Arc::new(AtomicUsize::new(0));
    let (registry, executor, _tmp) = helpers::cron_test_stack(
        "t-cron11",
        Arc::new(BlockingRunner {
            started: started.clone(),
            release: release.clone(),
            hits: hits.clone(),
            current: Arc::new(AtomicUsize::new(0)),
            peak: Arc::new(AtomicUsize::new(0)),
        }),
    )
    .await;
    let pool_a = registry.get_or_open("t-cron11").unwrap();
    // Second tenant with a fast read-RPC job — never touches the runner, so
    // its completion is observable while tenant A's runner gate stays held.
    let pool_b = registry.get_or_open("t-cron12").unwrap();
    create_rpc(&pool_b, "ping", "SELECT 1 AS x", "[]", "read").await;

    let j_a1 = pool_a
        .with_writer(|c| store::create_job(c, "a1", "* * * * *", "function", "f1", None, true))
        .await
        .unwrap();
    let j_a2 = pool_a
        .with_writer(|c| store::create_job(c, "a2", "* * * * *", "function", "f1", None, true))
        .await
        .unwrap();
    let j_b = pool_b
        .with_writer(|c| store::create_job(c, "b", "* * * * *", "rpc", "ping", None, true))
        .await
        .unwrap();

    let d = deps_with_permits(registry.clone(), executor, CronConfig::test_default(), 2);
    let t_a1 = tokio::spawn(run_due_job(
        d.clone(),
        "t-cron11".into(),
        indexed(&j_a1),
        minute_now(),
    ));
    let t_a2 = tokio::spawn(run_due_job(
        d.clone(),
        "t-cron11".into(),
        indexed(&j_a2),
        minute_now(),
    ));

    // One A job is parked inside the runner (tenant gate + one permit held).
    started.acquire().await.unwrap().forget();

    let t_b = tokio::spawn(run_due_job(
        d.clone(),
        "t-cron12".into(),
        indexed(&j_b),
        minute_now(),
    ));

    // B completes while A's runner gate is still held — the per-tenant
    // single-flight keeps A's second job off the global permits.
    tokio::time::timeout(std::time::Duration::from_secs(5), t_b)
        .await
        .expect("tenant B starved: tenant A's jobs hold every cron permit")
        .unwrap();
    let runs_b = runs_for(&pool_b, "b").await;
    assert_eq!(runs_b.len(), 1, "{runs_b:?}");
    assert_eq!(runs_b[0].status, "ok", "{runs_b:?}");

    // A's second job must NOT have entered the runner (per-tenant
    // serialization): probe with a bounded wait for a second `started` permit.
    let second_entered =
        tokio::time::timeout(std::time::Duration::from_millis(300), started.acquire()).await;
    assert!(
        second_entered.is_err(),
        "tenant A's second job entered the runner while its first still ran"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "exactly one A job dispatched so far"
    );

    // Release the parked A job; the second then takes the gate, runs, and is
    // released in turn — serialization delays, never drops, same-tenant work.
    release.notify_one();
    started.acquire().await.unwrap().forget();
    release.notify_one();
    t_a1.await.unwrap();
    t_a2.await.unwrap();

    assert_eq!(
        hits.load(Ordering::SeqCst),
        2,
        "both A jobs eventually dispatched"
    );
    for name in ["a1", "a2"] {
        let runs = runs_for(&pool_a, name).await;
        assert_eq!(runs.len(), 1, "{name}: {runs:?}");
        assert_eq!(runs[0].status, "ok", "{name}: {runs:?}");
    }
}

// ── RPC write target: executes via run_write_rpc, so record-history capture
//    rides the preupdate hook — actor is service (Privileged). ──────────────

#[tokio::test]
async fn rpc_write_target_executes_and_captures_record_history() {
    let hits = Arc::new(AtomicUsize::new(0));
    let (registry, executor, _tmp) =
        helpers::cron_test_stack("t-cron4", Arc::new(CountRunner(hits.clone()))).await;
    let pool = registry.get_or_open("t-cron4").unwrap();
    create_items_collection(&registry, "t-cron4").await;
    create_rpc(
        &pool,
        "ins",
        "INSERT INTO items (v) VALUES (:v)",
        r#"[{"name":"v","type":"text"}]"#,
        "write",
    )
    .await;
    let job = pool
        .with_writer(|c| {
            store::create_job(
                c,
                "nightly",
                "0 3 * * *",
                "rpc",
                "ins",
                Some(r#"{"v":"x"}"#),
                true,
            )
        })
        .await
        .unwrap();

    let d = deps(registry.clone(), executor);
    run_due_job(d, "t-cron4".into(), indexed(&job), minute_now()).await;

    // Row inserted with the payload-bound value.
    assert_eq!(count_rows(&pool, "SELECT COUNT(*) FROM items").await, 1);
    let v: String = pool
        .with_reader(|c| c.query_row("SELECT v FROM items", [], |r| r.get(0)))
        .await
        .unwrap();
    assert_eq!(v, "x", "payload bound as :v");

    // Run row ok.
    let runs = runs_for(&pool, "nightly").await;
    assert_eq!(runs.len(), 1, "{runs:?}");
    assert_eq!(runs[0].status, "ok", "{runs:?}");

    // Exactly one history row — capture rode run_write_rpc unchanged.
    let hist: Vec<(String, String, String)> = pool
        .with_reader(|c| {
            let mut st = c.prepare(
                "SELECT collection, op, actor_kind FROM _system_record_history ORDER BY id",
            )?;
            st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                .collect()
        })
        .await
        .unwrap();
    assert_eq!(hist.len(), 1, "one insert row captured: {hist:?}");
    assert_eq!(hist[0].0, "items");
    assert_eq!(hist[0].1, "insert");
    assert_eq!(hist[0].2, "service", "cron writes attribute as service");

    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "rpc target never touches the runner"
    );
}

// ── Fresh-row dispatch: payload_json is the one PATCH-mutable field the
//    fire-time re-assert does NOT compare, so a payload PATCH racing a queued
//    fire (id, active, schedule all unchanged — the re-assert passes) must
//    still dispatch the FRESH payload, never the tick snapshot's stale one. ──

#[tokio::test]
async fn dispatch_binds_fresh_payload_after_racing_patch() {
    let hits = Arc::new(AtomicUsize::new(0));
    let (registry, executor, _tmp) =
        helpers::cron_test_stack("t-cron13", Arc::new(CountRunner(hits.clone()))).await;
    let pool = registry.get_or_open("t-cron13").unwrap();
    create_items_collection(&registry, "t-cron13").await;
    create_rpc(
        &pool,
        "ins",
        "INSERT INTO items (v) VALUES (:v)",
        r#"[{"name":"v","type":"text"}]"#,
        "write",
    )
    .await;
    let job = pool
        .with_writer(|c| {
            store::create_job(
                c,
                "race",
                "* * * * *",
                "rpc",
                "ins",
                Some(r#"{"v":"old"}"#),
                true,
            )
        })
        .await
        .unwrap();
    let stale = indexed(&job);

    // Payload PATCH lands between the tick snapshot and the fire — id,
    // active, and schedule are unchanged, so the re-assert lets it through.
    pool.with_writer(|c| store::update_job(c, "race", None, Some(Some(r#"{"v":"new"}"#)), None))
        .await
        .unwrap();

    let d = deps(registry.clone(), executor);
    run_due_job(d, "t-cron13".into(), stale, minute_now()).await;

    let runs = runs_for(&pool, "race").await;
    assert_eq!(runs.len(), 1, "{runs:?}");
    assert_eq!(runs[0].status, "ok", "{runs:?}");
    let v: String = pool
        .with_reader(|c| c.query_row("SELECT v FROM items", [], |r| r.get(0)))
        .await
        .unwrap();
    assert_eq!(
        v, "new",
        "fire must bind the freshly re-read payload, not the tick snapshot's"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "rpc target never touches the runner"
    );
}

// ── Soft-delete race: tenant dir moved to _trash (pool evicted) between the
//    index snapshot and the fire. `run_due_job` must NOT re-create
//    `data.sqlite` via `get_or_open` (open_write: create_dir_all +
//    SQLITE_OPEN_CREATE + full schema) — the same hazard `boot_scan` guards
//    in src/cron/index.rs. ────────────────────────────────────────────────────

#[tokio::test]
async fn fire_after_tenant_soft_delete_skips_and_does_not_resurrect_db() {
    let hits = Arc::new(AtomicUsize::new(0));
    let (registry, executor, tmp) =
        helpers::cron_test_stack("t-cron6", Arc::new(CountRunner(hits.clone()))).await;
    let pool = registry.get_or_open("t-cron6").unwrap();
    let job = pool
        .with_writer(|c| store::create_job(c, "tick", "* * * * *", "function", "f1", None, true))
        .await
        .unwrap();
    let stale = indexed(&job);
    drop(pool);

    // Simulate soft-delete: dir moved into _trash, pool evicted from the
    // registry (src/mgmt/tenants.rs order).
    let tenant_dir = tmp.path().join("tenants").join("t-cron6");
    let trash = tmp.path().join("_trash");
    std::fs::create_dir_all(&trash).unwrap();
    std::fs::rename(&tenant_dir, trash.join("t-cron6-0")).unwrap();
    registry.evict("t-cron6");

    let d = deps(registry.clone(), executor);
    run_due_job(d, "t-cron6".into(), stale, minute_now()).await;

    assert_eq!(hits.load(Ordering::SeqCst), 0, "runner never invoked");
    let db = tmp
        .path()
        .join("tenants")
        .join("t-cron6")
        .join("data.sqlite");
    assert!(
        !db.exists(),
        "fire must not re-create data.sqlite for a soft-deleted tenant"
    );
}

// ── Executor-level closure of the same hazard: `run_one` re-enters the
//    registry by tenant id (resolve_and_run + record), so a soft-delete
//    landing during the permit/tenant-lock waits — AFTER `run_due_job`'s own
//    exists() probe passed — must NOT let `get_or_open`'s `open_write`
//    (create_dir_all + SQLITE_OPEN_CREATE + full schema) resurrect the dead
//    tenant outside `_trash`. Exercise `run_one` directly on a gone tenant:
//    error outcome, no runner call, nothing re-created, no log row. ──────────

#[tokio::test]
async fn executor_run_one_on_gone_tenant_errors_without_resurrecting_db() {
    let hits = Arc::new(AtomicUsize::new(0));
    let (registry, executor, tmp) =
        helpers::cron_test_stack("t-cron10", Arc::new(CountRunner(hits.clone()))).await;

    // Simulate soft-delete after the Invocation path was built: dir moved
    // into _trash, pool evicted from the registry (src/mgmt/tenants.rs order).
    let tenant_dir = tmp.path().join("tenants").join("t-cron10");
    let trash = tmp.path().join("_trash");
    std::fs::create_dir_all(&trash).unwrap();
    std::fs::rename(&tenant_dir, trash.join("t-cron10-0")).unwrap();
    registry.evict("t-cron10");

    let out = executor
        .run_one(Invocation {
            tenant_id: "t-cron10".into(),
            function_name: "f1".into(),
            trigger: "cron:tick".into(),
            event_json: "{}".into(),
            caller: CallerCtx::Privileged,
        })
        .await;

    assert_eq!(out.status, RunStatus::Error, "{out:?}");
    assert!(out.result.contains("tenant gone"), "got {}", out.result);
    assert_eq!(hits.load(Ordering::SeqCst), 0, "runner never invoked");
    assert!(
        !tenant_dir.exists(),
        "run_one must not re-create the tenant dir for a soft-deleted tenant"
    );
    assert!(
        !tenant_dir.join("data.sqlite").exists(),
        "run_one must not re-create data.sqlite for a soft-deleted tenant"
    );
}

// ── RPC declaring :user_id — cron has no user identity to bind, so the fire
//    is refused: error run, no execution. Covers BOTH modes (the guard sits
//    before mode dispatch; the write-mode sibling makes non-execution
//    observable — were the guard skipped, a row would land). ────────────────

#[tokio::test]
async fn rpc_declaring_user_id_records_error_and_does_not_execute() {
    let hits = Arc::new(AtomicUsize::new(0));
    let (registry, executor, _tmp) =
        helpers::cron_test_stack("t-cron5", Arc::new(CountRunner(hits.clone()))).await;
    let pool = registry.get_or_open("t-cron5").unwrap();
    create_items_collection(&registry, "t-cron5").await;

    // Read-mode RPC declaring :user_id (the plan's seed shape).
    create_rpc(
        &pool,
        "mine",
        "SELECT * FROM items WHERE v = :user_id",
        r#"[{"name":"user_id","type":"text"}]"#,
        "read",
    )
    .await;
    let j_read = pool
        .with_writer(|c| store::create_job(c, "read_uid", "* * * * *", "rpc", "mine", None, true))
        .await
        .unwrap();

    // Write-mode sibling: proves "does not execute" observably.
    create_rpc(
        &pool,
        "ins_uid",
        "INSERT INTO items (v) VALUES (:user_id)",
        r#"[{"name":"user_id","type":"text"}]"#,
        "write",
    )
    .await;
    let j_write = pool
        .with_writer(|c| {
            store::create_job(c, "write_uid", "* * * * *", "rpc", "ins_uid", None, true)
        })
        .await
        .unwrap();

    let d = deps(registry.clone(), executor);
    run_due_job(d.clone(), "t-cron5".into(), indexed(&j_read), minute_now()).await;
    run_due_job(d, "t-cron5".into(), indexed(&j_write), minute_now()).await;

    for name in ["read_uid", "write_uid"] {
        let runs = runs_for(&pool, name).await;
        assert_eq!(runs.len(), 1, "{name}: {runs:?}");
        assert_eq!(runs[0].status, "error", "{name}: {runs:?}");
        let err = runs[0].error.as_deref().unwrap_or_default();
        assert!(
            err.contains("user_id"),
            "{name}: error names the offending param: {err}"
        );
    }

    // No data touched, no history captured.
    assert_eq!(count_rows(&pool, "SELECT COUNT(*) FROM items").await, 0);
    let hist: i64 = pool
        .with_reader(|c| {
            match c.query_row("SELECT COUNT(*) FROM _system_record_history", [], |r| {
                r.get(0)
            }) {
                Ok(n) => Ok(n),
                Err(rusqlite::Error::SqliteFailure(_, Some(m))) if m.contains("no such table") => {
                    Ok(0)
                }
                Err(e) => Err(e),
            }
        })
        .await
        .unwrap();
    assert_eq!(hist, 0, "nothing executed, nothing captured");
}
