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
use drust::functions::executor::{Executor, FunctionRunner, RunOutcome, RunStatus};
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

/// Runner that parks inside `run_one` until released — makes the overlap
/// window deterministic: `started` fires once the first fire is definitely
/// holding the in-flight marker, `release` lets it finish.
struct BlockingRunner {
    started: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
    hits: Arc<AtomicUsize>,
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
        self.started.notify_one();
        self.release.notified().await;
        RunOutcome {
            status: RunStatus::Ok,
            result: "{}".into(),
            log_text: String::new(),
        }
    }
}

fn deps(registry: Arc<TenantRegistry>, executor: Arc<Executor>) -> Arc<CronDeps> {
    Arc::new(CronDeps {
        registry,
        index: Arc::new(CronIndex::new()),
        executor,
        in_flight: Arc::new(dashmap::DashMap::new()),
        cfg: CronConfig::test_default(),
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
    let started = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let hits = Arc::new(AtomicUsize::new(0));
    let (registry, executor, _tmp) = helpers::cron_test_stack(
        "t-cron3",
        Arc::new(BlockingRunner {
            started: started.clone(),
            release: release.clone(),
            hits: hits.clone(),
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
    started.notified().await;

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
