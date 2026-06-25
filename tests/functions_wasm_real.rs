// tests/functions_wasm_real.rs — the spec §7 sandbox claims PROVEN, not
// asserted: epoch deadline kills an infinite loop (timeout), ResourceLimiter
// kills unbounded allocation (oom), happy path writes through the host API
// and the write lands in the tenant DB.
//
// Cross-tenant access is unrepresentable AT THE TYPE LEVEL: host functions
// close over a DrustMcp built from the invocation's own tenant row; no host
// call takes a tenant parameter and the guest holds no token (spec §7.2).
// There is nothing to test at runtime — this header is the documentation
// the spec's testing strategy requires.
mod helpers;

use drust::functions::FnConfig;
use drust::functions::executor::{FunctionRunner, RunStatus};
use drust::functions::runtime::{HostStateSeed, WasmRunner};
use std::sync::Arc;

fn fixture(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/functions")
        .join(format!("{name}.wasm"))
}

/// Build a runner over a real tenant dir; returns (runner, registry, tmp).
async fn real_runner(
    cfg: FnConfig,
) -> (
    Arc<WasmRunner>,
    Arc<drust::storage::pool::TenantRegistry>,
    tempfile::TempDir,
) {
    let tmp = tempfile::tempdir().unwrap();
    let tenants = Arc::new(drust::storage::pool::TenantRegistry::new(
        tmp.path().to_path_buf(),
        2,
    ));
    // Minimal seed: no garage, in-memory audit, test rooms. Mirror the
    // McpRegistry::new test ctor's field sourcing (src/mcp/server.rs:182) —
    // `bus_rooms` / `bucket` / `rooms_cfg` use the same canonical
    // `RoomsConfig::test_defaults()` materialization the registry uses.
    let rooms_cfg = drust::tenant::rooms::RoomsConfig::test_defaults();
    let bucket = rooms_cfg.bucket();
    let seed = HostStateSeed {
        tenants: tenants.clone(),
        bus: drust::tenant::events::EventBus::new(),
        webhooks: drust::tenant::WebhookDispatcher::new(tenants.clone(), None),
        garage: None,
        public_base_url: String::new(),
        url_sign_secret: Arc::new([0u8; 32]),
        meta: None,
        max_upload_bytes: 52_428_800,
        index_large_table_rows: 1_000_000,
        audit_meta_read: Arc::new(tokio::sync::Mutex::new(
            drust::safety::audit_db::open_audit_db_memory().unwrap(),
        )),
        bus_rooms: drust::tenant::rooms::RoomBus::new(),
        bucket,
        rooms_cfg,
        disk_min_free_pct: 20,
    };
    (WasmRunner::new(cfg, seed), tenants, tmp)
}

#[tokio::test(flavor = "multi_thread")]
async fn happy_fixture_writes_through_host_api() {
    let (runner, tenants, _tmp) = real_runner(FnConfig::test_default()).await;
    let pool = tenants.get_or_open("t-w").unwrap();
    // the fixture inserts into fn_out — create that collection first
    helpers::create_collection_via_pool(&pool, "fn_out", &[("payload", "text")]).await;

    let out = runner
        .run(
            "t-w",
            &fixture("happy"),
            r#"{"trigger":"manual"}"#,
            drust::functions::caller::CallerCtx::Privileged,
        )
        .await;
    assert_eq!(out.status, RunStatus::Ok, "result: {}", out.result);
    assert!(
        out.log_text.contains("happy fixture running"),
        "guest log captured"
    );

    let n: i64 = pool
        .with_writer(|c| c.query_row("SELECT COUNT(*) FROM fn_out", [], |r| r.get(0)))
        .await
        .unwrap();
    assert_eq!(n, 1, "host insert-record landed in the tenant DB");
}

#[tokio::test(flavor = "multi_thread")]
async fn loop_fixture_hits_epoch_timeout() {
    let mut cfg = FnConfig::test_default();
    cfg.timeout_secs = 1;
    let (runner, _tenants, _tmp) = real_runner(cfg).await;
    let started = std::time::Instant::now();
    let out = runner
        .run(
            "t-w",
            &fixture("loop"),
            "{}",
            drust::functions::caller::CallerCtx::Privileged,
        )
        .await;
    assert_eq!(out.status, RunStatus::Timeout, "result: {}", out.result);
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "deadline must fire near 1s, not hang"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn membomb_fixture_hits_oom() {
    let mut cfg = FnConfig::test_default();
    cfg.memory_max_bytes = 32 * 1024 * 1024;
    let (runner, _tenants, _tmp) = real_runner(cfg).await;
    let out = runner
        .run(
            "t-w",
            &fixture("membomb"),
            "{}",
            drust::functions::caller::CallerCtx::Privileged,
        )
        .await;
    assert_eq!(out.status, RunStatus::Oom, "result: {}", out.result);
}
