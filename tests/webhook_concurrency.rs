//! v1.61 task #932 HIGH #2 — webhook fan-out must be bounded on BOTH axes.
//!
//! 1. **Delivery concurrency.** `dispatch_many` spawns one Tokio task (and one
//!    outbound socket) per (row × subscription). A bulk write into a
//!    well-subscribed collection therefore opened an unbounded number of tasks
//!    and FDs at once. `DRUST_WEBHOOK_MAX_CONCURRENCY` (default 64) bounds the
//!    number of deliveries actually in flight; the permit is acquired INSIDE
//!    the spawned task, because the fan-out loop must stay await-free between
//!    the egress-allowlist snapshot and the spawn.
//! 2. **Registration count.** Nothing capped how many subscriptions a tenant
//!    could register, and each one multiplies every write's fan-out.
//!    `DRUST_WEBHOOK_MAX_PER_TENANT` (default 32) caps it at registration time,
//!    inside the writer critical section so two concurrent creates cannot
//!    straddle the limit.
//!
//! Deliveries only reach loopback targets in a debug build (the dev carve-out
//! in `is_loopback_dev_url`), which is exactly what makes the first test
//! possible: the local counting server below receives REAL deliveries over the
//! real dispatch path, so the peak it observes is the peak the production
//! fan-out would open.

use drust::mcp::server::McpRegistry;
use drust::mcp::tools::batch::batch_insert;
use drust::mcp::tools::schema::{FieldSpec, create_collection};
use drust::mcp::tools::webhook::create_webhook;
use drust::storage::pool::TenantRegistry;
use drust::storage::record_history::AuditActor;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

/// Both knobs are process-global, and `delivery_permits()` latches its value in
/// a `OnceLock` at the FIRST delivery of the process — so the concurrency knob
/// has to be set before any dispatch happens in this binary. Setting both from
/// one `get_or_init` means whichever test runs first installs both values, and
/// neither `set_var` can race the other test's `env::var` read even when the
/// two tests run on separate threads.
fn env_once() {
    static ONCE: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    ONCE.get_or_init(|| unsafe {
        std::env::set_var("DRUST_WEBHOOK_MAX_CONCURRENCY", "2");
        std::env::set_var("DRUST_WEBHOOK_MAX_PER_TENANT", "3");
    });
}

async fn svc(dir: &tempfile::TempDir) -> drust::mcp::server::DrustMcp {
    let data = dir.path().to_path_buf();
    let tr = Arc::new(TenantRegistry::new(data.clone(), 2));
    let _ = drust::storage::tenant_db::open_write(&data, "blog").unwrap();
    let reg = McpRegistry::new(tr);
    reg.get_or_create("blog").await.unwrap()
}

fn tf(name: &str, ty: &str) -> FieldSpec {
    FieldSpec {
        name: name.into(),
        sql_type: ty.into(),
        nullable: false,
        unique: false,
        default_value: None,
        foreign_key: None,
        dim: None,
        description: None,
        ..Default::default()
    }
}

#[derive(Default)]
struct Counters {
    /// Requests currently inside the handler.
    inflight: AtomicUsize,
    /// High-water mark of `inflight` — the oracle for the semaphore.
    peak: AtomicUsize,
    /// Requests that finished.
    done: AtomicUsize,
}

/// Local receiver that holds every request open for `delay_ms` so overlapping
/// deliveries are actually observable, and records the high-water mark.
async fn start_counting_hook(c: Arc<Counters>, delay_ms: u64) -> String {
    use axum::Router;
    use axum::routing::post;
    let app = Router::new().route(
        "/hook",
        post(move || {
            let c = c.clone();
            async move {
                let now = c.inflight.fetch_add(1, Ordering::SeqCst) + 1;
                c.peak.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                c.inflight.fetch_sub(1, Ordering::SeqCst);
                c.done.fetch_add(1, Ordering::SeqCst);
                axum::http::StatusCode::OK
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}/hook")
}

/// Subscribe `collection` to `events` (a JSON array literal) at `url`, straight
/// through the writer — same shape `tests/batch_webhook_fanout.rs` uses, so the
/// registration cap under test cannot interfere with this fixture.
async fn subscribe(s: &drust::mcp::server::DrustMcp, collection: &str, events: &str, url: &str) {
    let (collection, events, url) = (collection.to_string(), events.to_string(), url.to_string());
    s.inner()
        .pool
        .with_writer(move |c| {
            c.execute(
                "INSERT INTO _system_webhooks
                    (collection, events, url, secret, active, created_at)
                 VALUES (?1, ?2, ?3, 'topsecret', 1, '2026-01-01T00:00:00Z')",
                rusqlite::params![collection, events, url],
            )
            .map(|_| ())
        })
        .await
        .unwrap();
}

/// HIGH #2: with `DRUST_WEBHOOK_MAX_CONCURRENCY=2`, eight simultaneous
/// deliveries must never hold more than 2 connections open at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delivery_concurrency_is_bounded_by_semaphore() {
    env_once();

    let counters = Arc::new(Counters::default());
    let url = start_counting_hook(counters.clone(), 300).await;

    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    create_collection(&s, "rows", &[tf("v", "text")])
        .await
        .unwrap();
    subscribe(&s, "rows", r#"["created"]"#, &url).await;

    // One batch, eight rows, one subscription → eight deliveries spawned in the
    // same instant. Unbounded, all eight sit in the handler together.
    let rows: Vec<serde_json::Value> = (0..8)
        .map(|i| serde_json::json!({ "v": format!("r{i}") }))
        .collect();
    batch_insert(&s, "rows", rows, AuditActor::service())
        .await
        .expect("batch insert");

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while counters.done.load(Ordering::SeqCst) < 8 {
        assert!(
            std::time::Instant::now() < deadline,
            "only {} of 8 deliveries landed before the deadline (peak={})",
            counters.done.load(Ordering::SeqCst),
            counters.peak.load(Ordering::SeqCst)
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    assert!(
        counters.peak.load(Ordering::SeqCst) <= 2,
        "peak={} exceeded semaphore",
        counters.peak.load(Ordering::SeqCst)
    );
    // Bounding must not DROP deliveries — queued is not lost.
    assert_eq!(
        counters.done.load(Ordering::SeqCst),
        8,
        "every delivery must still be made, just not all at once"
    );
}

/// A tenant may hold at most `DRUST_WEBHOOK_MAX_PER_TENANT` registrations.
#[tokio::test]
async fn registration_cap_rejects_the_next_webhook() {
    env_once();

    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    let pool = s.inner().pool.clone();

    for i in 0..3 {
        create_webhook(
            &pool,
            "rows".to_string(),
            vec!["created".to_string()],
            format!("http://127.0.0.1:{}/hook", 9000 + i),
        )
        .await
        .unwrap_or_else(|e| panic!("webhook {i} must be accepted under the cap of 3: {e}"));
    }

    let err = create_webhook(
        &pool,
        "rows".to_string(),
        vec!["created".to_string()],
        "http://127.0.0.1:9100/hook".to_string(),
    )
    .await
    .expect_err("the 4th webhook must be rejected once the tenant is at its cap");
    assert!(
        err.to_string().contains("WEBHOOK_LIMIT_EXCEEDED"),
        "the 4th create must fail with WEBHOOK_LIMIT_EXCEEDED, got: {err}"
    );

    // The rejected registration must not have landed.
    let n: i64 = pool
        .with_reader(|c| c.query_row("SELECT COUNT(*) FROM _system_webhooks", [], |r| r.get(0)))
        .await
        .unwrap();
    assert_eq!(n, 3, "the rejected create must not have inserted a row");
}
