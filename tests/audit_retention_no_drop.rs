//! v1.58 P1-5 — the audit writer must not drop inbound rows while a retention
//! pass (chunked DELETE, then VACUUM) is running.
//!
//! Measured on the live host before this fix: `drust_audit_drops_total` = 962
//! after two days, ~480 per daily retention pass. The cause was `run_retention`
//! executing inside the same `tokio::select!` arm as `rx.recv()`, so nothing
//! drained the bounded channel for the duration of the DELETE and VACUUM.
//!
//! `init_globals` is a `OnceLock`, so exactly ONE test in this binary may call
//! it — keep this file to a single test.

use drust::safety::audit::AuditEntry;
use drust::safety::audit_db::{AuditWriter, init_globals, try_send, writer_for_init_use};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

fn entry(op: &str) -> AuditEntry {
    AuditEntry::success("t1", "hint", op, 1)
}

/// Expired rows seeded so the DELETE has real work to do.
const SEEDED_EXPIRED: usize = 50_000;

/// The inbound flood is paced in wall-clock time rather than sent as one tight
/// burst: a burst overruns the writer's 100-row batch flush even when nothing
/// is blocking it, which would make the test fail for the wrong reason. At
/// ~5_000 rows/s the writer keeps up comfortably when it is draining, and the
/// bounded channel (capacity 1000) overflows after ~200 ms when it is not.
const PACE_BATCH: usize = 50;
const PACE_TICK: Duration = Duration::from_millis(10);
const FLOOD_DURATION: Duration = Duration::from_millis(3_000);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retention_pass_drops_no_inbound_rows() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("a.sqlite");
    let conn = drust::safety::audit_db::open_audit_db_write(&path).unwrap();

    // Seed expired rows so the DELETE has real work, and enough of them that
    // the pass is not instantaneous. One transaction — the seeding is setup,
    // not the thing under test.
    conn.execute_batch("BEGIN").unwrap();
    {
        let mut stmt = conn
            .prepare("INSERT INTO audit (ts, op, status, duration_ms) VALUES (?1, 'old', 200, 1)")
            .unwrap();
        for i in 0..SEEDED_EXPIRED {
            stmt.execute(rusqlite::params![format!(
                "2020-01-01T00:00:{:02}.000Z",
                i % 60
            )])
            .unwrap();
        }
    }
    conn.execute_batch("COMMIT").unwrap();

    // `try_send_inner` is private; the process-global `try_send` is the public
    // single-entry dispatch.
    init_globals(AuditWriter::new(conn));
    let w = writer_for_init_use().expect("writer initialised");
    let dropped_before = w.dropped.load(Ordering::Relaxed);

    // Kick off retention (DELETE everything seeded, then VACUUM) and flood the
    // writer concurrently. `send_retention` returns as soon as the command is
    // queued, so the pass runs in the writer task alongside the flood.
    w.send_retention(Some("2021-01-01T00:00:00.000Z".into()), true)
        .await;

    let deadline = Instant::now() + FLOOD_DURATION;
    let mut sent = 0usize;
    while Instant::now() < deadline {
        for _ in 0..PACE_BATCH {
            try_send(&entry(&format!("live-{sent}")));
            sent += 1;
        }
        tokio::time::sleep(PACE_TICK).await;
    }
    assert!(sent > 2_000, "flood must outlast the channel capacity");

    let dropped_after = w.dropped.load(Ordering::Relaxed);
    assert_eq!(
        dropped_after,
        dropped_before,
        "retention must not cause a single audit drop (dropped {} rows)",
        dropped_after - dropped_before
    );

    // Stronger than the counter: every flooded row must actually be on disk
    // once the pass finishes. Poll — the VACUUM holds the DB exclusively for
    // part of this window.
    let reader = drust::safety::audit_db::open_audit_db_read(&path).unwrap();
    let mut landed = 0i64;
    let settle = Instant::now() + Duration::from_secs(60);
    while Instant::now() < settle {
        tokio::time::sleep(Duration::from_millis(200)).await;
        landed = reader
            .query_row(
                "SELECT COUNT(*) FROM audit WHERE op LIKE 'live-%'",
                [],
                |r| r.get(0),
            )
            .unwrap_or(landed);
        if landed as usize >= sent {
            break;
        }
    }
    assert_eq!(
        landed as usize, sent,
        "every entry sent during the retention pass must be persisted"
    );

    // And the retention DELETE itself must still have done its job.
    let old_left: i64 = reader
        .query_row("SELECT COUNT(*) FROM audit WHERE op = 'old'", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(old_left, 0, "expired rows must be gone");
}
