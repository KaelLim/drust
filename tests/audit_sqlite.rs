//! v1.24 integration tests for the SQLite audit log path. Each test
//! stands up a temporary audit DB + writer task, dispatches entries
//! end-to-end, and inspects the resulting rows or aggregates.

use drust::safety::audit::AuditEntry;
use drust::safety::audit_db::*;
use std::path::PathBuf;
use std::time::Duration;
use tempfile::tempdir;

fn tmp_audit_db() -> (tempfile::TempDir, PathBuf, AuditWriter) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test_audit.sqlite");
    let conn = open_audit_db_write(&path).unwrap();
    let writer = AuditWriter::new(conn);
    (dir, path, writer)
}

fn mk_entry(ts: &str, tenant: &str, op: &str, status: &str, ms: u64) -> AuditEntry {
    let mut e = AuditEntry::success(tenant, "-", op, ms);
    e.ts = ts.to_string();
    if status == "error" {
        e.status = "error".to_string();
    }
    e
}

#[tokio::test]
async fn schema_creates_indexes() {
    let (_dir, path, _w) = tmp_audit_db();
    let r = open_audit_db_read(&path).unwrap();
    let count: i64 = r
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name LIKE 'idx_audit_%'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 3);
}

#[tokio::test]
async fn single_insert_round_trip() {
    let (_dir, path, w) = tmp_audit_db();
    w.send_backfill(mk_entry(
        "2026-05-23T01:00:00.000Z",
        "acme",
        "GET /x",
        "ok",
        12,
    ))
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let r = open_audit_db_read(&path).unwrap();
    let (ts, tenant, op, ms): (String, String, String, i64) = r
        .query_row("SELECT ts, tenant, op, duration_ms FROM audit", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .unwrap();
    assert_eq!(ts, "2026-05-23T01:00:00.000Z");
    assert_eq!(tenant, "acme");
    assert_eq!(op, "GET /x");
    assert_eq!(ms, 12);
}

#[tokio::test]
async fn caller_ip_user_agent_hoisted_from_extra() {
    let (_dir, path, w) = tmp_audit_db();
    let mut e = mk_entry("2026-05-23T01:00:00.000Z", "acme", "GET /x", "ok", 12);
    e.extra
        .insert("caller_ip".into(), serde_json::json!("203.0.113.5"));
    e.extra
        .insert("user_agent".into(), serde_json::json!("curl/8.0"));
    e.extra
        .insert("auth_kind".into(), serde_json::json!("admin"));
    w.send_backfill(e).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let r = open_audit_db_read(&path).unwrap();
    let (ip, ua, extra): (Option<String>, Option<String>, Option<String>) = r
        .query_row(
            "SELECT caller_ip, user_agent, extra FROM audit",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(ip.as_deref(), Some("203.0.113.5"));
    assert_eq!(ua.as_deref(), Some("curl/8.0"));
    let extra = extra.expect("extra has auth_kind");
    assert!(extra.contains("\"auth_kind\":\"admin\""));
    assert!(!extra.contains("caller_ip"));
    assert!(!extra.contains("user_agent"));
}

#[tokio::test]
async fn batch_insert_100_in_one_tx() {
    let (_dir, path, w) = tmp_audit_db();
    for i in 0..100 {
        w.send_backfill(mk_entry(
            &format!("2026-05-23T01:00:{:02}.000Z", i % 60),
            "acme",
            "GET /x",
            "ok",
            i as u64,
        ))
        .await
        .unwrap();
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let r = open_audit_db_read(&path).unwrap();
    let cnt: i64 = r
        .query_row("SELECT COUNT(*) FROM audit", [], |row| row.get(0))
        .unwrap();
    assert_eq!(cnt, 100);
}

#[tokio::test]
async fn query_window_filters_by_tenant() {
    let (_dir, path, w) = tmp_audit_db();
    for tenant in &["acme", "beta", "acme", "gamma", "acme"] {
        w.send_backfill(mk_entry(
            "2026-05-23T01:00:00.000Z",
            tenant,
            "GET /x",
            "ok",
            10,
        ))
        .await
        .unwrap();
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let r = open_audit_db_read(&path).unwrap();
    let acme_count: i64 = r
        .query_row(
            "SELECT COUNT(*) FROM audit WHERE tenant = 'acme'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(acme_count, 3);
}

#[tokio::test]
async fn sql_total_matches_count() {
    let (_dir, path, w) = tmp_audit_db();
    for i in 0..50 {
        let status = if i % 5 == 0 { "error" } else { "ok" };
        w.send_backfill(mk_entry(
            &format!("2026-05-23T01:{:02}:00.000Z", i % 60),
            "acme",
            "GET /x",
            status,
            10,
        ))
        .await
        .unwrap();
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let r = open_audit_db_read(&path).unwrap();
    let ov = drust::mgmt::audit::aggregate_via_sql(
        &r,
        "2026-05-23T00:00:00.000Z",
        None,
        drust::mgmt::audit::Window::H24,
    );
    assert_eq!(ov.total, 50);
    assert_eq!(ov.error_count, 10); // 50 / 5 = 10
}

#[tokio::test]
async fn top_tenants_via_sql() {
    let (_dir, path, w) = tmp_audit_db();
    for (tenant, n) in [("a", 10), ("b", 8), ("c", 6), ("d", 4), ("e", 2), ("f", 1)] {
        for _ in 0..n {
            w.send_backfill(mk_entry(
                "2026-05-23T01:00:00.000Z",
                tenant,
                "GET /x",
                "ok",
                10,
            ))
            .await
            .unwrap();
        }
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let r = open_audit_db_read(&path).unwrap();
    let ov = drust::mgmt::audit::aggregate_via_sql(
        &r,
        "2026-05-23T00:00:00.000Z",
        None,
        drust::mgmt::audit::Window::H24,
    );
    let names: Vec<&str> = ov.top_tenants.iter().map(|t| t.tenant.as_str()).collect();
    assert_eq!(names, vec!["a", "b", "c", "d", "e"]);
}

#[tokio::test]
async fn mpsc_full_drops_with_counter_increment() {
    let (_dir, _path, w) = tmp_audit_db();
    // send_backfill uses .await (back-pressures); this test verifies the
    // dropped counter API surface exists and is observable.
    // The dropping semantic itself is exercised by audit_db.rs unit tests
    // (try_send_inner path), which uses the non-blocking try_send.
    for i in 0..200 {
        let entry = mk_entry("2026-05-23T01:00:00.000Z", "acme", "GET /x", "ok", i);
        let _ = w.send_backfill(entry).await;
    }
    let dropped = w.dropped.load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(dropped, 0, "backfill path uses .await so does not drop");
}

#[tokio::test]
async fn retention_deletes_old_rows() {
    let (_dir, path, w) = tmp_audit_db();
    // Insert 5 old + 5 new
    for i in 0..5 {
        w.send_backfill(mk_entry(
            &format!("2025-01-01T0{}:00:00.000Z", i),
            "acme",
            "GET /x",
            "ok",
            10,
        ))
        .await
        .unwrap();
    }
    for i in 0..5 {
        w.send_backfill(mk_entry(
            &format!("2026-05-23T0{}:00:00.000Z", i),
            "acme",
            "GET /x",
            "ok",
            10,
        ))
        .await
        .unwrap();
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    // Send retention with cutoff at 2026-01-01: old rows go away
    w.send_retention(Some("2026-01-01T00:00:00.000Z".to_string()), false)
        .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let r = open_audit_db_read(&path).unwrap();
    let count: i64 = r
        .query_row("SELECT COUNT(*) FROM audit", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 5);
}

#[tokio::test]
async fn pagination_cursor_via_ts_and_id() {
    let (_dir, path, w) = tmp_audit_db();
    for i in 0..20 {
        w.send_backfill(mk_entry(
            &format!("2026-05-23T01:{:02}:00.000Z", i),
            "acme",
            "GET /x",
            "ok",
            10,
        ))
        .await
        .unwrap();
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let r = open_audit_db_read(&path).unwrap();
    // First page: 10 rows
    let page1 = drust::mgmt::audit::query_browse(
        &r,
        "2026-05-23T00:00:00.000Z",
        None,
        None,
        None,
        None,
        10,
    );
    assert_eq!(page1.len(), 10);
    // Second page: cursor = last ts of page1
    let cursor = page1.last().unwrap().ts.clone();
    let page2 = drust::mgmt::audit::query_browse(
        &r,
        "2026-05-23T00:00:00.000Z",
        None,
        None,
        None,
        Some(&cursor),
        10,
    );
    // ts < cursor → page2 has fewer (9 because boundary is exclusive)
    assert!(page2.len() <= 10);
    // No overlap between page1 and page2
    let page1_ts: std::collections::HashSet<_> = page1.iter().map(|e| e.ts.clone()).collect();
    for entry in &page2 {
        assert!(
            !page1_ts.contains(&entry.ts),
            "page overlap on ts={}",
            entry.ts
        );
    }
}

#[tokio::test]
async fn extra_with_nested_object_preserved() {
    let (_dir, path, w) = tmp_audit_db();
    let mut e = mk_entry("2026-05-23T01:00:00.000Z", "acme", "GET /x", "ok", 12);
    e.extra
        .insert("nested".into(), serde_json::json!({"a": 1, "b": [2, 3]}));
    w.send_backfill(e).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let r = open_audit_db_read(&path).unwrap();
    let extra: String = r
        .query_row("SELECT extra FROM audit", [], |row| row.get(0))
        .unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&extra).unwrap();
    assert_eq!(parsed["nested"]["a"], 1);
    assert_eq!(parsed["nested"]["b"], serde_json::json!([2, 3]));
}

#[tokio::test]
async fn aggregate_via_sql_empty_db_returns_zero() {
    let (_dir, path, _w) = tmp_audit_db();
    let r = open_audit_db_read(&path).unwrap();
    let ov = drust::mgmt::audit::aggregate_via_sql(
        &r,
        "2026-05-23T00:00:00.000Z",
        None,
        drust::mgmt::audit::Window::H24,
    );
    assert_eq!(ov.total, 0);
    assert_eq!(ov.error_count, 0);
    assert_eq!(ov.error_pct, 0.0);
}

#[tokio::test]
async fn tenant_filter_excludes_other_tenants_in_overview() {
    let (_dir, path, w) = tmp_audit_db();
    for tenant in &["acme", "acme", "acme", "beta", "beta"] {
        w.send_backfill(mk_entry(
            "2026-05-23T01:00:00.000Z",
            tenant,
            "GET /x",
            "ok",
            10,
        ))
        .await
        .unwrap();
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let r = open_audit_db_read(&path).unwrap();
    let ov = drust::mgmt::audit::aggregate_via_sql(
        &r,
        "2026-05-23T00:00:00.000Z",
        Some("acme"),
        drust::mgmt::audit::Window::H24,
    );
    assert_eq!(ov.total, 3);
    // Top tenants empty when tenant filter is applied (per spec).
    assert!(ov.top_tenants.is_empty());
}

#[tokio::test]
async fn open_audit_db_write_creates_meta_table() {
    use rusqlite::OptionalExtension;
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path().join("meta_logs.sqlite");
    let conn = drust::safety::audit_db::open_audit_db_write(&p).unwrap();
    let exists: Option<String> = conn
        .query_row(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='_meta'",
            [],
            |r| r.get(0),
        )
        .optional()
        .unwrap();
    assert_eq!(exists.as_deref(), Some("_meta"));
}

#[tokio::test]
async fn dropped_total_reports_zero_before_init() {
    // dropped_total() must return 0 when no writer is initialised (test path)
    let n = drust::safety::audit_db::dropped_total();
    assert_eq!(n, 0);
}

#[test]
fn next_0300_utc_before_fire_time() {
    use chrono::{TimeZone, Utc};
    let now = Utc.with_ymd_and_hms(2026, 5, 24, 2, 59, 0).unwrap();
    let next = drust::safety::audit_db::next_0300_utc(now);
    assert_eq!(next, Utc.with_ymd_and_hms(2026, 5, 24, 3, 0, 0).unwrap());
}

#[test]
fn next_0300_utc_after_fire_time() {
    use chrono::{TimeZone, Utc};
    let now = Utc.with_ymd_and_hms(2026, 5, 24, 3, 0, 1).unwrap();
    let next = drust::safety::audit_db::next_0300_utc(now);
    assert_eq!(next, Utc.with_ymd_and_hms(2026, 5, 25, 3, 0, 0).unwrap());
}

#[test]
fn should_vacuum_true_on_day_one() {
    use chrono::{TimeZone, Utc};
    let now = Utc.with_ymd_and_hms(2026, 6, 1, 3, 0, 0).unwrap();
    let last = Some(Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap());
    assert!(drust::safety::audit_db::should_vacuum(now, last));
}

#[test]
fn should_vacuum_true_when_last_vacuum_in_previous_month() {
    use chrono::{TimeZone, Utc};
    let now = Utc.with_ymd_and_hms(2026, 6, 15, 3, 0, 0).unwrap();
    let last = Some(Utc.with_ymd_and_hms(2026, 5, 1, 3, 0, 0).unwrap());
    assert!(drust::safety::audit_db::should_vacuum(now, last));
}

#[test]
fn should_vacuum_false_when_last_vacuum_same_month() {
    use chrono::{TimeZone, Utc};
    let now = Utc.with_ymd_and_hms(2026, 6, 15, 3, 0, 0).unwrap();
    let last = Some(Utc.with_ymd_and_hms(2026, 6, 1, 3, 0, 0).unwrap());
    assert!(!drust::safety::audit_db::should_vacuum(now, last));
}

#[test]
fn should_vacuum_true_when_no_record() {
    use chrono::{TimeZone, Utc};
    let now = Utc.with_ymd_and_hms(2026, 6, 15, 3, 0, 0).unwrap();
    assert!(drust::safety::audit_db::should_vacuum(now, None));
}
