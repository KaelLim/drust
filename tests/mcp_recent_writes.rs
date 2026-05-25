//! v1.26 recent_writes: integration test using a file-backed audit DB
//! to verify the SQL query filters correctly across tenants + op kinds.

use drust::safety::audit::AuditEntry;
use drust::safety::audit_db::{AuditWriter, open_audit_db_read, open_audit_db_write};
use drust::safety::recent_writes::query_recent;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::Mutex;

fn mk(ts: &str, tenant: &str, op: &str, coll: Option<&str>) -> AuditEntry {
    let mut e = AuditEntry::success(tenant, "-", op, 5);
    e.ts = ts.into();
    if let Some(c) = coll {
        e = e.with_extra(serde_json::json!({"collection": c}));
    }
    e
}

#[tokio::test]
async fn recent_writes_filters_tenant_and_excludes_reads() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("audit.sqlite");
    let writer_conn = open_audit_db_write(&path).unwrap();
    let w = AuditWriter::new(writer_conn);

    // Seed 3 entries.
    w.send_backfill(mk("2026-05-25T01:00:00.000Z", "acme", "insert_record", Some("posts"))).await.unwrap();
    w.send_backfill(mk("2026-05-25T02:00:00.000Z", "acme", "GET /records/posts", Some("posts"))).await.unwrap(); // read op — must be filtered out
    w.send_backfill(mk("2026-05-25T03:00:00.000Z", "other", "insert_record", Some("posts"))).await.unwrap();

    // Wait for the batched writer to flush.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // Open a read connection on the same path and query.
    let read_conn = open_audit_db_read(&path).unwrap();
    let arc_read = Arc::new(Mutex::new(read_conn));
    let rows = query_recent(&arc_read, "acme", 50, None, None).await.unwrap();

    assert_eq!(rows.len(), 1, "expected exactly the acme insert_record entry; got {} rows", rows.len());
    assert_eq!(rows[0].op, "insert_record");
    assert_eq!(rows[0].collection.as_deref(), Some("posts"));
}

#[tokio::test]
async fn recent_writes_collection_filter() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("audit.sqlite");
    let writer_conn = open_audit_db_write(&path).unwrap();
    let w = AuditWriter::new(writer_conn);

    w.send_backfill(mk("2026-05-25T01:00:00.000Z", "acme", "insert_record", Some("posts"))).await.unwrap();
    w.send_backfill(mk("2026-05-25T02:00:00.000Z", "acme", "insert_record", Some("users"))).await.unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let read_conn = open_audit_db_read(&path).unwrap();
    let arc_read = Arc::new(Mutex::new(read_conn));
    let rows = query_recent(&arc_read, "acme", 50, Some("posts"), None).await.unwrap();

    assert_eq!(rows.len(), 1, "collection filter should narrow to 1 row");
    assert_eq!(rows[0].collection.as_deref(), Some("posts"));
}

#[tokio::test]
async fn recent_writes_since_ts_filter() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("audit.sqlite");
    let writer_conn = open_audit_db_write(&path).unwrap();
    let w = AuditWriter::new(writer_conn);

    w.send_backfill(mk("2026-05-25T01:00:00.000Z", "acme", "insert_record", None)).await.unwrap();
    w.send_backfill(mk("2026-05-25T03:00:00.000Z", "acme", "insert_record", None)).await.unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let read_conn = open_audit_db_read(&path).unwrap();
    let arc_read = Arc::new(Mutex::new(read_conn));
    let rows = query_recent(&arc_read, "acme", 50, None, Some("2026-05-25T02:00:00.000Z")).await.unwrap();

    assert_eq!(rows.len(), 1, "since_ts should narrow to the 03:00 entry");
    assert_eq!(rows[0].ts, "2026-05-25T03:00:00.000Z");
}
