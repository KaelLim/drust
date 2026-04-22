//! Tests for the reconcile page's pending_revokes and orphan_buckets sections.
//! Uses real meta.sqlite (open_meta) but no Garage round-trip.

use drust::storage::meta::open_meta;
use rusqlite::Connection;
use tempfile::TempDir;

fn fresh_meta() -> (TempDir, Connection) {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("meta.sqlite");
    let conn = open_meta(&path).unwrap();
    (tmp, conn)
}

#[test]
fn pending_revokes_table_supports_insert_and_select() {
    let (_tmp, conn) = fresh_meta();
    conn.execute(
        "INSERT INTO _trash_pending_revokes (tenant_id, detected_at, last_error) \
         VALUES ('stuck', datetime('now'), 'boom')",
        [],
    )
    .unwrap();

    let row: (String, String, Option<String>) = conn
        .query_row(
            "SELECT tenant_id, detected_at, last_error FROM _trash_pending_revokes",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get::<_, Option<String>>(2)?)),
        )
        .unwrap();
    assert_eq!(row.0, "stuck");
    assert_eq!(row.2, Some("boom".to_string()));
}

#[test]
fn orphan_buckets_table_supports_insert_and_select() {
    let (_tmp, conn) = fresh_meta();
    conn.execute(
        "INSERT INTO _orphan_buckets (bucket_name, detected_at, reason) \
         VALUES ('tenant-zombie-pub', datetime('now'), 'tenant_hard_delete')",
        [],
    )
    .unwrap();

    let row: (String, String, String) = conn
        .query_row(
            "SELECT bucket_name, detected_at, reason FROM _orphan_buckets",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(row.0, "tenant-zombie-pub");
    assert_eq!(row.2, "tenant_hard_delete");
}

#[test]
fn pending_revokes_delete_clears_row() {
    let (_tmp, conn) = fresh_meta();
    conn.execute(
        "INSERT INTO _trash_pending_revokes (tenant_id) VALUES ('zap')",
        [],
    )
    .unwrap();
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM _trash_pending_revokes WHERE tenant_id='zap'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);

    conn.execute(
        "DELETE FROM _trash_pending_revokes WHERE tenant_id=?1",
        rusqlite::params!["zap"],
    )
    .unwrap();

    let after: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM _trash_pending_revokes WHERE tenant_id='zap'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(after, 0);
}
