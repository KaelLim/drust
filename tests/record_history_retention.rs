//! Task 6 — record-history retention janitor.
//!
//! `prune_tenant` deletes `_system_record_history` rows older than the
//! retention cutoff; `days == 0` disables pruning entirely (keep forever).
//! The daily task (`spawn_retention_task`) is a thin loop over live tenants
//! calling this same fn, so the correctness surface is the prune itself.

use rusqlite::Connection;

/// Fixture built from the SAME DDL const `migrate_tenant_db` /
/// `apply_schema` run in production, so it can never drift from the real
/// table shape.
fn hist_conn() -> Connection {
    let c = Connection::open_in_memory().unwrap();
    c.execute_batch(drust::db::migrations::SQL_CREATE_SYSTEM_RECORD_HISTORY_IF_NOT_EXISTS)
        .unwrap();
    c
}

#[test]
fn prune_deletes_rows_older_than_cutoff() {
    let c = hist_conn();
    c.execute(
        "INSERT INTO _system_record_history (collection, record_id, op, actor_kind, ts) \
         VALUES ('n', 1, 'insert', 'service', datetime('now','-30 days'))",
        [],
    )
    .unwrap();
    c.execute(
        "INSERT INTO _system_record_history (collection, record_id, op, actor_kind, ts) \
         VALUES ('n', 2, 'insert', 'service', datetime('now'))",
        [],
    )
    .unwrap();
    let deleted = drust::storage::record_history::prune_tenant(&c, 7).unwrap();
    assert_eq!(deleted, 1);
    let left: i64 = c
        .query_row("SELECT COUNT(*) FROM _system_record_history", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(left, 1);
    // The survivor is the fresh row, not the stale one.
    let survivor: i64 = c
        .query_row("SELECT record_id FROM _system_record_history", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(survivor, 2);
}

#[test]
fn prune_zero_days_disables() {
    let c = hist_conn();
    c.execute(
        "INSERT INTO _system_record_history (collection, record_id, op, actor_kind, ts) \
         VALUES ('n', 1, 'insert', 'service', datetime('now','-30 days'))",
        [],
    )
    .unwrap();
    assert_eq!(
        drust::storage::record_history::prune_tenant(&c, 0).unwrap(),
        0
    );
    let left: i64 = c
        .query_row("SELECT COUNT(*) FROM _system_record_history", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(left, 1, "days=0 keeps everything forever");
}
