//! v1.24 — SQLite-backed audit log storage. See spec
//! docs/superpowers/specs/2026-05-23-drust-audit-sqlite-design.md.
//!
//! Lives in src/safety/ alongside the existing JSONL-based audit.rs.
//! Both write paths run in parallel during the v1.24 dual-write window;
//! the JSONL writer is removed in v1.26 once SQLite has proven stable
//! in production.

use anyhow::Context;
use rusqlite::Connection;
use std::path::Path;

const SCHEMA_SQL: &str = "
CREATE TABLE IF NOT EXISTS audit (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  ts               TEXT    NOT NULL,
  tenant           TEXT    NOT NULL DEFAULT '-',
  token_hint       TEXT    NOT NULL DEFAULT '-',
  op               TEXT    NOT NULL,
  status           TEXT    NOT NULL,
  duration_ms      INTEGER NOT NULL DEFAULT 0,
  error_code       TEXT,
  auth_method      TEXT,
  oauth_email      TEXT,
  oauth_error_code TEXT,
  caller_ip        TEXT,
  user_agent       TEXT,
  extra            TEXT
) STRICT;

CREATE INDEX IF NOT EXISTS idx_audit_ts        ON audit(ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_tenant_ts ON audit(tenant, ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_status_ts ON audit(ts DESC) WHERE status = 'error';
";

const PRAGMAS_WRITE: &str = "
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA busy_timeout = 5000;
PRAGMA foreign_keys = OFF;
PRAGMA wal_autocheckpoint = 1000;
";

const PRAGMAS_READ: &str = "
PRAGMA query_only = ON;
PRAGMA busy_timeout = 5000;
";

/// Open the audit DB in read-write mode and apply schema + write PRAGMAs.
/// Idempotent: CREATE TABLE IF NOT EXISTS + index CREATE IF NOT EXISTS.
pub fn open_audit_db_write(path: &Path) -> anyhow::Result<Connection> {
    let conn = Connection::open(path)
        .with_context(|| format!("opening audit DB at {}", path.display()))?;
    conn.execute_batch(PRAGMAS_WRITE)
        .with_context(|| format!("opening audit DB at {}", path.display()))?;
    conn.execute_batch(SCHEMA_SQL)
        .with_context(|| format!("opening audit DB at {}", path.display()))?;
    Ok(conn)
}

/// Open the audit DB in read-only mode. Caller is responsible for
/// ensuring the file exists (open_audit_db_write was called at least
/// once first).
pub fn open_audit_db_read(path: &Path) -> anyhow::Result<Connection> {
    let conn = Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .with_context(|| format!("opening audit DB read-only at {}", path.display()))?;
    conn.execute_batch(PRAGMAS_READ)
        .with_context(|| format!("opening audit DB read-only at {}", path.display()))?;
    Ok(conn)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::params;

    fn tmp_db() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test_audit.sqlite");
        (dir, path)
    }

    #[test]
    fn open_creates_table_and_indexes() {
        let (_dir, path) = tmp_db();
        let conn = open_audit_db_write(&path).unwrap();
        let idx_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master \
                 WHERE type = 'index' AND tbl_name = 'audit' \
                 AND name LIKE 'idx_audit_%'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(idx_count, 3, "expect 3 indexes (ts / tenant_ts / status_ts)");
    }

    #[test]
    fn open_is_idempotent_on_second_call() {
        let (_dir, path) = tmp_db();
        let _c1 = open_audit_db_write(&path).unwrap();
        // Second open should not error on existing table / indexes.
        let _c2 = open_audit_db_write(&path).unwrap();
    }

    #[test]
    fn schema_is_strict_mode() {
        let (_dir, path) = tmp_db();
        let conn = open_audit_db_write(&path).unwrap();
        // STRICT mode enforces declared column type. Note: TEXT affinity
        // still coerces INTEGER/REAL → TEXT silently (per SQLite STRICT
        // rules — see https://www.sqlite.org/stricttables.html), so the
        // proof has to be BLOB into TEXT, which STRICT genuinely rejects
        // with `cannot store BLOB value in TEXT column`.
        let r = conn.execute(
            "INSERT INTO audit (ts, op, status) VALUES (?1, ?2, ?3)",
            params![vec![0u8, 1u8, 2u8], "GET /x", "ok"], // BLOB into ts (TEXT)
        );
        assert!(r.is_err(), "STRICT should reject BLOB into TEXT column");
    }

    #[test]
    fn read_connection_rejects_inserts() {
        let (_dir, path) = tmp_db();
        let _w = open_audit_db_write(&path).unwrap();
        let r = open_audit_db_read(&path).unwrap();
        let res = r.execute(
            "INSERT INTO audit (ts, op, status) VALUES ('2026-05-23T00:00:00Z', 'x', 'ok')",
            [],
        );
        assert!(res.is_err(), "read-only conn must reject writes");
    }
}
