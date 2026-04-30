//! Prepare-time SQL safety: reject anything the read-only authorizer
//! would deny, before persisting an RPC.

use crate::query::authorizer::{attach_readonly_authorizer, detach_authorizer};
use rusqlite::Connection;

#[derive(Debug, thiserror::Error)]
pub enum PrepareError {
    #[error("rpc sql failed prepare-time validation: {0}")]
    Rejected(String),
}

/// Open a read-only-style preparation: attach the authorizer, prepare
/// the SQL (no execution), detach. Returns the underlying SQLite error
/// message if prepare fails or the authorizer rejects.
///
/// Used by `create_rpc` and `update_rpc` to fail fast on:
/// - syntax errors,
/// - non-SELECT actions (UPDATE, INSERT, DELETE, ATTACH, …),
/// - references to sqlite_master / _system_*,
/// - unknown tables / columns.
pub fn validate_rpc_sql(conn: &Connection, sql: &str) -> Result<(), PrepareError> {
    attach_readonly_authorizer(conn);
    let res = conn.prepare(sql).map(|_| ()).map_err(|e| {
        PrepareError::Rejected(format!("{e}"))
    });
    detach_authorizer(conn);
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::tenant_db::open_write;
    use tempfile::TempDir;

    fn fresh() -> (TempDir, Connection) {
        let tmp = TempDir::new().unwrap();
        let conn = open_write(tmp.path(), "rpcprep").unwrap();
        conn.execute_batch(
            "CREATE TABLE posts (id INTEGER PRIMARY KEY, body TEXT);"
        ).unwrap();
        (tmp, conn)
    }

    #[test]
    fn valid_select_passes() {
        let (_t, conn) = fresh();
        validate_rpc_sql(&conn, "SELECT id, body FROM posts WHERE id = :id").unwrap();
    }

    #[test]
    fn syntax_error_rejected() {
        let (_t, conn) = fresh();
        let err = validate_rpc_sql(&conn, "SELECT FROM").unwrap_err();
        matches!(err, PrepareError::Rejected(_));
    }

    #[test]
    fn update_rejected() {
        let (_t, conn) = fresh();
        let err = validate_rpc_sql(&conn, "UPDATE posts SET body = 'x'").unwrap_err();
        matches!(err, PrepareError::Rejected(_));
    }

    #[test]
    fn delete_rejected() {
        let (_t, conn) = fresh();
        let err = validate_rpc_sql(&conn, "DELETE FROM posts").unwrap_err();
        matches!(err, PrepareError::Rejected(_));
    }

    #[test]
    fn attach_rejected() {
        let (_t, conn) = fresh();
        let err = validate_rpc_sql(&conn, "ATTACH 'other.db' AS x").unwrap_err();
        matches!(err, PrepareError::Rejected(_));
    }

    #[test]
    fn sqlite_master_rejected() {
        let (_t, conn) = fresh();
        let err = validate_rpc_sql(&conn, "SELECT * FROM sqlite_master").unwrap_err();
        matches!(err, PrepareError::Rejected(_));
    }

    #[test]
    fn unknown_table_rejected() {
        let (_t, conn) = fresh();
        let err = validate_rpc_sql(&conn, "SELECT * FROM nope").unwrap_err();
        matches!(err, PrepareError::Rejected(_));
    }

    #[test]
    fn system_rpc_rejected() {
        let (_t, conn) = fresh();
        let err = validate_rpc_sql(&conn, "SELECT * FROM _system_rpc").unwrap_err();
        matches!(err, PrepareError::Rejected(_));
    }
}
