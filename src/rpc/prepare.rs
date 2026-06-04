//! Prepare-time SQL safety: reject anything the mode-matched authorizer
//! would deny, before persisting an RPC.

use crate::query::authorizer::{
    attach_readonly_authorizer, attach_writable_authorizer, detach_authorizer,
};
use crate::rpc::registry::RpcMode;
use rusqlite::Connection;

#[derive(Debug, thiserror::Error)]
pub enum PrepareError {
    #[error("rpc sql failed prepare-time validation: {0}")]
    Rejected(String),
}

/// Validate the SQL body of a stored RPC at registry-write time. The
/// authorizer used matches the RPC's declared `mode`:
///
/// - `RpcMode::Read`  → attaches [`attach_readonly_authorizer`]; SELECTs
///   on user tables are Allowed; anything else (INSERT/UPDATE/DELETE,
///   DDL, ATTACH, sqlite_master / _system_* reads) is Denied at prepare.
/// - `RpcMode::Write` → attaches [`attach_writable_authorizer`]; the
///   same Read surface PLUS Insert/Update/Delete on non-protected user
///   tables. DDL, ATTACH, sqlite_master reads, and _system_* writes are
///   still Denied at prepare.
///
/// Multi-statement bodies are split via [`crate::rpc::exec_write::split_statements`]
/// (the same lexer the executor uses) and validated per-statement so a
/// body that mixes a legitimate INSERT with a sneaky `DROP` fails at the
/// offending statement rather than silently passing.
///
/// Reconciliation note (C5): empirical probe shows
/// `Connection::prepare` of a write statement SUCCEEDS on a connection
/// opened with `SQLITE_OPEN_READONLY` + `PRAGMA query_only = ON` —
/// SQLite's readonly guard fires only at `step()` time, not prepare.
/// So the authorizer (not the open-mode) is what decides allow/deny at
/// prepare-time. This function therefore runs cleanly on a reader
/// connection for BOTH modes; callers should dispatch through
/// `pool.with_reader` (avoids the per-tenant writer mutex on every
/// admin-form save).
pub fn validate_rpc_sql(conn: &Connection, sql: &str, mode: RpcMode) -> Result<(), PrepareError> {
    // Preserve pre-C5 behaviour: an empty body was rejected because
    // `conn.prepare("")` errors with "no SQL". The new split-then-prepare
    // path would otherwise loop zero times and silently accept "".
    if sql.trim().is_empty() {
        return Err(PrepareError::Rejected("rpc sql body is empty".to_string()));
    }

    // Defense in depth: if a previous closure on this conn left an
    // authorizer attached (it shouldn't — every code path is supposed to
    // detach), reset to a known state before we attach our own.
    detach_authorizer(conn);

    // Split first so we can validate each statement under its own attach.
    let stmts = match crate::rpc::exec_write::split_statements(sql) {
        Ok(s) => s,
        Err(e) => return Err(PrepareError::Rejected(e.message)),
    };

    // Defensive: split_statements may return Ok(vec![]) for a body that
    // is purely whitespace-with-semicolons (e.g. "   ;   "). The empty
    // check above only catches all-whitespace bodies, so reject this
    // edge case explicitly too.
    if stmts.is_empty() {
        return Err(PrepareError::Rejected(
            "rpc sql body has no statements".to_string(),
        ));
    }

    for stmt in &stmts {
        match mode {
            RpcMode::Read => attach_readonly_authorizer(conn),
            RpcMode::Write => attach_writable_authorizer(conn),
        }
        let res = conn
            .prepare(stmt)
            .map(|_| ())
            .map_err(|e| PrepareError::Rejected(format!("{e}")));
        // MANDATORY detach BEFORE we propagate the error or move on to
        // the next statement — otherwise the authorizer would leak to
        // the connection's next user (schema introspection, the next
        // RPC, etc.). This is the same invariant `call_rpc`'s STEP 5
        // observes for the runtime path.
        detach_authorizer(conn);
        res?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::tenant_db::open_write;
    use tempfile::TempDir;

    fn fresh() -> (TempDir, Connection) {
        let tmp = TempDir::new().unwrap();
        let conn = open_write(tmp.path(), "rpcprep").unwrap();
        conn.execute_batch("CREATE TABLE posts (id INTEGER PRIMARY KEY, body TEXT);")
            .unwrap();
        (tmp, conn)
    }

    #[test]
    fn valid_select_passes() {
        let (_t, conn) = fresh();
        validate_rpc_sql(
            &conn,
            "SELECT id, body FROM posts WHERE id = :id",
            RpcMode::Read,
        )
        .unwrap();
    }

    #[test]
    fn syntax_error_rejected() {
        let (_t, conn) = fresh();
        let err = validate_rpc_sql(&conn, "SELECT FROM", RpcMode::Read).unwrap_err();
        matches!(err, PrepareError::Rejected(_));
    }

    #[test]
    fn update_rejected() {
        let (_t, conn) = fresh();
        let err =
            validate_rpc_sql(&conn, "UPDATE posts SET body = 'x'", RpcMode::Read).unwrap_err();
        matches!(err, PrepareError::Rejected(_));
    }

    #[test]
    fn delete_rejected() {
        let (_t, conn) = fresh();
        let err = validate_rpc_sql(&conn, "DELETE FROM posts", RpcMode::Read).unwrap_err();
        matches!(err, PrepareError::Rejected(_));
    }

    #[test]
    fn attach_rejected() {
        let (_t, conn) = fresh();
        let err = validate_rpc_sql(&conn, "ATTACH 'other.db' AS x", RpcMode::Read).unwrap_err();
        matches!(err, PrepareError::Rejected(_));
    }

    #[test]
    fn sqlite_master_rejected() {
        let (_t, conn) = fresh();
        let err =
            validate_rpc_sql(&conn, "SELECT * FROM sqlite_master", RpcMode::Read).unwrap_err();
        matches!(err, PrepareError::Rejected(_));
    }

    #[test]
    fn unknown_table_rejected() {
        let (_t, conn) = fresh();
        let err = validate_rpc_sql(&conn, "SELECT * FROM nope", RpcMode::Read).unwrap_err();
        matches!(err, PrepareError::Rejected(_));
    }

    #[test]
    fn system_rpc_rejected() {
        let (_t, conn) = fresh();
        let err = validate_rpc_sql(&conn, "SELECT * FROM _system_rpc", RpcMode::Read).unwrap_err();
        matches!(err, PrepareError::Rejected(_));
    }

    #[test]
    fn empty_body_rejected() {
        let (_t, conn) = fresh();
        let err = validate_rpc_sql(&conn, "", RpcMode::Read).unwrap_err();
        matches!(err, PrepareError::Rejected(_));
        let err = validate_rpc_sql(&conn, "   \n\t  ", RpcMode::Read).unwrap_err();
        matches!(err, PrepareError::Rejected(_));
    }

    #[test]
    fn read_mode_does_not_leak_authorizer_on_success() {
        // After a successful read-mode validate, the next prepare should
        // not be authorizer-gated. We check by preparing a DDL — which
        // the read authorizer would Deny but a detached connection
        // accepts at prepare time (rusqlite returns Ok; step would fail
        // on a real readonly handle but this conn is a writer).
        let (_t, conn) = fresh();
        validate_rpc_sql(&conn, "SELECT id FROM posts", RpcMode::Read).unwrap();
        let r = conn.prepare("DROP TABLE posts");
        assert!(r.is_ok(), "authorizer leaked after success: {:?}", r.err());
    }

    #[test]
    fn read_mode_does_not_leak_authorizer_on_failure() {
        // Mirror of the success path: even if validate Rejects, the
        // detach in the body must run so the connection is clean for
        // the next user.
        let (_t, conn) = fresh();
        let _ = validate_rpc_sql(&conn, "UPDATE posts SET body = 'x'", RpcMode::Read).unwrap_err();
        let r = conn.prepare("DROP TABLE posts");
        assert!(r.is_ok(), "authorizer leaked after failure: {:?}", r.err());
    }
}
