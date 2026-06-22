//! Prepare-time SQL safety: reject anything the mode-matched authorizer
//! would deny, before persisting an RPC.

use crate::query::authorizer::{
    attach_readonly_authorizer, attach_writable_authorizer, detach_authorizer,
};
use crate::rpc::params::ParamSpec;
use crate::rpc::registry::RpcMode;
use rusqlite::Connection;
use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

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

/// Rejection sentinel for [`guard_anon_owner_scoped_rpc`]. Surfaced in the
/// `PrepareError::Rejected` message so callers (and tests) can pattern-match
/// the specific footgun rather than a generic prepare failure.
pub const RPC_ANON_OWNER_SCOPED: &str = "RPC_ANON_OWNER_SCOPED";

/// v1.41.3 — create-time guard against an anon-callable READ RPC whose body
/// SELECTs an owner-scoped collection without binding `:user_id`.
///
/// Unlike `/list` and `/search`, drust does NOT rewrite stored-RPC SQL, so no
/// owner row-filter is injected at call time. An anon-callable read RPC that
/// reads an owner-scoped collection therefore returns EVERY user's rows to an
/// anonymous caller — a cross-user leak that looks like a correct query. We
/// refuse it at create time.
///
/// Fires only for `mode == Read && anon_callable`. The escape hatch is a
/// declared `:user_id` param — the author is then expected to filter
/// `WHERE <owner> = :user_id` (auto-bound from `AuthCtx`), matching the
/// existing `anon_callable` + `:user_id` auto-bind contract. Service-only RPCs
/// (`anon_callable == false`) and bodies over non-owner-scoped collections pass
/// untouched.
///
/// Table discovery reuses the read-only authorizer surface: a capturing
/// authorizer records every `Read` table the prepared statement touches, then
/// each table's `owner_field` is probed. `sqlite_*` / protected (`_system_*`)
/// tables are skipped — they are never owner-scoped and are already denied by
/// the `validate_rpc_sql` pass that runs before this guard.
pub fn guard_anon_owner_scoped_rpc(
    conn: &Connection,
    sql: &str,
    params: &[ParamSpec],
    anon_callable: bool,
    mode: RpcMode,
) -> Result<(), PrepareError> {
    // Service-only RPCs and write RPCs cannot leak owner-scoped reads to anon.
    if mode != RpcMode::Read || !anon_callable {
        return Ok(());
    }
    // A declared :user_id param is the sanctioned owner-filter escape hatch.
    if params.iter().any(|p| p.name == "user_id") {
        return Ok(());
    }

    let stmts = match crate::rpc::exec_write::split_statements(sql) {
        Ok(s) => s,
        Err(e) => return Err(PrepareError::Rejected(e.message)),
    };

    // Collect every user-table the body reads under a capturing authorizer.
    let tables: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
    detach_authorizer(conn);
    for stmt in &stmts {
        let sink = Arc::clone(&tables);
        conn.authorizer(Some(move |ctx: AuthContext<'_>| -> Authorization {
            match ctx.action {
                AuthAction::Read { table_name, .. } => {
                    if !table_name.starts_with("sqlite_")
                        && !crate::storage::schema::is_protected_collection(table_name)
                    {
                        sink.lock().unwrap().insert(table_name.to_string());
                    }
                    Authorization::Allow
                }
                AuthAction::Select | AuthAction::Function { .. } | AuthAction::Recursive => {
                    Authorization::Allow
                }
                AuthAction::Pragma { pragma_name, .. } => match pragma_name {
                    "table_info" | "index_list" | "index_info" | "foreign_key_list"
                    | "table_xinfo" => Authorization::Allow,
                    _ => Authorization::Ignore,
                },
                _ => Authorization::Deny,
            }
        }))
        .expect("capturing authorizer must install");
        let prep = conn.prepare(stmt).map(|_| ());
        // Detach BEFORE propagating — never leak the capturing authorizer to
        // the connection's next user (same invariant validate_rpc_sql holds).
        detach_authorizer(conn);
        prep.map_err(|e| PrepareError::Rejected(format!("{e}")))?;
    }

    // Snapshot the captured set by value (no fail-open Arc::try_unwrap path).
    let referenced: Vec<String> = tables.lock().unwrap().iter().cloned().collect();
    for table in &referenced {
        let (owner_field, _scope) = crate::storage::schema::read_owner_field(conn, table)
            .map_err(|e| PrepareError::Rejected(format!("owner_field probe failed: {e}")))?;
        if owner_field.is_some() {
            return Err(PrepareError::Rejected(format!(
                "{RPC_ANON_OWNER_SCOPED}: an anon-callable read RPC over owner-scoped \
                 collection '{table}' must bind :user_id, else it returns every user's rows; \
                 declare a :user_id param or set anon_callable=false"
            )));
        }
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
