//! v1.30 — mutation-RPC executor. Used by `src/rpc/handler.rs::call_rpc`
//! when the looked-up RPC has `mode = RpcMode::Write`. The caller is
//! responsible for the SAVEPOINT plumbing (raw conn.execute before
//! attach, after detach); this module only handles the inside of the
//! authorizer-guarded region.

use crate::query::executor::QueryResult;
use crate::rpc::params::BoundValue;
use rusqlite::Connection;
use std::collections::BTreeMap;
use std::ffi::CString;

/// Result of a single statement inside an RPC body.
#[derive(Debug, Default)]
pub struct StatementOutcome {
    /// QueryResult ONLY for SELECT or RETURNING (rows-returning). For
    /// pure INSERT/UPDATE/DELETE this is None and the handler emits
    /// `rows:[], column_names:[]` instead.
    pub rows: Option<QueryResult>,
    pub affected_rows: i64,
    /// Set on INSERT only (rusqlite::Connection::last_insert_rowid()).
    pub last_insert_rowid: Option<i64>,
}

/// Aggregate outcome returned from the executor closure to the handler.
#[derive(Debug)]
pub struct WriteRpcOutcome {
    /// QueryResult from the LAST statement that returned rows. None if
    /// no statement was SELECT-shaped.
    pub last_rows: Option<QueryResult>,
    /// Sum of affected_rows across all statements.
    pub affected_rows: i64,
    /// Set if any statement was an INSERT (most recent wins).
    pub last_insert_rowid: Option<i64>,
    pub statement_count: usize,
    pub dry_run: bool,
}

/// Error from a single statement, carrying its 1-based index for
/// human-readable error messages.
#[derive(Debug, thiserror::Error)]
#[error("statement {statement_index} failed: {message}")]
pub struct RpcStatementError {
    pub statement_index: usize,
    pub message: String,
    /// True when the failure was an authorizer denial (rusqlite surfaces
    /// "not authorized" / "prohibited" in the error message). Lets the
    /// handler emit INVALID_SQL_FOR_MODE instead of RPC_STATEMENT_FAILED.
    pub authorizer_denied: bool,
}

/// Split `sql` on `;` and validate each chunk with `sqlite3_complete`.
/// Returns Err when any chunk is partial (e.g. `--` comment containing
/// `;` would otherwise produce a partial chunk that fails to parse;
/// `sqlite3_complete` understands comments + string literals).
///
/// Spec §14 Q1 mandates this — a naive split on `;` would mis-handle
/// `-- foo;` and `'a;b'` literals.
pub fn split_statements(sql: &str) -> Result<Vec<String>, RpcStatementError> {
    let mut out = Vec::new();
    let mut current = String::new();
    for ch in sql.chars() {
        current.push(ch);
        if ch == ';' {
            let cstr = CString::new(current.as_str())
                .map_err(|e| RpcStatementError {
                    statement_index: out.len() + 1,
                    message: format!("statement contains NUL byte: {e}"),
                    authorizer_denied: false,
                })?;
            // SAFETY: sqlite3_complete reads the NUL-terminated string we own.
            let complete = unsafe {
                rusqlite::ffi::sqlite3_complete(cstr.as_ptr())
            };
            if complete != 0 {
                let trimmed = current.trim();
                if !trimmed.is_empty() {
                    out.push(trimmed.to_string());
                }
                current.clear();
            }
            // else: `;` was inside a comment or string literal — keep
            // accumulating until the chunk is complete.
        }
    }
    // Tail: any remaining non-empty buffer must itself be a complete
    // statement (RPC body without trailing `;`). `sqlite3_complete`
    // wants a terminator before it will call a buffer "complete", so
    // append one for the check only — the stored statement is what the
    // user wrote.
    let tail = current.trim();
    if !tail.is_empty() {
        let probe = format!("{tail};");
        let cstr = CString::new(probe).map_err(|e| RpcStatementError {
            statement_index: out.len() + 1,
            message: format!("statement contains NUL byte: {e}"),
            authorizer_denied: false,
        })?;
        let complete = unsafe {
            rusqlite::ffi::sqlite3_complete(cstr.as_ptr())
        };
        if complete == 0 {
            return Err(RpcStatementError {
                statement_index: out.len() + 1,
                message: format!("incomplete statement at end of body: {tail}"),
                authorizer_denied: false,
            });
        }
        out.push(tail.to_string());
    }
    Ok(out)
}

/// Execute a single statement with bound named params. Returns rows
/// when the statement has any (SELECT or RETURNING); otherwise
/// reports affected_rows + last_insert_rowid.
pub fn execute_one(
    conn: &Connection,
    sql: &str,
    binds: &BTreeMap<String, BoundValue>,
    statement_index: usize,
) -> Result<StatementOutcome, RpcStatementError> {
    // bind preparation mirrors execute_read_query_with_named_inner.
    let bound: Vec<(String, rusqlite::types::Value)> = binds
        .iter()
        .map(|(k, v)| (format!(":{k}"), v.to_sql()))
        .collect();
    let refs: Vec<(&str, &dyn rusqlite::ToSql)> = bound
        .iter()
        .map(|(k, v)| (k.as_str(), v as &dyn rusqlite::ToSql))
        .collect();

    let mut stmt = conn.prepare(sql).map_err(|e| classify(e, statement_index))?;
    let column_count = stmt.column_count();

    if column_count == 0 {
        // Pure mutation (no SELECT / RETURNING).
        let affected = stmt.execute(refs.as_slice())
            .map_err(|e| classify(e, statement_index))? as i64;
        let last_id = if sql.trim_start().to_ascii_uppercase().starts_with("INSERT") {
            Some(conn.last_insert_rowid())
        } else {
            None
        };
        Ok(StatementOutcome {
            rows: None,
            affected_rows: affected,
            last_insert_rowid: last_id,
        })
    } else {
        // Rows-returning (SELECT or RETURNING). C4 fills this in by mirroring
        // execute_read_query_with_named_inner (src/query/executor.rs).
        todo!("collect rows like execute_read_query_with_named_inner; \
               set affected_rows = rows.len() as i64, last_insert_rowid \
               = Some(conn.last_insert_rowid()) when sql starts with INSERT")
    }
}

fn classify(err: rusqlite::Error, statement_index: usize) -> RpcStatementError {
    let msg = err.to_string();
    let lc = msg.to_lowercase();
    let denied = lc.contains("authoriz") || lc.contains("not authorized") || lc.contains("prohibited");
    RpcStatementError {
        statement_index,
        message: msg,
        authorizer_denied: denied,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_single_statement_no_trailing_semicolon() {
        let r = split_statements("SELECT 1").unwrap();
        assert_eq!(r, vec!["SELECT 1".to_string()]);
    }

    #[test]
    fn split_two_statements() {
        let r = split_statements("INSERT INTO t VALUES (1); UPDATE t SET x = 2;").unwrap();
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn split_semicolon_in_string_literal_not_split() {
        let r = split_statements("INSERT INTO t VALUES ('a;b');").unwrap();
        assert_eq!(r.len(), 1);
        assert!(r[0].contains("'a;b'"));
    }

    #[test]
    fn split_semicolon_in_line_comment_not_split() {
        let r = split_statements("-- ;\nSELECT 1;").unwrap();
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn split_incomplete_trailing_chunk_errors() {
        // Unclosed string literal — `sqlite3_complete` is lexical (it
        // catches dangling strings/comments/triggers), not syntactic, so
        // probe with something the lexer rejects rather than a
        // syntactically wrong but lexically closed buffer like
        // "SELECT 1 FROM".
        let err = split_statements("SELECT 'unterminated").unwrap_err();
        assert!(err.message.contains("incomplete"));
    }
}
