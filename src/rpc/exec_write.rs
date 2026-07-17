//! v1.30 — mutation-RPC executor. Two layers:
//!
//! - [`split_statements`] + [`execute_one`] are the inner primitives used
//!   inside the authorizer-guarded region.
//! - [`run_write_rpc`] is the high-level helper: it acquires the per-tenant
//!   writer mutex via the pool and runs the entire 8-step SAVEPOINT-
//!   around-authorizer dance. Both `src/rpc/handler.rs::call_rpc` (REST)
//!   and `src/mgmt/rpc_admin.rs::rpc_test_run` (admin playground) call it
//!   so the two surfaces share the same execution path — no behavior
//!   drift, same audit/error shape.

use crate::query::executor::QueryResult;
use crate::rpc::params::BoundValue;
use crate::storage::pool::SharedTenantPool;
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
    /// v1.46 R8: true when the failure is a record-history `CaptureLimits`
    /// cap hit (not a per-statement SQL failure — the flush runs after the
    /// statement loop; `statement_index` then carries the count of
    /// statements that executed). Caller-remediable (batch the operation,
    /// raise the knob, or disable audit) and the savepoint was resolved
    /// cleanly, so callers map it to HTTP 409 `CAPTURE_LIMIT_EXCEEDED`,
    /// never the 500 `TX_COMMIT_FAILED` class.
    pub capture_limit_exceeded: bool,
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
            let cstr = CString::new(current.as_str()).map_err(|e| RpcStatementError {
                statement_index: out.len() + 1,
                message: format!("statement contains NUL byte: {e}"),
                authorizer_denied: false,
                capture_limit_exceeded: false,
            })?;
            // SAFETY: sqlite3_complete reads the NUL-terminated string we own.
            let complete = unsafe { rusqlite::ffi::sqlite3_complete(cstr.as_ptr()) };
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
            capture_limit_exceeded: false,
        })?;
        let complete = unsafe { rusqlite::ffi::sqlite3_complete(cstr.as_ptr()) };
        if complete == 0 {
            return Err(RpcStatementError {
                statement_index: out.len() + 1,
                message: format!("incomplete statement at end of body: {tail}"),
                authorizer_denied: false,
                capture_limit_exceeded: false,
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

    let mut stmt = conn
        .prepare(sql)
        .map_err(|e| classify(e, statement_index))?;
    let column_count = stmt.column_count();

    if column_count == 0 {
        // Pure mutation (no SELECT / RETURNING).
        let affected = stmt
            .execute(refs.as_slice())
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
        // Rows-returning (SELECT or RETURNING). Mirrors
        // execute_read_query_with_named_inner (src/query/executor.rs).
        let column_names: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
        let col_count = column_names.len();
        let mut rows: Vec<Vec<crate::query::executor::Cell>> = Vec::new();
        let mut types: Vec<String> = vec!["null".into(); col_count];
        let mut rows_iter = stmt
            .query(refs.as_slice())
            .map_err(|e| classify(e, statement_index))?;
        // codex full-scan F4: report `affected_rows` as the TRUE mutated count for a
        // rows-returning DML statement (`INSERT/UPDATE/DELETE ... RETURNING`), not
        // the capped returned-row count. Detection is EMPIRICAL — a delta in
        // `total_changes()` across the statement — so it is robust to CTE-prefixed
        // (`WITH … UPDATE … RETURNING`) and comment-prefixed DML that a keyword
        // prefix match would miss. A plain SELECT (no delta) keeps the old
        // cap-and-count behavior. `changes_before` is captured BEFORE the first
        // step (mutations run on `step`, not on `query()`).
        let upper = sql.trim_start().to_ascii_uppercase();
        let is_dml_prefix = upper.starts_with("INSERT")
            || upper.starts_with("UPDATE")
            || upper.starts_with("DELETE");
        let changes_before = conn.total_changes();
        let mut truncated = false;
        while let Some(r) = rows_iter.next().map_err(|e| classify(e, statement_index))? {
            if rows.len() >= 1_000 {
                truncated = true;
                // A likely-DML statement drains past the cap so every matching row
                // mutates (forward-defense: SQLite today applies all mutations on
                // the first step, but a future streaming impl must not lose rows);
                // a SELECT honors the response cap and stops reading. Over-draining
                // a CTE/comment-prefixed DML that this prefix misses is only a
                // missed forward-defense, never a wrong count (below is empirical).
                if is_dml_prefix {
                    continue;
                } else {
                    break;
                }
            }
            let mut row = Vec::with_capacity(col_count);
            for (i, col_type) in types.iter_mut().enumerate() {
                let v = r.get_ref(i).map_err(|e| classify(e, statement_index))?;
                if col_type == "null" {
                    *col_type = crate::query::executor::type_name(v);
                }
                row.push(crate::query::executor::value_to_cell(v));
            }
            rows.push(row);
        }
        // Drop the row iterator before reading connection-level counters.
        drop(rows_iter);
        // A statement that changed rows (total_changes advanced) reports the true
        // mutated count. The convergent `<coll>_updated_at` AFTER trigger's rows
        // ARE counted by total_changes but NOT by changes(), so changes() stays the
        // user-visible top-level count while total_changes only serves as the
        // did-it-mutate probe. A pure SELECT (no delta) reports the returned count.
        let affected_rows = if conn.total_changes() != changes_before {
            conn.changes() as i64
        } else {
            rows.len() as i64
        };
        let last_id = if upper.starts_with("INSERT") {
            Some(conn.last_insert_rowid())
        } else {
            None
        };
        Ok(StatementOutcome {
            rows: Some(QueryResult {
                column_names,
                column_types: types,
                rows,
                truncated,
                sql_hash: crate::query::executor::sql_hash(sql),
            }),
            affected_rows,
            last_insert_rowid: last_id,
        })
    }
}

fn classify(err: rusqlite::Error, statement_index: usize) -> RpcStatementError {
    let msg = err.to_string();
    let lc = msg.to_lowercase();
    // "not authorized" is a substring of "authoriz" + "ed" — keep the
    // two distinct phrasings the codepath actually emits (drust's
    // authorizer "prohibited" + sqlite's "not authorized") and let
    // "authoriz" catch the rest.
    let denied = lc.contains("authoriz") || lc.contains("prohibited");
    RpcStatementError {
        statement_index,
        message: msg,
        authorizer_denied: denied,
        capture_limit_exceeded: false,
    }
}

/// SAVEPOINT RELEASE failed after the authorizer was detached — the
/// connection's savepoint stack is the operator-visible problem; the
/// caller turns this into HTTP 500 / `TX_COMMIT_FAILED`.
#[derive(Debug, thiserror::Error)]
#[error("savepoint release failed: {0}")]
pub struct TxCommitError(pub String);

/// High-level helper: run a write-mode stored RPC. Acquires the
/// per-tenant writer mutex, then executes the 8-step ordering:
///
/// 1. defensive `detach_authorizer` (spec §14 Q4 — `with_writer` does
///    not auto-detach; previous closures may have leaked one).
///    1b. precompute the audited table set (v1.46 R2) while the
///    connection is still unrestricted — the writable authorizer denies
///    the `sqlite_master` / `_system_collection_meta` reads this needs.
///    Skipped on `dry_run` (always rolled back → nothing to audit).
/// 2. raw `SAVEPOINT drust_rpc_v2` (authorizer would Deny Savepoint).
/// 3. `attach_writable_authorizer` — from here every prepare is gated.
///    3b. install the scoped preupdate capture hook (v1.46 — record
///    history for arbitrary RPC SQL) ONLY when the audited set is
///    non-empty and not `dry_run` — audit off must cost zero buffering
///    (R2). The hook buffers bounded per-row old/new images
///    (`CaptureLimits` caps rows/bytes; BLOBs buffer as length only);
///    when installed it MUST be removed on every exit path below.
/// 4. split + execute loop. On split or execute_one failure we record
///    the error but DO NOT short-circuit step 5/6 — the savepoint must
///    be resolved cleanly.
///    4b. remove the preupdate hook if installed (success AND error
///    paths) — a leaked hook would capture unrelated later writes on
///    this pooled connection.
/// 5. MANDATORY `detach_authorizer` BEFORE step 6 (RELEASE would be
///    Denied otherwise).
///    5b. on the commit path only (no error, hook installed — which
///    implies not `dry_run`): flush the buffered changes into
///    `_system_record_history` INSIDE the still-open savepoint, so
///    history commits atomically with the mutation. Fail-closed: a
///    flush error (including a `CaptureLimits` cap exceeded in the
///    hook) rolls the whole RPC back. The failure class splits (v1.46
///    R8): a cap hit returns as `Ok(Err(RpcStatementError))` with
///    `capture_limit_exceeded: true` (caller-remediable → HTTP 409
///    `CAPTURE_LIMIT_EXCEEDED`); any other flush failure stays
///    `TxCommitError`. On the error / `dry_run` path the buffer is
///    simply dropped — and even if rows had been flushed, the
///    `ROLLBACK TO` in step 6 would discard them with the mutation
///    (same savepoint).
/// 6. `ROLLBACK TO` (if error or `dry_run`) then `RELEASE`.
/// 7. return outcome.
///
/// Return shape:
/// - `Ok(Ok(WriteRpcOutcome))` — every statement succeeded; on `dry_run`
///   the SAVEPOINT was rolled back but `outcome.dry_run == true`.
/// - `Ok(Err(RpcStatementError))` — one statement failed (split or
///   execute_one), or the record-history capture limit was exceeded
///   (`capture_limit_exceeded: true`, v1.46 R8). All effects were
///   rolled back.
/// - `Err(TxCommitError)` — `RELEASE drust_rpc_v2` itself failed; the
///   savepoint state is undefined and the operator needs to look.
///
/// Connection-level errors (writer mutex acquisition, raw SAVEPOINT
/// command fail) surface as the inner `rusqlite::Result::Err` from
/// `pool.with_writer`; we re-wrap them as `TxCommitError` so callers
/// only deal with three arms.
pub async fn run_write_rpc(
    pool: &SharedTenantPool,
    stored_sql: String,
    bound: BTreeMap<String, BoundValue>,
    dry_run: bool,
    actor: crate::storage::record_history::AuditActor,
    limits: crate::storage::record_history::CaptureLimits,
) -> Result<Result<WriteRpcOutcome, RpcStatementError>, TxCommitError> {
    let res: rusqlite::Result<Result<Result<WriteRpcOutcome, RpcStatementError>, TxCommitError>> =
        pool.with_writer(move |conn| {
            // ── STEP 1: defensive detach. spec §14 Q4 confirms
            //    with_writer does NOT auto-detach. If any prior
            //    closure left an authorizer attached it would
            //    prevent step 2 (Savepoint is Denied).
            crate::query::authorizer::detach_authorizer(conn);

            // ── STEP 1b (v1.46 R2): precompute the audited table set
            //    while the connection is unrestricted (the writable
            //    authorizer denies sqlite_master/_system_* reads). The
            //    set cannot go stale mid-run: the authorizer denies
            //    writes to _system_collection_meta and all DDL.
            //    dry_run never flushes → skip capture entirely.
            //    Fail-closed: without the set the RPC must not run
            //    un-audited.
            let audited = if dry_run {
                std::collections::HashSet::new()
            } else {
                match crate::storage::record_history::audited_data_tables(conn) {
                    Ok(s) => s,
                    Err(e) => {
                        return Ok(Err(TxCommitError(format!(
                            "record-history audited-set precompute failed: {e}"
                        ))));
                    }
                }
            };

            // ── STEP 2: SAVEPOINT (raw, no authorizer). If this
            //    fails we have nothing to roll back; surface as
            //    TxCommitError so the caller's 500 path is uniform.
            if let Err(e) = conn.execute("SAVEPOINT drust_rpc_v2", []) {
                return Ok(Err(TxCommitError(e.to_string())));
            }

            // ── STEP 3: attach writable authorizer. From here,
            //    every conn.prepare is gated.
            crate::query::authorizer::attach_writable_authorizer(conn);

            // ── STEP 3b: install the scoped preupdate capture hook —
            //    ONLY when something can actually be captured (audited
            //    set non-empty; dry_run yields an empty set above).
            //    `None` = no hook installed; every later hook touchpoint
            //    (split-fail removal, STEP 4b, STEP 5b) is conditional
            //    on it. (Installing runs no SQL, so the authorizer is
            //    inert here.) Fail-closed: if the hook cannot be
            //    installed, the RPC must not run un-audited.
            let capture_buf = if audited.is_empty() {
                None
            } else {
                match crate::storage::record_history::install_preupdate_capture(
                    conn, audited, limits,
                ) {
                    Ok(b) => Some(b),
                    Err(e) => {
                        crate::query::authorizer::detach_authorizer(conn);
                        let _ = conn.execute("ROLLBACK TO drust_rpc_v2", []);
                        if let Err(rel) = conn.execute("RELEASE drust_rpc_v2", []) {
                            return Ok(Err(TxCommitError(rel.to_string())));
                        }
                        return Ok(Err(TxCommitError(format!(
                            "record-history hook install failed: {e}"
                        ))));
                    }
                }
            };

            // ── STEP 4: split + execute loop.
            let stmts = match split_statements(&stored_sql) {
                Ok(s) => s,
                Err(e) => {
                    // Split failed. Mirror the inline path: remove the
                    // capture hook (if installed), detach, ROLLBACK +
                    // RELEASE, return statement err.
                    if capture_buf.is_some() {
                        let _ = crate::storage::record_history::remove_preupdate_capture(conn);
                    }
                    crate::query::authorizer::detach_authorizer(conn);
                    let _ = conn.execute("ROLLBACK TO drust_rpc_v2", []);
                    if let Err(rel) = conn.execute("RELEASE drust_rpc_v2", []) {
                        return Ok(Err(TxCommitError(rel.to_string())));
                    }
                    return Ok(Ok(Err(e)));
                }
            };

            let mut last_rows: Option<QueryResult> = None;
            let mut combined_affected: i64 = 0;
            let mut last_insert_rowid: Option<i64> = None;
            let mut exec_error: Option<RpcStatementError> = None;
            let mut statement_count: usize = 0;

            // INVARIANT: execute_one MUST NOT panic. A panic here
            // would leave the writer connection with an open
            // SAVEPOINT drust_rpc_v2; tokio::sync::Mutex does not
            // poison and rusqlite::Connection's Drop only runs at
            // process exit, so the next request's STEP 2 would nest
            // a savepoint with the same name. The subsequent RELEASE
            // only releases the innermost — the leaked savepoint
            // would persist until process restart, holding any
            // pre-panic mutations in limbo. execute_one returns Err
            // on all known SQL-error paths; this invariant is
            // asserted by the `execute_one_never_panics_on_bad_sql`
            // test below.
            for (i, stmt) in stmts.iter().enumerate() {
                statement_count += 1;
                match execute_one(conn, stmt, &bound, i + 1) {
                    Ok(o) => {
                        if o.rows.is_some() {
                            last_rows = o.rows;
                        }
                        combined_affected += o.affected_rows;
                        if let Some(rid) = o.last_insert_rowid {
                            last_insert_rowid = Some(rid);
                        }
                    }
                    Err(e) => {
                        exec_error = Some(e);
                        break;
                    }
                }
            }

            // ── STEP 4b: remove the preupdate hook (when installed) —
            //    on EVERY path, BEFORE the flush and before savepoint
            //    resolution. Removal failure is fail-closed: roll
            //    everything back rather than leave a hook that captures
            //    later writes.
            if capture_buf.is_some()
                && let Err(e) = crate::storage::record_history::remove_preupdate_capture(conn)
            {
                crate::query::authorizer::detach_authorizer(conn);
                let _ = conn.execute("ROLLBACK TO drust_rpc_v2", []);
                if let Err(rel) = conn.execute("RELEASE drust_rpc_v2", []) {
                    return Ok(Err(TxCommitError(rel.to_string())));
                }
                return Ok(Err(TxCommitError(format!(
                    "record-history hook removal failed: {e}"
                ))));
            }

            // ── STEP 5: MANDATORY detach BEFORE savepoint resolution.
            crate::query::authorizer::detach_authorizer(conn);

            // ── STEP 5b: commit path only — flush buffered changes to
            //    `_system_record_history` INSIDE the still-open
            //    savepoint (authorizer already detached, so the
            //    `_system_` INSERTs are permitted). `capture_buf` is
            //    `Some` only when NOT dry_run, so the dry_run skip is
            //    by construction. On error the buffer is dropped;
            //    STEP 6's ROLLBACK TO would discard any flushed rows
            //    anyway (same savepoint). Fail-closed: flush failure
            //    (row-value read error OR a CaptureLimits cap
            //    exceeded) → roll the RPC back.
            if exec_error.is_none()
                && let Some(buf) = &capture_buf
                && let Err(e) = crate::storage::record_history::flush_captured(conn, buf, &actor)
            {
                let _ = conn.execute("ROLLBACK TO drust_rpc_v2", []);
                if let Err(rel) = conn.execute("RELEASE drust_rpc_v2", []) {
                    return Ok(Err(TxCommitError(rel.to_string())));
                }
                // v1.46 R8: split by remediation class. A CaptureLimits
                // cap hit is caller-remediable (batch the operation,
                // raise the knob, or disable audit) and the savepoint
                // was just resolved cleanly above — route it down the
                // statement-error channel (both callers map it to HTTP
                // 409 CAPTURE_LIMIT_EXCEEDED), never TxCommitError,
                // whose contract is "savepoint state undefined, operator
                // must look". Genuinely internal flush failures keep the
                // TxCommitError / 500 path.
                use crate::storage::record_history::FlushError;
                return match e {
                    FlushError::LimitExceeded(msg) => Ok(Ok(Err(RpcStatementError {
                        // Not a per-statement failure — the flush runs
                        // after the loop; carry the executed count.
                        statement_index: statement_count,
                        message: msg,
                        authorizer_denied: false,
                        capture_limit_exceeded: true,
                    }))),
                    FlushError::Db(db) => Ok(Err(TxCommitError(format!(
                        "record-history flush failed: {db}"
                    )))),
                };
            }

            // ── STEP 6: resolve savepoint.
            let should_rollback = exec_error.is_some() || dry_run;
            if should_rollback {
                let _ = conn.execute("ROLLBACK TO drust_rpc_v2", []);
            }
            if let Err(e) = conn.execute("RELEASE drust_rpc_v2", []) {
                return Ok(Err(TxCommitError(e.to_string())));
            }

            // ── STEP 7: return outcome.
            Ok(Ok(match exec_error {
                Some(e) => Err(e),
                None => Ok(WriteRpcOutcome {
                    last_rows,
                    affected_rows: combined_affected,
                    last_insert_rowid,
                    statement_count,
                    dry_run,
                }),
            }))
        })
        .await;

    match res {
        Ok(inner) => inner,
        Err(e) => Err(TxCommitError(e.to_string())),
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
    fn split_empty_body_returns_empty_vec() {
        let r = split_statements("").unwrap();
        assert!(r.is_empty(), "empty body must split to empty vec");
        let r = split_statements("   \n\t  ").unwrap();
        assert!(r.is_empty(), "whitespace-only body must split to empty vec");
    }

    #[test]
    fn execute_one_never_panics_on_bad_sql() {
        // C4 follow-up F2 — assert handler.rs's panic-free contract.
        // SQL-injection-shaped strings, malformed binds, etc. must return
        // Err, not panic. handler.rs:300-322 relies on this for
        // SAVEPOINT lifecycle safety (a panic mid-loop would leak the
        // savepoint until process restart).
        use crate::rpc::params::BoundValue;
        use std::collections::BTreeMap;
        let d = tempfile::tempdir().unwrap();
        let conn = crate::storage::tenant_db::open_write(d.path(), "t").unwrap();
        conn.execute_batch("CREATE TABLE t (x INTEGER);").unwrap();
        let binds: BTreeMap<String, BoundValue> = BTreeMap::new();
        for sql in [
            ";",                           // empty after semicolon strip
            "DROP TABLE t",                // DDL: prepare may succeed without authorizer
            "INSERT INTO nope VALUES (1)", // unknown table
            "SELECT ÿþ BAD",               // non-ASCII garbage
        ] {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                execute_one(&conn, sql, &binds, 1)
            }));
            assert!(result.is_ok(), "execute_one panicked on: {sql:?}");
        }
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
