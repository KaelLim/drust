use rusqlite::{Connection, types::ValueRef};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
use thiserror::Error;

#[derive(Debug, Serialize)]
pub struct QueryResult {
    pub column_names: Vec<String>,
    pub column_types: Vec<String>,
    pub rows: Vec<Vec<serde_json::Value>>,
    pub truncated: bool,
    pub sql_hash: String,
}

#[derive(Debug, Error)]
pub enum ExecError {
    #[error("query too large: {bytes} bytes (limit {limit})")]
    TooLarge { bytes: usize, limit: usize },
    #[error("query forbidden by authorizer: {0}")]
    Forbidden(String),
    #[error("query timed out after {0}ms")]
    Timeout(u64),
    #[error("query error: {0}")]
    Sql(String),
}

pub fn sql_hash(sql: &str) -> String {
    let d = Sha256::digest(sql.as_bytes());
    let mut s = String::with_capacity(71);
    s.push_str("sha256:");
    for b in d {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn value_to_json(v: ValueRef<'_>) -> serde_json::Value {
    match v {
        ValueRef::Null => serde_json::Value::Null,
        ValueRef::Integer(i) => serde_json::json!(i),
        ValueRef::Real(f) => serde_json::json!(f),
        ValueRef::Text(t) => serde_json::Value::String(String::from_utf8_lossy(t).into_owned()),
        ValueRef::Blob(b) => serde_json::json!({ "__blob_bytes": b.len() }),
    }
}

fn type_name(v: ValueRef<'_>) -> String {
    match v {
        ValueRef::Null => "null".into(),
        ValueRef::Integer(_) => "integer".into(),
        ValueRef::Real(_) => "real".into(),
        ValueRef::Text(_) => "text".into(),
        ValueRef::Blob(_) => "blob".into(),
    }
}

pub fn execute_read_query(
    conn: &Connection,
    sql: &str,
    row_cap: usize,
    max_sql_bytes: usize,
) -> Result<QueryResult, ExecError> {
    if sql.len() > max_sql_bytes {
        return Err(ExecError::TooLarge {
            bytes: sql.len(),
            limit: max_sql_bytes,
        });
    }
    crate::query::authorizer::attach_readonly_authorizer(conn);
    let result = execute_read_query_inner(conn, sql, row_cap);
    crate::query::authorizer::detach_authorizer(conn);
    result
}

/// Like [`execute_read_query`] but skips the read-only authorizer. Only
/// call this from **admin-authenticated** code paths where restricting
/// `_system_*` table access is not required (e.g. the admin UI table
/// browser). The connection is still opened `SQLITE_OPEN_READONLY`, so
/// mutation is impossible regardless.
pub fn execute_read_query_admin(
    conn: &Connection,
    sql: &str,
    row_cap: usize,
    max_sql_bytes: usize,
) -> Result<QueryResult, ExecError> {
    if sql.len() > max_sql_bytes {
        return Err(ExecError::TooLarge {
            bytes: sql.len(),
            limit: max_sql_bytes,
        });
    }
    execute_read_query_inner(conn, sql, row_cap)
}

fn execute_read_query_inner(
    conn: &Connection,
    sql: &str,
    row_cap: usize,
) -> Result<QueryResult, ExecError> {
    let hash = sql_hash(sql);
    let mut stmt = conn.prepare(sql).map_err(classify)?;
    let column_names: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
    let col_count = column_names.len();

    let mut rows: Vec<Vec<serde_json::Value>> = Vec::new();
    let mut types: Vec<String> = vec!["null".into(); col_count];

    let mut rows_iter = stmt.query([]).map_err(classify)?;
    let mut truncated = false;
    while let Some(r) = rows_iter.next().map_err(classify)? {
        if rows.len() >= row_cap {
            truncated = true;
            break;
        }
        let mut row = Vec::with_capacity(col_count);
        for (i, col_type) in types.iter_mut().enumerate() {
            let v = r.get_ref(i).map_err(classify)?;
            if col_type == "null" {
                *col_type = type_name(v);
            }
            row.push(value_to_json(v));
        }
        rows.push(row);
    }

    Ok(QueryResult {
        column_names,
        column_types: types,
        rows,
        truncated,
        sql_hash: hash,
    })
}

/// Same as [`execute_read_query`] but binds `:name`-style placeholders from a
/// name → [`crate::rpc::params::BoundValue`] map. Used by the RPC handler so
/// stored RPC SQL can use named params.
///
/// Returns the same [`QueryResult`] envelope; the read-only authorizer is
/// attached for the duration of the call.
pub fn execute_read_query_with_named(
    conn: &Connection,
    sql: &str,
    binds: &std::collections::BTreeMap<String, crate::rpc::params::BoundValue>,
    row_cap: usize,
    max_sql_bytes: usize,
) -> Result<QueryResult, ExecError> {
    if sql.len() > max_sql_bytes {
        return Err(ExecError::TooLarge {
            bytes: sql.len(),
            limit: max_sql_bytes,
        });
    }
    crate::query::authorizer::attach_readonly_authorizer(conn);
    let result = execute_read_query_with_named_inner(conn, sql, binds, row_cap);
    crate::query::authorizer::detach_authorizer(conn);
    result
}

fn execute_read_query_with_named_inner(
    conn: &Connection,
    sql: &str,
    binds: &std::collections::BTreeMap<String, crate::rpc::params::BoundValue>,
    row_cap: usize,
) -> Result<QueryResult, ExecError> {
    let hash = sql_hash(sql);
    let mut stmt = conn.prepare(sql).map_err(classify)?;
    let column_names: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
    let col_count = column_names.len();

    // rusqlite's named-binding API expects param names to include the
    // leading ':' prefix. Materialise to owned `Value`s first so we can
    // hand out borrowed `&dyn ToSql` refs in a parallel vector.
    let bound: Vec<(String, rusqlite::types::Value)> = binds
        .iter()
        .map(|(k, v)| (format!(":{k}"), v.to_sql()))
        .collect();
    let refs: Vec<(&str, &dyn rusqlite::ToSql)> = bound
        .iter()
        .map(|(k, v)| (k.as_str(), v as &dyn rusqlite::ToSql))
        .collect();

    let mut rows: Vec<Vec<serde_json::Value>> = Vec::new();
    let mut types: Vec<String> = vec!["null".into(); col_count];

    let mut rows_iter = stmt.query(refs.as_slice()).map_err(classify)?;
    let mut truncated = false;
    // TODO: factor row-collection helper — duplicate of execute_read_query_inner
    // body below. Kept inline to dodge borrow-checker headaches around the
    // borrowed `Rows<'_>` owning a borrow of `stmt`.
    while let Some(r) = rows_iter.next().map_err(classify)? {
        if rows.len() >= row_cap {
            truncated = true;
            break;
        }
        let mut row = Vec::with_capacity(col_count);
        for (i, col_type) in types.iter_mut().enumerate() {
            let v = r.get_ref(i).map_err(classify)?;
            if col_type == "null" {
                *col_type = type_name(v);
            }
            row.push(value_to_json(v));
        }
        rows.push(row);
    }

    Ok(QueryResult {
        column_names,
        column_types: types,
        rows,
        truncated,
        sql_hash: hash,
    })
}

fn classify(err: rusqlite::Error) -> ExecError {
    let msg = err.to_string().to_lowercase();
    // drust's authorizer surfaces its own "prohibited" phrasing (see
    // `src/query/authorizer.rs`); rusqlite's authorizer-reject uses "not
    // authorized". Accept both plus any message that references the
    // sqlite_master family (those are always authorizer hits).
    if msg.contains("authoriz")
        || msg.contains("not authorized")
        || msg.contains("prohibited")
        || msg.contains("sqlite_master")
        || msg.contains("sqlite_temp_master")
        || msg.contains("sqlite_schema")
    {
        return ExecError::Forbidden(err.to_string());
    }
    ExecError::Sql(err.to_string())
}

/// Spawn a task that interrupts the connection if a deadline passes.
/// Caller drops the returned guard to cancel. This is used in the axum
/// handler where the `conn` is moved into `spawn_blocking`.
pub struct InterruptGuard {
    cancel: tokio::sync::oneshot::Sender<()>,
}

impl InterruptGuard {
    pub fn arm(handle: rusqlite::InterruptHandle, timeout: Duration) -> Self {
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            tokio::select! {
                _ = tokio::time::sleep(timeout) => handle.interrupt(),
                _ = rx => {}
            }
        });
        Self { cancel: tx }
    }
    pub fn disarm(self) {
        let _ = self.cancel.send(());
    }
}

#[allow(dead_code)]
fn _unused_timing() -> Instant {
    Instant::now()
}

#[cfg(test)]
mod named_tests {
    use super::*;
    use crate::storage::tenant_db::open_write;
    use std::collections::BTreeMap;
    use tempfile::TempDir;

    #[test]
    fn named_params_filter_correctly() {
        let tmp = TempDir::new().unwrap();
        let _conn = open_write(tmp.path(), "namedtest").unwrap();
        conn_setup_data(&_conn);

        // Open a separate read connection on the same DB. Path:
        // <tmp>/tenants/namedtest/data.sqlite (matches open_write layout).
        let read = rusqlite::Connection::open_with_flags(
            tmp.path()
                .join("tenants")
                .join("namedtest")
                .join("data.sqlite"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();

        let mut binds = BTreeMap::new();
        binds.insert("min".into(), crate::rpc::params::BoundValue::Int(2));
        let qr = execute_read_query_with_named(
            &read,
            "SELECT id, body FROM posts WHERE n >= :min ORDER BY n",
            &binds,
            100,
            32_768,
        )
        .unwrap();
        assert_eq!(qr.rows.len(), 2);
    }

    fn conn_setup_data(conn: &rusqlite::Connection) {
        conn.execute_batch(
            "CREATE TABLE posts (id INTEGER PRIMARY KEY, body TEXT, n INTEGER);
             INSERT INTO posts (body, n) VALUES ('a', 1), ('b', 2), ('c', 3);",
        )
        .unwrap();
    }
}
