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

fn classify(err: rusqlite::Error) -> ExecError {
    let msg = err.to_string().to_lowercase();
    if msg.contains("authoriz") || msg.contains("not authorized") {
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
