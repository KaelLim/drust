use rusqlite::{Connection, types::ValueRef};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Serialize)]
pub struct QueryResult {
    pub column_names: Vec<String>,
    pub column_types: Vec<String>,
    pub rows: Vec<Vec<Cell>>,
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

/// A single result cell, buffered cheaply (no per-cell serde_json::Value tree).
/// Its `Serialize` impl MUST stay byte-identical to the legacy `value_to_json`
/// mapping (proven by the golden test): Null->null, Int->number, Real->number,
/// Text->JSON string, Blob->`{"__blob_bytes": <len>}`.
#[derive(Debug, Clone, PartialEq)]
pub enum Cell {
    Null,
    Int(i64),
    Real(f64),
    Text(String),
    Blob(usize),
}

impl serde::Serialize for Cell {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        match self {
            Cell::Null => s.serialize_none(),
            Cell::Int(i) => s.serialize_i64(*i),
            Cell::Real(f) => s.serialize_f64(*f),
            Cell::Text(t) => s.serialize_str(t),
            Cell::Blob(n) => {
                let mut m = s.serialize_map(Some(1))?;
                m.serialize_entry("__blob_bytes", n)?;
                m.end()
            }
        }
    }
}

impl Cell {
    /// Bridge to `serde_json::Value` for consumers that still manipulate cells
    /// as Values. MUST match the legacy `value_to_json` output exactly.
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            Cell::Null => serde_json::Value::Null,
            Cell::Int(i) => serde_json::json!(i),
            Cell::Real(f) => serde_json::json!(f),
            Cell::Text(t) => serde_json::Value::String(t.clone()),
            Cell::Blob(n) => serde_json::json!({ "__blob_bytes": n }),
        }
    }
}

/// Build a `Cell` from a borrowed `ValueRef` — replaces `value_to_json` at the
/// row-collection site. Same mapping; no intermediate Value.
pub(crate) fn value_to_cell(v: ValueRef<'_>) -> Cell {
    match v {
        ValueRef::Null => Cell::Null,
        ValueRef::Integer(i) => Cell::Int(i),
        ValueRef::Real(f) => Cell::Real(f),
        ValueRef::Text(t) => Cell::Text(String::from_utf8_lossy(t).into_owned()),
        ValueRef::Blob(b) => Cell::Blob(b.len()),
    }
}

pub(crate) fn type_name(v: ValueRef<'_>) -> String {
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

    let mut rows: Vec<Vec<Cell>> = Vec::new();
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
            row.push(value_to_cell(v));
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
    let mut stmt = conn.prepare_cached(sql).map_err(classify)?;
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

    let mut rows: Vec<Vec<Cell>> = Vec::new();
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
            row.push(value_to_cell(v));
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

#[cfg(test)]
mod o2_golden {
    use super::*;

    fn golden_rows() -> Vec<Vec<Cell>> {
        vec![
            vec![Cell::Null, Cell::Int(0), Cell::Real(1.5)],
            vec![
                Cell::Text("plain".into()),
                Cell::Text("ctrl\u{0001}\ttab\nnl\"quote\\back".into()),
                Cell::Text("unicode-\u{2028}\u{2029}-\u{1F600}".into()),
            ],
            vec![Cell::Blob(42), Cell::Int(-9223372036854775808), Cell::Real(-0.0)],
        ]
    }
    fn old_json(rows: &[Vec<Cell>]) -> String {
        let v: Vec<Vec<serde_json::Value>> = rows
            .iter()
            .map(|r| {
                r.iter()
                    .map(|c| match c {
                        Cell::Null => serde_json::Value::Null,
                        Cell::Int(i) => serde_json::json!(i),
                        Cell::Real(f) => serde_json::json!(f),
                        Cell::Text(t) => serde_json::Value::String(t.clone()),
                        Cell::Blob(n) => serde_json::json!({ "__blob_bytes": n }),
                    })
                    .collect()
            })
            .collect();
        serde_json::to_string(&v).unwrap()
    }
    #[test]
    fn cell_serialize_is_byte_identical_to_value_to_json() {
        let rows = golden_rows();
        let new_json = serde_json::to_string(&rows).unwrap(); // via Cell::Serialize
        assert_eq!(new_json, old_json(&rows));
    }
    #[test]
    fn cell_to_json_matches_value_mapping() {
        for r in golden_rows() {
            for c in r {
                // round-trip through to_json must serialize identically too
                assert_eq!(
                    serde_json::to_string(&c).unwrap(),
                    serde_json::to_string(&c.to_json()).unwrap()
                );
            }
        }
    }
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

    #[test]
    fn cached_stmt_reprepares_after_schema_change() {
        let tmp = TempDir::new().unwrap();
        let _conn = open_write(tmp.path(), "cachetest").unwrap();
        _conn.execute_batch(
            "CREATE TABLE posts (id INTEGER PRIMARY KEY, body TEXT, n INTEGER);
             INSERT INTO posts (body, n) VALUES ('a', 1), ('b', 2);",
        )
        .unwrap();

        let dbpath = tmp.path().join("tenants").join("cachetest").join("data.sqlite");
        let read = rusqlite::Connection::open_with_flags(
            &dbpath,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();

        let binds = std::collections::BTreeMap::new();
        // First call: prepares and caches `SELECT count(*) ...`.
        let q1 = execute_read_query_with_named(
            &read, "SELECT count(*) AS c FROM posts", &binds, 100, 32_768,
        )
        .unwrap();
        assert_eq!(q1.rows[0][0], Cell::Int(2));

        // Mutate schema + data on the writer, then re-run the SAME sql through
        // the SAME read connection (its cache now holds the old statement).
        _conn.execute_batch(
            "ALTER TABLE posts ADD COLUMN extra TEXT;
             INSERT INTO posts (body, n) VALUES ('c', 3);",
        )
        .unwrap();
        let q2 = execute_read_query_with_named(
            &read, "SELECT count(*) AS c FROM posts", &binds, 100, 32_768,
        )
        .unwrap();
        // Must reflect the new row count — NOT a stale cached 2.
        assert_eq!(q2.rows[0][0], Cell::Int(3));
    }

    fn conn_setup_data(conn: &rusqlite::Connection) {
        conn.execute_batch(
            "CREATE TABLE posts (id INTEGER PRIMARY KEY, body TEXT, n INTEGER);
             INSERT INTO posts (body, n) VALUES ('a', 1), ('b', 2), ('c', 3);",
        )
        .unwrap();
    }
}
