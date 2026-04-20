use rusqlite::Connection;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum QuotaError {
    #[error("database file size {current_bytes}B exceeds quota of {limit_mb} MB")]
    FileSize { current_bytes: u64, limit_mb: u64 },
    #[error("row count {current} exceeds quota of {limit}")]
    RowCount { current: i64, limit: i64 },
    #[error("quota io: {0}")]
    Io(#[from] std::io::Error),
    #[error("quota sql: {0}")]
    Sql(#[from] rusqlite::Error),
}

pub fn check_file_size(path: &Path, limit_mb: u64) -> Result<(), QuotaError> {
    let meta = std::fs::metadata(path)?;
    let size = meta.len();
    let limit = limit_mb.saturating_mul(1_048_576);
    if size > limit {
        return Err(QuotaError::FileSize { current_bytes: size, limit_mb });
    }
    Ok(())
}

pub fn check_row_count(conn: &Connection, limit: i64) -> Result<(), QuotaError> {
    let total: i64 = conn.query_row(
        "SELECT IFNULL(SUM(cnt), 0) FROM (
            SELECT (SELECT COUNT(*) FROM \"' || m.name || '\") AS cnt
            FROM sqlite_master m
            WHERE m.type='table' AND m.name NOT LIKE 'sqlite_%'
         )",
        [],
        |_| Ok(0i64),
    )
    .or_else(|_| -> Result<i64, rusqlite::Error> {
        // The dynamic-name trick above is awkward in SQL; do it in Rust instead.
        let mut stmt = conn.prepare(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
        )?;
        let names: Vec<String> = stmt
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<Result<_, _>>()?;
        let mut total = 0i64;
        for n in names {
            let sql = format!("SELECT COUNT(*) FROM \"{}\"", n.replace('"', "\"\""));
            let c: i64 = conn.query_row(&sql, [], |r| r.get(0))?;
            total += c;
        }
        Ok(total)
    })?;
    if total > limit {
        return Err(QuotaError::RowCount { current: total, limit });
    }
    Ok(())
}
