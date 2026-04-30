use crate::mcp::server::DrustMcp;
use crate::query::authorizer::{attach_readonly_authorizer, detach_authorizer};
use crate::query::executor::{ExecError, execute_read_query};
use serde_json::json;

/// Wrap a string message in `rusqlite::Error::SqliteFailure` so its `Display`
/// renders the message verbatim. `rusqlite::Error::InvalidQuery` — the
/// obvious-looking variant — is wrong: its `Display` is hard-coded to
/// `"Query is not read-only"`, which surfaces as a confusing error for
/// every authorizer rejection (including things that ARE read-only, like
/// `SELECT * FROM sqlite_master`).
fn as_rusqlite_error(msg: String) -> rusqlite::Error {
    rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(1), Some(msg))
}

pub async fn query(s: &DrustMcp, sql: &str) -> anyhow::Result<serde_json::Value> {
    let pool = s.inner().pool.clone();
    let sql_owned = sql.to_string();
    let qr = pool
        .with_reader(move |c| {
            execute_read_query(c, &sql_owned, 10_000, 16_384).map_err(|e| match e {
                ExecError::TooLarge { bytes, limit } => {
                    as_rusqlite_error(format!("query too large: {bytes} bytes (limit {limit})"))
                }
                ExecError::Timeout(ms) => {
                    as_rusqlite_error(format!("query timed out after {ms}ms"))
                }
                ExecError::Sql(msg) => as_rusqlite_error(format!("query error: {msg}")),
                ExecError::Forbidden(detail) => {
                    let low = detail.to_lowercase();
                    let msg = if low.contains("sqlite_master")
                        || low.contains("sqlite_temp_master")
                        || low.contains("sqlite_schema")
                    {
                        format!(
                            "access to SQLite metadata tables is denied — use \
                             `list_collections` or `describe_collection` to inspect \
                             schema (underlying: {detail})"
                        )
                    } else {
                        format!(
                            "`query` is read-only — use `insert_record` / \
                             `update_record` / `delete_record` for row writes, or \
                             `create_collection` / `drop_collection` / `add_field` / \
                             `drop_field` for schema changes (underlying: {detail})"
                        )
                    };
                    as_rusqlite_error(msg)
                }
            })
        })
        .await?;
    Ok(serde_json::to_value(qr)?)
}

pub async fn explain(s: &DrustMcp, sql: &str, _analyze: bool) -> anyhow::Result<serde_json::Value> {
    let pool = s.inner().pool.clone();
    let sql_owned = sql.to_string();
    let plan: String = pool
        .with_reader(move |c| -> rusqlite::Result<String> {
            attach_readonly_authorizer(c);
            let explain_sql = format!("EXPLAIN QUERY PLAN {sql_owned}");
            let result = (|| -> rusqlite::Result<String> {
                let mut stmt = c.prepare(&explain_sql)?;
                let lines: Vec<String> = stmt
                    .query_map([], |r| {
                        let detail: String = r.get(3)?;
                        Ok(detail)
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(lines.join("\n"))
            })();
            detach_authorizer(c);
            result
        })
        .await?;
    Ok(json!({ "plan": plan }))
}
