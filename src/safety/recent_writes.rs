//! v1.26 — read helper for the `recent_writes` MCP tool. Queries
//! `meta_logs.sqlite` with a tenant filter and a write-ops filter,
//! returning a minimal projection.

use rusqlite::Connection;
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Serialize)]
pub struct RecentWrite {
    pub ts: String,
    pub op: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collection: Option<String>,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
}

const WRITE_OPS: &[&str] = &[
    "insert_record", "update_record", "delete_record",
    "create_collection", "drop_collection", "add_field", "drop_field",
    "create_index", "drop_index",
    "call_rpc",
];

/// Look up recent write-op audit entries for `tenant`. `limit` is
/// clamped to 1..=200. `collection` filters on the audit row's
/// `extra.collection` value when set. `since_ts` filters `ts > since_ts`
/// when set.
pub async fn query_recent(
    conn: &Arc<Mutex<Connection>>,
    tenant: &str,
    limit: u32,
    collection: Option<&str>,
    since_ts: Option<&str>,
) -> anyhow::Result<Vec<RecentWrite>> {
    let limit = limit.clamp(1, 200);
    let placeholders = WRITE_OPS
        .iter()
        .enumerate()
        .map(|(i, _)| format!("?{}", i + 4))
        .collect::<Vec<_>>()
        .join(",");
    let sql = format!(
        "SELECT ts, op, json_extract(extra, '$.collection') AS coll, status, error_code \
         FROM audit \
         WHERE tenant = ?1 \
           AND op IN ({placeholders}) \
           AND (?2 = '' OR ts > ?2) \
           AND (?3 = '' OR json_extract(extra, '$.collection') = ?3) \
         ORDER BY ts DESC \
         LIMIT ?{}",
        WRITE_OPS.len() + 4
    );
    let tenant = tenant.to_string();
    let since = since_ts.unwrap_or("").to_string();
    let collection = collection.unwrap_or("").to_string();
    let limit_i: i64 = limit as i64;
    let guard = conn.lock().await;
    let mut stmt = guard.prepare(&sql)?;
    let mut params: Vec<&dyn rusqlite::ToSql> = Vec::with_capacity(4 + WRITE_OPS.len());
    params.push(&tenant);
    params.push(&since);
    params.push(&collection);
    for op in WRITE_OPS {
        params.push(op);
    }
    params.push(&limit_i);
    let rows = stmt.query_map(params.as_slice(), |r| {
        Ok(RecentWrite {
            ts: r.get(0)?,
            op: r.get(1)?,
            collection: r.get::<_, Option<String>>(2)?,
            status: r.get(3)?,
            error_code: r.get::<_, Option<String>>(4)?,
        })
    })?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::safety::audit_db::open_audit_db_memory;

    #[tokio::test]
    async fn query_compiles_and_runs_on_empty_db() {
        // Sanity: SQL prepares + executes, returns empty Vec on a fresh DB.
        let conn = open_audit_db_memory().unwrap();
        let arc = Arc::new(Mutex::new(conn));
        let rows = query_recent(&arc, "acme", 50, None, None).await.unwrap();
        assert!(rows.is_empty());
    }

    #[tokio::test]
    async fn limit_clamps_to_200() {
        // Indirect: ensure the function doesn't panic with limit=99999.
        let conn = open_audit_db_memory().unwrap();
        let arc = Arc::new(Mutex::new(conn));
        let rows = query_recent(&arc, "acme", 99999, None, None).await.unwrap();
        assert!(rows.is_empty());
    }
}
