//! v1.46 — MCP audit tools over the per-tenant record-history trail.
//!
//! `set_audit_enabled` toggles the per-collection capture gate (mirrors
//! `set_realtime`'s validation chain + writer-folded existence check, MINUS
//! the SSE evict — audit gates what is RECORDED, never what a subscriber may
//! SEE, so in-flight SSE connections are untouched). `get_record_history`
//! reads `_system_record_history` with the same SQL + row shape as the REST
//! `GET /t/<id>/collections/<coll>/history` handler. Both are service-only by
//! MCP dispatch (`/mcp` rejects anon/user bearers).

use crate::mcp::server::DrustMcp;
use crate::storage::schema::{collection_exists, is_protected_collection, write_audit_enabled};
use serde_json::json;

pub async fn set_audit_enabled(
    s: &DrustMcp,
    collection: &str,
    enabled: bool,
) -> anyhow::Result<serde_json::Value> {
    super::schema::identifier(collection)?;
    if is_protected_collection(collection) {
        anyhow::bail!(
            "refusing to set audit on system collection {collection:?} \
             (protected by _system_ prefix)"
        );
    }
    let pool = s.inner().pool.clone();
    let coll = collection.to_string();
    // Existence check folded inside the writer closure (same TOCTOU posture
    // as set_realtime): a concurrent drop_collection cannot leave an orphan
    // _system_collection_meta row.
    pool.with_writer(move |c| {
        if !collection_exists(c, &coll)? {
            return Err(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(1),
                Some(format!("COLLECTION_NOT_FOUND: {coll}")),
            ));
        }
        write_audit_enabled(c, &coll, enabled)
    })
    .await
    .map_err(|e| {
        let msg = e.to_string();
        if msg.contains("COLLECTION_NOT_FOUND") {
            anyhow::anyhow!(
                "unknown collection: {}",
                msg.split_once(": ").map(|x| x.1).unwrap_or(&msg)
            )
        } else {
            anyhow::anyhow!("{e}")
        }
    })?;
    // Refresh the cached CollectionSchema the REST write choke point reads.
    // NO `bus.evict_collection` here — unlike realtime/anon_caps, this flag
    // does not gate SSE row visibility.
    pool.schema_cache.invalidate(collection);
    Ok(json!({
        "ok": true,
        "collection": collection,
        "audit_enabled": enabled,
    }))
}

/// Service-only read over `_system_record_history` — same SQL + row shape as
/// the REST history endpoint (`{id, op, old, new, actor_kind, actor_id, ts}`,
/// id DESC / newest first, snapshots parsed back to JSON), with a single
/// `limit` knob (1..=200, default 50) instead of REST pagination.
pub async fn get_record_history(
    s: &DrustMcp,
    collection: &str,
    record_id: Option<i64>,
    limit: Option<u32>,
) -> anyhow::Result<serde_json::Value> {
    let limit = limit.unwrap_or(50).clamp(1, 200) as i64;
    let coll = collection.to_string();
    let (rows, total) = s
        .inner()
        .pool
        .with_reader(
            move |c| -> rusqlite::Result<(Vec<serde_json::Value>, i64)> {
                let mut where_sql = String::from("collection = ?");
                let mut binds: Vec<rusqlite::types::Value> =
                    vec![rusqlite::types::Value::Text(coll.clone())];
                if let Some(rid) = record_id {
                    where_sql.push_str(" AND record_id = ?");
                    binds.push(rusqlite::types::Value::Integer(rid));
                }
                let total: i64 = {
                    let refs: Vec<&dyn rusqlite::ToSql> =
                        binds.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
                    c.query_row(
                        &format!("SELECT COUNT(*) FROM _system_record_history WHERE {where_sql}"),
                        &refs[..],
                        |r| r.get(0),
                    )?
                };
                let sql = format!(
                    "SELECT id, op, old_json, new_json, actor_kind, actor_id, ts \
                     FROM _system_record_history WHERE {where_sql} \
                     ORDER BY id DESC LIMIT ?"
                );
                binds.push(rusqlite::types::Value::Integer(limit));
                let mut stmt = c.prepare(&sql)?;
                let refs: Vec<&dyn rusqlite::ToSql> =
                    binds.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
                let mut rows_iter = stmt.query(&refs[..])?;
                // Snapshots were stored via serde_json::Value::to_string, so
                // they parse back losslessly; a NULL column renders as null.
                let parse_snapshot = |s: Option<String>| -> serde_json::Value {
                    s.and_then(|x| serde_json::from_str(&x).ok())
                        .unwrap_or(serde_json::Value::Null)
                };
                let mut rows: Vec<serde_json::Value> = Vec::new();
                while let Some(r) = rows_iter.next()? {
                    rows.push(json!({
                        "id": r.get::<_, i64>(0)?,
                        "op": r.get::<_, String>(1)?,
                        "old": parse_snapshot(r.get::<_, Option<String>>(2)?),
                        "new": parse_snapshot(r.get::<_, Option<String>>(3)?),
                        "actor_kind": r.get::<_, String>(4)?,
                        "actor_id": r.get::<_, Option<String>>(5)?,
                        "ts": r.get::<_, String>(6)?,
                    }));
                }
                Ok((rows, total))
            },
        )
        .await?;
    Ok(json!({
        "collection": collection,
        "rows": rows,
        "total": total,
        "limit": limit,
    }))
}
