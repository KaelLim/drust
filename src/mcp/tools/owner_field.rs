//! Pure async helpers for T25 MCP owner-field + set_self_register tools.

use crate::storage::pool::SharedTenantPool;
use rusqlite::Connection;
use serde_json::json;
use tokio::sync::Mutex;

// ─── set_owner_field ─────────────────────────────────────────────────────────

/// Validate then persist the owner-field for `collection`.
/// Mirrors the validation in `src/tenant/owner_field.rs::validate_owner_column`.
pub async fn set_owner_field(
    pool: &SharedTenantPool,
    collection: String,
    field: String,
    read_scope: String,
) -> anyhow::Result<serde_json::Value> {
    if read_scope != "own" && read_scope != "all" {
        anyhow::bail!("INVALID_READ_SCOPE: read_scope must be 'own' or 'all'");
    }

    // v1.20 TOCTOU fix: fold the existence + FK validation AND the write into a
    // single writer closure so a concurrent drop_collection between the two
    // cannot leave an orphan _system_collection_meta row.
    let pool = pool.clone();
    let coll_for_set = collection.clone();
    let field_for_set = field.clone();
    let scope_for_set = read_scope.clone();
    pool.with_writer(move |c| {
        // 1) Check collection exists.
        let tbl_count: i64 = c.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
            rusqlite::params![coll_for_set],
            |r| r.get(0),
        )?;
        if tbl_count == 0 {
            return Err(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(1),
                Some(format!("COLLECTION_NOT_FOUND: {coll_for_set}")),
            ));
        }
        // 2) Validate the column + FK inside the writer (PRAGMAs are read-only).
        let validation = validate_owner_column(c, &coll_for_set, &field_for_set)?;
        if let Err(code) = validation {
            return Err(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(1),
                Some(code.to_string()),
            ));
        }
        // 3) Persist.
        crate::storage::schema::set_owner_field(
            c,
            &coll_for_set,
            Some(&field_for_set),
            Some(&scope_for_set),
        )
    })
    .await
    .map_err(|e| {
        let msg = e.to_string();
        anyhow::anyhow!("{msg}")
    })?;
    pool.schema_cache.invalidate(&collection);

    Ok(json!({"owner_field": field, "read_scope": read_scope}))
}

// ─── clear_owner_field ───────────────────────────────────────────────────────

pub async fn clear_owner_field(
    pool: &SharedTenantPool,
    collection: String,
) -> anyhow::Result<serde_json::Value> {
    let pool = pool.clone();
    let coll_for_clear = collection.clone();
    pool.with_writer(move |c| {
        crate::storage::schema::set_owner_field(c, &coll_for_clear, None, None)
    })
    .await
    .map_err(|e| anyhow::anyhow!("DB_ERROR: {e}"))?;
    pool.schema_cache.invalidate(&collection);
    Ok(json!({"cleared": true}))
}

// ─── set_self_register ───────────────────────────────────────────────────────

/// Update `tenants.allow_self_register` for this tenant in meta.sqlite.
pub async fn set_self_register(
    meta: &std::sync::Arc<Mutex<Connection>>,
    tenant_id: &str,
    enabled: bool,
) -> anyhow::Result<serde_json::Value> {
    let value = if enabled { 1i64 } else { 0i64 };
    let tid = tenant_id.to_string();
    let conn = meta.lock().await;
    let n = conn
        .execute(
            "UPDATE tenants SET allow_self_register = ?1 WHERE id = ?2",
            rusqlite::params![value, tid],
        )
        .map_err(|e| anyhow::anyhow!("DB: {e}"))?;
    if n == 0 {
        anyhow::bail!("NOT_FOUND: tenant not found");
    }
    Ok(json!({"allow_self_register": enabled}))
}

// ─── validation helper (same logic as owner_field.rs) ────────────────────────

fn validate_owner_column(
    conn: &Connection,
    table: &str,
    field: &str,
) -> rusqlite::Result<Result<(), &'static str>> {
    // 1) Column exists?
    let cols: Vec<String> = conn
        .prepare(&format!(
            "PRAGMA table_info(\"{}\")",
            table.replace('"', "\"\"")
        ))?
        .query_map([], |r| r.get::<_, String>(1))?
        .filter_map(Result::ok)
        .collect();
    if !cols.iter().any(|c| c == field) {
        return Ok(Err("OWNER_FIELD_INVALID_COLUMN"));
    }
    // 2) FK to _system_users(id)?
    let fks: Vec<(String, String, String)> = conn
        .prepare(&format!(
            "PRAGMA foreign_key_list(\"{}\")",
            table.replace('"', "\"\"")
        ))?
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(2)?, // referenced table
                r.get::<_, String>(3)?, // from column
                r.get::<_, String>(4)?, // to column
            ))
        })?
        .filter_map(Result::ok)
        .collect();
    let ok = fks
        .iter()
        .any(|(ref_t, from, to)| ref_t == "_system_users" && from == field && to == "id");
    if !ok {
        return Ok(Err("OWNER_FIELD_NOT_FK"));
    }
    Ok(Ok(()))
}
