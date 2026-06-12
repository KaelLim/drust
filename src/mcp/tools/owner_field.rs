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
    field: Option<String>,
    read_scope: String,
) -> anyhow::Result<serde_json::Value> {
    // null / empty field => clear ownership (absorbs the old clear_owner_field tool).
    let field = field.map(|f| f.trim().to_string()).filter(|f| !f.is_empty());
    let Some(field) = field else {
        let pool = pool.clone();
        let coll_for_clear = collection.clone();
        pool.with_writer(move |c| {
            crate::storage::schema::set_owner_field(c, &coll_for_clear, None, None)
        })
        .await
        .map_err(|e| anyhow::anyhow!("DB_ERROR: {e}"))?;
        pool.schema_cache.invalidate(&collection);
        return Ok(json!({"cleared": true}));
    };

    if read_scope != "own" && read_scope != "all" {
        anyhow::bail!("INVALID_READ_SCOPE: read_scope must be 'own' or 'all'");
    }
    // v1.20 TOCTOU fix: fold existence + FK validation AND the write into a single
    // writer closure so a concurrent drop_collection cannot leave an orphan row.
    let pool = pool.clone();
    let coll_for_set = collection.clone();
    let field_for_set = field.clone();
    let scope_for_set = read_scope.clone();
    pool.with_writer(move |c| {
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
        let validation = validate_owner_column(c, &coll_for_set, &field_for_set)?;
        if let Err(code) = validation {
            return Err(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(1),
                Some(code.to_string()),
            ));
        }
        crate::storage::schema::set_owner_field(c, &coll_for_set, Some(&field_for_set), Some(&scope_for_set))
    })
    .await
    .map_err(|e| anyhow::anyhow!("{e}"))?;
    pool.schema_cache.invalidate(&collection);
    Ok(json!({"owner_field": field, "read_scope": read_scope}))
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

// ─── set_publish_policy (v1.32.5) ────────────────────────────────────────────

/// Update one or both of `tenants.{allow_user_publish, allow_anon_publish}`.
/// Either argument may be `None` to leave that flag untouched. Returns the
/// current state of both flags after the update.
///
/// MCP `broadcast` does NOT consult these flags — MCP dispatch is service-only
/// by construction. These flags only affect REST `POST /t/{tenant}/rooms/{room}`
/// and WS `op:publish` on `/t/{tenant}/realtime`.
///
/// v1.35 hook 11 (MCP face) — `auth_cache` is the same seam as the hooks 7/8
/// MCP tools: when a flag actually changes, every cached entry for this tenant
/// is dropped so the next request re-reads the new policy from the CTE
/// (otherwise cached `publish_*_allowed` values would serve the OLD policy
/// for up to the safety TTL).
pub async fn set_publish_policy(
    meta: &std::sync::Arc<Mutex<Connection>>,
    tenant_id: &str,
    allow_user: Option<bool>,
    allow_anon: Option<bool>,
    auth_cache: Option<&crate::tenant::auth_cache::AuthCache>,
) -> anyhow::Result<serde_json::Value> {
    let tid = tenant_id.to_string();
    let conn = meta.lock().await;
    // Verify tenant exists up-front so a no-op call still surfaces NOT_FOUND.
    let exists: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM tenants WHERE id = ?1 AND deleted_at IS NULL",
            rusqlite::params![tid],
            |r| r.get(0),
        )
        .map_err(|e| anyhow::anyhow!("DB: {e}"))?;
    if exists == 0 {
        anyhow::bail!("NOT_FOUND: tenant not found");
    }
    if let Some(v) = allow_user {
        conn.execute(
            "UPDATE tenants SET allow_user_publish = ?1 WHERE id = ?2",
            rusqlite::params![v as i64, tid],
        )
        .map_err(|e| anyhow::anyhow!("DB: {e}"))?;
    }
    if let Some(v) = allow_anon {
        conn.execute(
            "UPDATE tenants SET allow_anon_publish = ?1 WHERE id = ?2",
            rusqlite::params![v as i64, tid],
        )
        .map_err(|e| anyhow::anyhow!("DB: {e}"))?;
    }
    let (u, a): (i64, i64) = conn
        .query_row(
            "SELECT COALESCE(allow_user_publish, 0), COALESCE(allow_anon_publish, 0) \
             FROM tenants WHERE id = ?1",
            rusqlite::params![tid],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(|e| anyhow::anyhow!("DB: {e}"))?;
    // v1.35 hook 11 (MCP face) — the UPDATEs above committed; drop the
    // tenant's cached entries so the next request refills with the new
    // policy. Skipped when neither flag was supplied (no auth state changed).
    if allow_user.is_some() || allow_anon.is_some() {
        if let Some(cache) = auth_cache {
            cache.clear_tenant(&tid);
        }
    }
    Ok(json!({
        "allow_user_publish": u != 0,
        "allow_anon_publish": a != 0,
    }))
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
