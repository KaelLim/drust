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
    bus: &crate::tenant::events::EventBus,
    tenant: &str,
) -> anyhow::Result<serde_json::Value> {
    // null / empty field => clear ownership (absorbs the old clear_owner_field tool).
    let field = field
        .map(|f| f.trim().to_string())
        .filter(|f| !f.is_empty());
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
        // v1.41.3 defense-in-depth: refuse to make this collection owner-scoped
        // while an existing anon-callable RPC reads it without :user_id — the
        // create/update guard never re-runs on this config change, so the toggle
        // would otherwise silently turn that RPC into a cross-user leak. Runs
        // before the write (this path is autocommit), so a rejection leaves the
        // owner-scope config unchanged.
        crate::rpc::prepare::guard_owner_scope_change_against_anon_rpcs(c, &coll_for_set).map_err(
            |e| rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(1), Some(e.to_string())),
        )?;
        crate::storage::schema::set_owner_field(
            c,
            &coll_for_set,
            Some(&field_for_set),
            Some(&scope_for_set),
        )
    })
    .await
    .map_err(|e| anyhow::anyhow!("{e}"))?;
    pool.schema_cache.invalidate(&collection);
    // audit3 F3 — owner-scoping RESTRICTS anon read (anon can no longer subscribe
    // to an owner-scoped collection), so drop any in-flight anon SSE subscriber
    // that connected before this change — mirrors set_anon_caps / set_policy.
    bus.evict_collection(tenant, &collection);
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
    if (allow_user.is_some() || allow_anon.is_some())
        && let Some(cache) = auth_cache
    {
        cache.clear_tenant(&tid);
    }
    Ok(json!({
        "allow_user_publish": u != 0,
        "allow_anon_publish": a != 0,
    }))
}

// ─── set_file_caps (v1.42) ───────────────────────────────────────────────────

/// Update one or both of `tenants.{file_anon_caps_json, file_user_caps_json}`.
/// Each argument is the FULL desired cap set (replace, not merge); `None` leaves
/// that role's caps untouched. Caps are a subset of {read,list,upload,delete};
/// empty = service-only for that role (the default for every tenant). make-public
/// (set-visibility) stays service-only and is NOT a cap verb. Returns both
/// effective sets after the update.
///
/// v1.35 hook 12 (MCP face) — file caps gate request handling on the hot path
/// (like publish policy), so a change must drop the tenant's cached auth entries
/// or stale caps would serve for up to the safety TTL.
pub async fn set_file_caps(
    meta: &std::sync::Arc<Mutex<Connection>>,
    tenant_id: &str,
    anon: Option<Vec<crate::storage::schema::FileVerb>>,
    user: Option<Vec<crate::storage::schema::FileVerb>>,
    auth_cache: Option<&crate::tenant::auth_cache::AuthCache>,
) -> anyhow::Result<serde_json::Value> {
    use crate::storage::schema::file_caps_to_json;
    let tid = tenant_id.to_string();
    let conn = meta.lock().await;
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
    if let Some(v) = &anon {
        let json = file_caps_to_json(&v.iter().copied().collect());
        conn.execute(
            "UPDATE tenants SET file_anon_caps_json = ?1 WHERE id = ?2",
            rusqlite::params![json, tid],
        )
        .map_err(|e| anyhow::anyhow!("DB: {e}"))?;
    }
    if let Some(v) = &user {
        let json = file_caps_to_json(&v.iter().copied().collect());
        conn.execute(
            "UPDATE tenants SET file_user_caps_json = ?1 WHERE id = ?2",
            rusqlite::params![json, tid],
        )
        .map_err(|e| anyhow::anyhow!("DB: {e}"))?;
    }
    let (anon_json, user_json): (String, String) = conn
        .query_row(
            "SELECT COALESCE(file_anon_caps_json, '[]'), COALESCE(file_user_caps_json, '[]') \
             FROM tenants WHERE id = ?1",
            rusqlite::params![tid],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(|e| anyhow::anyhow!("DB: {e}"))?;
    // v1.35 hook 12 — UPDATEs committed; drop cached entries so the next request
    // refills with the new caps. Skipped when neither arg supplied (no change).
    if (anon.is_some() || user.is_some())
        && let Some(cache) = auth_cache
    {
        cache.clear_tenant(&tid);
    }
    Ok(json!({
        "file_anon_caps": serde_json::from_str::<serde_json::Value>(&anon_json).unwrap_or_else(|_| json!([])),
        "file_user_caps": serde_json::from_str::<serde_json::Value>(&user_json).unwrap_or_else(|_| json!([])),
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
