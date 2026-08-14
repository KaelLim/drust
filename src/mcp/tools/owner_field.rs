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
            // #950 — dropping owner_field WIDENS every anon-callable
            // query-kind RPC over this collection from a per-user grant to a
            // whole-table one. Refuse until the RPC is disarmed. Only a real
            // Some → None transition can widen anything, so an already-null
            // collection stays idempotently clearable. Before the write (this
            // path is autocommit).
            let (current, _scope) = crate::storage::schema::read_owner_field(c, &coll_for_clear)?;
            if current.is_some() {
                crate::rpc::prepare::guard_clear_against_anon_query_rpcs(
                    c,
                    &coll_for_clear,
                    "owner_field",
                )
                .map_err(|e| {
                    rusqlite::Error::SqliteFailure(
                        rusqlite::ffi::Error::new(1),
                        Some(e.to_string()),
                    )
                })?;
            }
            crate::storage::schema::set_owner_field(c, &coll_for_clear, None, None)
        })
        .await
        .map_err(|e| {
            // A guard rejection is a typed refusal, not a DB failure. Both
            // the `DB_ERROR:` prefix AND `PrepareError`'s own Display prefix
            // would bury the sentinel: `bail_mcp` reads everything before the
            // FIRST colon as `error_code`, so without this the wire code is
            // the prose prefix. Hoist the sentinel to the front.
            let msg = e.to_string();
            match msg.find(crate::rpc::prepare::RPC_QUERY_GRANT_ACTIVE) {
                Some(i) => anyhow::anyhow!("{}", &msg[i..]),
                None => anyhow::anyhow!("DB_ERROR: {msg}"),
            }
        })?;
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
        crate::rpc::prepare::guard_owner_scope_change_against_anon_rpcs(
            c,
            &coll_for_set,
            &field_for_set,
        )
        .map_err(|e| {
            rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(1), Some(e.to_string()))
        })?;
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
///
/// #955 — the SECOND obligation of this station, in lockstep with its REST
/// twin `mgmt::tenants::crud::patch_publish_policy`. A live rooms WS
/// connection captures its `TenantPublishPolicy` ONCE at upgrade and never
/// re-reads it, so a tenant turning `allow_anon_publish` off over
/// `/t/<id>/mcp` — the natural way to stop publish abuse — would otherwise
/// leave every existing socket publishing under the OLD flag until it
/// disconnected on its own. A call that MOVES the effective `(user, anon)`
/// pair therefore evicts `bus_rooms`, which bumps the eviction epoch and
/// closes each socket (`CONN_EVICTED` + Close 1008) at its next frame or
/// keepalive tick. A **no-op** call does NOT evict.
///
/// The evict lives HERE rather than in the `#[tool]` wrapper (where the #952
/// `delete_user` / `revoke_user_sessions` evicts sit) for ONE reason: it is
/// conditional on a pre-image only readable under the meta lock this fn holds.
/// The wrapper has no pre-image, so an evict there could only be
/// unconditional, and a no-op call would then thunder-herd the tenant.
///
/// It is NOT because a wrapper is untestable. Until the #955 T3 round-2 review,
/// this doc, `src/mcp/handler.rs` and `tests/auth_cache_mcp_publish_policy.rs`
/// all stated that a `#[tool]` method is "a private `impl DrustMcp` fn no
/// integration test can call". That is FALSE: `#[tool]` wrappers are reachable
/// over `/t/<id>/mcp` by JSON-RPC `tools/call`, which is exactly how
/// `tests/admin_users.rs` drives `revoke_user_sessions` — whose #952 evict sits
/// in such a wrapper arm. Left standing, that sentence would tell the next
/// author a wrapper-arm evict is ungateable and push a conditional somewhere
/// worse.
///
/// Measured caveat, so nobody re-derives it the hard way: under every
/// `helpers::spin_up_*` stack this particular tool stops inside the wrapper,
/// because `McpRegistry::with_bus` passes `meta: None` — `tools/call
/// set_publish_policy` returns "meta connection not available in this context"
/// and never reaches this fn, leaving the epoch untouched. That is a harness
/// gap, not a design constraint: a fixture that builds its registry with
/// `Some(meta)` drives the wrapper fine, which is what
/// `mcp_tools_call_set_publish_policy_evicts_the_stacks_own_bus`
/// (`tests/auth_cache_mcp_publish_policy.rs`) does to pin WHICH bus the wrapper
/// forwards. The rest of this station's tests call this fn directly, and
/// therefore say nothing about that argument.
///
/// `bus_rooms` is a REQUIRED parameter, not an `Option` like `auth_cache`:
/// `DrustMcpInner.bus_rooms` is always present, and #955 made the same choice
/// for `McpRegistry::with_bus` — a defaulted bus is a silently detached one.
/// Precedent in this file: `set_owner_field` takes the `EventBus` and calls
/// `evict_collection` itself.
pub async fn set_publish_policy(
    meta: &std::sync::Arc<Mutex<Connection>>,
    tenant_id: &str,
    allow_user: Option<bool>,
    allow_anon: Option<bool>,
    auth_cache: Option<&crate::tenant::auth_cache::AuthCache>,
    bus_rooms: &crate::tenant::rooms::RoomBus,
) -> anyhow::Result<serde_json::Value> {
    use rusqlite::OptionalExtension;
    let tid = tenant_id.to_string();
    let conn = meta.lock().await;
    // The pre-image, read under the SAME meta lock the UPDATEs below hold, so
    // no concurrent writer can slip between the read and the write and make
    // the change detection lie. It doubles as the existence check the flags'
    // NOT_FOUND contract needs, so a no-op call still surfaces NOT_FOUND.
    // Three-way on purpose (mirrors the REST twin): a read FAULT is a DB
    // error, not a missing tenant — collapsing it into `None` would report an
    // existing tenant as gone and silently discard a valid call.
    let old: (i64, i64) = match conn
        .query_row(
            "SELECT COALESCE(allow_user_publish, 0), COALESCE(allow_anon_publish, 0) \
             FROM tenants WHERE id = ?1 AND deleted_at IS NULL",
            rusqlite::params![tid],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
    {
        Err(e) => return Err(anyhow::anyhow!("DB: {e}")),
        Ok(None) => anyhow::bail!("NOT_FOUND: tenant not found"),
        Ok(Some(pair)) => pair,
    };
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
    // #955 — and only on a REAL change, close the live sockets still holding
    // the OLD policy. AFTER the cache clear, never before — same ordering as
    // the REST twin and the same reason: evicting first opens a window where
    // the closed client reconnects, hits the not-yet-cleared cache entry and
    // captures the STALE flags for the whole life of the new socket, with no
    // further bump coming to correct it. No test separates the two statements
    // (swapping them stays green), so this comment is the only thing holding
    // the order.
    if (u, a) != old {
        bus_rooms.evict_tenant(&tid);
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
