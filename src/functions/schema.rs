//! `_system_functions` + `_system_function_logs` — lazy DDL (v1.33
//! `_system_upload_sessions` pattern) + row CRUD through `pool.with_writer`.
//! Both tables are `_system_`-prefixed ⇒ automatically drop-protected and
//! invisible to `/records/*` / MCP record tools / SSE (storage/schema.rs:8).

use crate::storage::pool::SharedTenantPool;
use serde::Serialize;

/// Trim-on-write retention: newest N log rows kept per function.
pub const FN_LOG_KEEP_PER_FUNCTION: i64 = 500;

const DDL: &str = "
CREATE TABLE IF NOT EXISTS _system_functions (
  id            INTEGER PRIMARY KEY,
  name          TEXT NOT NULL UNIQUE,
  wasm_sha256   TEXT NOT NULL,
  size_bytes    INTEGER NOT NULL,
  triggers_json TEXT NOT NULL,
  active        INTEGER NOT NULL DEFAULT 1,
  description   TEXT NOT NULL DEFAULT '',
  created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE TABLE IF NOT EXISTS _system_function_logs (
  id            INTEGER PRIMARY KEY,
  invocation_id TEXT NOT NULL,
  function_name TEXT NOT NULL,
  trigger       TEXT NOT NULL,
  status        TEXT NOT NULL,
  duration_ms   INTEGER NOT NULL,
  log_text      TEXT NOT NULL DEFAULT '',
  result_json   TEXT,
  created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_sysfnlogs_fn ON _system_function_logs(function_name, id);
";

fn ensure_tables(c: &rusqlite::Connection) -> rusqlite::Result<()> {
    c.execute_batch(DDL)
}

#[derive(Clone, Debug, Serialize)]
pub struct FunctionRow {
    pub id: i64,
    pub name: String,
    pub wasm_sha256: String,
    pub size_bytes: i64,
    pub triggers_json: String,
    pub active: bool,
    pub description: String,
    pub created_at: String,
    pub updated_at: String,
}

pub struct CreateFunctionParams {
    pub name: String,
    pub wasm_sha256: String,
    pub size_bytes: i64,
    pub triggers_json: String,
    pub description: String,
}

/// `[a-z0-9_-]{1,64}` — enforced here so every surface shares one rule.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

fn row_from(r: &rusqlite::Row<'_>) -> rusqlite::Result<FunctionRow> {
    Ok(FunctionRow {
        id: r.get(0)?,
        name: r.get(1)?,
        wasm_sha256: r.get(2)?,
        size_bytes: r.get(3)?,
        triggers_json: r.get(4)?,
        active: r.get::<_, i64>(5)? != 0,
        description: r.get(6)?,
        created_at: r.get(7)?,
        updated_at: r.get(8)?,
    })
}

const COLS: &str = "id, name, wasm_sha256, size_bytes, triggers_json, active, description, created_at, updated_at";

/// Create-or-replace by name. Errors are sentinel-prefixed (`FN_NAME_INVALID:`,
/// `FN_LIMIT:`) so REST/MCP layers map them to error codes mechanically.
pub async fn create_function(
    pool: &SharedTenantPool,
    p: CreateFunctionParams,
    max_per_tenant: u32,
) -> anyhow::Result<FunctionRow> {
    if !valid_name(&p.name) {
        anyhow::bail!("FN_NAME_INVALID: function name must match [a-z0-9_-]{{1,64}}");
    }
    pool.with_writer(move |c| {
        ensure_tables(c)?;
        let existing: i64 = c.query_row(
            "SELECT COUNT(*) FROM _system_functions WHERE name != ?1",
            rusqlite::params![p.name],
            |r| r.get(0),
        )?;
        if existing as u32 >= max_per_tenant {
            return Err(rusqlite::Error::InvalidParameterName(format!(
                "FN_LIMIT: tenant already has {existing} functions (max {max_per_tenant})"
            )));
        }
        c.execute(
            "INSERT INTO _system_functions (name, wasm_sha256, size_bytes, triggers_json, description)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(name) DO UPDATE SET
               wasm_sha256 = excluded.wasm_sha256,
               size_bytes = excluded.size_bytes,
               triggers_json = excluded.triggers_json,
               description = excluded.description,
               updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')",
            rusqlite::params![p.name, p.wasm_sha256, p.size_bytes, p.triggers_json, p.description],
        )?;
        c.query_row(
            &format!("SELECT {COLS} FROM _system_functions WHERE name = ?1"),
            rusqlite::params![p.name],
            row_from,
        )
    })
    .await
    .map_err(|e| anyhow::anyhow!(unwrap_module_err(e)))
}

/// `rusqlite::Error::InvalidParameterName` is our sentinel carrier through
/// `with_writer` (the plan's `ModuleError` is gated behind rusqlite's `vtab`
/// feature, which this crate does not enable — same String payload, same
/// semantics); unwrap it back to the bare `CODE: message` string.
fn unwrap_module_err(e: rusqlite::Error) -> String {
    match e {
        rusqlite::Error::InvalidParameterName(s) => s,
        other => other.to_string(),
    }
}

pub async fn list_functions(pool: &SharedTenantPool) -> anyhow::Result<Vec<FunctionRow>> {
    pool.with_writer(move |c| {
        ensure_tables(c)?;
        let mut st = c.prepare(&format!(
            "SELECT {COLS} FROM _system_functions ORDER BY name"
        ))?;
        let rows = st.query_map([], row_from)?.collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    })
    .await
    .map_err(|e| anyhow::anyhow!(unwrap_module_err(e)))
}

pub async fn get_function(
    pool: &SharedTenantPool,
    name: &str,
) -> anyhow::Result<Option<FunctionRow>> {
    let name = name.to_string();
    pool.with_writer(move |c| {
        ensure_tables(c)?;
        match c.query_row(
            &format!("SELECT {COLS} FROM _system_functions WHERE name = ?1"),
            rusqlite::params![name],
            row_from,
        ) {
            Ok(r) => Ok(Some(r)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    })
    .await
    .map_err(|e| anyhow::anyhow!(unwrap_module_err(e)))
}

pub async fn set_active(pool: &SharedTenantPool, name: &str, active: bool) -> anyhow::Result<bool> {
    let name = name.to_string();
    pool.with_writer(move |c| {
        ensure_tables(c)?;
        let n = c.execute(
            "UPDATE _system_functions SET active = ?2,
             updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE name = ?1",
            rusqlite::params![name, active as i64],
        )?;
        Ok(n > 0)
    })
    .await
    .map_err(|e| anyhow::anyhow!(unwrap_module_err(e)))
}

pub async fn update_meta(
    pool: &SharedTenantPool,
    name: &str,
    triggers_json: Option<String>,
    description: Option<String>,
) -> anyhow::Result<bool> {
    let name = name.to_string();
    pool.with_writer(move |c| {
        ensure_tables(c)?;
        let mut n = 0;
        if let Some(t) = triggers_json {
            n += c.execute(
                "UPDATE _system_functions SET triggers_json = ?2,
                 updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE name = ?1",
                rusqlite::params![name, t],
            )?;
        }
        if let Some(d) = description {
            n += c.execute(
                "UPDATE _system_functions SET description = ?2,
                 updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE name = ?1",
                rusqlite::params![name, d],
            )?;
        }
        Ok(n > 0)
    })
    .await
    .map_err(|e| anyhow::anyhow!(unwrap_module_err(e)))
}

/// Returns true if a row was deleted. Also reports whether any OTHER row
/// still references the same sha (artifact GC decision belongs to the caller).
pub async fn delete_function(pool: &SharedTenantPool, name: &str) -> anyhow::Result<bool> {
    let name = name.to_string();
    pool.with_writer(move |c| {
        ensure_tables(c)?;
        let n = c.execute(
            "DELETE FROM _system_functions WHERE name = ?1",
            rusqlite::params![name],
        )?;
        Ok(n > 0)
    })
    .await
    .map_err(|e| anyhow::anyhow!(unwrap_module_err(e)))
}

pub async fn sha_still_referenced(pool: &SharedTenantPool, sha: &str) -> anyhow::Result<bool> {
    let sha = sha.to_string();
    pool.with_writer(move |c| {
        ensure_tables(c)?;
        let n: i64 = c.query_row(
            "SELECT COUNT(*) FROM _system_functions WHERE wasm_sha256 = ?1",
            rusqlite::params![sha],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    })
    .await
    .map_err(|e| anyhow::anyhow!(unwrap_module_err(e)))
}

#[derive(Clone, Debug, Serialize)]
pub struct LogRow {
    pub invocation_id: String,
    pub function_name: String,
    pub trigger: String,
    pub status: String,
    pub duration_ms: i64,
    pub log_text: String,
    pub result_json: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct LogRowOut {
    pub invocation_id: String,
    pub function_name: String,
    pub trigger: String,
    pub status: String,
    pub duration_ms: i64,
    pub log_text: String,
    pub result_json: Option<String>,
    pub created_at: String,
}

/// Insert + trim-on-write (keep newest FN_LOG_KEEP_PER_FUNCTION per function).
pub async fn insert_log(pool: &SharedTenantPool, row: LogRow) -> anyhow::Result<()> {
    pool.with_writer(move |c| {
        ensure_tables(c)?;
        c.execute(
            "INSERT INTO _system_function_logs
             (invocation_id, function_name, trigger, status, duration_ms, log_text, result_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                row.invocation_id,
                row.function_name,
                row.trigger,
                row.status,
                row.duration_ms,
                row.log_text,
                row.result_json
            ],
        )?;
        c.execute(
            "DELETE FROM _system_function_logs WHERE function_name = ?1 AND id NOT IN
             (SELECT id FROM _system_function_logs WHERE function_name = ?1
              ORDER BY id DESC LIMIT ?2)",
            rusqlite::params![row.function_name, FN_LOG_KEEP_PER_FUNCTION],
        )?;
        Ok(())
    })
    .await
    .map_err(|e| anyhow::anyhow!(unwrap_module_err(e)))
}

pub async fn list_logs(
    pool: &SharedTenantPool,
    function_name: &str,
    limit: i64,
) -> anyhow::Result<Vec<LogRowOut>> {
    let function_name = function_name.to_string();
    let limit = limit.clamp(1, 1000);
    pool.with_writer(move |c| {
        ensure_tables(c)?;
        let mut st = c.prepare(
            "SELECT invocation_id, function_name, trigger, status, duration_ms,
                    log_text, result_json, created_at
             FROM _system_function_logs WHERE function_name = ?1
             ORDER BY id DESC LIMIT ?2",
        )?;
        let rows = st
            .query_map(rusqlite::params![function_name, limit], |r| {
                Ok(LogRowOut {
                    invocation_id: r.get(0)?,
                    function_name: r.get(1)?,
                    trigger: r.get(2)?,
                    status: r.get(3)?,
                    duration_ms: r.get(4)?,
                    log_text: r.get(5)?,
                    result_json: r.get(6)?,
                    created_at: r.get(7)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    })
    .await
    .map_err(|e| anyhow::anyhow!(unwrap_module_err(e)))
}
