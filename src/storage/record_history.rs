//! v1.46 — supa_audit-style record-history capture. One shared helper wired
//! into BOTH write choke points (REST `records.rs` and MCP `write.rs`), invoked
//! INSIDE each mutation's `with_writer_tx` so the history row commits atomically
//! with the write (spec §5.3). Row values stay in the tenant DB (isolation).

use crate::auth::middleware::AuthCtx;
use crate::storage::pool::TenantRegistry;
use rusqlite::{Connection, OptionalExtension};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone, Copy, Debug)]
pub enum HistoryOp {
    Insert,
    Update,
    Delete,
}

impl HistoryOp {
    pub fn as_str(&self) -> &'static str {
        match self {
            HistoryOp::Insert => "insert",
            HistoryOp::Update => "update",
            HistoryOp::Delete => "delete",
        }
    }
}

/// Best-effort attribution for a history row. `id`/`hint` are nullable — the
/// per-request access log already carries the token fingerprint; this is the
/// forensic "who" on the row value.
#[derive(Clone, Debug)]
pub struct AuditActor {
    pub kind: &'static str,
    pub id: Option<String>,
    /// User arm only: 12-hex-char prefix of the session token hash, joinable
    /// to `_system_sessions.token_hash` (and the access log's token
    /// fingerprint) to correlate a history row with the session that wrote
    /// it. `None` for anon (no token identity) and service (admin
    /// attribution rides `id`).
    pub hint: Option<String>,
}

impl AuditActor {
    /// Service/Privileged caller (MCP service key, edge-function `Privileged`,
    /// event triggers). `admin_id` is not known at these call sites → `None`.
    pub fn service() -> Self {
        AuditActor {
            kind: "service",
            id: None,
            hint: None,
        }
    }

    pub fn from_auth_ctx(ctx: &AuthCtx) -> Self {
        match ctx {
            AuthCtx::Anon => AuditActor {
                kind: "anon",
                id: None,
                hint: None,
            },
            AuthCtx::Service { admin_id } => AuditActor {
                kind: "service",
                id: admin_id.map(|i| i.to_string()),
                hint: None,
            },
            AuthCtx::User {
                user_id,
                token_hash,
            } => AuditActor {
                kind: "user",
                id: Some(user_id.clone()),
                // 12-hex-char prefix of the session token hash (spec §5.1).
                // `get(..12)` is char-boundary-safe on the hex string and
                // falls back to the whole string when shorter — never panics.
                hint: Some(
                    token_hash
                        .get(..12)
                        .unwrap_or(token_hash.as_str())
                        .to_string(),
                ),
            },
        }
    }
}

/// Gated in-tx INSERT into `_system_record_history`. `audit_enabled=false` →
/// no-op (zero cost beyond this bool check). Runs inside the caller's write tx.
#[allow(clippy::too_many_arguments)]
pub fn capture(
    tx: &Connection,
    collection: &str,
    op: HistoryOp,
    record_id: i64,
    old: Option<&serde_json::Value>,
    new: Option<&serde_json::Value>,
    actor: &AuditActor,
    audit_enabled: bool,
) -> rusqlite::Result<()> {
    if !audit_enabled {
        return Ok(());
    }
    let old_s = old.map(|v| v.to_string());
    let new_s = new.map(|v| v.to_string());
    tx.execute(
        "INSERT INTO _system_record_history
             (collection, record_id, op, old_json, new_json, actor_kind, actor_id, actor_hint)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        rusqlite::params![
            collection,
            record_id,
            op.as_str(),
            old_s,
            new_s,
            actor.kind,
            actor.id,
            actor.hint,
        ],
    )?;
    Ok(())
}

/// Pre-image projection for update/delete: `SELECT *` the target row (scoped by
/// the SAME owner clause the mutation uses, so only a row the caller may touch is
/// recorded) and render it to JSON exactly like the write path's response
/// (BLOB → `{__blob_bytes}`, vectors hidden). PLAIN `prepare` — never
/// `prepare_cached` (v1.43 reader-cache invariant: a cached `SELECT *` serves a
/// stale column set after DDL). `owner = &None` for the service/non-scoped case.
pub fn select_row_json_owner(
    tx: &Connection,
    collection: &str,
    id: i64,
    owner: &Option<(String, String)>,
    vector_names: &HashSet<String>,
) -> rusqlite::Result<Option<serde_json::Value>> {
    // user_id is UUID-shaped → safe to inline after escaping, same as the
    // owner clause the mutation itself builds.
    let owner_clause = match owner {
        Some((field, uid)) => format!(
            " AND \"{}\" = '{}'",
            field.replace('"', "\"\""),
            uid.replace('\'', "''")
        ),
        None => String::new(),
    };
    let sql = format!(
        "SELECT * FROM \"{}\" WHERE id = ?1{}",
        collection.replace('"', "\"\""),
        owner_clause
    );
    let mut stmt = tx.prepare(&sql)?;
    let col_names: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
    stmt.query_row(rusqlite::params![id], |r| {
        crate::mcp::tools::write::materialize_row(r, &col_names, vector_names)
    })
    .optional()
}

/// Per-row pre-image capture for a bulk owner cascade (the `delete_user`
/// "DELETE all rows owned by uid" paths — spec §4: bulk-delete paths must
/// iterate and capture per row). Runs INSIDE the caller's write tx so every
/// history row commits (or rolls back) atomically with the cascade DELETE it
/// records. Gated by the collection's `audit_enabled` (off → `Ok(0)`).
///
/// Rows are projected through the SAME projector the single-row paths use
/// (`materialize_row`: BLOB → `{__blob_bytes}`, vector columns hidden). The
/// `SELECT *` uses PLAIN `prepare` — never `prepare_cached` (v1.43 invariant:
/// a cached `SELECT *` serves a stale column set after DDL).
///
/// Returns the number of rows captured. Shared by BOTH cascade sites
/// (`mcp/tools/user.rs::delete_user` and
/// `tenant/admin_user_routes.rs::delete_user_handler`).
pub fn capture_owner_cascade(
    tx: &Connection,
    collection: &str,
    owner_field: &str,
    owner_value: &str,
    actor: &AuditActor,
) -> rusqlite::Result<usize> {
    if !crate::storage::schema::read_audit_enabled(tx, collection)? {
        return Ok(0);
    }
    let vector_names: HashSet<String> = crate::storage::schema::read_vector_fields(tx, collection)?
        .into_iter()
        .map(|vf| vf.name)
        .collect();
    let sql = format!(
        "SELECT * FROM \"{}\" WHERE \"{}\" = ?1",
        collection.replace('"', "\"\""),
        owner_field.replace('"', "\"\"")
    );
    let mut stmt = tx.prepare(&sql)?;
    let col_names: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
    let mut rows = stmt.query(rusqlite::params![owner_value])?;
    let mut captured = 0usize;
    while let Some(r) = rows.next()? {
        let id: i64 = r.get("id")?;
        let old = crate::mcp::tools::write::materialize_row(r, &col_names, &vector_names)?;
        capture(
            tx,
            collection,
            HistoryOp::Delete,
            id,
            Some(&old),
            None,
            actor,
            true,
        )?;
        captured += 1;
    }
    Ok(captured)
}

// ─── Write-mode RPC capture via a scoped SQLite preupdate hook ──────────────
//
// `run_write_rpc` executes arbitrary tenant SQL (INSERT/UPDATE/DELETE) that
// the structured choke points never see, so per-row old/new images are
// captured at the CONNECTION level: a preupdate hook installed for exactly
// the duration of the RPC savepoint buffers each row change, and
// `flush_captured` writes the gated history rows INSIDE the same savepoint —
// atomic with the mutation by construction. The hook closure must NOT touch
// the `Connection` (SQLite forbids re-entrant use from inside the hook); it
// only copies accessor values into owned `Value`s and pushes them.

/// One buffered row change from the preupdate hook. `old`/`new` hold the raw
/// column values in table-declaration (storage) order — projection to JSON
/// happens later in [`flush_captured`], where the `Connection` may be used.
#[derive(Debug)]
pub struct BufferedChange {
    pub table: String,
    pub op: HistoryOp,
    pub rowid: i64,
    pub old: Option<Vec<rusqlite::types::Value>>,
    pub new: Option<Vec<rusqlite::types::Value>>,
}

/// Shared hook buffer. `error` is set when the hook could not read a row
/// value — [`flush_captured`] then fails closed (the caller rolls back the
/// RPC rather than committing an unaudited mutation).
///
/// `Arc<std::sync::Mutex<..>>` rather than `Rc<RefCell<..>>` because
/// `Connection::preupdate_hook` requires the closure to be `Send + 'static`.
/// The lock is never contended (hook + flush run on the same thread inside
/// the writer closure); it exists only to satisfy the bound.
#[derive(Debug, Default)]
pub struct CaptureBuffer {
    pub changes: Vec<BufferedChange>,
    pub error: Option<String>,
}

pub type SharedCaptureBuffer = Arc<std::sync::Mutex<CaptureBuffer>>;

/// Owned copy of a preupdate accessor value. Deliberately NOT
/// `rusqlite::types::Value::from(ValueRef)` — that impl panics on invalid
/// UTF-8, and a panic inside the hook is swallowed by rusqlite's
/// `catch_unwind` (the change would silently vanish → fail-open). Lossy text
/// conversion matches `materialize_row`'s `from_utf8_lossy` semantics.
fn owned_value(v: rusqlite::types::ValueRef<'_>) -> rusqlite::types::Value {
    use rusqlite::types::{Value, ValueRef};
    match v {
        ValueRef::Null => Value::Null,
        ValueRef::Integer(i) => Value::Integer(i),
        ValueRef::Real(f) => Value::Real(f),
        ValueRef::Text(t) => Value::Text(String::from_utf8_lossy(t).into_owned()),
        ValueRef::Blob(b) => Value::Blob(b.to_vec()),
    }
}

fn copy_old(
    acc: &rusqlite::hooks::PreUpdateOldValueAccessor,
) -> Result<Vec<rusqlite::types::Value>, String> {
    let n = acc.get_column_count();
    let mut out = Vec::with_capacity(n as usize);
    for i in 0..n {
        match acc.get_old_column_value(i) {
            Ok(v) => out.push(owned_value(v)),
            Err(e) => return Err(format!("preupdate old[{i}]: {e}")),
        }
    }
    Ok(out)
}

fn copy_new(
    acc: &rusqlite::hooks::PreUpdateNewValueAccessor,
) -> Result<Vec<rusqlite::types::Value>, String> {
    let n = acc.get_column_count();
    let mut out = Vec::with_capacity(n as usize);
    for i in 0..n {
        match acc.get_new_column_value(i) {
            Ok(v) => out.push(owned_value(v)),
            Err(e) => return Err(format!("preupdate new[{i}]: {e}")),
        }
    }
    Ok(out)
}

/// Install the scoped preupdate capture hook on `conn` and return the shared
/// buffer it fills. The closure filters `_system_*` tables (which also keeps
/// the flush's own history INSERTs invisible → no recursion) and `sqlite_*`
/// internals. Callers MUST pair this with [`remove_preupdate_capture`] on
/// every exit path — a leaked hook would buffer unrelated later writes.
pub fn install_preupdate_capture(conn: &Connection) -> rusqlite::Result<SharedCaptureBuffer> {
    use rusqlite::hooks::{Action, PreUpdateCase};
    let buf: SharedCaptureBuffer = Arc::new(std::sync::Mutex::new(CaptureBuffer::default()));
    let hook_buf = Arc::clone(&buf);
    conn.preupdate_hook(Some(
        move |_action: Action, _db: &str, tbl: &str, case: &PreUpdateCase| {
            if tbl.starts_with("_system_") || tbl.starts_with("sqlite_") {
                return;
            }
            let mut g = match hook_buf.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            if g.error.is_some() {
                return; // already failed — flush will reject the whole run
            }
            // Trigger-driven UPDATE (query depth > 0): every canonical
            // collection carries the convergent `<name>_updated_at` AFTER
            // UPDATE trigger, so one logical UPDATE fires this hook twice —
            // depth 0 (the statement; stale updated_at) and depth 1 (the
            // trigger; refreshed updated_at). Merge the trigger's fresh
            // new-image into the pending depth-0 change so `new_json`
            // equals the COMMITTED row — the same fidelity contract the
            // structured path gets from `RETURNING *` (v1.43
            // convergent-trigger note) — instead of double-capturing.
            // Insert/Delete are buffered as-is at any depth: no drust
            // trigger produces them today.
            if let PreUpdateCase::Update {
                new_value_accessor, ..
            } = case
                && new_value_accessor.get_query_depth() > 0
            {
                let new = match copy_new(new_value_accessor) {
                    Ok(n) => n,
                    Err(e) => {
                        g.error = Some(e);
                        return;
                    }
                };
                let rowid = new_value_accessor.get_new_row_id();
                if let Some(pending) = g
                    .changes
                    .iter_mut()
                    .rev()
                    .find(|c| c.table == tbl && c.rowid == rowid && c.new.is_some())
                {
                    pending.new = Some(new);
                    return;
                }
                // No pending change to merge into — unreachable today
                // (tenants cannot create triggers; drust's only trigger is
                // the convergent updated_at one, which always follows its
                // buffered depth-0 change). Fall through fail-closed so a
                // hypothetical future trigger's changes are captured as
                // their own change rather than silently dropped.
            }
            let change = match case {
                PreUpdateCase::Insert(acc) => copy_new(acc).map(|new| BufferedChange {
                    table: tbl.to_string(),
                    op: HistoryOp::Insert,
                    rowid: acc.get_new_row_id(),
                    old: None,
                    new: Some(new),
                }),
                PreUpdateCase::Delete(acc) => copy_old(acc).map(|old| BufferedChange {
                    table: tbl.to_string(),
                    op: HistoryOp::Delete,
                    rowid: acc.get_old_row_id(),
                    old: Some(old),
                    new: None,
                }),
                PreUpdateCase::Update {
                    old_value_accessor,
                    new_value_accessor,
                } => copy_old(old_value_accessor).and_then(|old| {
                    copy_new(new_value_accessor).map(|new| BufferedChange {
                        table: tbl.to_string(),
                        op: HistoryOp::Update,
                        rowid: new_value_accessor.get_new_row_id(),
                        old: Some(old),
                        new: Some(new),
                    })
                }),
                PreUpdateCase::Unknown => Err("unknown preupdate case".to_string()),
            };
            match change {
                Ok(c) => g.changes.push(c),
                Err(e) => g.error = Some(e),
            }
        },
    ))?;
    Ok(buf)
}

/// Remove the preupdate capture hook. Must run on EVERY `run_write_rpc` exit
/// path (success and error) BEFORE `flush_captured` / savepoint resolution.
pub fn remove_preupdate_capture(conn: &Connection) -> rusqlite::Result<()> {
    use rusqlite::hooks::{Action, PreUpdateCase};
    conn.preupdate_hook(None::<fn(Action, &str, &str, &PreUpdateCase)>)
}

/// Per-table projection metadata for [`flush_captured`]. `None` in the cache
/// means audit is disabled for that table → drop its buffered rows.
struct TableProjection {
    col_names: Vec<String>,
    vector_names: HashSet<String>,
}

/// Typed internal error for capture failures — keeps flush inside
/// `rusqlite::Result` so the executor's error plumbing stays uniform.
fn capture_error(msg: String) -> rusqlite::Error {
    rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_ERROR),
        Some(msg),
    )
}

fn load_table_projection(
    tx: &Connection,
    table: &str,
) -> rusqlite::Result<Option<TableProjection>> {
    if !crate::storage::schema::read_audit_enabled(tx, table)? {
        return Ok(None);
    }
    // PLAIN prepare — never prepare_cached (v1.43 invariant). Column order
    // from pragma_table_info (cid ASC) matches the preupdate accessors'
    // column indices (both are table-declaration order).
    let mut stmt = tx.prepare("SELECT name FROM pragma_table_info(?1) ORDER BY cid")?;
    let col_names: Vec<String> = stmt
        .query_map(rusqlite::params![table], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    if col_names.is_empty() {
        // Table vanished between the hook firing and the flush (same-run
        // DDL). Fail closed rather than guessing a projection.
        return Err(capture_error(format!(
            "record-history flush: no columns for table {table}"
        )));
    }
    let vector_names: HashSet<String> = crate::storage::schema::read_vector_fields(tx, table)?
        .into_iter()
        .map(|vf| vf.name)
        .collect();
    Ok(Some(TableProjection {
        col_names,
        vector_names,
    }))
}

/// Zip buffered values to column names — SAME projection semantics as
/// `materialize_row` (Null/Integer/Real/Text as-is, Blob → `{__blob_bytes}`,
/// vector columns omitted entirely).
fn project_values(
    table: &str,
    vals: &[rusqlite::types::Value],
    proj: &TableProjection,
) -> rusqlite::Result<serde_json::Value> {
    use rusqlite::types::Value;
    if vals.len() != proj.col_names.len() {
        return Err(capture_error(format!(
            "record-history flush: {table} captured {} values but has {} columns",
            vals.len(),
            proj.col_names.len()
        )));
    }
    let mut obj = serde_json::Map::new();
    for (name, v) in proj.col_names.iter().zip(vals) {
        if proj.vector_names.contains(name) {
            continue;
        }
        let jv = match v {
            Value::Null => serde_json::Value::Null,
            Value::Integer(i) => serde_json::json!(i),
            Value::Real(f) => serde_json::json!(f),
            Value::Text(t) => serde_json::Value::String(t.clone()),
            Value::Blob(b) => serde_json::json!({ "__blob_bytes": b.len() }),
        };
        obj.insert(name.clone(), jv);
    }
    Ok(serde_json::Value::Object(obj))
}

/// Flush the buffered preupdate changes into `_system_record_history`,
/// INSIDE the caller's still-open savepoint. Per table: `audit_enabled`
/// off → that table's rows are dropped; otherwise each row is projected
/// and written via [`capture`]. Returns the number of history rows written.
/// Fails closed: a buffered hook error or projection mismatch returns `Err`
/// so the caller rolls the whole RPC back.
pub fn flush_captured(
    tx: &Connection,
    buf: &SharedCaptureBuffer,
    actor: &AuditActor,
) -> rusqlite::Result<usize> {
    let (changes, error) = {
        let mut g = match buf.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        (std::mem::take(&mut g.changes), g.error.take())
    };
    if let Some(msg) = error {
        return Err(capture_error(format!(
            "record-history preupdate capture failed: {msg}"
        )));
    }
    let mut meta: std::collections::HashMap<String, Option<TableProjection>> =
        std::collections::HashMap::new();
    let mut written = 0usize;
    for ch in &changes {
        let proj = match meta.entry(ch.table.clone()) {
            std::collections::hash_map::Entry::Occupied(o) => o.into_mut(),
            std::collections::hash_map::Entry::Vacant(v) => {
                v.insert(load_table_projection(tx, &ch.table)?)
            }
        };
        let Some(proj) = proj else {
            continue; // audit_enabled = 0 → drop this table's rows
        };
        let old_json = ch
            .old
            .as_ref()
            .map(|vals| project_values(&ch.table, vals, proj))
            .transpose()?;
        let new_json = ch
            .new
            .as_ref()
            .map(|vals| project_values(&ch.table, vals, proj))
            .transpose()?;
        capture(
            tx,
            &ch.table,
            ch.op,
            ch.rowid,
            old_json.as_ref(),
            new_json.as_ref(),
            actor,
            true, // gated above via read_audit_enabled
        )?;
        written += 1;
    }
    Ok(written)
}

/// Retention window in days for `_system_record_history` rows. Env knob
/// `DRUST_AUDIT_HISTORY_RETENTION_DAYS`, default 7; `0` disables pruning
/// (keep forever). Unparseable values fall back to the default.
pub fn retention_days_from_env() -> u64 {
    std::env::var("DRUST_AUDIT_HISTORY_RETENTION_DAYS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(7)
}

/// Delete history rows older than `days`. Returns the number of rows
/// deleted. `days == 0` → retention disabled → no delete, `Ok(0)`.
pub fn prune_tenant(conn: &Connection, days: u64) -> rusqlite::Result<usize> {
    if days == 0 {
        return Ok(0); // retention disabled → keep forever
    }
    let cutoff = format!("-{days} days");
    conn.execute(
        "DELETE FROM _system_record_history WHERE ts < datetime('now', ?1)",
        rusqlite::params![cutoff],
    )
}

/// Daily retention janitor over every live tenant's `_system_record_history`.
///
/// Anchored to wall-clock 03:00 UTC via the same `next_0300_utc` helper the
/// `meta_logs` audit-retention loop uses, so the cadence doesn't drift with
/// process uptime. Live-tenant iteration mirrors the session/upload janitors:
/// enumerate `tenants WHERE deleted_at IS NULL` from meta, skip tenants whose
/// `data.sqlite` is gone, then prune through the SHARED per-tenant writer
/// mutex (`pool.with_writer`) so deletes serialize with request writes.
///
/// `DRUST_AUDIT_HISTORY_RETENTION_DAYS=0` → log once and never schedule a
/// delete. Spawn from main as
/// `tokio::spawn(record_history::spawn_retention_task(meta, registry))`.
pub async fn spawn_retention_task(meta: Arc<Mutex<Connection>>, registry: Arc<TenantRegistry>) {
    let days = retention_days_from_env();
    if days == 0 {
        tracing::info!(
            "record-history retention disabled (DRUST_AUDIT_HISTORY_RETENTION_DAYS=0); keeping rows forever"
        );
        return;
    }
    loop {
        let now = chrono::Utc::now();
        let next = crate::safety::audit_db::next_0300_utc(now);
        let dur = (next - now)
            .to_std()
            .unwrap_or(std::time::Duration::from_secs(60));
        tokio::time::sleep(dur).await;

        let ids: Vec<String> = {
            let conn = meta.lock().await;
            conn.prepare("SELECT id FROM tenants WHERE deleted_at IS NULL")
                .and_then(|mut s| {
                    s.query_map([], |r| r.get::<_, String>(0))
                        .and_then(|it| it.collect())
                })
                .unwrap_or_default()
        };
        let mut total = 0usize;
        for tid in ids {
            // Same guard as the session janitor: a live meta row whose
            // data.sqlite is already gone must not be re-created by the
            // pool open.
            let p = registry
                .data_root()
                .join("tenants")
                .join(&tid)
                .join("data.sqlite");
            if !p.exists() {
                continue;
            }
            match registry.get_or_open(&tid) {
                Ok(pool) => match pool.with_writer(|c| prune_tenant(c, days)).await {
                    Ok(n) => total += n,
                    Err(e) => {
                        tracing::warn!(tenant = %tid, err = ?e, "record-history retention prune failed")
                    }
                },
                Err(e) => {
                    tracing::warn!(tenant = %tid, err = ?e, "record-history retention: pool open failed")
                }
            }
        }
        if total > 0 {
            tracing::info!(
                deleted = total,
                days,
                "record-history retention pruned stale rows"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn hist_conn() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        // Same DDL const migrate_tenant_db / apply_schema run in production, so
        // this fixture can never drift from the real table shape.
        c.execute_batch(crate::db::migrations::SQL_CREATE_SYSTEM_RECORD_HISTORY_IF_NOT_EXISTS)
            .unwrap();
        c
    }

    #[test]
    fn capture_gate_off_is_noop() {
        let c = hist_conn();
        let new = serde_json::json!({"id": 1});
        capture(
            &c,
            "notes",
            HistoryOp::Insert,
            1,
            None,
            Some(&new),
            &AuditActor::service(),
            false,
        )
        .unwrap();
        let n: i64 = c
            .query_row("SELECT COUNT(*) FROM _system_record_history", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(n, 0, "gate off writes nothing");
    }

    #[test]
    fn capture_writes_old_new_actor() {
        let c = hist_conn();
        let old = serde_json::json!({"id": 7, "body": "a"});
        let new = serde_json::json!({"id": 7, "body": "b"});
        let actor = AuditActor {
            kind: "user",
            id: Some("u-1".into()),
            hint: None,
        };
        capture(
            &c,
            "notes",
            HistoryOp::Update,
            7,
            Some(&old),
            Some(&new),
            &actor,
            true,
        )
        .unwrap();
        let (op, oj, nj, ak, ai): (String, String, String, String, String) = c
            .query_row(
                "SELECT op, old_json, new_json, actor_kind, actor_id FROM _system_record_history",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap();
        assert_eq!(op, "update");
        assert_eq!(serde_json::from_str::<serde_json::Value>(&oj).unwrap(), old);
        assert_eq!(serde_json::from_str::<serde_json::Value>(&nj).unwrap(), new);
        assert_eq!(ak, "user");
        assert_eq!(ai, "u-1");
    }

    #[test]
    fn preupdate_capture_roundtrip_insert_update_delete() {
        let c = hist_conn();
        c.execute_batch("CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT, data BLOB);")
            .unwrap();
        let buf = install_preupdate_capture(&c).unwrap();
        c.execute_batch(
            "INSERT INTO notes (id, body, data) VALUES (1, 'a', x'0102');
             UPDATE notes SET body = 'b' WHERE id = 1;
             DELETE FROM notes WHERE id = 1;",
        )
        .unwrap();
        remove_preupdate_capture(&c).unwrap();
        let actor = AuditActor::service();
        let n = flush_captured(&c, &buf, &actor).unwrap();
        assert_eq!(n, 3, "insert + update + delete each captured");

        let rows: Vec<(String, i64, Option<String>, Option<String>)> = {
            let mut stmt = c
                .prepare(
                    "SELECT op, record_id, old_json, new_json \
                     FROM _system_record_history ORDER BY id",
                )
                .unwrap();
            stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        };
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].0, "insert");
        assert_eq!(rows[0].1, 1);
        assert!(rows[0].2.is_none());
        let new: serde_json::Value = serde_json::from_str(rows[0].3.as_deref().unwrap()).unwrap();
        assert_eq!(new["body"], "a");
        assert_eq!(new["id"].as_i64(), Some(1), "IPK column carries the rowid");
        assert_eq!(
            new["data"],
            serde_json::json!({"__blob_bytes": 2}),
            "BLOB projects as __blob_bytes"
        );
        assert_eq!(rows[1].0, "update");
        let old: serde_json::Value = serde_json::from_str(rows[1].2.as_deref().unwrap()).unwrap();
        let new: serde_json::Value = serde_json::from_str(rows[1].3.as_deref().unwrap()).unwrap();
        assert_eq!(old["body"], "a");
        assert_eq!(new["body"], "b");
        assert_eq!(rows[2].0, "delete");
        assert!(rows[2].3.is_none());

        // Post-removal writes are NOT captured.
        c.execute_batch("INSERT INTO notes (id, body) VALUES (2, 'later');")
            .unwrap();
        assert_eq!(flush_captured(&c, &buf, &actor).unwrap(), 0);
    }

    #[test]
    fn preupdate_capture_skips_system_and_gate_off_tables() {
        let c = hist_conn();
        c.execute_batch(
            "CREATE TABLE _system_collection_meta (collection_name TEXT PRIMARY KEY, audit_enabled INTEGER NOT NULL DEFAULT 1);
             CREATE TABLE loud (id INTEGER PRIMARY KEY, x TEXT);
             CREATE TABLE quiet (id INTEGER PRIMARY KEY, x TEXT);
             INSERT INTO _system_collection_meta (collection_name, audit_enabled) VALUES ('quiet', 0);",
        )
        .unwrap();
        let buf = install_preupdate_capture(&c).unwrap();
        c.execute_batch(
            "INSERT INTO loud (id, x) VALUES (1, 'a');
             INSERT INTO quiet (id, x) VALUES (1, 'b');
             INSERT INTO _system_collection_meta (collection_name, audit_enabled) VALUES ('other', 1);",
        )
        .unwrap();
        remove_preupdate_capture(&c).unwrap();
        {
            let g = buf.lock().unwrap();
            assert_eq!(
                g.changes.len(),
                2,
                "_system_* writes never enter the buffer"
            );
        }
        let n = flush_captured(&c, &buf, &AuditActor::service()).unwrap();
        assert_eq!(n, 1, "gate-off table's rows dropped at flush");
        let coll: String = c
            .query_row("SELECT collection FROM _system_record_history", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(coll, "loud");
    }

    #[test]
    fn from_auth_ctx_maps_all_roles() {
        use crate::auth::middleware::AuthCtx;
        let anon = AuditActor::from_auth_ctx(&AuthCtx::Anon);
        assert_eq!(anon.kind, "anon");
        assert_eq!(anon.hint, None, "anon carries no token hint");
        let svc = AuditActor::from_auth_ctx(&AuthCtx::Service { admin_id: Some(3) });
        assert_eq!(svc.id.as_deref(), Some("3"));
        assert_eq!(svc.hint, None, "service attribution rides id, not hint");
        let u = AuditActor::from_auth_ctx(&AuthCtx::User {
            user_id: "u9".into(),
            token_hash: "abcdef0123456789deadbeef".into(),
        });
        assert_eq!(u.kind, "user");
        assert_eq!(u.id.as_deref(), Some("u9"));
        assert_eq!(
            u.hint.as_deref(),
            Some("abcdef012345"),
            "user hint = first 12 chars of token_hash"
        );
        // token_hash shorter than 12 chars → whole string, never panic.
        let short = AuditActor::from_auth_ctx(&AuthCtx::User {
            user_id: "u9".into(),
            token_hash: "x".into(),
        });
        assert_eq!(short.hint.as_deref(), Some("x"));
    }
}
