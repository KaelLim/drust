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
            AuthCtx::User { user_id, .. } => AuditActor {
                kind: "user",
                id: Some(user_id.clone()),
                hint: None,
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
    fn from_auth_ctx_maps_all_roles() {
        use crate::auth::middleware::AuthCtx;
        assert_eq!(AuditActor::from_auth_ctx(&AuthCtx::Anon).kind, "anon");
        assert_eq!(
            AuditActor::from_auth_ctx(&AuthCtx::Service { admin_id: Some(3) })
                .id
                .as_deref(),
            Some("3")
        );
        let u = AuditActor::from_auth_ctx(&AuthCtx::User {
            user_id: "u9".into(),
            token_hash: "x".into(),
        });
        assert_eq!(u.kind, "user");
        assert_eq!(u.id.as_deref(), Some("u9"));
    }
}
