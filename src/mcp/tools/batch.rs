//! M2 — batch insert (+ upsert, next task), service-only on both faces.
//!
//! Batch runs MANY rows through the SAME per-row guards as a single insert
//! (`write::insert_row_in_tx`) inside ONE `with_writer_tx`, atomically: quota
//! re-measures per row (usage reflects in-tx page growth), record-history
//! captures per row, and a mid-batch failure rolls back every data AND history
//! row. Schema read + vector pre-encode happen OUTSIDE the tx so typed errors
//! surface before the writer lock is taken.
//!
//! The write is a primitive-based `batch_insert_core` so BOTH faces reuse it:
//! the MCP `insert_records` tool (thin `batch_insert` wrapper) and the REST
//! `records:batch` handler (which has `TenantRef` + extensions, not a DrustMcp).

use crate::functions::dispatcher::FunctionDispatcher;
use crate::mcp::server::DrustMcp;
use crate::mcp::tools::write::{
    insert_row_in_tx, invalid_input, pre_encode_vectors, upsert_row_in_tx, validate_conflict_target,
};
use crate::storage::pool::SharedTenantPool;
use crate::storage::record_history::AuditActor;
use crate::storage::record_history::HistoryOp;
use crate::storage::schema::{describe_collection, is_protected_collection};
use crate::tenant::events::{Event, EventBus};
use crate::tenant::webhook_dispatcher::WebhookDispatcher;
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// MCP arg shape for `insert_records`. Mirrors REST `POST .../records:batch`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct InsertRecordsArgs {
    /// Collection name.
    pub collection: String,
    /// Rows to insert — a JSON array of objects, each an `insert_record`-shaped
    /// `data` map. All-or-nothing: any invalid row rolls back the whole batch.
    pub records: Vec<serde_json::Value>,
}

/// MCP arg shape for `upsert_records`. Mirrors REST `POST .../records:upsert`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct UpsertRecordsArgs {
    /// Collection name.
    pub collection: String,
    /// Rows to upsert — each an `insert_record`-shaped object that MUST include
    /// every `on_conflict` column. All-or-nothing: any invalid row rolls back.
    pub records: Vec<serde_json::Value>,
    /// Columns identifying the conflict target — must match a declared UNIQUE
    /// index (incl. a `UNIQUE` column) or the primary key, else `UPSERT_NO_UNIQUE`.
    pub on_conflict: Vec<String>,
}

/// Row cap per batch/upsert call — bounds tx duration + memory. Env override
/// `DRUST_BATCH_MAX_ROWS` (default 1000; non-positive/garbage → default).
pub(crate) fn batch_max_rows() -> usize {
    std::env::var("DRUST_BATCH_MAX_ROWS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(1000)
}

/// Parse `records` into object maps (typed error otherwise).
pub(crate) fn parse_rows(
    records: Vec<serde_json::Value>,
) -> anyhow::Result<Vec<serde_json::Map<String, serde_json::Value>>> {
    records
        .into_iter()
        .map(|r| {
            r.as_object().cloned().ok_or_else(|| {
                anyhow::anyhow!("BATCH_ROW_NOT_OBJECT: each record must be a JSON object")
            })
        })
        .collect()
}

/// Atomic batch insert over the raw primitives — shared by the MCP tool and the
/// REST handler. `quota_tier` is resolved by the caller (MCP: `read_tier`; REST:
/// the bearer-CTE `TenantQuotaTier` extension). Returns
/// `{"inserted":[row, ...], "count": N}`.
#[allow(clippy::too_many_arguments)]
pub async fn batch_insert_core(
    pool: &SharedTenantPool,
    tenant_id: &str,
    bus: &EventBus,
    webhooks: &Arc<WebhookDispatcher>,
    functions: Option<&Arc<FunctionDispatcher>>,
    quota_tier: i64,
    collection: &str,
    records: Vec<serde_json::Value>,
    actor: AuditActor,
) -> anyhow::Result<serde_json::Value> {
    if is_protected_collection(collection) {
        anyhow::bail!(
            "PROTECTED_COLLECTION: _system_* tables are read-only via the records tools."
        );
    }
    if records.is_empty() {
        anyhow::bail!("BATCH_EMPTY: records must contain at least one row");
    }
    let max = batch_max_rows();
    if records.len() > max {
        anyhow::bail!(
            "BATCH_TOO_LARGE: {} rows exceeds DRUST_BATCH_MAX_ROWS ({max})",
            records.len()
        );
    }
    let rows = parse_rows(records)?;

    let coll = collection.to_string();

    // Schema OUTSIDE the tx: vector fields for pre-encode + a typed early error.
    let coll_for_schema = coll.clone();
    let schema = pool
        .with_reader(move |c| describe_collection(c, &coll_for_schema))
        .await?
        .ok_or_else(|| anyhow::anyhow!("unknown collection: '{}'", coll))?;
    let vector_names: HashSet<String> = schema
        .vector_fields
        .iter()
        .map(|v| v.name.clone())
        .collect();

    // owner_field required per row on an owner-scoped collection — a batch row
    // must carry a non-empty owner_field (whole batch fails otherwise). Stricter
    // than the MCP single-insert path (safer for a service bulk load).
    if let Some(of) = &schema.owner_field {
        for (i, m) in rows.iter().enumerate() {
            let ok = m
                .get(of)
                .and_then(|v| v.as_str())
                .is_some_and(|s| !s.is_empty());
            if !ok {
                anyhow::bail!(
                    "OWNER_FIELD_REQUIRED: row {i} must supply a non-empty '{of}' on owner-scoped collection '{coll}'"
                );
            }
        }
    }

    // Pre-encode vectors per row OUTSIDE the tx (typed errors before the lock).
    let mut encoded: Vec<(
        serde_json::Map<String, serde_json::Value>,
        HashMap<String, Vec<u8>>,
    )> = Vec::with_capacity(rows.len());
    for m in rows {
        let vb = pre_encode_vectors(&schema.vector_fields, &m)?;
        encoded.push((m, vb));
    }

    // ONE writer tx — all-or-nothing. Any row error rolls back every data AND
    // history row (record_history::capture runs inside this same tx).
    let coll_tx = coll.clone();
    let inserted: Vec<serde_json::Value> = pool
        .with_writer_tx(move |tx| -> rusqlite::Result<Vec<serde_json::Value>> {
            let schema_tx = describe_collection(tx, &coll_tx)?
                .ok_or_else(|| invalid_input(format!("unknown collection: '{}'", coll_tx)))?;
            let mut out = Vec::with_capacity(encoded.len());
            for (m, vb) in &encoded {
                let (_, rec) = insert_row_in_tx(
                    tx,
                    &schema_tx,
                    m,
                    vb,
                    &vector_names,
                    quota_tier,
                    None,
                    &actor,
                )?;
                out.push(rec);
            }
            Ok(out)
        })
        .await?;

    // Post-commit fan-out per row (outside the tx), mirroring single insert.
    for rec in &inserted {
        let ev = Event::Created {
            record: rec.clone(),
        };
        bus.publish(tenant_id, collection, ev.clone());
        if let Some(f) = functions {
            f.dispatch(tenant_id, collection, &ev);
        }
        webhooks.dispatch(tenant_id, collection, ev);
    }

    Ok(json!({ "inserted": inserted, "count": inserted.len() }))
}

/// MCP-facing thin wrapper: resolves the quota tier from the host state then
/// delegates to [`batch_insert_core`]. Service-identity `actor`.
pub async fn batch_insert(
    s: &DrustMcp,
    collection: &str,
    records: Vec<serde_json::Value>,
    actor: AuditActor,
) -> anyhow::Result<serde_json::Value> {
    let inner = s.inner();
    let quota_tier = match inner.meta.as_ref() {
        Some(m) => crate::storage::quota::read_tier(m, &inner.tenant_id).await,
        None => 1,
    };
    batch_insert_core(
        &inner.pool,
        &inner.tenant_id,
        &inner.bus,
        &inner.webhooks,
        inner.functions.as_ref(),
        quota_tier,
        collection,
        records,
        actor,
    )
    .await
}

/// Atomic batch UPSERT over the raw primitives — shared by the MCP tool and the
/// REST handler. `on_conflict` names the conflict-target columns (validated
/// in-tx against declared UNIQUE indexes + PK). Each row is INSERT-or-UPDATE:
/// history captures the correct per-row op, and the fan-out emits `Created` for
/// inserts / `Updated` for updates. Returns `{"results":[{op, record}], count}`
/// where `op` is `"inserted"` | `"updated"`.
#[allow(clippy::too_many_arguments)]
pub async fn batch_upsert_core(
    pool: &SharedTenantPool,
    tenant_id: &str,
    bus: &EventBus,
    webhooks: &Arc<WebhookDispatcher>,
    functions: Option<&Arc<FunctionDispatcher>>,
    quota_tier: i64,
    collection: &str,
    records: Vec<serde_json::Value>,
    on_conflict: Vec<String>,
    actor: AuditActor,
) -> anyhow::Result<serde_json::Value> {
    if is_protected_collection(collection) {
        anyhow::bail!(
            "PROTECTED_COLLECTION: _system_* tables are read-only via the records tools."
        );
    }
    if on_conflict.is_empty() {
        anyhow::bail!("UPSERT_NO_CONFLICT_COLS: on_conflict must list at least one column");
    }
    if records.is_empty() {
        anyhow::bail!("BATCH_EMPTY: records must contain at least one row");
    }
    let max = batch_max_rows();
    if records.len() > max {
        anyhow::bail!(
            "BATCH_TOO_LARGE: {} rows exceeds DRUST_BATCH_MAX_ROWS ({max})",
            records.len()
        );
    }
    let rows = parse_rows(records)?;
    let coll = collection.to_string();

    // Schema OUTSIDE the tx: vector fields for pre-encode + a typed early error.
    let coll_for_schema = coll.clone();
    let schema = pool
        .with_reader(move |c| describe_collection(c, &coll_for_schema))
        .await?
        .ok_or_else(|| anyhow::anyhow!("unknown collection: '{}'", coll))?;
    let vector_names: HashSet<String> = schema
        .vector_fields
        .iter()
        .map(|v| v.name.clone())
        .collect();

    // owner_field required per row on an owner-scoped collection (same as batch
    // insert — a service bulk write must attribute every row to a real user).
    if let Some(of) = &schema.owner_field {
        for (i, m) in rows.iter().enumerate() {
            let ok = m
                .get(of)
                .and_then(|v| v.as_str())
                .is_some_and(|s| !s.is_empty());
            if !ok {
                anyhow::bail!(
                    "OWNER_FIELD_REQUIRED: row {i} must supply a non-empty '{of}' on owner-scoped collection '{coll}'"
                );
            }
        }
    }

    // Pre-encode vectors per row OUTSIDE the tx (typed errors before the lock).
    let mut encoded: Vec<(
        serde_json::Map<String, serde_json::Value>,
        HashMap<String, Vec<u8>>,
    )> = Vec::with_capacity(rows.len());
    for m in rows {
        let vb = pre_encode_vectors(&schema.vector_fields, &m)?;
        encoded.push((m, vb));
    }

    // ONE writer tx — all-or-nothing. The conflict target is validated ONCE,
    // in-tx (authoritative vs concurrent DDL), before any row runs.
    let coll_tx = coll.clone();
    let on_conflict_tx = on_conflict.clone();
    let results: Vec<(HistoryOp, serde_json::Value)> = pool
        .with_writer_tx(
            move |tx| -> rusqlite::Result<Vec<(HistoryOp, serde_json::Value)>> {
                let schema_tx = describe_collection(tx, &coll_tx)?
                    .ok_or_else(|| invalid_input(format!("unknown collection: '{}'", coll_tx)))?;
                validate_conflict_target(tx, &coll_tx, &on_conflict_tx)?;
                let mut out = Vec::with_capacity(encoded.len());
                for (m, vb) in &encoded {
                    let (op, rec) = upsert_row_in_tx(
                        tx,
                        &schema_tx,
                        m,
                        vb,
                        &vector_names,
                        &on_conflict_tx,
                        quota_tier,
                        &actor,
                    )?;
                    out.push((op, rec));
                }
                Ok(out)
            },
        )
        .await?;

    // Post-commit fan-out per row (outside the tx) — Created for inserts,
    // Updated for updates, mirroring single insert/update.
    let mut out_rows = Vec::with_capacity(results.len());
    for (op, rec) in &results {
        let (label, ev) = match op {
            HistoryOp::Insert => (
                "inserted",
                Event::Created {
                    record: rec.clone(),
                },
            ),
            _ => (
                "updated",
                Event::Updated {
                    record: rec.clone(),
                },
            ),
        };
        bus.publish(tenant_id, collection, ev.clone());
        if let Some(f) = functions {
            f.dispatch(tenant_id, collection, &ev);
        }
        webhooks.dispatch(tenant_id, collection, ev);
        out_rows.push(json!({ "op": label, "record": rec }));
    }
    Ok(json!({ "results": out_rows, "count": out_rows.len() }))
}

/// MCP-facing thin wrapper for upsert: resolves the quota tier then delegates to
/// [`batch_upsert_core`]. Service-identity `actor`.
pub async fn batch_upsert(
    s: &DrustMcp,
    collection: &str,
    records: Vec<serde_json::Value>,
    on_conflict: Vec<String>,
    actor: AuditActor,
) -> anyhow::Result<serde_json::Value> {
    let inner = s.inner();
    let quota_tier = match inner.meta.as_ref() {
        Some(m) => crate::storage::quota::read_tier(m, &inner.tenant_id).await,
        None => 1,
    };
    batch_upsert_core(
        &inner.pool,
        &inner.tenant_id,
        &inner.bus,
        &inner.webhooks,
        inner.functions.as_ref(),
        quota_tier,
        collection,
        records,
        on_conflict,
        actor,
    )
    .await
}
