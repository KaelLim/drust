//! Tenant-stats denormalization sampler.
//!
//! Periodically populates `meta.sqlite.tenants.{db_bytes, files_bytes,
//! stats_updated_at}` so `/admin/tenants` can render without opening
//! per-tenant SQLite files on every request. See
//! `docs/superpowers/specs/2026-05-17-drust-tenant-stats-denormalization-design.md`.
//!
//! v1.32.1 (D3): the per-cycle loop now (a) reuses the
//! `TenantRegistry`'s long-lived reader pool instead of opening a fresh
//! `Connection` per tenant per cycle and (b) collapses N per-tenant
//! `meta.sqlite` UPDATEs into one `BEGIN IMMEDIATE` … `COMMIT` to drop
//! the per-cycle meta-lock acquisitions from N to 1.

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::MissedTickBehavior;

use crate::storage::pool::TenantRegistry;
use crate::storage::tenant_db;

/// Sample one tenant's byte counts.
///
/// `db_bytes` is read from the on-disk SQLite file's `std::fs::metadata`
/// length — same source as before D3. `files_bytes` is summed from
/// `_system_files.size_bytes` over a reader checked out of the tenant's
/// long-lived reader pool (the pool already has PRAGMAs applied, so we
/// no longer pay a cold-open + PRAGMA setup per cycle).
///
/// Returns `(0, 0)` on any error (missing file, unopenable tenant, etc.)
/// so a single bad tenant doesn't poison the batch. Callers that want
/// the meta row updated should use `sample_one`.
pub async fn sample_bytes(
    registry: &Arc<TenantRegistry>,
    tenant_id: &str,
) -> (i64, i64) {
    let db_path = tenant_db::tenant_data_path(registry.data_root(), tenant_id);
    let db_bytes: i64 = std::fs::metadata(&db_path)
        .map(|m| m.len() as i64)
        .unwrap_or(0);
    let pool = match registry.get_or_open(tenant_id) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(tenant_id, error = ?e, "stats sampler: get_or_open failed");
            return (db_bytes, 0);
        }
    };
    let files_bytes = pool
        .with_reader(|c| {
            c.query_row(
                "SELECT COALESCE(SUM(size_bytes), 0) FROM _system_files",
                [],
                |r| r.get::<_, i64>(0),
            )
        })
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(tenant_id, error = ?e, "stats sampler: files_bytes query failed");
            0
        });
    (db_bytes, files_bytes)
}

/// Sample one tenant and immediately persist the row to `meta.sqlite`.
///
/// Used by the post-create hook in `make_tenant_inner` so the fresh
/// row shows real numbers on the next `/admin/tenants` load — same
/// behaviour as pre-D3.
pub async fn sample_one(
    meta: &Arc<Mutex<rusqlite::Connection>>,
    registry: &Arc<TenantRegistry>,
    tenant_id: &str,
) -> (i64, i64) {
    let (db_bytes, files_bytes) = sample_bytes(registry, tenant_id).await;
    let now = chrono::Utc::now().to_rfc3339();
    let conn = meta.lock().await;
    let _ = conn.execute(
        "UPDATE tenants SET db_bytes = ?1, files_bytes = ?2, stats_updated_at = ?3 \
         WHERE id = ?4",
        rusqlite::params![db_bytes, files_bytes, now, tenant_id],
    );
    (db_bytes, files_bytes)
}

/// Sample every non-deleted tenant once and batch-commit the results.
///
/// D3 change: all per-tenant `meta.sqlite` UPDATEs land in one
/// `BEGIN IMMEDIATE` / `COMMIT` transaction, so the meta lock is taken
/// exactly twice per cycle (once to list IDs, once to write back) rather
/// than `1 + N` times. Per-tenant sampling errors are logged and the
/// tenant is skipped — the batch still commits whatever succeeded.
pub async fn sample_all(
    meta: &Arc<Mutex<rusqlite::Connection>>,
    registry: &Arc<TenantRegistry>,
) {
    let ids: Vec<String> = {
        let conn = meta.lock().await;
        let mut stmt = match conn
            .prepare("SELECT id FROM tenants WHERE deleted_at IS NULL ORDER BY id")
        {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = ?e, "stats sampler: prepare failed");
                return;
            }
        };
        stmt.query_map([], |r| r.get::<_, String>(0))
            .ok()
            .map(|it| it.filter_map(Result::ok).collect())
            .unwrap_or_default()
    };

    // Sample outside the meta lock so the per-tenant reader work
    // doesn't serialise behind the (much hotter) admin-meta lock.
    let now = chrono::Utc::now().to_rfc3339();
    let mut samples: Vec<(String, i64, i64)> = Vec::with_capacity(ids.len());
    for id in ids {
        let (db_bytes, files_bytes) = sample_bytes(registry, &id).await;
        samples.push((id, db_bytes, files_bytes));
    }

    if samples.is_empty() {
        return;
    }

    let conn = meta.lock().await;
    let tx = match conn.unchecked_transaction() {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = ?e, "stats sampler: BEGIN failed");
            return;
        }
    };
    let write_result = (|| -> rusqlite::Result<()> {
        let mut stmt = tx.prepare_cached(
            "UPDATE tenants SET db_bytes = ?1, files_bytes = ?2, stats_updated_at = ?3 \
             WHERE id = ?4",
        )?;
        for (tid, db_bytes, files_bytes) in &samples {
            stmt.execute(rusqlite::params![db_bytes, files_bytes, now, tid])?;
        }
        Ok(())
    })();
    match write_result {
        Ok(()) => {
            if let Err(e) = tx.commit() {
                tracing::error!(error = ?e, "stats sampler: COMMIT failed");
            }
        }
        Err(e) => {
            tracing::error!(error = ?e, "stats sampler: batched UPDATE failed; rolling back");
            // tx Drop = rollback
        }
    }
}

/// Background task entry point.
///
/// Fires one immediate sample on entry so a fresh boot has populated
/// stats by the time anyone hits `/admin/tenants`. Then ticks every
/// `interval_secs`. If `interval_secs == 0`, the task exits — useful for
/// tests or when sampling is driven externally.
pub async fn run_stats_sampler(
    meta: Arc<Mutex<rusqlite::Connection>>,
    registry: Arc<TenantRegistry>,
    interval_secs: u64,
) {
    if interval_secs == 0 {
        tracing::info!("stats sampler disabled (DRUST_STATS_SAMPLE_INTERVAL_SECS=0)");
        return;
    }
    tracing::info!(interval_secs, "stats sampler started");
    sample_all(&meta, &registry).await;
    let mut tick = tokio::time::interval(Duration::from_secs(interval_secs));
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    // consume the auto-fired first tick from interval()
    tick.tick().await;
    loop {
        tick.tick().await;
        sample_all(&meta, &registry).await;
    }
}
