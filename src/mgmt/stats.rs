//! Tenant-stats denormalization sampler.
//!
//! Periodically populates `meta.sqlite.tenants.{db_bytes, files_bytes,
//! stats_updated_at}` so `/admin/tenants` can render without opening
//! per-tenant SQLite files on every request. See
//! `docs/superpowers/specs/2026-05-17-drust-tenant-stats-denormalization-design.md`.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::MissedTickBehavior;

use crate::storage::tenant_db;

/// Sample one tenant's stats and persist into `meta.sqlite.tenants`.
///
/// Returns `(db_bytes, files_bytes)` so callers (notably
/// `make_tenant_inner`) can use the values directly without a follow-up
/// query.
pub async fn sample_one(
    meta: &Arc<Mutex<rusqlite::Connection>>,
    data_root: &Path,
    tenant_id: &str,
) -> (i64, i64) {
    let db_path = tenant_db::tenant_dir(data_root, tenant_id).join("data.sqlite");
    let db_bytes: i64 = std::fs::metadata(&db_path)
        .map(|m| m.len() as i64)
        .unwrap_or(0);
    let files_bytes: i64 = tenant_db::open_read(data_root, tenant_id)
        .ok()
        .and_then(|c| {
            c.query_row(
                "SELECT COALESCE(SUM(size_bytes), 0) FROM _system_files",
                [],
                |r| r.get::<_, i64>(0),
            )
            .ok()
        })
        .unwrap_or(0);
    let now = chrono::Utc::now().to_rfc3339();
    let conn = meta.lock().await;
    let _ = conn.execute(
        "UPDATE tenants SET db_bytes = ?1, files_bytes = ?2, stats_updated_at = ?3 \
         WHERE id = ?4",
        rusqlite::params![db_bytes, files_bytes, now, tenant_id],
    );
    (db_bytes, files_bytes)
}

/// Sample every non-deleted tenant once.
///
/// Errors per tenant are logged and skipped so one bad tenant doesn't
/// poison the rest.
pub async fn sample_all(meta: &Arc<Mutex<rusqlite::Connection>>, data_root: &Path) {
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
    for id in ids {
        sample_one(meta, data_root, &id).await;
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
    data_root: std::path::PathBuf,
    interval_secs: u64,
) {
    if interval_secs == 0 {
        tracing::info!("stats sampler disabled (DRUST_STATS_SAMPLE_INTERVAL_SECS=0)");
        return;
    }
    tracing::info!(interval_secs, "stats sampler started");
    sample_all(&meta, &data_root).await;
    let mut tick = tokio::time::interval(Duration::from_secs(interval_secs));
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    // consume the auto-fired first tick from interval()
    tick.tick().await;
    loop {
        tick.tick().await;
        sample_all(&meta, &data_root).await;
    }
}
