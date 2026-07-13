//! In-memory schedule index: tenant id → that tenant's ACTIVE cron jobs.
//!
//! Invalidate-on-write like the auth cache / binding cache family:
//! **every mutation site calls `reload(tenant, pool)` after commit** (not just
//! `invalidate`) so a created/enabled job starts firing without a restart.
//! The scheduler's fire-time re-assert (`scheduler::run_due_job`) is the
//! fail-closed net for staleness in the other direction — a stale entry can
//! at worst trigger a re-read that finds the job gone/disabled and does
//! nothing.
//!
//! Reads go through the reader lane ONLY (`store::list_jobs_reader`), which
//! tolerates the tables not existing — a tenant that never used cron must not
//! grow `_system_cron_*` tables from an index reload or the boot scan.

use crate::cron::store;
use crate::storage::pool::{SharedTenantPool, TenantRegistry};
use std::sync::Arc;

/// The subset of a `store::CronJob` the scheduler needs to decide and
/// dispatch a fire. `last_*` / timestamps stay in the DB — the fire-time
/// re-assert re-reads the row anyway.
#[derive(Clone, Debug)]
pub struct IndexedJob {
    pub id: i64,
    pub name: String,
    pub schedule: String,
    pub target_kind: String,
    pub target_name: String,
    pub payload_json: Option<String>,
}

/// tenant id → `Arc` snapshot of that tenant's active jobs. Entries only
/// exist for tenants with ≥1 active job, so the minute tick's `snapshot()`
/// is proportional to cron adoption, not tenant count.
pub struct CronIndex {
    map: dashmap::DashMap<String, Arc<Vec<IndexedJob>>>,
}

impl Default for CronIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl CronIndex {
    pub fn new() -> Self {
        Self {
            map: dashmap::DashMap::new(),
        }
    }

    /// Reload one tenant's entry from its DB: ACTIVE jobs only; an empty
    /// result (or a read error — fail closed, logged) removes the entry.
    /// Reader lane only: never creates the cron tables.
    pub async fn reload(&self, tenant: &str, pool: &SharedTenantPool) {
        let jobs = match pool.with_reader(store::list_jobs_reader).await {
            Ok(jobs) => jobs,
            Err(e) => {
                tracing::warn!(tenant = %tenant, err = ?e, "cron index reload failed; clearing tenant entry");
                Vec::new()
            }
        };
        let active: Vec<IndexedJob> = jobs
            .into_iter()
            .filter(|j| j.active)
            .map(|j| IndexedJob {
                id: j.id,
                name: j.name,
                schedule: j.schedule,
                target_kind: j.target_kind,
                target_name: j.target_name,
                payload_json: j.payload_json,
            })
            .collect();
        if active.is_empty() {
            self.map.remove(tenant);
        } else {
            self.map.insert(tenant.to_string(), Arc::new(active));
        }
    }

    /// Drop a tenant's entry outright (tenant soft-delete path — the DB is
    /// gone/moving, so there is nothing to reload from).
    pub fn invalidate(&self, tenant: &str) {
        self.map.remove(tenant);
    }

    /// Point-in-time copy for the minute tick. Cheap: clones the `Arc`s,
    /// not the job vectors.
    pub fn snapshot(&self) -> Vec<(String, Arc<Vec<IndexedJob>>)> {
        self.map
            .iter()
            .map(|e| (e.key().clone(), e.value().clone()))
            .collect()
    }

    /// Boot: populate the index from every live tenant. Iteration mirrors
    /// `record_history::spawn_retention_task` — enumerate
    /// `tenants WHERE deleted_at IS NULL` from meta, skip tenants whose
    /// `data.sqlite` is gone (a live meta row must not re-create the file
    /// via the pool open), then `reload` each through the reader lane.
    pub async fn boot_scan(
        &self,
        meta: Arc<tokio::sync::Mutex<rusqlite::Connection>>,
        registry: Arc<TenantRegistry>,
    ) {
        let ids: Vec<String> = {
            let conn = meta.lock().await;
            conn.prepare("SELECT id FROM tenants WHERE deleted_at IS NULL")
                .and_then(|mut s| {
                    s.query_map([], |r| r.get::<_, String>(0))
                        .and_then(|it| it.collect())
                })
                .unwrap_or_default()
        };
        for tid in ids {
            let p = registry
                .data_root()
                .join("tenants")
                .join(&tid)
                .join("data.sqlite");
            if !p.exists() {
                continue;
            }
            match registry.get_or_open(&tid) {
                Ok(pool) => self.reload(&tid, &pool).await,
                Err(e) => {
                    tracing::warn!(tenant = %tid, err = ?e, "cron boot scan: pool open failed")
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::pool::TenantRegistry;
    use std::sync::Arc;

    /// Fresh registry over a tempdir with one opened tenant. `get_or_open`
    /// runs `open_write` → standard `_system_*` schema, NO cron tables (those
    /// are lazy, created only by cron writer fns).
    fn test_registry_with_tenant() -> (Arc<TenantRegistry>, String, tempfile::TempDir) {
        let tmp = tempfile::TempDir::new().unwrap();
        let registry = Arc::new(TenantRegistry::new(tmp.path().to_path_buf(), 2));
        let tenant = "t-cron-index".to_string();
        registry.get_or_open(&tenant).unwrap();
        (registry, tenant, tmp)
    }

    #[tokio::test]
    async fn reload_indexes_only_active_jobs_and_empty_removes() {
        let (registry, tenant, _tmp) = test_registry_with_tenant();
        let pool = registry.get_or_open(&tenant).unwrap();
        pool.with_writer(|c| {
            crate::cron::store::create_job(c, "on", "* * * * *", "function", "f", None, true)?;
            crate::cron::store::create_job(c, "off", "* * * * *", "function", "f", None, false)
        })
        .await
        .unwrap();
        let idx = CronIndex::new();
        idx.reload(&tenant, &pool).await;
        let snap = idx.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].0, tenant);
        assert_eq!(snap[0].1.len(), 1);
        assert_eq!(snap[0].1[0].name, "on");
        // Deactivate the last active job → reload empties the tenant entry.
        pool.with_writer(|c| crate::cron::store::update_job(c, "on", None, None, Some(false)))
            .await
            .unwrap();
        idx.reload(&tenant, &pool).await;
        assert!(idx.snapshot().is_empty());
    }

    #[tokio::test]
    async fn reload_on_cronless_tenant_is_noop_and_creates_no_tables() {
        let (registry, tenant, _tmp) = test_registry_with_tenant();
        let pool = registry.get_or_open(&tenant).unwrap();
        let idx = CronIndex::new();
        idx.reload(&tenant, &pool).await;
        assert!(idx.snapshot().is_empty());
        let has: i64 = pool
            .with_reader(|c| {
                c.query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE name='_system_cron_jobs'",
                    [],
                    |r| r.get(0),
                )
            })
            .await
            .unwrap();
        assert_eq!(has, 0, "reader path must not create tables");
    }
}
