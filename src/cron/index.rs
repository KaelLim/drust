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
    /// Per-tenant reload serialization. `reload` is read-then-insert with an
    /// await between; without this lock two concurrent reloads could commit
    /// an OLDER snapshot last, silently dropping the newest job until the
    /// next reload/restart.
    locks: dashmap::DashMap<String, Arc<tokio::sync::Mutex<()>>>,
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
            locks: dashmap::DashMap::new(),
        }
    }

    /// Reload one tenant's entry from its DB: ACTIVE jobs only; an empty
    /// result (or a read error — fail closed, logged) removes the entry.
    /// Reader lane only: never creates the cron tables.
    ///
    /// Reloads for the same tenant are serialized: the DB read happens under
    /// the same per-tenant lock as the map write, so the last writer always
    /// observed the newest DB state (no lost-update between concurrent
    /// reloads).
    pub async fn reload(&self, tenant: &str, pool: &SharedTenantPool) {
        let lock = self.locks.entry(tenant.to_string()).or_default().clone();
        let _guard = lock.lock().await;
        let jobs = match pool.with_reader(store::list_jobs_reader).await {
            Ok(jobs) => jobs,
            Err(e) => {
                tracing::warn!(tenant = %tenant, err = ?e, "cron index reload failed; clearing tenant entry");
                Vec::new()
            }
        };
        self.apply_jobs(tenant, jobs);
    }

    /// Shared jobs→entry mapping for `reload` and `boot_scan`: keep ACTIVE
    /// jobs only; an empty result removes the tenant's entry. Callers hold
    /// the per-tenant reload lock so read-then-apply stays atomic.
    fn apply_jobs(&self, tenant: &str, jobs: Vec<store::CronJob>) {
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
    ///
    /// Takes the SAME per-tenant lock as `reload`: a reload already in
    /// flight at soft-delete time would otherwise re-insert the entry AFTER
    /// this removal — a ghost entry spawning a skipped fire every due minute
    /// until restart. Serialized, either the reload finishes first and this
    /// removes its entry for good, or the reload runs after — it re-reads a
    /// renamed/gone DB, fails closed, and leaves the entry absent. The
    /// locks-map entry is removed too: in-flight holders keep their `Arc`
    /// clone, and a later reload lazily recreates it.
    pub async fn invalidate(&self, tenant: &str) {
        let lock = self.locks.entry(tenant.to_string()).or_default().clone();
        let _guard = lock.lock().await;
        self.map.remove(tenant);
        self.locks.remove(tenant);
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
    /// `data.sqlite` is gone (a live meta row must not re-create the file),
    /// then read each through a TRANSIENT read-only connection. The registry
    /// is a parameter for `data_root()` ONLY — `get_or_open` would cache
    /// every live tenant's full pool (writer + readers) forever, regressing
    /// the lazy-on-first-request pool opens (v1.47 behavior).
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
            // Same per-tenant lock as `reload`: a mutation-driven reload
            // racing the boot scan must not be overwritten by a stale read.
            let lock = self.locks.entry(tid.clone()).or_default().clone();
            let _guard = lock.lock().await;
            let jobs = match rusqlite::Connection::open_with_flags(
                &p,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )
            .and_then(|c| store::list_jobs_reader(&c))
            {
                Ok(jobs) => jobs,
                Err(e) => {
                    tracing::warn!(tenant = %tid, err = ?e, "cron boot scan: transient read failed; skipping tenant");
                    continue;
                }
            };
            self.apply_jobs(&tid, jobs);
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

    /// Lost-update race: two concurrent reloads read-then-insert with an
    /// await between, so an OLDER snapshot can be committed last and the
    /// newest job silently vanishes from the index. With per-tenant reload
    /// serialization this is deterministic: every reload reads under the
    /// lock, so whichever reload runs last observed the final DB state.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn concurrent_reloads_never_lose_the_newest_job() {
        let (registry, tenant, _tmp) = test_registry_with_tenant();
        let pool = registry.get_or_open(&tenant).unwrap();
        let idx = Arc::new(CronIndex::new());
        let mut handles = Vec::new();
        for i in 0..8 {
            let pool = pool.clone();
            let idx = idx.clone();
            let tenant = tenant.clone();
            handles.push(tokio::spawn(async move {
                let name = format!("j{i}");
                pool.with_writer(move |c| {
                    crate::cron::store::create_job(
                        c,
                        &name,
                        "* * * * *",
                        "function",
                        "f",
                        None,
                        true,
                    )
                })
                .await
                .unwrap();
                idx.reload(&tenant, &pool).await;
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        let snap = idx.snapshot();
        assert_eq!(snap.len(), 1);
        let names: std::collections::HashSet<&str> =
            snap[0].1.iter().map(|j| j.name.as_str()).collect();
        for i in 0..8 {
            let name = format!("j{i}");
            assert!(
                names.contains(name.as_str()),
                "job {name} lost from index after concurrent reloads; indexed: {names:?}"
            );
        }
    }

    /// In-memory "meta" connection with the shape `boot_scan` queries,
    /// seeded with one live tenant row.
    fn test_meta_with_tenant(tenant: &str) -> Arc<tokio::sync::Mutex<rusqlite::Connection>> {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE tenants (id TEXT PRIMARY KEY, deleted_at TEXT)")
            .unwrap();
        conn.execute(
            "INSERT INTO tenants (id) VALUES (?1)",
            rusqlite::params![tenant],
        )
        .unwrap();
        Arc::new(tokio::sync::Mutex::new(conn))
    }

    /// Boot scan must populate the index from disk WITHOUT opening tenant
    /// pools — v1.47 opened pools lazily on first request, and the boot
    /// scan must not regress that by warming every live tenant's pool.
    #[tokio::test]
    async fn boot_scan_populates_index_via_transient_reads_not_pool_cache() {
        let (registry, tenant, _tmp) = test_registry_with_tenant();
        let pool = registry.get_or_open(&tenant).unwrap();
        pool.with_writer(|c| {
            crate::cron::store::create_job(c, "boot", "* * * * *", "function", "f", None, true)
        })
        .await
        .unwrap();
        // Fresh registry over the same data root: boot-time state, no pools open.
        let boot_registry = Arc::new(TenantRegistry::new(registry.data_root().to_path_buf(), 2));
        let idx = CronIndex::new();
        idx.boot_scan(test_meta_with_tenant(&tenant), boot_registry.clone())
            .await;
        let snap = idx.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].0, tenant);
        assert_eq!(snap[0].1.len(), 1);
        assert_eq!(snap[0].1[0].name, "boot");
        assert_eq!(
            boot_registry.cached_count(),
            0,
            "boot scan must read via transient connections, not cache tenant pools"
        );
    }

    /// Transient-read property: scanning a tenant that never used cron must
    /// neither create `_system_cron_jobs` nor cache the tenant's pool.
    #[tokio::test]
    async fn boot_scan_on_cronless_tenant_creates_no_tables_and_caches_no_pool() {
        let (registry, tenant, _tmp) = test_registry_with_tenant();
        let boot_registry = Arc::new(TenantRegistry::new(registry.data_root().to_path_buf(), 2));
        let idx = CronIndex::new();
        idx.boot_scan(test_meta_with_tenant(&tenant), boot_registry.clone())
            .await;
        assert!(idx.snapshot().is_empty());
        assert_eq!(
            boot_registry.cached_count(),
            0,
            "boot scan must not cache tenant pools"
        );
        let p = registry
            .data_root()
            .join("tenants")
            .join(&tenant)
            .join("data.sqlite");
        let c =
            rusqlite::Connection::open_with_flags(&p, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .unwrap();
        let has: i64 = c
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE name='_system_cron_jobs'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(has, 0, "boot scan must not create cron tables");
    }

    /// Ghost-entry race: `invalidate` must take the SAME per-tenant lock
    /// `reload` uses, otherwise a reload already in flight at soft-delete
    /// time can re-insert the entry AFTER invalidate removed it.
    /// Deterministic interleave: with the tenant's reload lock held
    /// (simulating an in-flight reload), a spawned `invalidate` must block
    /// and the entry must stay present; once the lock is released it
    /// completes, the entry is gone, and the locks-map entry is dropped too.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn invalidate_blocks_on_reload_lock_then_removes_entry_and_lock() {
        let (registry, tenant, _tmp) = test_registry_with_tenant();
        let pool = registry.get_or_open(&tenant).unwrap();
        pool.with_writer(|c| {
            crate::cron::store::create_job(c, "ghost", "* * * * *", "function", "f", None, true)
        })
        .await
        .unwrap();
        let idx = Arc::new(CronIndex::new());
        idx.reload(&tenant, &pool).await;
        assert_eq!(idx.snapshot().len(), 1);

        // Hold the tenant's reload lock, as an in-flight `reload` would.
        let lock = idx.locks.entry(tenant.clone()).or_default().clone();
        let guard = lock.lock().await;

        let idx2 = idx.clone();
        let t2 = tenant.clone();
        let handle = tokio::spawn(async move { idx2.invalidate(&t2).await });

        // invalidate must block behind the held lock: entry stays visible.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(
            !handle.is_finished(),
            "invalidate must block while the reload lock is held"
        );
        assert_eq!(
            idx.snapshot().len(),
            1,
            "entry must not be removed while the reload lock is held"
        );

        drop(guard);
        handle.await.unwrap();
        assert!(
            idx.snapshot().is_empty(),
            "invalidate must remove the entry once it acquires the lock"
        );
        assert!(
            !idx.locks.contains_key(&tenant),
            "invalidate must drop the locks-map entry too"
        );
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
