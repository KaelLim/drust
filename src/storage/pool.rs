use crate::storage::schema_cache::SchemaCache;
use crate::storage::tenant_db::{open_read, open_write};
use rusqlite::{Connection, Transaction};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::{Mutex, Semaphore};

/// Run a bounded `PRAGMA optimize` on the long-lived writer connection once
/// every N successful writes. The writer connection never returns to a pool,
/// so there is no natural "connection close" moment to hook optimize onto;
/// a per-pool write counter drives it instead. `analysis_limit = 400`
/// (set in `apply_common_pragmas`) bounds each run's cost.
const DRUST_OPTIMIZE_EVERY: u64 = 1000;

pub struct TenantPool {
    data_root: PathBuf,
    tenant_id: String,
    writer: Mutex<Connection>,
    readers: Vec<Mutex<Connection>>,
    reader_sema: Semaphore,
    /// Monotonic count of successful writes through `with_writer` /
    /// `with_writer_tx`. Drives the periodic `PRAGMA optimize`.
    write_count: AtomicU64,
    /// Test/debug-only observability: how many times `PRAGMA optimize` fired.
    #[cfg(any(test, debug_assertions))]
    optimize_runs: AtomicU64,
    /// Per-tenant in-process schema cache. Populated lazily by handlers
    /// that look up collection metadata; invalidated by DDL paths and
    /// the anon_caps admin endpoint.
    pub schema_cache: SchemaCache,
}

impl TenantPool {
    pub fn new(data_root: PathBuf, tenant_id: &str, read_pool_size: usize) -> anyhow::Result<Self> {
        let writer = open_write(&data_root, tenant_id)?;
        let mut readers = Vec::with_capacity(read_pool_size);
        for _ in 0..read_pool_size {
            readers.push(Mutex::new(open_read(&data_root, tenant_id)?));
        }
        Ok(Self {
            data_root,
            tenant_id: tenant_id.to_string(),
            writer: Mutex::new(writer),
            readers,
            reader_sema: Semaphore::new(read_pool_size),
            write_count: AtomicU64::new(0),
            #[cfg(any(test, debug_assertions))]
            optimize_runs: AtomicU64::new(0),
            schema_cache: SchemaCache::new(),
        })
    }

    /// How many times `PRAGMA optimize` has fired on this pool's writer.
    /// Test/observability hook (test+debug builds only).
    #[cfg(any(test, debug_assertions))]
    pub fn optimize_runs(&self) -> u64 {
        self.optimize_runs.load(Ordering::Relaxed)
    }

    /// Bump the write counter and, every `DRUST_OPTIMIZE_EVERY` writes, run a
    /// bounded `PRAGMA optimize` on the (already-locked) writer connection.
    /// Best-effort: optimize errors are swallowed — a failed maintenance run
    /// must never fail the write that triggered it.
    fn note_write_and_maybe_optimize(&self, conn: &Connection) {
        let n = self.write_count.fetch_add(1, Ordering::Relaxed) + 1;
        if n.is_multiple_of(DRUST_OPTIMIZE_EVERY) {
            let _ = conn.execute_batch("PRAGMA optimize;");
            #[cfg(any(test, debug_assertions))]
            self.optimize_runs.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn data_root(&self) -> &std::path::Path {
        &self.data_root
    }

    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    pub async fn with_writer<F, T>(&self, f: F) -> rusqlite::Result<T>
    where
        F: FnOnce(&mut Connection) -> rusqlite::Result<T> + Send,
        T: Send,
    {
        let mut g = self.writer.lock().await;
        let v = f(&mut g)?;
        // Successful write: bump counter, maybe run bounded PRAGMA optimize
        // on the still-locked connection.
        self.note_write_and_maybe_optimize(&g);
        Ok(v)
    }

    /// Like `with_writer`, but the closure receives a `&Transaction`. The
    /// transaction commits on `Ok`, rolls back on `Err` (or panic — rusqlite's
    /// `Transaction::drop` is rollback-by-default). Use this for any
    /// multi-statement write where partial-commit would leave a half-state
    /// (collection-without-meta, record-without-readback, etc.).
    ///
    /// Single-statement writes can stay on `with_writer` for the smaller API
    /// surface — both helpers acquire the same per-tenant writer mutex.
    /// A failed `commit()` also returns `Err`; SQLite rolls the transaction
    /// back internally in that case.
    pub async fn with_writer_tx<F, T>(&self, f: F) -> rusqlite::Result<T>
    where
        F: for<'a> FnOnce(&'a Transaction<'a>) -> rusqlite::Result<T> + Send,
        T: Send,
    {
        let mut g = self.writer.lock().await;
        let tx = g.transaction()?;
        match f(&tx) {
            Ok(v) => {
                tx.commit()?;
                // Commit returned and `tx` is consumed, so the connection is
                // no longer borrowed — run the bounded PRAGMA optimize on it
                // while the writer mutex is still held.
                self.note_write_and_maybe_optimize(&g);
                Ok(v)
            }
            Err(e) => {
                // Explicit drop runs Transaction::drop = rollback.
                drop(tx);
                Err(e)
            }
        }
    }

    pub async fn with_reader<F, T>(&self, f: F) -> rusqlite::Result<T>
    where
        F: FnOnce(&Connection) -> rusqlite::Result<T> + Send,
        T: Send,
    {
        let _permit = self.reader_sema.acquire().await.expect("semaphore closed");
        for slot in &self.readers {
            if let Ok(g) = slot.try_lock() {
                return f(&g);
            }
        }
        // All readers busy? Wait on the first one (rare, semaphore should prevent this).
        let g = self.readers[0].lock().await;
        f(&g)
    }
}

pub type SharedTenantPool = Arc<TenantPool>;

pub struct TenantRegistry {
    data_root: PathBuf,
    read_pool_size: usize,
    pools: dashmap::DashMap<String, SharedTenantPool>,
}

impl TenantRegistry {
    pub fn new(data_root: PathBuf, read_pool_size: usize) -> Self {
        Self {
            data_root,
            read_pool_size,
            pools: dashmap::DashMap::new(),
        }
    }

    pub fn data_root(&self) -> &std::path::Path {
        &self.data_root
    }

    pub fn get_or_open(&self, tenant_id: &str) -> anyhow::Result<SharedTenantPool> {
        if let Some(p) = self.pools.get(tenant_id) {
            return Ok(p.clone());
        }
        let pool = Arc::new(TenantPool::new(
            self.data_root.clone(),
            tenant_id,
            self.read_pool_size,
        )?);
        self.pools.insert(tenant_id.to_string(), pool.clone());
        Ok(pool)
    }

    pub fn evict(&self, tenant_id: &str) {
        self.pools.remove(tenant_id);
    }

    /// How many tenant pools are currently cached. Test/observability hook.
    pub fn cached_count(&self) -> usize {
        self.pools.len()
    }
}

#[cfg(test)]
mod tx_tests {
    use super::*;
    use tempfile::TempDir;

    async fn pool() -> (TempDir, TenantPool) {
        let tmp = TempDir::new().unwrap();
        let pool = TenantPool::new(tmp.path().to_path_buf(), "txtest", 2).unwrap();
        // Seed a trivial collection so we can write to it.
        pool.with_writer(|c| {
            c.execute(
                "CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT)",
                [],
            )?;
            Ok(())
        })
        .await
        .unwrap();
        (tmp, pool)
    }

    #[tokio::test]
    async fn with_writer_tx_commits_on_ok() {
        let (_t, pool) = pool().await;
        let n: i64 = pool
            .with_writer_tx(|tx| -> rusqlite::Result<i64> {
                tx.execute(
                    "INSERT INTO kv (k, v) VALUES (?1, ?2)",
                    rusqlite::params!["a", "1"],
                )?;
                tx.execute(
                    "INSERT INTO kv (k, v) VALUES (?1, ?2)",
                    rusqlite::params!["b", "2"],
                )?;
                tx.query_row("SELECT COUNT(*) FROM kv", [], |r| r.get(0))
            })
            .await
            .unwrap();
        assert_eq!(n, 2);

        // Verify persisted through a fresh reader.
        let persisted: i64 = pool
            .with_reader(|c| c.query_row("SELECT COUNT(*) FROM kv", [], |r| r.get(0)))
            .await
            .unwrap();
        assert_eq!(persisted, 2);
    }

    #[tokio::test]
    async fn with_writer_tx_rolls_back_on_err() {
        let (_t, pool) = pool().await;
        // First insert succeeds, second is forced to fail. Whole tx must roll back.
        let res: rusqlite::Result<()> = pool
            .with_writer_tx(|tx| -> rusqlite::Result<()> {
                tx.execute(
                    "INSERT INTO kv (k, v) VALUES (?1, ?2)",
                    rusqlite::params!["a", "1"],
                )?;
                // Force a constraint failure (duplicate PK).
                tx.execute(
                    "INSERT INTO kv (k, v) VALUES (?1, ?2)",
                    rusqlite::params!["a", "DUP"],
                )?;
                Ok(())
            })
            .await;
        assert!(res.is_err(), "expected SQL constraint error, got {res:?}");

        // The first insert must NOT be visible — tx rolled back.
        let persisted: i64 = pool
            .with_reader(|c| c.query_row("SELECT COUNT(*) FROM kv", [], |r| r.get(0)))
            .await
            .unwrap();
        assert_eq!(persisted, 0, "rolled-back transaction must leave 0 rows");
    }
}
