use crate::storage::schema_cache::SchemaCache;
use crate::storage::tenant_db::{open_read, open_write};
use rusqlite::{Connection, Transaction};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{Mutex, Semaphore};

pub struct TenantPool {
    data_root: PathBuf,
    tenant_id: String,
    writer: Mutex<Connection>,
    readers: Vec<Mutex<Connection>>,
    reader_sema: Semaphore,
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
            schema_cache: SchemaCache::new(),
        })
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
        f(&mut g)
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
