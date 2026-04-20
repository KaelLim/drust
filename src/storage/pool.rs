use crate::storage::tenant_db::{open_read, open_write};
use rusqlite::Connection;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{Mutex, Semaphore};

pub struct TenantPool {
    data_root: PathBuf,
    tenant_id: String,
    writer: Mutex<Connection>,
    readers: Vec<Mutex<Connection>>,
    reader_sema: Semaphore,
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
        Self { data_root, read_pool_size, pools: dashmap::DashMap::new() }
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
}
