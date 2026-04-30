use crate::storage::schema::{CollectionSchema, describe_collection};
use rusqlite::Connection;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// In-process per-tenant schema cache. Each tenant gets one of these,
/// stored on `TenantPool` (the per-tenant connection-pool struct in
/// `crate::storage::pool`). Lookups are amortised RwLock reads;
/// invalidations are write-locks but DDL is rare.
///
/// The cache speaks the same `CollectionSchema` type as
/// `describe_collection` so callers can use it as a drop-in.
#[derive(Clone, Default)]
pub struct SchemaCache {
    inner: Arc<RwLock<HashMap<String, CollectionSchema>>>,
}

impl SchemaCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Read a cached schema. Returns `None` if not present — caller
    /// should fall back to `ensure_loaded`.
    pub fn get(&self, coll: &str) -> Option<CollectionSchema> {
        self.inner.read().ok()?.get(coll).cloned()
    }

    /// Lazy populate: read from cache, falling back to a SQLite query.
    /// Cached on success. Returns `Ok(None)` if the collection does
    /// not exist (keeps the cache from holding phantom entries).
    pub fn ensure_loaded(
        &self,
        conn: &Connection,
        coll: &str,
    ) -> rusqlite::Result<Option<CollectionSchema>> {
        if let Some(s) = self.get(coll) {
            return Ok(Some(s));
        }
        match describe_collection(conn, coll)? {
            None => Ok(None),
            Some(s) => {
                if let Ok(mut w) = self.inner.write() {
                    w.insert(coll.to_string(), s.clone());
                }
                Ok(Some(s))
            }
        }
    }

    /// Invalidate one entry. Safe to call from any DDL or anon_caps
    /// mutation path. Next `ensure_loaded` repopulates from SQLite.
    pub fn invalidate(&self, coll: &str) {
        if let Ok(mut w) = self.inner.write() {
            w.remove(coll);
        }
    }

    /// Drop every entry. Used on tenant restore / soft-delete reversal.
    pub fn clear(&self) {
        if let Ok(mut w) = self.inner.write() {
            w.clear();
        }
    }

    #[cfg(test)]
    pub fn entry_count(&self) -> usize {
        self.inner.read().map(|r| r.len()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::tenant_db::open_write;
    use tempfile::TempDir;

    fn fresh() -> (TempDir, Connection) {
        let tmp = TempDir::new().unwrap();
        let conn = open_write(tmp.path(), "cachetest").unwrap();
        conn.execute_batch(
            "CREATE TABLE posts (id INTEGER PRIMARY KEY, body TEXT);"
        ).unwrap();
        (tmp, conn)
    }

    #[test]
    fn empty_cache_returns_none() {
        let cache = SchemaCache::new();
        assert!(cache.get("posts").is_none());
    }

    #[test]
    fn ensure_loaded_populates() {
        let (_t, conn) = fresh();
        let cache = SchemaCache::new();
        let s = cache.ensure_loaded(&conn, "posts").unwrap().unwrap();
        assert_eq!(s.name, "posts");
        assert_eq!(cache.entry_count(), 1);
    }

    #[test]
    fn second_lookup_is_cache_hit() {
        let (_t, conn) = fresh();
        let cache = SchemaCache::new();
        cache.ensure_loaded(&conn, "posts").unwrap();
        // second lookup via .get() should not require the connection
        assert!(cache.get("posts").is_some());
    }

    #[test]
    fn nonexistent_collection_does_not_pollute_cache() {
        let (_t, conn) = fresh();
        let cache = SchemaCache::new();
        let res = cache.ensure_loaded(&conn, "ghost").unwrap();
        assert!(res.is_none());
        assert_eq!(cache.entry_count(), 0);
    }

    #[test]
    fn invalidate_drops_entry() {
        let (_t, conn) = fresh();
        let cache = SchemaCache::new();
        cache.ensure_loaded(&conn, "posts").unwrap();
        cache.invalidate("posts");
        assert!(cache.get("posts").is_none());
    }

    #[test]
    fn clear_drops_all() {
        let (_t, conn) = fresh();
        let cache = SchemaCache::new();
        cache.ensure_loaded(&conn, "posts").unwrap();
        cache.clear();
        assert_eq!(cache.entry_count(), 0);
    }
}
