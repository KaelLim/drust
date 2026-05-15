use rusqlite::{Connection, OpenFlags};
use std::path::{Path, PathBuf};

const RESERVED_TENANT_IDS: &[&str] = &["admin", "system", "root", "public"];

#[derive(Debug, thiserror::Error)]
pub enum TenantIdError {
    #[error("tenant id must be 1–52 characters, got {0}")]
    BadLength(usize),
    #[error("tenant id must match [a-z0-9-]+")]
    BadChars,
    #[error("tenant id '{0}' is reserved")]
    Reserved(String),
}

pub fn validate_tenant_id(id: &str) -> Result<(), TenantIdError> {
    let len = id.len();
    if !(1..=52).contains(&len) {
        return Err(TenantIdError::BadLength(len));
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(TenantIdError::BadChars);
    }
    if RESERVED_TENANT_IDS.contains(&id) {
        return Err(TenantIdError::Reserved(id.to_string()));
    }
    Ok(())
}

pub fn tenant_dir(data_root: &Path, tenant_id: &str) -> PathBuf {
    data_root.join("tenants").join(tenant_id)
}

pub fn tenant_data_path(data_root: &Path, tenant_id: &str) -> PathBuf {
    tenant_dir(data_root, tenant_id).join("data.sqlite")
}

fn apply_common_pragmas(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;
        PRAGMA cache_size = -65536;
        PRAGMA mmap_size = 268435456;
        PRAGMA temp_store = MEMORY;
        PRAGMA busy_timeout = 5000;
        PRAGMA foreign_keys = ON;
        ",
    )
}

const SCHEMA_SQL: &str = r#"
BEGIN;

CREATE TABLE IF NOT EXISTS "_system_files" (
  id                  INTEGER PRIMARY KEY AUTOINCREMENT,
  key                 TEXT    NOT NULL UNIQUE,
  original_name       TEXT    NOT NULL,
  content_type        TEXT,
  size_bytes          INTEGER NOT NULL,
  content_disposition TEXT,
  visibility          TEXT    NOT NULL DEFAULT 'public',
  cache_control       TEXT,
  meta_json           TEXT,
  uploaded_at         TEXT    NOT NULL DEFAULT (datetime('now')),
  uploader            TEXT    NOT NULL,
  created_at          TEXT    NOT NULL DEFAULT (datetime('now')),
  updated_at          TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_system_files_uploaded_at
  ON "_system_files"(uploaded_at DESC);
CREATE INDEX IF NOT EXISTS idx_system_files_visibility
  ON "_system_files"(visibility);

-- v1.6: per-collection anon DML capability allowlist.
-- Rows are upserted by the structured DDL handlers (create_collection,
-- drop_collection); admin-UI edits to anon_caps also write here. A
-- collection with no row defaults to ["select"] (status quo for legacy
-- collections that pre-date this table).
CREATE TABLE IF NOT EXISTS "_system_collection_meta" (
  collection_name      TEXT PRIMARY KEY,
  anon_caps_json       TEXT NOT NULL DEFAULT '["select"]',
  updated_at           TEXT NOT NULL DEFAULT (datetime('now')),
  owner_field          TEXT,
  read_scope           TEXT,
  vector_fields_json   TEXT NOT NULL DEFAULT '[]'
);

-- v1.6: stored RPC functions (Supabase-style named SELECTs).
-- service-key only for create / update / delete. anon callers gated
-- by `anon_callable`. Counters bumped by drust internally on success.
CREATE TABLE IF NOT EXISTS "_system_rpc" (
  name              TEXT PRIMARY KEY,
  sql               TEXT NOT NULL,
  params_json       TEXT NOT NULL,
  description       TEXT,
  anon_callable     INTEGER NOT NULL DEFAULT 0,
  anon_calls        INTEGER NOT NULL DEFAULT 0,
  service_calls     INTEGER NOT NULL DEFAULT 0,
  last_called_at    TEXT,
  created_at        TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

-- v1.12: per-tenant OAuth provider configuration. Tenants register their
-- own client_id / client_secret pairs for Google / GitHub / etc.; v1.12
-- routing reads this table to dispatch /t/<id>/oauth/<provider>/* flows.
CREATE TABLE IF NOT EXISTS "_system_oauth_providers" (
  provider              TEXT PRIMARY KEY,
  client_id             TEXT NOT NULL,
  client_secret         TEXT NOT NULL,
  allowed_redirect_uris TEXT NOT NULL,
  created_at            TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at            TEXT NOT NULL DEFAULT (datetime('now'))
);

COMMIT;
"#;

fn apply_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(SCHEMA_SQL)
}

pub fn open_write(data_root: &Path, tenant_id: &str) -> anyhow::Result<Connection> {
    let dir = tenant_dir(data_root, tenant_id);
    std::fs::create_dir_all(&dir)?;
    // Register sqlite-vec's auto-extension BEFORE Connection::open so
    // the new connection sees vec_distance_* on first use. Idempotent.
    ensure_sqlite_vec_loaded();
    let path = tenant_data_path(data_root, tenant_id);
    let conn = Connection::open_with_flags(
        &path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
    )?;
    apply_common_pragmas(&conn)?;
    apply_schema(&conn)?;
    Ok(conn)
}

pub fn open_read(data_root: &Path, tenant_id: &str) -> anyhow::Result<Connection> {
    let path = tenant_data_path(data_root, tenant_id);
    if !path.exists() {
        anyhow::bail!("tenant data not found: {}", path.display());
    }
    // Auto-extension must register before Connection::open. Idempotent.
    ensure_sqlite_vec_loaded();
    let conn = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    conn.execute_batch(
        "PRAGMA query_only = ON;
         PRAGMA cache_size = -65536;
         PRAGMA mmap_size = 268435456;",
    )?;
    // Enable defensive mode to prevent schema corruption attempts.
    // Note: SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION is not exposed in rusqlite 0.32
    // (the constant is commented out in the upstream source), so we only set DEFENSIVE.
    conn.set_db_config(rusqlite::config::DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    Ok(conn)
}

/// Register sqlite-vec's scalar function family (`vec_distance_cosine`
/// / `_l2` / `_l1`, `vec_to_json`, etc.) as a SQLite auto-extension —
/// every subsequent `Connection::open*` call in this process picks it
/// up automatically.
///
/// Idempotent: the `OnceLock` guarantees the underlying
/// `sqlite3_auto_extension` is called exactly once per process. Safe to
/// invoke from `main.rs` boot, `open_write`, and `open_read` — whichever
/// fires first wins, the rest are no-ops.
///
/// We can't use a `load(&conn)` per-connection path because
/// `sqlite_vec::sqlite3_vec_init` is declared with a zero-arg C ABI in
/// the upstream crate — it is designed to be invoked **by** SQLite
/// through the auto-extension callback, which passes the real
/// `(db, errmsg, api)` triple at registration time.
pub fn ensure_sqlite_vec_loaded() {
    use std::sync::OnceLock;
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        unsafe {
            let rc = rusqlite::ffi::sqlite3_auto_extension(Some(std::mem::transmute(
                sqlite_vec::sqlite3_vec_init as *const (),
            )));
            if rc != rusqlite::ffi::SQLITE_OK {
                // We can't return an error from OnceLock::get_or_init,
                // and failing this is a programmer error (linker
                // misconfig). Panic loudly so the test/boot path
                // doesn't silently produce broken connections.
                panic!("sqlite3_auto_extension(sqlite_vec) failed: rc={rc}");
            }
        }
    });
}

#[cfg(test)]
mod schema_tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn new_tenant_meta_has_vector_fields_json_column() {
        let tmp = TempDir::new().unwrap();
        let conn = open_write(tmp.path(), "newtenant").unwrap();
        let cols: Vec<String> = conn
            .prepare("PRAGMA table_info(_system_collection_meta)")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(
            cols.contains(&"vector_fields_json".to_string()),
            "fresh tenant missing vector_fields_json; cols = {cols:?}"
        );
    }

    #[test]
    fn open_write_creates_v1_6_system_tables() {
        let tmp = TempDir::new().unwrap();
        let conn = open_write(tmp.path(), "smoketest").unwrap();
        let exists = |t: &str| -> bool {
            conn.query_row(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
                rusqlite::params![t],
                |_| Ok(true),
            )
            .unwrap_or(false)
        };
        assert!(exists("_system_files"), "_system_files missing");
        assert!(
            exists("_system_collection_meta"),
            "_system_collection_meta missing"
        );
        assert!(exists("_system_rpc"), "_system_rpc missing");
    }
}
