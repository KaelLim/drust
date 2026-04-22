use rusqlite::{Connection, OpenFlags};
use std::path::{Path, PathBuf};

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

COMMIT;
"#;

fn apply_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(SCHEMA_SQL)
}

pub fn open_write(data_root: &Path, tenant_id: &str) -> anyhow::Result<Connection> {
    let dir = tenant_dir(data_root, tenant_id);
    std::fs::create_dir_all(&dir)?;
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
