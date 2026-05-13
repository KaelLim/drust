use rusqlite::Connection;
use std::path::Path;

pub const SQL_CREATE_SYSTEM_USERS_IF_NOT_EXISTS: &str = r#"
CREATE TABLE IF NOT EXISTS _system_users (
  id            TEXT PRIMARY KEY,
  email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  verified      INTEGER NOT NULL DEFAULT 0,
  profile       TEXT,
  created_at    TEXT NOT NULL,
  updated_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_system_users_email ON _system_users(email);
"#;

pub const SQL_CREATE_SYSTEM_SESSIONS_IF_NOT_EXISTS: &str = r#"
CREATE TABLE IF NOT EXISTS _system_sessions (
  token_hash    TEXT PRIMARY KEY,
  user_id       TEXT NOT NULL REFERENCES _system_users(id) ON DELETE CASCADE,
  created_at    TEXT NOT NULL,
  expires_at    TEXT NOT NULL,
  last_seen_at  TEXT NOT NULL,
  ip_at_login   TEXT
);
CREATE INDEX IF NOT EXISTS idx_system_sessions_user ON _system_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_system_sessions_expires ON _system_sessions(expires_at);
"#;

pub fn add_column_if_missing(
    conn: &Connection,
    table: &str,
    col: &str,
    decl: &str,
) -> rusqlite::Result<()> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({})", table))?;
    let cols: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(1))?
        .collect::<rusqlite::Result<_>>()?;
    if !cols.iter().any(|c| c == col) {
        conn.execute(
            &format!("ALTER TABLE {} ADD COLUMN {} {}", table, col, decl),
            [],
        )?;
    }
    Ok(())
}

pub fn migrate_tenant_db(tenants_dir: &Path, tid: &str) -> rusqlite::Result<()> {
    let path = tenants_dir.join("tenants").join(tid).join("data.sqlite");
    if !path.exists() {
        return Ok(());
    }
    let mut conn = Connection::open(&path)?;
    let tx = conn.transaction()?;
    tx.execute_batch(SQL_CREATE_SYSTEM_USERS_IF_NOT_EXISTS)?;
    tx.execute_batch(SQL_CREATE_SYSTEM_SESSIONS_IF_NOT_EXISTS)?;
    add_column_if_missing(&tx, "_system_collection_meta", "owner_field", "TEXT")?;
    add_column_if_missing(&tx, "_system_collection_meta", "read_scope", "TEXT")?;
    add_column_if_missing(
        &tx,
        "_system_collection_meta",
        "vector_fields_json",
        "TEXT NOT NULL DEFAULT '[]'",
    )?;
    tx.commit()
}

#[derive(Debug, Default)]
pub struct MigrationReport {
    pub meta_done: bool,
    pub tenants_ok: Vec<String>,
    pub tenants_failed: Vec<(String, String)>,
}

pub fn run_migrations(
    meta: &Connection,
    tenants_root: &Path,
) -> rusqlite::Result<MigrationReport> {
    let mut report = MigrationReport::default();

    add_column_if_missing(meta, "tenants", "allow_self_register",
        "INTEGER NOT NULL DEFAULT 0")?;
    report.meta_done = true;

    let mut stmt = meta.prepare("SELECT id FROM tenants")?;
    let ids: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<_>>()?;

    for tid in ids {
        match migrate_tenant_db(tenants_root, &tid) {
            Ok(_) => report.tenants_ok.push(tid),
            Err(e) => {
                tracing::error!(tenant = %tid, error = ?e, "tenant migration failed");
                report.tenants_failed.push((tid, e.to_string()));
            }
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn fresh() -> Connection {
        Connection::open_in_memory().unwrap()
    }

    #[test]
    fn create_system_users_idempotent() {
        let c = fresh();
        c.execute_batch(SQL_CREATE_SYSTEM_USERS_IF_NOT_EXISTS).unwrap();
        c.execute_batch(SQL_CREATE_SYSTEM_USERS_IF_NOT_EXISTS).unwrap();
        let n: i64 = c.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='_system_users'",
            [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn create_system_sessions_idempotent() {
        let c = fresh();
        c.execute_batch(SQL_CREATE_SYSTEM_SESSIONS_IF_NOT_EXISTS).unwrap();
        c.execute_batch(SQL_CREATE_SYSTEM_SESSIONS_IF_NOT_EXISTS).unwrap();
        let n: i64 = c.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='_system_sessions'",
            [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn add_column_if_missing_adds_once() {
        let c = fresh();
        c.execute("CREATE TABLE t (a TEXT)", []).unwrap();
        add_column_if_missing(&c, "t", "b", "INTEGER NOT NULL DEFAULT 0").unwrap();
        add_column_if_missing(&c, "t", "b", "INTEGER NOT NULL DEFAULT 0").unwrap();
        let cols: Vec<String> = c.prepare("PRAGMA table_info(t)").unwrap()
            .query_map([], |r| r.get::<_, String>(1)).unwrap()
            .collect::<Result<_, _>>().unwrap();
        assert_eq!(cols, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn migrate_tenant_db_creates_tables_and_columns() {
        let dir = tempfile::tempdir().unwrap();
        let tdir = dir.path().join("tenants").join("t-x");
        std::fs::create_dir_all(&tdir).unwrap();
        let p = tdir.join("data.sqlite");
        // Simulate existing tenant DB with a _system_collection_meta table
        {
            let c = Connection::open(&p).unwrap();
            c.execute_batch(
                "CREATE TABLE _system_collection_meta (collection_name TEXT PRIMARY KEY, anon_caps_json TEXT, updated_at TEXT)",
            )
            .unwrap();
        }

        migrate_tenant_db(dir.path(), "t-x").unwrap();
        migrate_tenant_db(dir.path(), "t-x").unwrap(); // idempotent

        let c = Connection::open(&p).unwrap();
        let n_users: i64 = c.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='_system_users'",
            [], |r| r.get(0)).unwrap();
        let n_sess: i64 = c.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='_system_sessions'",
            [], |r| r.get(0)).unwrap();
        assert_eq!(n_users, 1);
        assert_eq!(n_sess, 1);

        let cols: Vec<String> = c.prepare("PRAGMA table_info(_system_collection_meta)").unwrap()
            .query_map([], |r| r.get::<_, String>(1)).unwrap()
            .collect::<Result<_, _>>().unwrap();
        assert!(cols.contains(&"owner_field".to_string()));
        assert!(cols.contains(&"read_scope".to_string()));
    }

    #[test]
    fn migrate_tenant_db_adds_vector_fields_json() {
        let dir = tempfile::tempdir().unwrap();
        let tdir = dir.path().join("tenants").join("t-vec");
        std::fs::create_dir_all(&tdir).unwrap();
        let p = tdir.join("data.sqlite");
        {
            let c = Connection::open(&p).unwrap();
            c.execute_batch(
                "CREATE TABLE _system_collection_meta (
                    collection_name TEXT PRIMARY KEY,
                    anon_caps_json  TEXT NOT NULL,
                    updated_at      TEXT NOT NULL)",
            )
            .unwrap();
        }
        migrate_tenant_db(dir.path(), "t-vec").unwrap();
        migrate_tenant_db(dir.path(), "t-vec").unwrap(); // idempotent

        let c = Connection::open(&p).unwrap();
        let cols: Vec<String> = c
            .prepare("PRAGMA table_info(_system_collection_meta)")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(
            cols.contains(&"vector_fields_json".to_string()),
            "vector_fields_json column missing after migration; cols = {cols:?}"
        );
    }

    #[test]
    fn migrate_tenant_db_skips_missing_path() {
        let dir = tempfile::tempdir().unwrap();
        // No tenants/t-gone/ dir at all
        migrate_tenant_db(dir.path(), "t-gone").unwrap();
    }

    #[test]
    fn run_migrations_isolates_per_tenant_failure() {
        let dir = tempfile::tempdir().unwrap();
        let meta_path = dir.path().join("meta.sqlite");
        // meta.sqlite with two tenants
        let meta = Connection::open(&meta_path).unwrap();
        meta.execute_batch(
            "CREATE TABLE tenants (id TEXT PRIMARY KEY); \
             INSERT INTO tenants VALUES ('t-ok'), ('t-locked');",
        ).unwrap();

        // t-ok has a normal data.sqlite with the old _system_collection_meta
        let ok_dir = dir.path().join("tenants").join("t-ok");
        std::fs::create_dir_all(&ok_dir).unwrap();
        Connection::open(ok_dir.join("data.sqlite")).unwrap().execute_batch(
            "CREATE TABLE _system_collection_meta (collection_name TEXT PRIMARY KEY, anon_caps_json TEXT, updated_at TEXT)",
        ).unwrap();
        // t-locked's data.sqlite has a corrupt path (use a directory instead of file to provoke open failure)
        let bad_dir = dir.path().join("tenants").join("t-locked");
        std::fs::create_dir_all(bad_dir.join("data.sqlite")).unwrap(); // dir where a file should be → open fails

        let report = run_migrations(&meta, dir.path()).unwrap();
        assert!(report.tenants_ok.contains(&"t-ok".to_string()));
        assert!(report.tenants_failed.iter().any(|(t, _)| t == "t-locked"));
        // t-ok must have been migrated despite t-locked failing
        let c = Connection::open(ok_dir.join("data.sqlite")).unwrap();
        let n: i64 = c.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='_system_users'",
            [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1);
    }
}
