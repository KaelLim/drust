use rusqlite::Connection;
use std::path::Path;

pub const SQL_CREATE_ADMIN_TOKENS_IF_NOT_EXISTS: &str = r#"
CREATE TABLE IF NOT EXISTS _admin_tokens (
    id              INTEGER PRIMARY KEY,
    admin_id        INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    token_hash      TEXT    NOT NULL UNIQUE,
    plaintext       TEXT,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    last_used_at    TEXT,
    revoked_at      TEXT
) STRICT;

CREATE INDEX IF NOT EXISTS idx_admin_tokens_admin ON _admin_tokens(admin_id);
"#;

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

pub const SQL_CREATE_SYSTEM_OAUTH_PROVIDERS_IF_NOT_EXISTS: &str = r#"
CREATE TABLE IF NOT EXISTS _system_oauth_providers (
  provider              TEXT PRIMARY KEY,
  client_id             TEXT NOT NULL,
  client_secret         TEXT NOT NULL,
  allowed_redirect_uris TEXT NOT NULL,
  created_at            TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at            TEXT NOT NULL DEFAULT (datetime('now'))
);
"#;

pub const SQL_CREATE_SYSTEM_WEBHOOKS_IF_NOT_EXISTS: &str = r#"
CREATE TABLE IF NOT EXISTS _system_webhooks (
  id                   INTEGER PRIMARY KEY AUTOINCREMENT,
  collection           TEXT    NOT NULL,
  events               TEXT    NOT NULL,
  url                  TEXT    NOT NULL,
  secret               TEXT    NOT NULL,
  active               INTEGER NOT NULL DEFAULT 1,
  last_failure_at      TEXT,
  last_failure_reason  TEXT,
  created_at           TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_system_webhooks_collection
  ON _system_webhooks(collection) WHERE active = 1;
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
    tx.execute_batch(SQL_CREATE_SYSTEM_OAUTH_PROVIDERS_IF_NOT_EXISTS)?;
    tx.execute_batch(SQL_CREATE_SYSTEM_WEBHOOKS_IF_NOT_EXISTS)?;
    add_column_if_missing(&tx, "_system_collection_meta", "owner_field", "TEXT")?;
    add_column_if_missing(&tx, "_system_collection_meta", "read_scope", "TEXT")?;
    add_column_if_missing(
        &tx,
        "_system_collection_meta",
        "vector_fields_json",
        "TEXT NOT NULL DEFAULT '[]'",
    )?;
    add_column_if_missing(
        &tx,
        "_system_collection_meta",
        "realtime_enabled",
        "INTEGER NOT NULL DEFAULT 1",
    )?;
    add_column_if_missing(&tx, "_system_collection_meta", "description", "TEXT")?;
    add_column_if_missing(
        &tx,
        "_system_collection_meta",
        "field_descriptions_json",
        "TEXT NOT NULL DEFAULT '{}'",
    )?;
    add_column_if_missing(
        &tx,
        "_system_collection_meta",
        "index_descriptions_json",
        "TEXT NOT NULL DEFAULT '{}'",
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
    // v1.15.0 — denormalized dashboard stats sampled in background.
    add_column_if_missing(meta, "tenants", "db_bytes",
        "INTEGER NOT NULL DEFAULT 0")?;
    add_column_if_missing(meta, "tenants", "files_bytes",
        "INTEGER NOT NULL DEFAULT 0")?;
    add_column_if_missing(meta, "tenants", "stats_updated_at", "TEXT")?;

    // v1.29.0 — team management: role column + backfill
    add_column_if_missing(meta, "admins", "role", "TEXT NOT NULL DEFAULT 'member'")?;
    let any_owner: bool = meta
        .query_row("SELECT 1 FROM admins WHERE role='owner' LIMIT 1", [], |_| Ok(()))
        .is_ok();
    if !any_owner {
        meta.execute("UPDATE admins SET role='owner'", [])?;
    }

    // v1.29.0 — PAT table for headless admin attribution
    meta.execute_batch(SQL_CREATE_ADMIN_TOKENS_IF_NOT_EXISTS)?;

    // v1.29.2 — retract v1.29.0 OAuth AS bundle. Drop tables in dependency
    // order (FK children before parents). Idempotent: no-op when tables are
    // already absent (fresh installs that never saw v1.29.0).
    meta.execute_batch(
        "DROP TABLE IF EXISTS _oauth_refresh_tokens;
         DROP TABLE IF EXISTS _oauth_access_tokens;
         DROP TABLE IF EXISTS _oauth_authorization_codes;
         DROP TABLE IF EXISTS _oauth_clients;"
    )?;

    // v1.29.3 — collapse the two-PAT model (Task 8 manual + v1.29.2 auto_mcp)
    // into a single plaintext-retrievable PAT per admin. See spec
    // docs/superpowers/specs/2026-05-28-drust-v1293-one-pat-per-admin-design.md.

    // 1. Ensure revoked_at column exists (it does on v1.29.2; this is a
    //    defense-in-depth no-op for the constant-update path).
    add_column_if_missing(meta, "_admin_tokens", "revoked_at", "TEXT")?;

    // 2. Add plaintext column (NULL for any pre-existing hash-only rows).
    add_column_if_missing(meta, "_admin_tokens", "plaintext", "TEXT")?;

    // 3. Soft-revoke EVERY active legacy row (both kind='manual' from Task 8
    //    and kind='auto_mcp' from v1.29.2 — neither has plaintext stored).
    //    The backfill loop below produces fresh plaintext-bearing rows.
    meta.execute_batch(
        "UPDATE _admin_tokens SET revoked_at = datetime('now') WHERE revoked_at IS NULL;"
    )?;

    // 4. Swap the partial unique index: drop the kind-based one, create one
    //    that enforces at-most-one-active-PAT-per-admin via revoked_at.
    meta.execute_batch(
        "DROP INDEX IF EXISTS uniq_admin_tokens_auto_mcp;
         CREATE UNIQUE INDEX IF NOT EXISTS uniq_admin_tokens_active \
             ON _admin_tokens(admin_id) WHERE revoked_at IS NULL;"
    )?;

    // 5 & 6. Drop the `kind` and `name` columns.
    //    SQLite 3.35+ supports DROP COLUMN but rejects it when the column
    //    is referenced by a constraint (UNIQUE(admin_id, name) blocks dropping
    //    `name` directly). We use the classic rename-create-insert-drop
    //    table rebuild when either column is present.
    let has_kind: i64 = meta.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('_admin_tokens') WHERE name = 'kind'",
        [], |r| r.get(0)
    ).unwrap_or(0);
    let has_name: i64 = meta.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('_admin_tokens') WHERE name = 'name'",
        [], |r| r.get(0)
    ).unwrap_or(0);
    if has_kind > 0 || has_name > 0 {
        // Rebuild the table without the obsolete columns, preserving all rows.
        meta.execute_batch(
            "ALTER TABLE _admin_tokens RENAME TO _admin_tokens_legacy;
             CREATE TABLE _admin_tokens (
                 id              INTEGER PRIMARY KEY,
                 admin_id        INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
                 token_hash      TEXT    NOT NULL UNIQUE,
                 plaintext       TEXT,
                 created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
                 last_used_at    TEXT,
                 revoked_at      TEXT
             ) STRICT;
             INSERT INTO _admin_tokens
                 (id, admin_id, token_hash, plaintext, created_at, last_used_at, revoked_at)
             SELECT id, admin_id, token_hash, plaintext, created_at, last_used_at, revoked_at
             FROM _admin_tokens_legacy;
             DROP TABLE _admin_tokens_legacy;
             CREATE INDEX IF NOT EXISTS idx_admin_tokens_admin ON _admin_tokens(admin_id);
             CREATE UNIQUE INDEX IF NOT EXISTS uniq_admin_tokens_active
                 ON _admin_tokens(admin_id) WHERE revoked_at IS NULL;"
        )?;
    }

    // 7. Backfill: every admin missing an active PAT gets a fresh one.
    //    Idempotent — admins that already have an active row are skipped.
    let admin_ids: Vec<i64> = {
        let mut stmt = meta.prepare("SELECT id FROM admins")?;
        stmt.query_map([], |r| r.get(0))?
            .collect::<rusqlite::Result<Vec<i64>>>()?
    };
    for aid in admin_ids {
        let has_active: bool = meta.query_row(
            "SELECT 1 FROM _admin_tokens WHERE admin_id = ?1 AND revoked_at IS NULL",
            rusqlite::params![aid], |_| Ok(())
        ).is_ok();
        if !has_active {
            let plaintext = crate::auth::admin_token::generate_token();
            let hash = crate::auth::admin_token::hash_token(&plaintext);
            meta.execute(
                "INSERT INTO _admin_tokens (admin_id, token_hash, plaintext) VALUES (?1, ?2, ?3)",
                rusqlite::params![aid, hash, plaintext],
            )?;
        }
    }

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
    use tempfile::TempDir;

    fn fresh() -> Connection {
        Connection::open_in_memory().unwrap()
    }

    #[test]
    fn v129_admins_role_column_added_and_backfilled_to_owner() {
        let conn = Connection::open_in_memory().unwrap();
        // Mimic pre-v1.29 admins table shape + minimal meta tables run_migrations needs
        conn.execute_batch(
            "CREATE TABLE tenants (id TEXT PRIMARY KEY, allow_self_register INTEGER NOT NULL DEFAULT 0, db_bytes INTEGER NOT NULL DEFAULT 0, files_bytes INTEGER NOT NULL DEFAULT 0, stats_updated_at TEXT);
            CREATE TABLE admins (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            INSERT INTO admins (username, password_hash, email) VALUES ('alice', 'hash', 'a@x');
            INSERT INTO admins (username, password_hash, email) VALUES ('bob',   'hash', 'b@x');"
        ).unwrap();

        let tmp = TempDir::new().unwrap();
        run_migrations(&conn, tmp.path()).unwrap();

        // Column exists
        let cols: Vec<String> = conn
            .prepare("PRAGMA table_info(admins)").unwrap()
            .query_map([], |r| r.get::<_, String>(1)).unwrap()
            .collect::<rusqlite::Result<_>>().unwrap();
        assert!(cols.contains(&"role".to_string()), "missing role column: {cols:?}");

        // All existing admins backfilled to 'owner'
        let roles: Vec<String> = conn
            .prepare("SELECT role FROM admins ORDER BY id").unwrap()
            .query_map([], |r| r.get::<_, String>(0)).unwrap()
            .collect::<rusqlite::Result<_>>().unwrap();
        assert_eq!(roles, vec!["owner", "owner"], "backfill should lift all existing admins");

        // Idempotent: second run is a no-op
        run_migrations(&conn, tmp.path()).unwrap();
        let roles: Vec<String> = conn
            .prepare("SELECT role FROM admins ORDER BY id").unwrap()
            .query_map([], |r| r.get::<_, String>(0)).unwrap()
            .collect::<rusqlite::Result<_>>().unwrap();
        assert_eq!(roles, vec!["owner", "owner"]);
    }

    #[test]
    fn v1292_oauth_tables_dropped() {
        // Simulate a v1.29.0 install: meta has the 4 OAuth tables.
        // After run_migrations, they MUST be dropped.
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE tenants (id TEXT PRIMARY KEY, allow_self_register INTEGER NOT NULL DEFAULT 0, db_bytes INTEGER NOT NULL DEFAULT 0, files_bytes INTEGER NOT NULL DEFAULT 0, stats_updated_at TEXT);
            CREATE TABLE admins (id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT NOT NULL, email TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now')));
            CREATE TABLE _oauth_clients (id TEXT PRIMARY KEY);
            CREATE TABLE _oauth_authorization_codes (code_hash TEXT PRIMARY KEY);
            CREATE TABLE _oauth_access_tokens (token_hash TEXT PRIMARY KEY);
            CREATE TABLE _oauth_refresh_tokens (token_hash TEXT PRIMARY KEY);"
        ).unwrap();
        let tmp = TempDir::new().unwrap();
        run_migrations(&conn, tmp.path()).unwrap();

        for table in &[
            "_oauth_clients",
            "_oauth_authorization_codes",
            "_oauth_access_tokens",
            "_oauth_refresh_tokens",
        ] {
            let row: i64 = conn
                .query_row(
                    &format!("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='{table}'"),
                    [], |r| r.get(0)
                ).unwrap();
            assert_eq!(row, 0, "table {table} should have been dropped");
        }
    }

    #[test]
    fn v1293_fresh_admin_tokens_table_shape() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE tenants (id TEXT PRIMARY KEY, allow_self_register INTEGER NOT NULL DEFAULT 0, db_bytes INTEGER NOT NULL DEFAULT 0, files_bytes INTEGER NOT NULL DEFAULT 0, stats_updated_at TEXT);
             CREATE TABLE admins (id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT NOT NULL, email TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now')));"
        ).unwrap();
        let tmp = TempDir::new().unwrap();
        run_migrations(&conn, tmp.path()).unwrap();

        let cols: Vec<String> = conn
            .prepare("PRAGMA table_info(_admin_tokens)").unwrap()
            .query_map([], |r| r.get::<_, String>(1)).unwrap()
            .collect::<rusqlite::Result<_>>().unwrap();
        assert!(cols.contains(&"plaintext".to_string()), "plaintext column missing: {:?}", cols);
        assert!(!cols.contains(&"kind".to_string()), "kind column should be dropped: {:?}", cols);
        assert!(!cols.contains(&"name".to_string()), "name column should be dropped: {:?}", cols);
    }

    #[test]
    fn v1293_migration_drops_kind_softrevokes_legacy_and_backfills() {
        let conn = Connection::open_in_memory().unwrap();
        // Seed a v1.29.2-shaped DB.
        conn.execute_batch(
            "CREATE TABLE tenants (id TEXT PRIMARY KEY, allow_self_register INTEGER NOT NULL DEFAULT 0, db_bytes INTEGER NOT NULL DEFAULT 0, files_bytes INTEGER NOT NULL DEFAULT 0, stats_updated_at TEXT);
             CREATE TABLE admins (id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT NOT NULL, email TEXT, role TEXT NOT NULL DEFAULT 'member', created_at TEXT NOT NULL DEFAULT (datetime('now')));
             CREATE TABLE _admin_tokens (
                id INTEGER PRIMARY KEY,
                admin_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                last_used_at TEXT,
                revoked_at TEXT,
                kind TEXT NOT NULL DEFAULT 'manual',
                UNIQUE(admin_id, name)
             );
             CREATE UNIQUE INDEX uniq_admin_tokens_auto_mcp ON _admin_tokens(admin_id) WHERE kind='auto_mcp' AND revoked_at IS NULL;
             INSERT INTO admins (id, username, password_hash, email, role) VALUES (1, 'alice', 'h', 'a@x', 'owner');
             INSERT INTO admins (id, username, password_hash, email, role) VALUES (2, 'bob',   'h', 'b@x', 'member');
             INSERT INTO _admin_tokens (admin_id, name, token_hash, kind) VALUES (1, 'legacy', 'hash_legacy', 'manual');"
        ).unwrap();
        let tmp = TempDir::new().unwrap();
        run_migrations(&conn, tmp.path()).unwrap();

        // (a) kind column dropped.
        let cols: Vec<String> = conn.prepare("PRAGMA table_info(_admin_tokens)").unwrap()
            .query_map([], |r| r.get::<_, String>(1)).unwrap()
            .collect::<rusqlite::Result<_>>().unwrap();
        assert!(!cols.contains(&"kind".to_string()), "kind should be dropped");
        assert!(cols.contains(&"plaintext".to_string()), "plaintext should be added");

        // (b) Old auto_mcp index gone, new active index present.
        let old: Option<String> = conn.query_row(
            "SELECT name FROM sqlite_master WHERE type='index' AND name='uniq_admin_tokens_auto_mcp'",
            [], |r| r.get(0)
        ).ok();
        assert!(old.is_none(), "old auto_mcp index should be dropped");
        let new_sql: String = conn.query_row(
            "SELECT sql FROM sqlite_master WHERE type='index' AND name='uniq_admin_tokens_active'",
            [], |r| r.get(0)
        ).expect("new uniq_admin_tokens_active index should exist");
        assert!(new_sql.contains("revoked_at IS NULL"));

        // (c) Legacy hash_legacy row was soft-revoked.
        let legacy_revoked: Option<String> = conn.query_row(
            "SELECT revoked_at FROM _admin_tokens WHERE token_hash = 'hash_legacy'",
            [], |r| r.get(0)
        ).ok().flatten();
        assert!(legacy_revoked.is_some(), "legacy PAT must be soft-revoked");

        // (d) Backfill: both admins have one active PAT with non-NULL plaintext.
        for aid in [1, 2] {
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM _admin_tokens WHERE admin_id = ?1 AND revoked_at IS NULL AND plaintext IS NOT NULL",
                rusqlite::params![aid], |r| r.get(0)
            ).unwrap();
            assert_eq!(count, 1, "admin {} must have exactly 1 active plaintext PAT, got {}", aid, count);
        }

        // (e) Partial unique index prevents a second active row.
        conn.execute(
            "INSERT INTO _admin_tokens (admin_id, token_hash, plaintext) VALUES (1, 'h2', 'p2')", []
        ).expect_err("second active row should violate uniq_admin_tokens_active");
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
    fn create_system_oauth_providers_idempotent() {
        let c = fresh();
        c.execute_batch(SQL_CREATE_SYSTEM_OAUTH_PROVIDERS_IF_NOT_EXISTS).unwrap();
        c.execute_batch(SQL_CREATE_SYSTEM_OAUTH_PROVIDERS_IF_NOT_EXISTS).unwrap();
        let n: i64 = c.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='_system_oauth_providers'",
            [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn create_system_webhooks_idempotent() {
        let c = fresh();
        c.execute_batch(SQL_CREATE_SYSTEM_WEBHOOKS_IF_NOT_EXISTS).unwrap();
        c.execute_batch(SQL_CREATE_SYSTEM_WEBHOOKS_IF_NOT_EXISTS).unwrap(); // second run is a no-op
        let n: i64 = c.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='_system_webhooks'",
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
    fn migrate_tenant_db_adds_realtime_enabled_defaulting_to_one() {
        let dir = tempfile::tempdir().unwrap();
        let tdir = dir.path().join("tenants").join("t-rt");
        std::fs::create_dir_all(&tdir).unwrap();
        let p = tdir.join("data.sqlite");
        // v1.15-shape meta table: no realtime_enabled column, one row present.
        {
            let c = Connection::open(&p).unwrap();
            c.execute_batch(
                "CREATE TABLE _system_collection_meta (
                    collection_name TEXT PRIMARY KEY,
                    anon_caps_json  TEXT NOT NULL,
                    updated_at      TEXT NOT NULL);
                 INSERT INTO _system_collection_meta
                    (collection_name, anon_caps_json, updated_at)
                    VALUES ('legacy', '[\"select\"]', '2026-01-01');",
            )
            .unwrap();
        }
        migrate_tenant_db(dir.path(), "t-rt").unwrap();
        migrate_tenant_db(dir.path(), "t-rt").unwrap(); // idempotent

        let c = Connection::open(&p).unwrap();
        // Column exists.
        let cols: Vec<String> = c
            .prepare("PRAGMA table_info(_system_collection_meta)")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(
            cols.contains(&"realtime_enabled".to_string()),
            "realtime_enabled column missing after migration; cols = {cols:?}"
        );
        // Existing row backfilled to 1 by the column DEFAULT.
        let v: i64 = c
            .query_row(
                "SELECT realtime_enabled FROM _system_collection_meta WHERE collection_name = 'legacy'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(v, 1, "existing row should preserve current SSE behaviour (= 1)");
    }

    #[test]
    fn migrate_tenant_db_adds_description_columns() {
        let dir = tempfile::tempdir().unwrap();
        let tdir = dir.path().join("tenants").join("t-desc");
        std::fs::create_dir_all(&tdir).unwrap();
        let p = tdir.join("data.sqlite");
        // v1.16-shape meta table: has owner_field/read_scope/vector_fields_json/realtime_enabled
        // but no description / field_descriptions_json / index_descriptions_json.
        {
            let c = Connection::open(&p).unwrap();
            c.execute_batch(
                "CREATE TABLE _system_collection_meta (
                    collection_name     TEXT PRIMARY KEY,
                    anon_caps_json      TEXT NOT NULL,
                    updated_at          TEXT NOT NULL,
                    owner_field         TEXT,
                    read_scope          TEXT,
                    vector_fields_json  TEXT NOT NULL DEFAULT '[]',
                    realtime_enabled    INTEGER NOT NULL DEFAULT 1);
                 INSERT INTO _system_collection_meta
                    (collection_name, anon_caps_json, updated_at)
                    VALUES ('legacy', '[\"select\"]', '2026-01-01');",
            ).unwrap();
        }

        migrate_tenant_db(dir.path(), "t-desc").unwrap();
        migrate_tenant_db(dir.path(), "t-desc").unwrap(); // idempotent

        let c = Connection::open(&p).unwrap();
        let cols: Vec<String> = c
            .prepare("PRAGMA table_info(_system_collection_meta)").unwrap()
            .query_map([], |r| r.get::<_, String>(1)).unwrap()
            .collect::<Result<_, _>>().unwrap();
        assert!(cols.contains(&"description".to_string()),
            "description column missing; cols = {cols:?}");
        assert!(cols.contains(&"field_descriptions_json".to_string()),
            "field_descriptions_json column missing; cols = {cols:?}");
        assert!(cols.contains(&"index_descriptions_json".to_string()),
            "index_descriptions_json column missing; cols = {cols:?}");

        // Existing row defaults: description NULL, both JSON blobs '{}'.
        let (d, fd, id): (Option<String>, String, String) = c.query_row(
            "SELECT description, field_descriptions_json, index_descriptions_json
               FROM _system_collection_meta WHERE collection_name='legacy'",
            [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        ).unwrap();
        assert!(d.is_none(), "legacy row description should default to NULL");
        assert_eq!(fd, "{}", "legacy row field_descriptions_json should default to {{}}");
        assert_eq!(id, "{}", "legacy row index_descriptions_json should default to {{}}");
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
             INSERT INTO tenants VALUES ('t-ok'), ('t-locked'); \
             CREATE TABLE admins (id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT NOT NULL, email TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now')));",
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
