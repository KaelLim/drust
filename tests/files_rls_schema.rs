//! #950-B (Files RLS) T1 — schema landing points for `path` / `_system_file_policy`.
//!
//! The known failure mode of this codebase is a schema change landing at ONE
//! application point and silently missing another, so every assertion here is
//! written twice: once against a FRESH database (the `SCHEMA_SQL` +
//! `apply_schema` path a runtime-created tenant takes) and once against a
//! MIGRATED database (the `migrate_tenant_db` / `apply_migrations` path an
//! existing install takes at boot). Fresh and migrated must agree column for
//! column — that is the v1.32.8 parity rule (`tenant_db.rs` §apply_schema).

use rusqlite::Connection;
use tempfile::tempdir;

fn cols(conn: &Connection, table: &str) -> Vec<String> {
    conn.prepare(&format!("PRAGMA table_info(\"{}\")", table))
        .unwrap()
        .query_map([], |r| r.get::<_, String>(1))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

fn object_exists(conn: &Connection, kind: &str, name: &str) -> bool {
    conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = ?1 AND name = ?2",
        rusqlite::params![kind, name],
        |r| r.get::<_, i64>(0),
    )
    .unwrap()
        > 0
}

const FILE_POLICY_COLS: [&str; 8] = [
    "prefix",
    "owner_scoped",
    "public_read",
    "select_policy_json",
    "delete_policy_json",
    "created_at",
    "updated_at",
    // v1.64 (#974) — the per-prefix publish grant. LAST, because
    // `add_column_if_missing` appends and this assertion is order-sensitive on
    // purpose: fresh and migrated must agree on ORDER, not just on membership.
    "public_upload_roles",
];

/// Every tenant-side assertion, applied to whichever connection is handed in.
fn assert_tenant_shape(conn: &Connection, whence: &str) {
    let files = cols(conn, "_system_files");
    assert!(
        files.contains(&"path".to_string()),
        "{whence}: _system_files must have `path` (got {files:?})"
    );
    // Nullable, no default — an existing row must stay "unfiled" (NULL).
    let (ty, notnull, dflt): (String, i64, Option<String>) = conn
        .query_row(
            "SELECT type, \"notnull\", dflt_value FROM pragma_table_info('_system_files') \
             WHERE name = 'path'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(ty, "TEXT", "{whence}: path must be TEXT");
    assert_eq!(notnull, 0, "{whence}: path must be nullable");
    assert!(dflt.is_none(), "{whence}: path must have no default");

    assert!(
        object_exists(conn, "index", "idx_system_files_path"),
        "{whence}: partial index idx_system_files_path must exist"
    );

    let sessions = cols(conn, "_system_upload_sessions");
    assert!(
        sessions.contains(&"path".to_string()),
        "{whence}: _system_upload_sessions must have `path` (got {sessions:?})"
    );

    assert!(
        object_exists(conn, "table", "_system_file_policy"),
        "{whence}: _system_file_policy table must exist"
    );
    let policy = cols(conn, "_system_file_policy");
    assert_eq!(
        policy,
        FILE_POLICY_COLS.map(String::from).to_vec(),
        "{whence}: _system_file_policy column set/order"
    );
}

#[test]
fn fresh_tenant_db_has_path_and_file_policy() {
    let dir = tempdir().unwrap();
    let tid = "t-frls-fresh";
    let _ = drust::storage::tenant_db::open_write(dir.path(), tid).unwrap();
    let conn = Connection::open(dir.path().join("tenants").join(tid).join("data.sqlite")).unwrap();
    assert_tenant_shape(&conn, "fresh");
}

#[test]
fn migrated_tenant_db_matches_fresh_and_is_idempotent() {
    let dir = tempdir().unwrap();

    // Reference: an untouched fresh tenant.
    let fresh_id = "t-frls-ref";
    let _ = drust::storage::tenant_db::open_write(dir.path(), fresh_id).unwrap();
    let fresh_path = dir
        .path()
        .join("tenants")
        .join(fresh_id)
        .join("data.sqlite");

    // Subject: a tenant rolled back to the pre-v1.63 shape, then migrated.
    let old_id = "t-frls-old";
    let _ = drust::storage::tenant_db::open_write(dir.path(), old_id).unwrap();
    let old_path = dir.path().join("tenants").join(old_id).join("data.sqlite");
    {
        let conn = Connection::open(&old_path).unwrap();
        conn.execute_batch(
            r#"
            DROP INDEX IF EXISTS idx_system_files_path;
            ALTER TABLE "_system_files" DROP COLUMN path;
            ALTER TABLE "_system_upload_sessions" DROP COLUMN path;
            DROP TABLE IF EXISTS "_system_file_policy";
            "#,
        )
        .unwrap();
        // A legacy row: the migration must leave it addressable with path NULL.
        conn.execute(
            "INSERT INTO \"_system_files\" (key, original_name, size_bytes, uploader) \
             VALUES ('legacy.bin', 'legacy.bin', 3, 'service')",
            [],
        )
        .unwrap();
    }

    // run_migrations calls this on EVERY boot — twice here proves idempotency.
    drust::db::migrations::migrate_tenant_db(dir.path(), old_id).unwrap();
    drust::db::migrations::migrate_tenant_db(dir.path(), old_id).unwrap();

    let migrated = Connection::open(&old_path).unwrap();
    assert_tenant_shape(&migrated, "migrated");

    let legacy_path: Option<String> = migrated
        .query_row(
            "SELECT path FROM \"_system_files\" WHERE key = 'legacy.bin'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        legacy_path.is_none(),
        "a legacy file row must migrate to path IS NULL, not to a fabricated path"
    );

    // Column-for-column parity between the two paths.
    let fresh = Connection::open(&fresh_path).unwrap();
    for table in [
        "_system_files",
        "_system_upload_sessions",
        "_system_file_policy",
    ] {
        assert_eq!(
            cols(&migrated, table),
            cols(&fresh, table),
            "fresh vs migrated column drift on {table}"
        );
    }
}

/// v1.64 (#974) — the publish-grant column reaches a tenant that ALREADY has
/// the v1.63 registry.
///
/// `migrated_tenant_db_matches_fresh_and_is_idempotent` above drops the whole
/// table, so it exercises the `CREATE TABLE` const and says nothing about the
/// upgrade door that every real v1.63 install takes: the table exists, so
/// `CREATE TABLE IF NOT EXISTS` is a no-op and only `add_column_if_missing` can
/// deliver the column. Existing rows must survive with a NULL grant — NULL is
/// the deny state, and the grandfather grant is a separate marker-guarded step.
#[test]
fn a_v163_registry_gains_the_publish_grant_column_with_its_rows_intact() {
    let dir = tempdir().unwrap();
    let tid = "t-frls-grant";
    let _ = drust::storage::tenant_db::open_write(dir.path(), tid).unwrap();
    let db = dir.path().join("tenants").join(tid).join("data.sqlite");
    {
        let conn = Connection::open(&db).unwrap();
        conn.execute_batch(
            r#"
            ALTER TABLE "_system_file_policy" DROP COLUMN public_upload_roles;
            INSERT INTO "_system_file_policy" (prefix, owner_scoped, public_read)
              VALUES ('', 0, 1), ('avatars/', 1, 0);
            "#,
        )
        .unwrap();
    }

    // Twice: run_migrations runs on every boot.
    drust::db::migrations::migrate_tenant_db(dir.path(), tid).unwrap();
    drust::db::migrations::migrate_tenant_db(dir.path(), tid).unwrap();

    let conn = Connection::open(&db).unwrap();
    assert_eq!(
        cols(&conn, "_system_file_policy"),
        FILE_POLICY_COLS.map(String::from).to_vec(),
        "the upgraded registry must match the fresh one column for column"
    );
    let grants: Vec<(String, Option<String>)> = conn
        .prepare("SELECT prefix, public_upload_roles FROM \"_system_file_policy\" ORDER BY prefix")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(
        grants,
        vec![(String::new(), None), ("avatars/".to_string(), None)],
        "existing rules survive the add, and every one of them lands in the \
         DENY state — the migration must not grant anything by itself"
    );
}

/// The tenant-side twin of `migrated_meta_gains_file_path_column`, and the
/// reason the column add cannot live only in the boot migration.
///
/// `apply_schema` runs on EVERY writer open, and `SCHEMA_SQL` now carries a
/// partial index `ON "_system_files"(path)`. `CREATE INDEX IF NOT EXISTS` does
/// **not** tolerate a missing column — it raises `no such column` — so a
/// database whose `_system_files` predates v1.63 fails to open unless the
/// column is added BEFORE that batch. `migrate_tenant_db` masks this at boot,
/// but only for a tenant that is (a) still listed in `tenants` and (b) migrated
/// cleanly; `open_write_existing` exists precisely to catch up the ones that
/// are not (restored-from-`_trash`, previously failed), and it only runs
/// `apply_schema`.
#[test]
fn writer_open_on_a_pre_v163_tenant_db_succeeds() {
    let dir = tempdir().unwrap();
    let tid = "t-frls-reopen";
    let _ = drust::storage::tenant_db::open_write(dir.path(), tid).unwrap();
    let db = dir.path().join("tenants").join(tid).join("data.sqlite");
    {
        let conn = Connection::open(&db).unwrap();
        conn.execute_batch(
            r#"
            DROP INDEX IF EXISTS idx_system_files_path;
            ALTER TABLE "_system_files" DROP COLUMN path;
            "#,
        )
        .unwrap();
    }

    let conn = drust::storage::tenant_db::open_write(dir.path(), tid)
        .expect("apply_schema must be safe on a tenant DB that predates _system_files.path");
    assert!(
        cols(&conn, "_system_files").contains(&"path".to_string()),
        "the writer open must restore _system_files.path, not just tolerate its absence"
    );
    assert!(object_exists(&conn, "index", "idx_system_files_path"));

    // Same for the never-creates open, which is the actual upgrade-catch-up door.
    drop(conn);
    let conn = drust::storage::tenant_db::open_write_existing(dir.path(), tid).unwrap();
    assert!(cols(&conn, "_system_files").contains(&"path".to_string()));
}

#[test]
fn fresh_meta_has_file_path_column() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("meta.sqlite");
    let conn = drust::storage::meta::open_meta(&path).unwrap();
    let files = cols(&conn, "_system_files");
    assert!(
        files.contains(&"path".to_string()),
        "meta _system_files must have `path` (got {files:?})"
    );
    assert!(
        object_exists(&conn, "index", "idx_system_files_path"),
        "meta must have the partial path index"
    );
    // _system_file_policy is TENANT-side only — it must NOT leak into meta
    // (tests/meta_sqlite.rs pins the meta table list exactly).
    assert!(
        !object_exists(&conn, "table", "_system_file_policy"),
        "_system_file_policy must not be created in meta.sqlite"
    );
}

#[test]
fn migrated_meta_gains_file_path_column() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("meta.sqlite");
    {
        // Pre-v1.63 meta shape: _system_files without `path`. open_meta's
        // CREATE TABLE IF NOT EXISTS is a no-op on it, so only
        // apply_migrations can add the column.
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE "_system_files" (
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
            "#,
        )
        .unwrap();
    }
    let conn = drust::storage::meta::open_meta(&path).unwrap();
    assert!(
        cols(&conn, "_system_files").contains(&"path".to_string()),
        "meta apply_migrations must add _system_files.path on upgrade"
    );
    assert!(
        object_exists(&conn, "index", "idx_system_files_path"),
        "meta apply_migrations must create the partial path index on upgrade"
    );
    // Second open = second boot: must be a clean no-op.
    let conn = drust::storage::meta::open_meta(&path).unwrap();
    assert!(cols(&conn, "_system_files").contains(&"path".to_string()));
}

#[test]
fn run_migrations_adds_file_policy_seeded_marker() {
    let dir = tempdir().unwrap();
    let conn = drust::storage::meta::open_meta(&dir.path().join("meta.sqlite")).unwrap();
    drust::db::migrations::run_migrations(&conn, dir.path()).unwrap();
    let tenant_cols = cols(&conn, "tenants");
    assert!(
        tenant_cols.contains(&"file_policy_seeded".to_string()),
        "tenants must gain file_policy_seeded (got {tenant_cols:?})"
    );
    let (notnull, dflt): (i64, Option<String>) = conn
        .query_row(
            "SELECT \"notnull\", dflt_value FROM pragma_table_info('tenants') \
             WHERE name = 'file_policy_seeded'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(notnull, 1, "file_policy_seeded must be NOT NULL");
    assert_eq!(
        dflt.as_deref(),
        Some("0"),
        "file_policy_seeded must default to 0 (= not yet seeded)"
    );
    // Every boot re-runs this; the marker column must not be re-added or reset.
    drust::db::migrations::run_migrations(&conn, dir.path()).unwrap();
    assert!(cols(&conn, "tenants").contains(&"file_policy_seeded".to_string()));
}

/// v1.64 (#974) — the second marker, same shape and same reason as the first.
#[test]
fn run_migrations_adds_public_upload_seeded_marker() {
    let dir = tempdir().unwrap();
    let conn = drust::storage::meta::open_meta(&dir.path().join("meta.sqlite")).unwrap();
    drust::db::migrations::run_migrations(&conn, dir.path()).unwrap();
    let tenant_cols = cols(&conn, "tenants");
    assert!(
        tenant_cols.contains(&"public_upload_seeded".to_string()),
        "tenants must gain public_upload_seeded (got {tenant_cols:?})"
    );
    let (notnull, dflt): (i64, Option<String>) = conn
        .query_row(
            "SELECT \"notnull\", dflt_value FROM pragma_table_info('tenants') \
             WHERE name = 'public_upload_seeded'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(notnull, 1, "public_upload_seeded must be NOT NULL");
    assert_eq!(
        dflt.as_deref(),
        Some("0"),
        "it must default to 0, or an EXISTING tenant (whose row predates the \
         column) would be stamped as already-grandfathered and lose the grant \
         that keeps its uploads working"
    );
    drust::db::migrations::run_migrations(&conn, dir.path()).unwrap();
    assert!(cols(&conn, "tenants").contains(&"public_upload_seeded".to_string()));
}
