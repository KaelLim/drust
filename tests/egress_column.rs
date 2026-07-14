//! meta `tenants.egress_allowlist_json` column + `read_egress_allowlist` read
//! path (v1.49, Task 2). Mirrors the `file_anon_caps_json` / `audit_default`
//! migration siblings: a fresh install gets the column via SCHEMA_SQL, an
//! upgraded DB gets it via the idempotent `add_column_if_missing` in
//! `run_migrations`, both defaulting to the deny-all `'[]'`.

use drust::db::migrations::run_migrations;
use drust::storage::meta::open_meta;
use drust::tenant::egress::read_egress_allowlist;
use rusqlite::Connection;
use tempfile::TempDir;

#[test]
fn fresh_tenant_defaults_to_empty_and_read_helper_round_trips() {
    let dir = TempDir::new().unwrap();
    let data_dir = dir.path();
    // Full real boot path: open_meta (SCHEMA_SQL) then run_migrations, exactly
    // as main.rs does.
    let meta = open_meta(&data_dir.join("meta.sqlite")).unwrap();
    run_migrations(&meta, data_dir).unwrap();

    meta.execute("INSERT INTO tenants (id, name) VALUES ('t1', 'One')", [])
        .unwrap();

    // (a) a freshly-created tenant row defaults to the deny-all '[]'.
    let stored: String = meta
        .query_row(
            "SELECT egress_allowlist_json FROM tenants WHERE id = 't1'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(stored, "[]", "fresh tenant defaults to deny-all");

    // (b) the read helper returns the same '[]'.
    assert_eq!(read_egress_allowlist(&meta, "t1").unwrap(), "[]");

    // (b') an absent row is fail-safe: deny-all '[]', never an error.
    assert_eq!(
        read_egress_allowlist(&meta, "no-such-tenant").unwrap(),
        "[]"
    );

    // (c) after an UPDATE to a JSON value, the helper reads it back verbatim.
    let val = r#"[{"system":"webhook","uri":"https://a.com"}]"#;
    meta.execute(
        "UPDATE tenants SET egress_allowlist_json = ?1 WHERE id = 't1'",
        [val],
    )
    .unwrap();
    assert_eq!(read_egress_allowlist(&meta, "t1").unwrap(), val);

    // (d) re-running the migration is a no-op: no error, value preserved.
    run_migrations(&meta, data_dir).unwrap();
    assert_eq!(read_egress_allowlist(&meta, "t1").unwrap(), val);
}

#[test]
fn migration_adds_column_and_backfills_existing_tenant() {
    let dir = TempDir::new().unwrap();
    let meta = Connection::open(dir.path().join("meta.sqlite")).unwrap();
    // Pre-egress meta shape: a tenants table WITHOUT egress_allowlist_json,
    // seeded with a live tenant. Mirrors the audit_default migration test.
    meta.execute_batch(
        "CREATE TABLE tenants (id TEXT PRIMARY KEY, name TEXT NOT NULL, deleted_at TEXT);
         INSERT INTO tenants (id, name) VALUES ('t1', 'One');
         CREATE TABLE admins (id INTEGER PRIMARY KEY, username TEXT, \
             password_hash TEXT NOT NULL, email TEXT, \
             created_at TEXT NOT NULL DEFAULT (datetime('now')));",
    )
    .unwrap();
    let tdir = dir.path().join("tenants");
    std::fs::create_dir_all(&tdir).unwrap();

    run_migrations(&meta, dir.path()).unwrap();
    // Existing tenant is backfilled to the deny-all '[]' via the column DEFAULT.
    assert_eq!(read_egress_allowlist(&meta, "t1").unwrap(), "[]");

    // Idempotent: a second run does not error and preserves the value.
    run_migrations(&meta, dir.path()).unwrap();
    assert_eq!(read_egress_allowlist(&meta, "t1").unwrap(), "[]");
}
