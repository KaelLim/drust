//! v1.30 C2 — integration tests for attach_writable_authorizer.
//!
//! Every test opens a per-test temp tenant DB via [`open_write`], creates a
//! canonical `orders` collection as the non-protected target, attaches
//! [`attach_writable_authorizer`], then calls `conn.prepare(sql)` to assert
//! the authorizer's allow/deny decision (prepare exercises the authorizer
//! without needing to execute).

use drust::query::authorizer::{attach_writable_authorizer, detach_authorizer};
use drust::storage::tenant_db::open_write;
use tempfile::tempdir;

/// Per-test fresh tenant DB with a canonical non-protected `orders` table.
pub fn seed(name: &str) -> tempfile::TempDir {
    let d = tempdir().unwrap();
    let conn = open_write(d.path(), name).unwrap();
    conn.execute_batch("CREATE TABLE orders (id INTEGER PRIMARY KEY, qty INTEGER);")
        .unwrap();
    d
}

#[test]
fn insert_into_user_table_allowed() {
    let d = seed("alloc_insert");
    let conn = open_write(d.path(), "alloc_insert").unwrap();
    attach_writable_authorizer(&conn);
    let sql = "INSERT INTO orders (qty) VALUES (1)";
    let r = conn.prepare(sql);
    assert!(
        r.is_ok(),
        "expected allow for: {} (err: {:?})",
        sql,
        r.err()
    );
}

#[test]
fn update_user_table_allowed() {
    let d = seed("alloc_update");
    let conn = open_write(d.path(), "alloc_update").unwrap();
    attach_writable_authorizer(&conn);
    let sql = "UPDATE orders SET qty = 2 WHERE id = 1";
    let r = conn.prepare(sql);
    assert!(
        r.is_ok(),
        "expected allow for: {} (err: {:?})",
        sql,
        r.err()
    );
}

#[test]
fn delete_user_table_allowed() {
    let d = seed("alloc_delete");
    let conn = open_write(d.path(), "alloc_delete").unwrap();
    attach_writable_authorizer(&conn);
    let sql = "DELETE FROM orders WHERE id = 1";
    let r = conn.prepare(sql);
    assert!(
        r.is_ok(),
        "expected allow for: {} (err: {:?})",
        sql,
        r.err()
    );
}

#[test]
fn pragma_table_info_allowed() {
    let d = seed("alloc_pragma_ti");
    let conn = open_write(d.path(), "alloc_pragma_ti").unwrap();
    attach_writable_authorizer(&conn);
    let sql = "SELECT * FROM pragma_table_info('orders')";
    let r = conn.prepare(sql);
    assert!(
        r.is_ok(),
        "expected allow for: {} (err: {:?})",
        sql,
        r.err()
    );
}

#[test]
fn pragma_writable_schema_ignored() {
    let d = seed("alloc_pragma_ws");
    let conn = open_write(d.path(), "alloc_pragma_ws").unwrap();
    attach_writable_authorizer(&conn);
    // Prepare succeeds because the authorizer's Pragma arm returns Ignore
    // (no-op) for any pragma not in the table_info/index_* whitelist —
    // including writable_schema. Ignore means the statement compiles but
    // the action is silently dropped.
    let sql = "PRAGMA writable_schema = 1";
    let r = conn.prepare(sql);
    assert!(
        r.is_ok(),
        "expected allow (Ignore) for: {} (err: {:?})",
        sql,
        r.err()
    );
    // Execute it too — should still be a no-op under Ignore semantics.
    let _ = conn.execute("PRAGMA writable_schema = 1", []);
    // Confirm the write was dropped: writable_schema must still report 0.
    // Detach first because the authorizer's Ignore arm also suppresses the
    // pragma-read, returning QueryReturnedNoRows; the assertion target is
    // the persisted DB state, not the in-authorizer query path.
    detach_authorizer(&conn);
    let val: i32 = conn
        .pragma_query_value(None, "writable_schema", |row| row.get(0))
        .unwrap();
    assert_eq!(
        val, 0,
        "PRAGMA writable_schema = 1 must be a no-op under Ignore; got {}",
        val
    );
}

#[test]
fn insert_into_system_users_denied() {
    let d = seed("t_ins_sys_users");
    let conn = open_write(d.path(), "t_ins_sys_users").unwrap();
    attach_writable_authorizer(&conn);
    let r = conn.prepare(
        "INSERT INTO _system_users (id, email, password_hash, created_at, updated_at) VALUES ('a','a','a','a','a')",
    );
    assert!(
        r.is_err(),
        "expected denial for: {}",
        "INSERT INTO _system_users (id, email, password_hash, created_at, updated_at) VALUES ('a','a','a','a','a')"
    );
}

#[test]
fn update_system_files_denied() {
    let d = seed("t_upd_sys_files");
    let conn = open_write(d.path(), "t_upd_sys_files").unwrap();
    attach_writable_authorizer(&conn);
    let r = conn.prepare("UPDATE _system_files SET visibility = 'public'");
    assert!(
        r.is_err(),
        "expected denial for: {}",
        "UPDATE _system_files SET visibility = 'public'"
    );
}

#[test]
fn drop_table_denied() {
    let d = seed("t_drop_table");
    let conn = open_write(d.path(), "t_drop_table").unwrap();
    attach_writable_authorizer(&conn);
    let r = conn.prepare("DROP TABLE orders");
    assert!(r.is_err(), "expected denial for: {}", "DROP TABLE orders");
}

#[test]
fn alter_table_add_column_denied() {
    let d = seed("t_alter_table");
    let conn = open_write(d.path(), "t_alter_table").unwrap();
    attach_writable_authorizer(&conn);
    let r = conn.prepare("ALTER TABLE orders ADD COLUMN foo TEXT");
    assert!(
        r.is_err(),
        "expected denial for: {}",
        "ALTER TABLE orders ADD COLUMN foo TEXT"
    );
}

#[test]
fn create_trigger_denied() {
    let d = seed("t_create_trigger");
    let conn = open_write(d.path(), "t_create_trigger").unwrap();
    attach_writable_authorizer(&conn);
    let r = conn.prepare("CREATE TRIGGER tr AFTER INSERT ON orders BEGIN SELECT 1; END");
    assert!(
        r.is_err(),
        "expected denial for: {}",
        "CREATE TRIGGER tr AFTER INSERT ON orders BEGIN SELECT 1; END"
    );
}

#[test]
fn attach_database_denied() {
    let d = seed("t_attach_db");
    let conn = open_write(d.path(), "t_attach_db").unwrap();
    attach_writable_authorizer(&conn);
    let r = conn.prepare("ATTACH DATABASE '/tmp/x.db' AS other");
    assert!(
        r.is_err(),
        "expected denial for: {}",
        "ATTACH DATABASE '/tmp/x.db' AS other"
    );
}

#[test]
fn begin_transaction_denied() {
    let d = seed("t_begin_txn");
    let conn = open_write(d.path(), "t_begin_txn").unwrap();
    attach_writable_authorizer(&conn);
    let r = conn.prepare("BEGIN TRANSACTION");
    assert!(r.is_err(), "expected denial for: {}", "BEGIN TRANSACTION");
}

#[test]
fn case4_all_system_collections_insert_denied() {
    let d = seed("t");
    let conn = open_write(d.path(), "t").unwrap();

    // open_write applies tenant_db::SCHEMA_SQL plus per-tenant migrations,
    // which now create _system_users / _system_sessions themselves. Use
    // CREATE TABLE IF NOT EXISTS so this batch is a no-op when they already
    // exist, while still guaranteeing every protected _system_* collection is
    // present so each INSERT below can only fail via the authorizer.
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS _system_users (
           id            TEXT PRIMARY KEY,
           email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
           password_hash TEXT NOT NULL,
           verified      INTEGER NOT NULL DEFAULT 0,
           profile       TEXT,
           created_at    TEXT NOT NULL,
           updated_at    TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS _system_sessions (
           token_hash    TEXT PRIMARY KEY,
           user_id       TEXT NOT NULL REFERENCES _system_users(id) ON DELETE CASCADE,
           created_at    TEXT NOT NULL,
           expires_at    TEXT NOT NULL,
           last_seen_at  TEXT NOT NULL,
           ip_at_login   TEXT
         );",
    )
    .unwrap();

    attach_writable_authorizer(&conn);

    // One INSERT per protected _system_* collection, columns matching the
    // canonical CREATE TABLE in src/storage/tenant_db.rs SCHEMA_SQL and
    // src/db/migrations.rs. Each statement is structurally valid against
    // the schema above — only the authorizer should reject it.
    let cases: &[(&str, &str)] = &[
        (
            "_system_users",
            "INSERT INTO _system_users (id, email, password_hash, verified, created_at, updated_at) \
             VALUES ('u1','a@b.test','hash',0,'2026-01-01','2026-01-01')",
        ),
        (
            "_system_files",
            "INSERT INTO _system_files (key, original_name, size_bytes, uploader) \
             VALUES ('k1','name.txt',1,'svc')",
        ),
        (
            "_system_rpc",
            "INSERT INTO _system_rpc (name, sql, params_json) \
             VALUES ('r1','SELECT 1','[]')",
        ),
        (
            "_system_webhooks",
            "INSERT INTO _system_webhooks (collection, events, url, secret, created_at) \
             VALUES ('orders','insert','https://example.test/hook','sec','2026-01-01')",
        ),
        (
            "_system_oauth_providers",
            "INSERT INTO _system_oauth_providers (provider, client_id, client_secret, allowed_redirect_uris) \
             VALUES ('google','cid','csec','https://example.test/cb')",
        ),
        (
            "_system_sessions",
            "INSERT INTO _system_sessions (token_hash, user_id, created_at, expires_at, last_seen_at) \
             VALUES ('th1','u1','2026-01-01','2027-01-01','2026-01-01')",
        ),
    ];

    for (coll, sql) in cases {
        let r = conn.prepare(sql);
        assert!(
            r.is_err(),
            "expected authorizer denial for protected collection {coll}: {sql}"
        );
    }
}
