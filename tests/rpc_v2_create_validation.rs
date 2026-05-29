//! v1.30 C5 / S4 — create-time validation under the mode-matched authorizer.
//!
//! Asserts spec §8 table for `validate_rpc_sql(_, _, mode)`:
//! - Write-mode REJECTS DDL / ATTACH / writes to _system_* at prepare
//!   time, so they cannot enter the stored-RPC catalog.
//! - Write-mode ACCEPTS a legitimate INSERT/UPDATE/DELETE on a user table.
//! - Read-mode still rejects any write (existing C1 contract).
//!
//! Defense-in-depth (spec §11): the same `attach_writable_authorizer`
//! gates the runtime path in `src/rpc/handler.rs::call_rpc` (C4) — so a
//! body that passes the registry check will also pass runtime auth, and
//! a body that pre-existed registry-side gets rejected at runtime anyway.

use drust::rpc::prepare::{validate_rpc_sql, PrepareError};
use drust::rpc::registry::RpcMode;
use drust::storage::tenant_db::open_write;
use rusqlite::Connection;
use tempfile::TempDir;

/// Seed a fresh per-test tenant DB with a canonical non-protected
/// `orders` table. Mirrors `tests/authorizer_writable.rs::seed`.
fn seed(name: &str) -> (TempDir, Connection) {
    let d = TempDir::new().unwrap();
    let conn = open_write(d.path(), name).unwrap();
    conn.execute_batch("CREATE TABLE orders (id INTEGER PRIMARY KEY, qty INTEGER);")
        .unwrap();
    (d, conn)
}

#[test]
fn write_with_drop_table_rejected_at_create() {
    let (_d, conn) = seed("c5_drop");
    let err = validate_rpc_sql(&conn, "DROP TABLE orders", RpcMode::Write).unwrap_err();
    let PrepareError::Rejected(msg) = err;
    // The authorizer denies DropTable, so prepare returns "not authorized".
    let lc = msg.to_lowercase();
    assert!(
        lc.contains("authoriz") || lc.contains("prohibited"),
        "expected authorizer denial, got: {msg}"
    );
}

#[test]
fn write_with_insert_into_system_files_rejected() {
    let (_d, conn) = seed("c5_sysfiles");
    // Columns mirror src/storage/tenant_db.rs:58-72 so the prepare
    // failure is from the authorizer (Insert on protected table), NOT
    // from SQLite complaining about an unknown column.
    let sql = "INSERT INTO _system_files (key, original_name, size_bytes, uploader) \
               VALUES ('a', 'a', 1, 'a')";
    let err = validate_rpc_sql(&conn, sql, RpcMode::Write).unwrap_err();
    let PrepareError::Rejected(msg) = err;
    let lc = msg.to_lowercase();
    assert!(
        lc.contains("authoriz") || lc.contains("prohibited"),
        "expected authorizer denial on _system_files insert, got: {msg}"
    );
}

#[test]
fn write_with_attach_database_rejected() {
    let (_d, conn) = seed("c5_attach");
    let err = validate_rpc_sql(
        &conn,
        "ATTACH DATABASE '/tmp/x.db' AS y",
        RpcMode::Write,
    )
    .unwrap_err();
    let PrepareError::Rejected(msg) = err;
    let lc = msg.to_lowercase();
    assert!(
        lc.contains("authoriz") || lc.contains("prohibited"),
        "expected authorizer denial on ATTACH, got: {msg}"
    );
}

#[test]
fn read_with_insert_still_rejected() {
    let (_d, conn) = seed("c5_read_insert");
    // Existing C1 contract: read-mode rejects any write.
    let err = validate_rpc_sql(
        &conn,
        "INSERT INTO orders (qty) VALUES (1)",
        RpcMode::Read,
    )
    .unwrap_err();
    let PrepareError::Rejected(msg) = err;
    let lc = msg.to_lowercase();
    assert!(
        lc.contains("authoriz") || lc.contains("prohibited"),
        "expected read-mode authorizer denial on INSERT, got: {msg}"
    );
}

#[test]
fn write_with_valid_mutation_accepts() {
    let (_d, conn) = seed("c5_valid_insert");
    // Spec §8 row "valid Write body" — INSERT/UPDATE/DELETE on a
    // non-protected user table under the writable authorizer must pass
    // prepare. Bind placeholder `:q` exercises the same path the
    // runtime executor uses.
    validate_rpc_sql(
        &conn,
        "INSERT INTO orders (qty) VALUES (:q)",
        RpcMode::Write,
    )
    .expect("valid write-mode INSERT must pass prepare-time validation");

    // Bonus: UPDATE + DELETE for symmetry with C2's authorizer tests.
    validate_rpc_sql(
        &conn,
        "UPDATE orders SET qty = :q WHERE id = :id",
        RpcMode::Write,
    )
    .expect("valid write-mode UPDATE must pass");
    validate_rpc_sql(
        &conn,
        "DELETE FROM orders WHERE id = :id",
        RpcMode::Write,
    )
    .expect("valid write-mode DELETE must pass");
}
