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

use drust::rpc::prepare::{PrepareError, validate_rpc_sql};
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
    let err =
        validate_rpc_sql(&conn, "ATTACH DATABASE '/tmp/x.db' AS y", RpcMode::Write).unwrap_err();
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
    let err =
        validate_rpc_sql(&conn, "INSERT INTO orders (qty) VALUES (1)", RpcMode::Read).unwrap_err();
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
    validate_rpc_sql(&conn, "DELETE FROM orders WHERE id = :id", RpcMode::Write)
        .expect("valid write-mode DELETE must pass");
}

// ── v1.41.3: anon-callable read RPC over an owner-scoped collection ──
//
// An anon-callable READ RPC that SELECTs an owner-scoped collection without
// binding :user_id would return EVERY user's rows to an anonymous caller
// (drust does not rewrite stored-RPC SQL, so no owner row-filter is injected).
// The create-time guard must refuse it; the safe shapes must still create.

use drust::rpc::params::{ParamSpec, ParamType};
use drust::rpc::prepare::{RPC_ANON_OWNER_SCOPED, guard_anon_owner_scoped_rpc};
use drust::storage::schema::set_owner_field;

/// Seed `orders` as owner-scoped (owner_field set on its meta row).
fn seed_owner_scoped(name: &str) -> (TempDir, Connection) {
    let (d, conn) = seed(name);
    set_owner_field(&conn, "orders", Some("user_id"), Some("own")).unwrap();
    (d, conn)
}

fn user_id_param() -> Vec<ParamSpec> {
    vec![ParamSpec {
        name: "user_id".into(),
        ty: ParamType::Text,
        required: true,
        default: None,
    }]
}

#[test]
fn anon_callable_read_over_owner_scoped_without_user_id_rejected() {
    let (_d, conn) = seed_owner_scoped("anon_owner_no_uid");
    let sql = "SELECT id, qty FROM orders";
    // Sanity: the body itself is a valid read.
    validate_rpc_sql(&conn, sql, RpcMode::Read).expect("plain SELECT is valid read SQL");
    // Guard must REJECT: anon_callable + owner-scoped + no :user_id.
    let err = guard_anon_owner_scoped_rpc(&conn, sql, &[], true, RpcMode::Read).unwrap_err();
    let PrepareError::Rejected(msg) = err;
    assert!(
        msg.contains(RPC_ANON_OWNER_SCOPED),
        "expected {RPC_ANON_OWNER_SCOPED} rejection, got: {msg}"
    );
}

#[test]
fn anon_callable_read_over_owner_scoped_with_user_id_param_accepts() {
    let (_d, conn) = seed_owner_scoped("anon_owner_with_uid");
    // Same RPC but it declares a :user_id param → still creates fine.
    guard_anon_owner_scoped_rpc(
        &conn,
        "SELECT id, qty FROM orders WHERE user_id = :user_id",
        &user_id_param(),
        true,
        RpcMode::Read,
    )
    .expect(":user_id-bound anon read RPC over owner-scoped collection must still create");
}

#[test]
fn service_only_read_over_owner_scoped_accepts() {
    let (_d, conn) = seed_owner_scoped("svc_only_owner");
    // anon_callable=false → service-only → no leak → must create fine.
    guard_anon_owner_scoped_rpc(
        &conn,
        "SELECT id, qty FROM orders",
        &[],
        false,
        RpcMode::Read,
    )
    .expect("service-only read RPC over owner-scoped collection must create");
}

#[test]
fn anon_callable_read_over_non_owner_collection_accepts() {
    // `orders` left non-owner-scoped (no set_owner_field call).
    let (_d, conn) = seed("anon_non_owner");
    guard_anon_owner_scoped_rpc(
        &conn,
        "SELECT id, qty FROM orders",
        &[],
        true,
        RpcMode::Read,
    )
    .expect("anon read RPC over a non-owner collection must create");
}
