//! v1.58 P1-3 — an owner-scoped collection must never accept a row with a
//! missing or empty owner field, on ANY surface.
//!
//! REST (`records.rs`), edge (`enforce.rs`) and batch (`batch.rs`) all enforced
//! this; MCP `insert_record` did not, so it could mint rows that the owning user
//! can never read and that anon is refused outright.
//!
//! The fix lives in `insert_row_in_tx`, the one per-row body all three MCP-side
//! surfaces share, rather than as a fourth parallel check.

use drust::mcp::server::{DrustMcp, McpRegistry};
use drust::mcp::tools::schema::{FieldSpec, create_collection};
use drust::storage::pool::TenantRegistry;
use std::sync::Arc;

async fn svc(dir: &tempfile::TempDir) -> DrustMcp {
    let data = dir.path().to_path_buf();
    let tr = Arc::new(TenantRegistry::new(data.clone(), 2));
    let _ = drust::storage::tenant_db::open_write(&data, "blog").unwrap();
    let reg = McpRegistry::new(tr);
    reg.get_or_create("blog").await.unwrap()
}

fn tf(name: &str, ty: &str) -> FieldSpec {
    FieldSpec {
        name: name.into(),
        sql_type: ty.into(),
        nullable: true,
        ..Default::default()
    }
}

/// Owner-scoped `notes(body, uid)` where `uid` FKs `_system_users(id)` —
/// `set_owner_field` refuses any column that is not such an FK, so the raw DDL
/// shape from `functions_caller_enforcement.rs` is the only way to build one.
async fn make_owner_scoped_notes(mcp: &DrustMcp) {
    mcp.inner()
        .pool
        .with_writer(|c| {
            c.execute_batch(
                "PRAGMA foreign_keys = ON;
                 CREATE TABLE \"notes\" (
                     id         INTEGER PRIMARY KEY AUTOINCREMENT,
                     uid        TEXT REFERENCES _system_users(id) ON DELETE RESTRICT,
                     body       TEXT,
                     created_at TEXT DEFAULT (datetime('now')),
                     updated_at TEXT DEFAULT (datetime('now'))
                 );",
            )?;
            drust::storage::schema::set_owner_field(c, "notes", Some("uid"), Some("own"))
        })
        .await
        .unwrap();
    mcp.inner().pool.schema_cache.invalidate("notes");
}

/// The owner column is a real FK, so a happy-path insert needs a real user row.
async fn seed_user(mcp: &DrustMcp, id: &str) {
    let id = id.to_string();
    mcp.inner()
        .pool
        .with_writer(move |c| {
            c.execute(
                "INSERT INTO _system_users (id, email, password_hash, created_at, updated_at) \
                 VALUES (?1, ?1, 'x', datetime('now'), datetime('now'))",
                rusqlite::params![id],
            )
            .map(|_| ())
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn mcp_insert_refuses_missing_owner_field() {
    let d = tempfile::tempdir().unwrap();
    let mcp = svc(&d).await;
    make_owner_scoped_notes(&mcp).await;

    let err =
        drust::mcp::tools::write::insert_record(&mcp, "notes", serde_json::json!({ "body": "hi" }))
            .await
            .expect_err("insert without the owner field must fail");
    assert!(
        err.to_string().contains("OWNER_FIELD_REQUIRED"),
        "expected OWNER_FIELD_REQUIRED, got: {err}"
    );
}

#[tokio::test]
async fn mcp_insert_refuses_empty_owner_field() {
    let d = tempfile::tempdir().unwrap();
    let mcp = svc(&d).await;
    make_owner_scoped_notes(&mcp).await;

    let err = drust::mcp::tools::write::insert_record(
        &mcp,
        "notes",
        serde_json::json!({ "body": "hi", "uid": "" }),
    )
    .await
    .expect_err("an empty owner field is not an owner");
    assert!(
        err.to_string().contains("OWNER_FIELD_REQUIRED"),
        "expected OWNER_FIELD_REQUIRED, got: {err}"
    );
}

#[tokio::test]
async fn mcp_insert_accepts_a_populated_owner_field() {
    let d = tempfile::tempdir().unwrap();
    let mcp = svc(&d).await;
    make_owner_scoped_notes(&mcp).await;
    seed_user(&mcp, "u-1").await;

    let out = drust::mcp::tools::write::insert_record(
        &mcp,
        "notes",
        serde_json::json!({ "body": "hi", "uid": "u-1" }),
    )
    .await
    .expect("a populated owner field must still insert");
    assert!(out.get("id").is_some(), "unexpected shape: {out}");
}

#[tokio::test]
async fn collections_without_an_owner_field_are_unaffected() {
    let d = tempfile::tempdir().unwrap();
    let mcp = svc(&d).await;
    create_collection(&mcp, "plain", &[tf("body", "text")])
        .await
        .unwrap();

    let out =
        drust::mcp::tools::write::insert_record(&mcp, "plain", serde_json::json!({ "body": "hi" }))
            .await
            .expect("no owner_field configured means no constraint");
    assert!(out.get("id").is_some(), "unexpected shape: {out}");
}
