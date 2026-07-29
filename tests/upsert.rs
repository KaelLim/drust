//! v1.55 — MCP `upsert_records` tests (SQLite Wave 1 M2).
//!
//! Upsert = `INSERT ... ON CONFLICT(<cols>) DO UPDATE ... RETURNING *`, atomic
//! (one writer tx), per-row record-history with the CORRECT op: a pre-image hit
//! captures `op=update` (old/new), a miss captures `op=insert`. Conflict-target
//! discovery must accept a `UNIQUE` COLUMN constraint (a `sqlite_autoindex` that
//! `describe_collection` filters out) and the PK — hence `sku`-unique + `id`(PK)
//! coverage below.

#[path = "helpers.rs"]
mod helpers;

use drust::mcp::server::McpRegistry;
use drust::mcp::tools::batch::batch_upsert;
use drust::mcp::tools::schema::{FieldSpec, create_collection};
use drust::storage::pool::TenantRegistry;
use drust::storage::record_history::AuditActor;
use serde_json::{Value, json};
use std::sync::Arc;

async fn svc(dir: &tempfile::TempDir) -> drust::mcp::server::DrustMcp {
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
        nullable: false,
        unique: false,
        default_value: None,
        foreign_key: None,
        dim: None,
        description: None,
        ..Default::default()
    }
}

fn tfu(name: &str, ty: &str) -> FieldSpec {
    FieldSpec {
        unique: true,
        ..tf(name, ty)
    }
}

/// `products(sku TEXT UNIQUE, name TEXT)` — the UNIQUE column constraint makes a
/// `sqlite_autoindex` (invisible to `describe_collection`), so on_conflict:[sku]
/// exercises the direct-PRAGMA discovery path.
async fn make_products(s: &drust::mcp::server::DrustMcp) {
    create_collection(s, "products", &[tfu("sku", "text"), tf("name", "text")])
        .await
        .unwrap();
}

async fn count_rows(dir: &tempfile::TempDir, table: &str) -> i64 {
    let tr = TenantRegistry::new(dir.path().to_path_buf(), 2);
    let pool = tr.get_or_open("blog").unwrap();
    let sql = format!("SELECT COUNT(*) FROM \"{}\"", table.replace('"', "\"\""));
    pool.with_reader(move |c| c.query_row(&sql, [], |r| r.get::<_, i64>(0)))
        .await
        .unwrap()
}

/// All `_system_record_history` rows as `(op, old_json, new_json)`, oldest first.
async fn history(dir: &tempfile::TempDir) -> Vec<(String, Option<String>, Option<String>)> {
    let tr = TenantRegistry::new(dir.path().to_path_buf(), 2);
    let pool = tr.get_or_open("blog").unwrap();
    pool.with_reader(|c| {
        let mut stmt =
            c.prepare("SELECT op, old_json, new_json FROM _system_record_history ORDER BY id ASC")?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Option<String>>(1)?,
                    r.get::<_, Option<String>>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn upsert_inserts_then_updates_with_correct_history() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    make_products(&s).await;

    // (a) Two NEW rows → both "inserted".
    let out = batch_upsert(
        &s,
        "products",
        vec![
            json!({"sku":"a","name":"Apple"}),
            json!({"sku":"b","name":"Banana"}),
        ],
        vec!["sku".into()],
        AuditActor::service(),
    )
    .await
    .unwrap();
    assert_eq!(out["count"], 2);
    let results = out["results"].as_array().unwrap();
    assert!(results.iter().all(|r| r["op"] == "inserted"), "got {out}");
    assert_eq!(count_rows(&d, "products").await, 2);

    // (b) Same sku "a" with a new name → "updated", value reflects the change,
    // still 2 data rows (no duplicate), and a history `update` with old/new.
    let out = batch_upsert(
        &s,
        "products",
        vec![json!({"sku":"a","name":"Apricot"})],
        vec!["sku".into()],
        AuditActor::service(),
    )
    .await
    .unwrap();
    assert_eq!(out["count"], 1);
    assert_eq!(out["results"][0]["op"], "updated", "got {out}");
    assert_eq!(out["results"][0]["record"]["name"], "Apricot");
    assert_eq!(count_rows(&d, "products").await, 2, "update, not insert");

    // History: 2 inserts then 1 update (old.name=Apple, new.name=Apricot).
    let h = history(&d).await;
    assert_eq!(h.len(), 3, "2 insert + 1 update history rows: {h:?}");
    assert_eq!(h[2].0, "update");
    let old: Value = serde_json::from_str(h[2].1.as_ref().unwrap()).unwrap();
    let new: Value = serde_json::from_str(h[2].2.as_ref().unwrap()).unwrap();
    assert_eq!(old["name"], "Apple");
    assert_eq!(new["name"], "Apricot");
}

#[tokio::test]
async fn upsert_non_unique_conflict_target_rejected() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    make_products(&s).await;
    // `name` is not unique → not a valid ON CONFLICT target.
    let err = batch_upsert(
        &s,
        "products",
        vec![json!({"sku":"a","name":"Apple"})],
        vec!["name".into()],
        AuditActor::service(),
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("UPSERT_NO_UNIQUE"), "got {err}");
    assert_eq!(count_rows(&d, "products").await, 0);
}

#[tokio::test]
async fn upsert_pk_conflict_target_accepted() {
    // on_conflict:[id] — the INTEGER PRIMARY KEY, discovered via table_info
    // (never a describe_collection index). Insert then update by explicit id.
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    make_products(&s).await;
    let out = batch_upsert(
        &s,
        "products",
        vec![json!({"id":100,"sku":"z","name":"Zed"})],
        vec!["id".into()],
        AuditActor::service(),
    )
    .await
    .unwrap();
    assert_eq!(out["results"][0]["op"], "inserted", "got {out}");
    let out = batch_upsert(
        &s,
        "products",
        vec![json!({"id":100,"sku":"z","name":"Zeta"})],
        vec!["id".into()],
        AuditActor::service(),
    )
    .await
    .unwrap();
    assert_eq!(out["results"][0]["op"], "updated", "got {out}");
    assert_eq!(out["results"][0]["record"]["name"], "Zeta");
    assert_eq!(count_rows(&d, "products").await, 1);
}

#[tokio::test]
async fn upsert_missing_conflict_key_rejected() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    make_products(&s).await;
    // Row omits the on_conflict key `sku` → can't determine the conflict target.
    let err = batch_upsert(
        &s,
        "products",
        vec![json!({"name":"NoSku"})],
        vec!["sku".into()],
        AuditActor::service(),
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("UPSERT_MISSING_KEY"), "got {err}");
    assert_eq!(count_rows(&d, "products").await, 0);
}

#[tokio::test]
async fn upsert_atomic_bad_row_rolls_back() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    make_products(&s).await;
    batch_upsert(
        &s,
        "products",
        vec![json!({"sku":"a","name":"Apple"})],
        vec!["sku".into()],
        AuditActor::service(),
    )
    .await
    .unwrap();
    // One good + one bad (unknown field) → whole tx rolls back.
    let err = batch_upsert(
        &s,
        "products",
        vec![json!({"sku":"c","name":"Cherry"}), json!({"nope":"x"})],
        vec!["sku".into()],
        AuditActor::service(),
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("unknown field"), "got {err}");
    assert_eq!(count_rows(&d, "products").await, 1, "no partial upsert");
    assert_eq!(
        count_rows(&d, "_system_record_history").await,
        1,
        "no orphan history"
    );
}

#[tokio::test]
async fn upsert_empty_and_protected_rejected() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    make_products(&s).await;
    let err = batch_upsert(
        &s,
        "products",
        vec![],
        vec!["sku".into()],
        AuditActor::service(),
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("BATCH_EMPTY"), "got {err}");

    let err = batch_upsert(
        &s,
        "_system_files",
        vec![json!({"x":"y"})],
        vec!["id".into()],
        AuditActor::service(),
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string().contains("PROTECTED_COLLECTION"),
        "got {err}"
    );
}
