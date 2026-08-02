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
    let pool = tr.get_or_create("blog").unwrap();
    let sql = format!("SELECT COUNT(*) FROM \"{}\"", table.replace('"', "\"\""));
    pool.with_reader(move |c| c.query_row(&sql, [], |r| r.get::<_, i64>(0)))
        .await
        .unwrap()
}

/// All `_system_record_history` rows as `(op, old_json, new_json)`, oldest first.
async fn history(dir: &tempfile::TempDir) -> Vec<(String, Option<String>, Option<String>)> {
    let tr = TenantRegistry::new(dir.path().to_path_buf(), 2);
    let pool = tr.get_or_create("blog").unwrap();
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

/// (codex F1) Fix: the pre-image probe honors the conflict INDEX's collation.
/// A `NOCASE` unique index makes SQLite take the DO UPDATE branch for 'a' vs
/// stored 'A'; a BINARY probe would misclassify it as an insert (wrong op +
/// lost old image). No MCP tool builds a COLLATE index, so create it raw.
async fn exec(dir: &tempfile::TempDir, sql: &str) {
    let tr = TenantRegistry::new(dir.path().to_path_buf(), 2);
    let pool = tr.get_or_create("blog").unwrap();
    let sql = sql.to_string();
    pool.with_writer(move |c| c.execute_batch(&sql))
        .await
        .unwrap();
}

#[tokio::test]
async fn upsert_honors_conflict_index_collation() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    create_collection(&s, "citems", &[tf("sku", "text"), tf("name", "text")])
        .await
        .unwrap();
    exec(
        &d,
        "CREATE UNIQUE INDEX ux_citems_sku ON citems(sku COLLATE NOCASE)",
    )
    .await;

    batch_upsert(
        &s,
        "citems",
        vec![json!({"sku":"A","name":"Apple"})],
        vec!["sku".into()],
        AuditActor::service(),
    )
    .await
    .unwrap();
    // sku 'a' differs only by case → NOCASE index → SQLite UPDATEs the 'A' row.
    let out = batch_upsert(
        &s,
        "citems",
        vec![json!({"sku":"a","name":"Apricot"})],
        vec!["sku".into()],
        AuditActor::service(),
    )
    .await
    .unwrap();
    assert_eq!(
        out["results"][0]["op"], "updated",
        "NOCASE collation must classify as update: {out}"
    );
    assert_eq!(count_rows(&d, "citems").await, 1, "one row, not two");
    let h = history(&d).await;
    assert_eq!(
        h.last().unwrap().0,
        "update",
        "history op must be update: {h:?}"
    );
}

async fn read_id_created(dir: &tempfile::TempDir, sku: &str) -> (i64, String) {
    let tr = TenantRegistry::new(dir.path().to_path_buf(), 2);
    let pool = tr.get_or_create("blog").unwrap();
    let sku = sku.to_string();
    pool.with_reader(move |c| {
        c.query_row(
            "SELECT id, created_at FROM products WHERE sku=?1",
            [sku],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
        )
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn upsert_update_preserves_server_managed_id_and_created_at() {
    // (codex F2) Fix: the DO UPDATE branch never overwrites id / created_at,
    // even when the payload supplies them (external-sync payloads carry ids).
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    make_products(&s).await;
    batch_upsert(
        &s,
        "products",
        vec![json!({"sku":"a","name":"X"})],
        vec!["sku".into()],
        AuditActor::service(),
    )
    .await
    .unwrap();
    let (id0, ca0) = read_id_created(&d, "a").await;
    let out = batch_upsert(
        &s,
        "products",
        vec![json!({"sku":"a","id":999,"created_at":"2000-01-01 00:00:00","name":"Y"})],
        vec!["sku".into()],
        AuditActor::service(),
    )
    .await
    .unwrap();
    assert_eq!(out["results"][0]["op"], "updated");
    let (id1, ca1) = read_id_created(&d, "a").await;
    assert_eq!(id1, id0, "id must be preserved, not moved to 999");
    assert_eq!(ca1, ca0, "created_at must be preserved");
    assert_eq!(out["results"][0]["record"]["name"], "Y");
}

#[tokio::test]
async fn upsert_within_batch_duplicate_key_rejected() {
    // (workflow F1) Two rows with the same conflict key in one call → reject
    // (Postgres "cannot affect row a second time"); whole batch rolls back.
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    make_products(&s).await;
    let err = batch_upsert(
        &s,
        "products",
        vec![json!({"sku":"a","name":"X"}), json!({"sku":"a","name":"Y"})],
        vec!["sku".into()],
        AuditActor::service(),
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string().contains("UPSERT_DUPLICATE_IN_BATCH"),
        "got {err}"
    );
    assert_eq!(count_rows(&d, "products").await, 0, "atomic rollback");
}

#[tokio::test]
async fn upsert_duplicate_on_conflict_columns_rejected() {
    // (workflow F4) on_conflict:["sku","sku"] must reject, not build malformed SQL.
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    make_products(&s).await;
    let err = batch_upsert(
        &s,
        "products",
        vec![json!({"sku":"a","name":"X"})],
        vec!["sku".into(), "sku".into()],
        AuditActor::service(),
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string().contains("UPSERT_DUPLICATE_COLUMN"),
        "got {err}"
    );
}

#[tokio::test]
async fn upsert_within_batch_duplicate_rejected_on_id_less_table() {
    // (codex r2) Fix: dedup still fires for a table with no `id` column
    // (falls back to the raw conflict-key tuple).
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    exec(&d, "CREATE TABLE noid (sku TEXT UNIQUE, name TEXT)").await;
    let err = batch_upsert(
        &s,
        "noid",
        vec![json!({"sku":"a","name":"X"}), json!({"sku":"a","name":"Y"})],
        vec!["sku".into()],
        AuditActor::service(),
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string().contains("UPSERT_DUPLICATE_IN_BATCH"),
        "got {err}"
    );
    assert_eq!(count_rows(&d, "noid").await, 0, "atomic rollback");
}

#[tokio::test]
async fn upsert_partial_unique_index_rejected_as_target() {
    // (codex r2) Fix: a partial unique index is not a valid ON CONFLICT target
    // → clean UPSERT_NO_UNIQUE, not a confusing runtime SQLite error.
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    exec(
        &d,
        "CREATE TABLE pt (sku TEXT, name TEXT); \
         CREATE UNIQUE INDEX ux_pt ON pt(sku) WHERE name IS NOT NULL;",
    )
    .await;
    let err = batch_upsert(
        &s,
        "pt",
        vec![json!({"sku":"a","name":"X"})],
        vec!["sku".into()],
        AuditActor::service(),
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string().contains("UPSERT_NO_UNIQUE"),
        "partial index must not be a target: {err}"
    );
}

// The mixed-expression-index case (`(sku, lower(name))` must NOT satisfy
// on_conflict=["sku"]) is covered as a direct `validate_conflict_target` unit
// test in src/mcp/tools/write.rs — a full batch_upsert can't reach it because
// `describe_collection` itself cannot read a table carrying an expression index
// (pre-existing; and such indexes are unreachable via drust's API — create_index
// only takes column names).
