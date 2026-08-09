//! Wave 2 M3 Task 4 — lifecycle of the service-only fts index tools:
//! create/drop/list, validation sentinels, the mandatory ('rebuild') backfill
//! (the SQLITE_CORRUPT pin), the authoritative drop_collection sweep, and the
//! drop_field guard.

use drust::mcp::server::{DrustMcp, McpRegistry};
use drust::mcp::tools::fts::{create_fts_index, drop_fts_index, list_fts_indexes};
use drust::mcp::tools::schema::{FieldSpec, create_collection, drop_collection, drop_field};
use drust::mcp::tools::write::{delete_record, insert_record, update_record};
use drust::storage::pool::{SharedTenantPool, TenantRegistry};
use drust::storage::search_names::fts_head_name;
use std::sync::Arc;

async fn svc(dir: &tempfile::TempDir) -> DrustMcp {
    let data = dir.path().to_path_buf();
    let tr = Arc::new(TenantRegistry::new(data.clone(), 2));
    let _ = drust::storage::tenant_db::open_write(&data, "blog").unwrap();
    let reg = McpRegistry::new(tr);
    reg.get_or_create("blog").await.unwrap()
}

fn text_field(name: &str, nullable: bool) -> FieldSpec {
    FieldSpec {
        name: name.into(),
        sql_type: "text".into(),
        nullable,
        unique: false,
        default_value: None,
        foreign_key: None,
        dim: None,
        description: None,
        ..Default::default()
    }
}

async fn make_notes(s: &DrustMcp) {
    create_collection(
        s,
        "notes",
        &[text_field("title", true), text_field("body", true)],
    )
    .await
    .unwrap();
}

fn pool_of(s: &DrustMcp) -> SharedTenantPool {
    s.inner().pool.clone()
}

/// count of rows the head matches for `term` (direct SQL on the writer-built
/// external-content head; `$fts` operand wiring is Task 5).
async fn match_count(pool: &SharedTenantPool, head: &str, term: &str) -> i64 {
    let head = head.to_string();
    let term = term.to_string();
    pool.with_reader(move |c| {
        c.query_row(
            &format!(
                "SELECT count(*) FROM \"{h}\" WHERE \"{h}\" MATCH ?1",
                h = head.replace('"', "\"\"")
            ),
            rusqlite::params![term],
            |r| r.get::<_, i64>(0),
        )
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn create_list_and_match_roundtrip() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    make_notes(&s).await;

    let out = create_fts_index(&s, "notes", "main", &["title".into(), "body".into()], None)
        .await
        .unwrap();
    assert_eq!(out["ok"], true);
    assert_eq!(out["tokenizer"], "trigram");

    let listed = list_fts_indexes(&s, "notes").await.unwrap();
    let arr = listed["fts_indexes"].as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["name"], "main");
    assert_eq!(arr[0]["fields"], serde_json::json!(["title", "body"]));

    insert_record(
        &s,
        "notes",
        serde_json::json!({"title":"alpha report","body":"quarterly"}),
    )
    .await
    .unwrap();
    let head = fts_head_name("notes", "main");
    let pool = pool_of(&s);
    assert_eq!(match_count(&pool, &head, "alpha").await, 1);
    assert_eq!(match_count(&pool, &head, "quarterly").await, 1);
    assert_eq!(match_count(&pool, &head, "absent").await, 0);
}

#[tokio::test]
async fn duplicate_index_is_rejected() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    make_notes(&s).await;
    create_fts_index(&s, "notes", "main", &["title".into()], None)
        .await
        .unwrap();
    let err = create_fts_index(&s, "notes", "main", &["body".into()], None)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("FTS_INDEX_EXISTS"), "{err}");
}

#[tokio::test]
async fn reserved_index_name_is_rejected() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    make_notes(&s).await;
    let err = create_fts_index(&s, "notes", "main_data", &["title".into()], None)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("FTS_NAME_RESERVED"), "{err}");
}

#[tokio::test]
async fn non_text_vector_and_updated_at_fields_are_rejected() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    // A collection carrying a TEXT, an INTEGER, and a vector field.
    create_collection(
        &s,
        "docs",
        &[
            text_field("title", true),
            FieldSpec {
                name: "views".into(),
                sql_type: "integer".into(),
                nullable: true,
                ..Default::default()
            },
            FieldSpec {
                name: "embed".into(),
                sql_type: "vector".into(),
                nullable: true,
                dim: Some(4),
                ..Default::default()
            },
        ],
    )
    .await
    .unwrap();

    for bad in ["views", "embed", "updated_at"] {
        let err = create_fts_index(&s, "docs", "main", &[bad.into()], None)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("FTS_FIELD_INVALID"), "{bad}: {err}");
    }
}

/// THE critical pin: rows inserted BEFORE the index exist only in the parent.
/// The ('rebuild') backfill must seed the shadow so a later UPDATE/DELETE (whose
/// _au/_ad trigger issues a `'delete'` command by old rowid) does NOT raise
/// SQLITE_CORRUPT.
#[tokio::test]
async fn backfill_keeps_preexisting_rows_deletable() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    make_notes(&s).await;

    let a = insert_record(
        &s,
        "notes",
        serde_json::json!({"title":"alpha","body":"one"}),
    )
    .await
    .unwrap();
    let b = insert_record(
        &s,
        "notes",
        serde_json::json!({"title":"beta","body":"two"}),
    )
    .await
    .unwrap();
    let id_a = a["id"].as_i64().unwrap();
    let id_b = b["id"].as_i64().unwrap();

    // Index built AFTER the rows exist — rebuild must seed both.
    create_fts_index(&s, "notes", "main", &["title".into(), "body".into()], None)
        .await
        .unwrap();
    let head = fts_head_name("notes", "main");
    let pool = pool_of(&s);
    assert_eq!(match_count(&pool, &head, "alpha").await, 1);

    // UPDATE a pre-index row (fires _au: delete-old + insert-new). No corruption.
    update_record(&s, "notes", id_a, serde_json::json!({"title":"gamma"}))
        .await
        .expect("update of a pre-index row must not corrupt the fts index");
    assert_eq!(match_count(&pool, &head, "alpha").await, 0);
    assert_eq!(match_count(&pool, &head, "gamma").await, 1);

    // DELETE the other pre-index row (fires _ad: delete-old). No corruption.
    delete_record(&s, "notes", id_b)
        .await
        .expect("delete of a pre-index row must not corrupt the fts index");
    assert_eq!(match_count(&pool, &head, "beta").await, 0);

    // Integrity holds.
    let head2 = head.clone();
    pool.with_writer(move |c| {
        c.execute_batch(&format!(
            "INSERT INTO \"{h}\"(\"{h}\") VALUES('integrity-check');",
            h = head2.replace('"', "\"\"")
        ))
    })
    .await
    .expect("fts5 integrity-check must pass");
}

/// drop_collection sweeps every fts head from pragma_table_list (authoritative),
/// and a recreated same-name collection + same-name index answers only new data.
#[tokio::test]
async fn drop_collection_sweeps_fts_and_recreate_is_clean() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    make_notes(&s).await;
    create_fts_index(&s, "notes", "main", &["title".into()], None)
        .await
        .unwrap();
    insert_record(&s, "notes", serde_json::json!({"title":"alpha old"}))
        .await
        .unwrap();

    drop_collection(&s, "notes").await.unwrap();

    let pool = pool_of(&s);
    let leftover: i64 = pool
        .with_reader(|c| {
            c.query_row(
                "SELECT count(*) FROM pragma_table_list \
                 WHERE name LIKE '\\_system\\_search\\_fts$notes$%' ESCAPE '\\'",
                [],
                |r| r.get(0),
            )
        })
        .await
        .unwrap();
    assert_eq!(leftover, 0, "no fts tables may survive drop_collection");

    // Recreate the same names; the index must answer only the new corpus.
    make_notes(&s).await;
    create_fts_index(&s, "notes", "main", &["title".into()], None)
        .await
        .unwrap();
    insert_record(&s, "notes", serde_json::json!({"title":"beta new"}))
        .await
        .unwrap();
    let head = fts_head_name("notes", "main");
    assert_eq!(match_count(&pool, &head, "beta").await, 1);
    assert_eq!(match_count(&pool, &head, "alpha").await, 0);
}

#[tokio::test]
async fn drop_field_on_indexed_field_is_rejected() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    make_notes(&s).await;
    create_fts_index(&s, "notes", "main", &["title".into()], None)
        .await
        .unwrap();

    // `body` is not indexed → drop succeeds.
    drop_field(&s, "notes", "body")
        .await
        .expect("dropping a non-indexed field must succeed");

    // `title` is indexed → refused with the sentinel.
    let err = drop_field(&s, "notes", "title")
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("FTS_FIELD_INDEXED"), "{err}");
}

#[tokio::test]
async fn drop_fts_index_removes_head_and_registry() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    make_notes(&s).await;
    create_fts_index(&s, "notes", "main", &["title".into()], None)
        .await
        .unwrap();

    // Unknown index → FTS_INDEX_NOT_FOUND.
    let err = drop_fts_index(&s, "notes", "nope")
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("FTS_INDEX_NOT_FOUND"), "{err}");

    let out = drop_fts_index(&s, "notes", "main").await.unwrap();
    assert_eq!(out["ok"], true);
    assert!(out["fts_indexes"].as_array().unwrap().is_empty());

    // Head is gone from pragma_table_list; registry is empty.
    let pool = pool_of(&s);
    let head = fts_head_name("notes", "main");
    let head_check = head.clone();
    let leftover: i64 = pool
        .with_reader(move |c| {
            c.query_row(
                "SELECT count(*) FROM pragma_table_list WHERE name = ?1",
                rusqlite::params![head_check],
                |r| r.get(0),
            )
        })
        .await
        .unwrap();
    assert_eq!(leftover, 0);
    let listed = list_fts_indexes(&s, "notes").await.unwrap();
    assert!(listed["fts_indexes"].as_array().unwrap().is_empty());
}

/// Parity: a brand-new tenant's `_system_collection_meta` carries the
/// `fts_indexes_json` column (SCHEMA_SQL half of the two-site column add).
#[tokio::test]
async fn fresh_tenant_meta_has_fts_indexes_json_column() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    let pool = pool_of(&s);
    let cols: Vec<String> = pool
        .with_reader(|c| {
            c.prepare("PRAGMA table_info(_system_collection_meta)")?
                .query_map([], |r| r.get::<_, String>(1))?
                .collect::<Result<_, _>>()
        })
        .await
        .unwrap();
    assert!(
        cols.contains(&"fts_indexes_json".to_string()),
        "fresh tenant missing fts_indexes_json; cols = {cols:?}"
    );
}

/// The three tools are service-only by ROUTE dispatch (`/t/<id>/mcp` → anon
/// `WRITE_DENIED`, user `MCP_USER_DENIED`), exactly like `create_index`: the
/// tool fns take no role/CallerCtx param. Driving the HTTP endpoint with an
/// anon token is heavier than this task needs; instead pin that the three tools
/// are registered (count 70 → 73) and that their signatures carry no role gate.
#[test]
fn tool_count_reflects_three_new_service_only_tools() {
    assert_eq!(drust::mcp::handler::DrustMcpService::tool_count(), 73);
}
