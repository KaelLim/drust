// WS1a — new tenant collections are created STRICT, and add_field (ALTER TABLE,
// which inherits the table's STRICT property) does not lose it.
//
// STRICT-ness is verified through a direct (authorizer-free) rusqlite connection
// to the tenant's data.sqlite, querying the `strict` column of pragma_table_list
// (SQLite >= 3.37). The read-only pool authorizer does not expose pragma_table_list,
// so we read the file directly — the same approach tests/strict_rebuild.rs uses.

use drust::mcp::server::McpRegistry;
use drust::mcp::tools::schema::{FieldSpec, add_field, create_collection};
use drust::storage::pool::TenantRegistry;
use rusqlite::Connection;
use std::sync::Arc;

async fn svc(dir: &tempfile::TempDir) -> drust::mcp::server::DrustMcp {
    let data = dir.path().to_path_buf();
    let tr = Arc::new(TenantRegistry::new(data.clone(), 2));
    let _ = drust::storage::tenant_db::open_write(&data, "blog").unwrap();
    let reg = McpRegistry::new(tr);
    reg.get_or_create("blog").await.unwrap()
}

fn field(name: &str, ty: &str, nullable: bool) -> FieldSpec {
    FieldSpec {
        name: name.into(),
        sql_type: ty.into(),
        nullable,
        unique: false,
        default_value: None,
        foreign_key: None,
        dim: None,
        description: None,
        ..Default::default()
    }
}

fn strict_of(dir: &tempfile::TempDir, table: &str) -> i64 {
    let c = Connection::open(dir.path().join("tenants/blog/data.sqlite")).unwrap();
    c.query_row(
        "SELECT strict FROM pragma_table_list WHERE name=?1",
        [table],
        |r| r.get(0),
    )
    .unwrap()
}

#[tokio::test]
async fn new_collection_is_strict_and_add_field_preserves_it() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;

    create_collection(
        &s,
        "widgets",
        &[
            field("qty", "integer", false),
            field("label", "text", false),
        ],
    )
    .await
    .unwrap();

    assert_eq!(
        strict_of(&d, "widgets"),
        1,
        "new collection table must be STRICT"
    );

    // add_field is an ALTER TABLE — STRICT is a table-level property that
    // ALTER inherits; it must survive.
    add_field(&s, "widgets", field("note", "text", true))
        .await
        .unwrap();
    assert_eq!(
        strict_of(&d, "widgets"),
        1,
        "add_field must not lose STRICT"
    );
}

#[tokio::test]
async fn strict_table_rejects_wrong_storage_class() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    create_collection(&s, "nums", &[field("qty", "integer", true)])
        .await
        .unwrap();

    // STRICT refuses a non-integer string into an INTEGER column.
    let c = Connection::open(d.path().join("tenants/blog/data.sqlite")).unwrap();
    let bad = c.execute("INSERT INTO nums(qty) VALUES ('not-an-int')", []);
    assert!(
        bad.is_err(),
        "STRICT must reject a string into an INTEGER column"
    );
}
