// WS6 Task 6.2 — structured CHECK constraints are (a) emitted as a native
// inline CHECK in the CREATE TABLE DDL so SQLite rejects out-of-range /
// off-enum / over-long values, and (b) persisted to
// `_system_collection_meta.field_constraints_json` so describe_collection
// carries them onto each Field (for the write-path pre-check + codegen).
//
// Native rejection is verified through a direct (authorizer-free) rusqlite
// connection — the same approach tests/strict_new_collection.rs uses.

use drust::mcp::server::McpRegistry;
use drust::mcp::tools::schema::{FieldSpec, create_collection};
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

fn data_conn(dir: &tempfile::TempDir) -> Connection {
    Connection::open(dir.path().join("tenants/blog/data.sqlite")).unwrap()
}

#[tokio::test]
async fn constraints_persist_and_native_check_rejects() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;

    let schema = create_collection(
        &s,
        "people",
        &[
            FieldSpec {
                name: "age".into(),
                sql_type: "integer".into(),
                nullable: true,
                min: Some(0.0),
                max: Some(150.0),
                ..Default::default()
            },
            FieldSpec {
                name: "role".into(),
                sql_type: "text".into(),
                nullable: true,
                enum_values: Some(vec!["admin".into(), "user".into()]),
                ..Default::default()
            },
            FieldSpec {
                name: "bio".into(),
                sql_type: "text".into(),
                nullable: true,
                max_length: Some(10),
                ..Default::default()
            },
        ],
    )
    .await
    .unwrap();

    // (a) Native CHECK rejects out-of-range / off-enum / over-long.
    let c = data_conn(&d);
    assert!(
        c.execute("INSERT INTO people(age,role) VALUES (999,'admin')", [])
            .is_err(),
        "age above max must be rejected by the native CHECK"
    );
    assert!(
        c.execute("INSERT INTO people(age,role) VALUES (-1,'admin')", [])
            .is_err(),
        "age below min must be rejected"
    );
    assert!(
        c.execute("INSERT INTO people(age,role) VALUES (20,'ghost')", [])
            .is_err(),
        "off-enum role must be rejected"
    );
    assert!(
        c.execute(
            "INSERT INTO people(bio) VALUES ('this string is far too long')",
            []
        )
        .is_err(),
        "over-length bio must be rejected by length() CHECK"
    );
    // In-range row passes.
    c.execute(
        "INSERT INTO people(age,role,bio) VALUES (20,'admin','short')",
        [],
    )
    .unwrap();

    // (b) Constraints are carried on the schema returned by create_collection
    // (which serialises a CollectionSchema, so each Field has `constraints`).
    let fields = schema["fields"].as_array().expect("fields array");
    let age = fields
        .iter()
        .find(|f| f["name"] == "age")
        .expect("age field present");
    assert_eq!(age["constraints"]["max"], 150.0);
    assert_eq!(age["constraints"]["min"], 0.0);
    let role = fields.iter().find(|f| f["name"] == "role").unwrap();
    assert_eq!(role["constraints"]["enum_values"][0], "admin");
    let bio = fields.iter().find(|f| f["name"] == "bio").unwrap();
    assert_eq!(bio["constraints"]["max_length"], 10);

    // Fields with no constraints carry no `constraints` key (skip_serializing).
    let created = fields.iter().find(|f| f["name"] == "created_at").unwrap();
    assert!(
        created.get("constraints").is_none(),
        "constraint-free field must omit the constraints key"
    );
}

#[tokio::test]
async fn add_field_with_constraints_persists_and_rejects() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;

    create_collection(
        &s,
        "widgets",
        &[FieldSpec {
            name: "label".into(),
            sql_type: "text".into(),
            nullable: true,
            ..Default::default()
        }],
    )
    .await
    .unwrap();

    drust::mcp::tools::schema::add_field(
        &s,
        "widgets",
        FieldSpec {
            name: "qty".into(),
            sql_type: "integer".into(),
            nullable: true,
            min: Some(1.0),
            max: Some(100.0),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let c = data_conn(&d);
    assert!(
        c.execute("INSERT INTO widgets(qty) VALUES (0)", [])
            .is_err(),
        "qty below min must be rejected after add_field"
    );
    c.execute("INSERT INTO widgets(qty) VALUES (50)", [])
        .unwrap();

    // Persisted to meta so describe_collection reflects it.
    let cons = drust::storage::schema::read_field_constraints(&c, "widgets").unwrap();
    assert_eq!(cons.get("qty").and_then(|f| f.max), Some(100.0));
}
