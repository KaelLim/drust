mod helpers;
use drust::mcp::server::McpRegistry;
use drust::mcp::tools::schema::{
    FieldSpec, add_field, create_collection, drop_collection, drop_field,
};
use drust::mcp::tools::write::{delete_record, insert_record, update_record};
use drust::storage::pool::TenantRegistry;
use std::sync::Arc;

async fn svc(dir: &tempfile::TempDir) -> drust::mcp::server::DrustMcp {
    let data = dir.path().to_path_buf();
    let tr = Arc::new(TenantRegistry::new(data.clone(), 2));
    let _ = drust::storage::tenant_db::open_write(&data, "blog").unwrap();
    let reg = McpRegistry::new(tr);
    reg.get_or_create("blog").await.unwrap()
}

#[tokio::test]
async fn create_insert_update_delete_roundtrip() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    create_collection(
        &s,
        "posts",
        &[FieldSpec {
            name: "title".into(),
            sql_type: "text".into(),
            nullable: false,
            unique: false,
            default_value: None,
            foreign_key: None,
        }],
    )
    .await
    .unwrap();
    let ins = insert_record(&s, "posts", serde_json::json!({"title":"a"}))
        .await
        .unwrap();
    let id = ins["id"].as_i64().unwrap();
    let upd = update_record(&s, "posts", id, serde_json::json!({"title":"b"}))
        .await
        .unwrap();
    assert_eq!(upd["record"]["title"], "b");
    let del = delete_record(&s, "posts", id).await.unwrap();
    assert_eq!(del["ok"], true);
}

#[tokio::test]
async fn add_field_adds_column() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    create_collection(
        &s,
        "posts",
        &[FieldSpec {
            name: "title".into(),
            sql_type: "text".into(),
            nullable: false,
            unique: false,
            default_value: None,
            foreign_key: None,
        }],
    )
    .await
    .unwrap();
    add_field(
        &s,
        "posts",
        FieldSpec {
            name: "views".into(),
            sql_type: "integer".into(),
            nullable: true,
            unique: false,
            default_value: Some(serde_json::json!(0)),
            foreign_key: None,
        },
    )
    .await
    .unwrap();
    let ins = insert_record(&s, "posts", serde_json::json!({"title":"a","views":5}))
        .await
        .unwrap();
    assert_eq!(ins["record"]["views"], 5);
}

#[tokio::test]
async fn sql_default_datetime_now_is_applied() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    create_collection(
        &s,
        "events",
        &[
            FieldSpec {
                name: "label".into(),
                sql_type: "text".into(),
                nullable: false,
                unique: false,
                default_value: None,
                foreign_key: None,
            },
            FieldSpec {
                name: "scheduled_at".into(),
                sql_type: "datetime".into(),
                nullable: false,
                unique: false,
                default_value: Some(serde_json::json!({"sql": "datetime('now')"})),
                foreign_key: None,
            },
        ],
    )
    .await
    .unwrap();
    // Insert without scheduled_at — the default should kick in and give
    // us a timestamp string.
    let ins = insert_record(&s, "events", serde_json::json!({"label": "launch"}))
        .await
        .unwrap();
    let stamp = ins["record"]["scheduled_at"].as_str().unwrap();
    // YYYY-MM-DD HH:MM:SS (19 chars) is SQLite's datetime('now') shape.
    assert_eq!(
        stamp.len(),
        19,
        "expected SQLite datetime format, got {stamp:?}"
    );
    assert_eq!(&stamp[4..5], "-");
    assert_eq!(&stamp[10..11], " ");
}

#[tokio::test]
async fn sql_default_allowlist_covers_all_entries() {
    // Every entry in SQL_DEFAULT_ALLOWLIST must actually be accepted by
    // SQLite — otherwise the allowlist is lying. We try each one in a
    // fresh column and expect no error.
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    create_collection(
        &s,
        "t",
        &[FieldSpec {
            name: "label".into(),
            sql_type: "text".into(),
            nullable: false,
            unique: false,
            default_value: None,
            foreign_key: None,
        }],
    )
    .await
    .unwrap();
    for (i, expr) in drust::mcp::tools::schema::SQL_DEFAULT_ALLOWLIST
        .iter()
        .enumerate()
    {
        add_field(
            &s,
            "t",
            FieldSpec {
                name: format!("f{i}"),
                sql_type: "datetime".into(),
                nullable: true,
                unique: false,
                default_value: Some(serde_json::json!({"sql": expr})),
                foreign_key: None,
            },
        )
        .await
        .unwrap_or_else(|e| panic!("allowlist entry {expr:?} rejected: {e}"));
    }
}

#[tokio::test]
async fn foreign_key_field_is_reported_in_describe() {
    use drust::mcp::tools::exploration::describe_collection as describe_mcp;
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    create_collection(
        &s,
        "authors",
        &[FieldSpec {
            name: "name".into(),
            sql_type: "text".into(),
            nullable: false,
            unique: false,
            default_value: None,
            foreign_key: None,
        }],
    )
    .await
    .unwrap();
    create_collection(
        &s,
        "posts",
        &[
            FieldSpec {
                name: "title".into(),
                sql_type: "text".into(),
                nullable: false,
                unique: false,
                default_value: None,
                foreign_key: None,
            },
            FieldSpec {
                name: "author_id".into(),
                sql_type: "integer".into(),
                nullable: false,
                unique: false,
                default_value: None,
                foreign_key: Some("authors".into()),
            },
        ],
    )
    .await
    .unwrap();
    let schema = describe_mcp(&s, "posts").await.unwrap();
    let author_id = schema["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["name"] == "author_id")
        .unwrap();
    assert_eq!(author_id["foreign_key"], "authors");
}

#[tokio::test]
async fn foreign_key_rejected_when_target_missing() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    let err = create_collection(
        &s,
        "orphans",
        &[FieldSpec {
            name: "parent_id".into(),
            sql_type: "integer".into(),
            nullable: true,
            unique: false,
            default_value: None,
            foreign_key: Some("nonexistent".into()),
        }],
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string().contains("unknown collection"),
        "expected pre-DDL FK validation, got: {err}"
    );
}

#[tokio::test]
async fn foreign_key_constraint_is_enforced_on_insert() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    create_collection(
        &s,
        "authors",
        &[FieldSpec {
            name: "name".into(),
            sql_type: "text".into(),
            nullable: false,
            unique: false,
            default_value: None,
            foreign_key: None,
        }],
    )
    .await
    .unwrap();
    create_collection(
        &s,
        "posts",
        &[FieldSpec {
            name: "author_id".into(),
            sql_type: "integer".into(),
            nullable: false,
            unique: false,
            default_value: None,
            foreign_key: Some("authors".into()),
        }],
    )
    .await
    .unwrap();
    // Inserting a post referencing a nonexistent author must fail.
    let err = insert_record(&s, "posts", serde_json::json!({"author_id": 999}))
        .await
        .unwrap_err();
    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("foreign key") || msg.contains("constraint"),
        "expected FK-constraint error, got: {err}"
    );
}

#[tokio::test]
async fn foreign_key_restrict_blocks_parent_delete_while_children_exist() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    create_collection(
        &s,
        "authors",
        &[FieldSpec {
            name: "name".into(),
            sql_type: "text".into(),
            nullable: false,
            unique: false,
            default_value: None,
            foreign_key: None,
        }],
    )
    .await
    .unwrap();
    create_collection(
        &s,
        "posts",
        &[FieldSpec {
            name: "author_id".into(),
            sql_type: "integer".into(),
            nullable: false,
            unique: false,
            default_value: None,
            foreign_key: Some("authors".into()),
        }],
    )
    .await
    .unwrap();
    let author = insert_record(&s, "authors", serde_json::json!({"name": "A"}))
        .await
        .unwrap();
    let author_id = author["record"]["id"].as_i64().unwrap();
    insert_record(&s, "posts", serde_json::json!({"author_id": author_id}))
        .await
        .unwrap();
    // RESTRICT means deleting the author while posts reference them must
    // fail, preserving referential integrity.
    let err = delete_record(&s, "authors", author_id).await.unwrap_err();
    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("foreign key") || msg.contains("constraint"),
        "expected ON DELETE RESTRICT error, got: {err}"
    );
}

#[tokio::test]
async fn sql_default_rejects_non_allowlisted() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    let err = create_collection(
        &s,
        "bad",
        &[FieldSpec {
            name: "evil".into(),
            sql_type: "text".into(),
            nullable: true,
            unique: false,
            default_value: Some(serde_json::json!({"sql": "(SELECT password FROM admins)"})),
            foreign_key: None,
        }],
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string().contains("not in allowlist"),
        "expected allowlist rejection, got: {err}"
    );
}

#[tokio::test]
async fn drop_field_removes_column() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    create_collection(
        &s,
        "posts",
        &[
            FieldSpec {
                name: "title".into(),
                sql_type: "text".into(),
                nullable: false,
                unique: false,
                default_value: None,
                foreign_key: None,
            },
            FieldSpec {
                name: "draft".into(),
                sql_type: "boolean".into(),
                nullable: true,
                unique: false,
                default_value: Some(serde_json::json!(1)),
                foreign_key: None,
            },
        ],
    )
    .await
    .unwrap();
    // row with `draft` set — drop still allowed (column-level drop is
    // independent of row contents).
    insert_record(&s, "posts", serde_json::json!({"title":"a","draft":0}))
        .await
        .unwrap();
    let v = drop_field(&s, "posts", "draft").await.unwrap();
    assert_eq!(v["dropped_field"], "draft");
    let field_names: Vec<String> = v["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["name"].as_str().unwrap().to_string())
        .collect();
    assert!(!field_names.contains(&"draft".to_string()));
    assert!(field_names.contains(&"title".to_string()));
    // existing rows survive with remaining columns intact
    let row = insert_record(&s, "posts", serde_json::json!({"title":"b"}))
        .await
        .unwrap();
    assert_eq!(row["record"]["title"], "b");
}

#[tokio::test]
async fn drop_field_rejects_system_columns() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    create_collection(
        &s,
        "posts",
        &[FieldSpec {
            name: "title".into(),
            sql_type: "text".into(),
            nullable: false,
            unique: false,
            default_value: None,
            foreign_key: None,
        }],
    )
    .await
    .unwrap();
    for bad in &["id", "created_at", "updated_at"] {
        let err = drop_field(&s, "posts", bad).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("system column") && msg.contains(bad),
            "expected system-column rejection for {bad}, got: {msg}"
        );
    }
}

#[tokio::test]
async fn drop_field_rejects_unknown() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    create_collection(
        &s,
        "posts",
        &[FieldSpec {
            name: "title".into(),
            sql_type: "text".into(),
            nullable: false,
            unique: false,
            default_value: None,
            foreign_key: None,
        }],
    )
    .await
    .unwrap();
    let err = drop_field(&s, "posts", "nope").await.unwrap_err();
    assert!(
        err.to_string().contains("unknown collection or field"),
        "expected unknown-field rejection, got: {err}"
    );
    let err2 = drop_field(&s, "ghosts", "title").await.unwrap_err();
    assert!(
        err2.to_string().contains("unknown collection or field"),
        "expected unknown-collection rejection, got: {err2}"
    );
}

#[tokio::test]
async fn drop_collection_removes_table_and_trigger() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    create_collection(
        &s,
        "posts",
        &[FieldSpec {
            name: "title".into(),
            sql_type: "text".into(),
            nullable: false,
            unique: false,
            default_value: None,
            foreign_key: None,
        }],
    )
    .await
    .unwrap();
    insert_record(&s, "posts", serde_json::json!({"title":"a"}))
        .await
        .unwrap();
    let v = drop_collection(&s, "posts").await.unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["dropped_collection"], "posts");
    // The collection no longer exists — a subsequent insert_record must
    // surface an error rather than silently succeed. The exact error
    // depends on which layer (authorizer / write path) catches the
    // missing table first; we only care that it's not a success.
    let _err = insert_record(&s, "posts", serde_json::json!({"title":"b"}))
        .await
        .unwrap_err();
    // list_collections should no longer include the dropped table.
    let cols = drust::mcp::tools::exploration::list_collections(&s)
        .await
        .unwrap();
    let names: Vec<String> = cols["collections"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap().to_string())
        .collect();
    assert!(
        !names.contains(&"posts".to_string()),
        "expected posts gone, got {names:?}"
    );
}

#[tokio::test]
async fn drop_collection_rejects_when_fk_referrers_exist() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    create_collection(
        &s,
        "authors",
        &[FieldSpec {
            name: "name".into(),
            sql_type: "text".into(),
            nullable: false,
            unique: false,
            default_value: None,
            foreign_key: None,
        }],
    )
    .await
    .unwrap();
    create_collection(
        &s,
        "posts",
        &[FieldSpec {
            name: "author_id".into(),
            sql_type: "integer".into(),
            nullable: false,
            unique: false,
            default_value: None,
            foreign_key: Some("authors".into()),
        }],
    )
    .await
    .unwrap();
    let err = drop_collection(&s, "authors").await.unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("foreign-key references") && msg.contains("posts.author_id"),
        "expected FK-referrer rejection listing posts.author_id, got: {msg}"
    );
    // After we drop the referring column, the parent drop succeeds.
    drop_field(&s, "posts", "author_id").await.unwrap();
    let ok = drop_collection(&s, "authors").await.unwrap();
    assert_eq!(ok["ok"], true);
}

#[tokio::test]
async fn drop_collection_rejects_unknown() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    let err = drop_collection(&s, "ghosts").await.unwrap_err();
    assert!(
        err.to_string().contains("unknown collection"),
        "expected unknown-collection rejection, got: {err}"
    );
}

#[tokio::test]
async fn drop_collection_rejects_system_prefix() {
    // The guard fires on the `_system_` prefix check before any existence
    // lookup, so the table does not need to exist in the tenant DB for
    // this test — the refusal error surfaces immediately.
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    let err = drop_collection(&s, "_system_public_files")
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("protected") && msg.contains("_system_"),
        "expected _system_ protection error, got: {msg}"
    );
}
