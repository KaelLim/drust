//! v1.46 Task 4 — record-history capture at the REST write choke point.
//!
//! Each REST mutation (`create_handler` / `update_handler` / `delete_handler`)
//! must emit exactly one `_system_record_history` row INSIDE its own write
//! transaction: op + old/new snapshots + actor, gated by the per-collection
//! `audit_enabled` flag (default ON, spec D4).

mod helpers;

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use helpers::{grab_pool, spin_up_tenant};
use tower::ServiceExt;

/// One `_system_record_history` row projected for assertions.
struct HistRow {
    op: String,
    record_id: i64,
    old_json: Option<String>,
    new_json: Option<String>,
    actor_kind: String,
}

/// Raw-SQL collection seed, same shape the canonical `create_collection`
/// produces (id PK + timestamps). No `_system_collection_meta` row → the
/// audit gate falls back to its default ON.
async fn seed_notes(dir: &tempfile::TempDir) {
    let pool = grab_pool("hist", dir).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                body TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );",
        )
    })
    .await
    .unwrap();
}

/// All history rows for `op`, ordered by insertion.
async fn history_rows(dir: &tempfile::TempDir, op: &str) -> Vec<HistRow> {
    let pool = grab_pool("hist", dir).await;
    let op = op.to_string();
    pool.with_reader(move |c| {
        let mut stmt = c.prepare(
            "SELECT op, record_id, old_json, new_json, actor_kind \
             FROM _system_record_history WHERE op = ?1 ORDER BY id",
        )?;
        let rows = stmt
            .query_map(rusqlite::params![op], |r| {
                Ok(HistRow {
                    op: r.get(0)?,
                    record_id: r.get(1)?,
                    old_json: r.get(2)?,
                    new_json: r.get(3)?,
                    actor_kind: r.get(4)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    })
    .await
    .unwrap()
}

async fn history_total(dir: &tempfile::TempDir) -> i64 {
    let pool = grab_pool("hist", dir).await;
    pool.with_reader(|c| {
        c.query_row("SELECT COUNT(*) FROM _system_record_history", [], |r| {
            r.get(0)
        })
    })
    .await
    .unwrap()
}

/// POST one note through the REST route; returns the new record id.
async fn insert_note(app: &Router, tok: &str, body_text: &str) -> i64 {
    let r = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/t/hist/records/notes")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(format!(
                    r#"{{"data":{{"body":"{body_text}"}}}}"#
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    let b = axum::body::to_bytes(r.into_body(), 65_536).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
    v["id"].as_i64().unwrap()
}

// REST insert → one history row, op=insert, old NULL, new = the row.
#[tokio::test]
async fn rest_insert_captures_history() {
    let (app, tok, d) = spin_up_tenant("hist").await;
    seed_notes(&d).await;

    let id = insert_note(&app, &tok, "hi").await;

    let rows = history_rows(&d, "insert").await;
    assert_eq!(rows.len(), 1, "exactly one insert history row");
    let row = &rows[0];
    assert_eq!(row.op, "insert");
    assert_eq!(row.record_id, id);
    assert!(row.old_json.is_none(), "insert has no pre-image");
    assert_eq!(row.actor_kind, "service");
    let new: serde_json::Value =
        serde_json::from_str(row.new_json.as_deref().expect("new_json present")).unwrap();
    assert_eq!(new["body"], "hi");
    assert_eq!(new["id"].as_i64(), Some(id));
}

// REST update → op=update, old.body=="a", new.body=="b".
#[tokio::test]
async fn rest_update_captures_old_and_new() {
    let (app, tok, d) = spin_up_tenant("hist").await;
    seed_notes(&d).await;

    let id = insert_note(&app, &tok, "a").await;
    let r = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PATCH)
                .uri(format!("/t/hist/records/notes/{id}"))
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"data":{"body":"b"}}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);

    let rows = history_rows(&d, "update").await;
    assert_eq!(rows.len(), 1, "exactly one update history row");
    let row = &rows[0];
    assert_eq!(row.record_id, id);
    assert_eq!(row.actor_kind, "service");
    let old: serde_json::Value =
        serde_json::from_str(row.old_json.as_deref().expect("old_json present")).unwrap();
    let new: serde_json::Value =
        serde_json::from_str(row.new_json.as_deref().expect("new_json present")).unwrap();
    assert_eq!(old["body"], "a", "pre-image carries the old value");
    assert_eq!(new["body"], "b", "post-image carries the new value");
    assert_eq!(old["id"].as_i64(), Some(id));
    assert_eq!(new["id"].as_i64(), Some(id));
}

// REST delete → op=delete, old present, new NULL.
#[tokio::test]
async fn rest_delete_captures_old_new_null() {
    let (app, tok, d) = spin_up_tenant("hist").await;
    seed_notes(&d).await;

    let id = insert_note(&app, &tok, "x").await;
    let r = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!("/t/hist/records/notes/{id}"))
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);

    let rows = history_rows(&d, "delete").await;
    assert_eq!(rows.len(), 1, "exactly one delete history row");
    let row = &rows[0];
    assert_eq!(row.record_id, id);
    assert_eq!(row.actor_kind, "service");
    assert!(row.new_json.is_none(), "delete has no post-image");
    let old: serde_json::Value =
        serde_json::from_str(row.old_json.as_deref().expect("old_json present")).unwrap();
    assert_eq!(old["body"], "x", "pre-image carries the deleted row");
    assert_eq!(old["id"].as_i64(), Some(id));
}

// audit_enabled=0 → the write succeeds but leaves zero history rows.
#[tokio::test]
async fn disabled_collection_captures_nothing() {
    let (app, tok, d) = spin_up_tenant("hist").await;
    seed_notes(&d).await;

    // Flip the gate off BEFORE any request so both the cached schema and the
    // in-tx describe_collection read audit_enabled=0.
    let pool = grab_pool("hist", &d).await;
    pool.with_writer(|c| drust::storage::schema::write_audit_enabled(c, "notes", false))
        .await
        .unwrap();

    let _id = insert_note(&app, &tok, "silent").await;

    assert_eq!(
        history_total(&d).await,
        0,
        "gate off → no history row for the insert"
    );
}
