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

// ── Task 5: MCP/edge write path (write.rs *_checked + enforce.rs) ────────────

/// DrustMcp harness over a fresh tenant dir — same shape as
/// `tests/mcp_write_schema.rs::svc`. `McpRegistry::new` builds with
/// `meta: None`, so `create_collection` stamps the default-ON audit gate.
async fn mcp_svc(dir: &tempfile::TempDir, tenant: &str) -> drust::mcp::server::DrustMcp {
    let data = dir.path().to_path_buf();
    let tr = std::sync::Arc::new(drust::storage::pool::TenantRegistry::new(data.clone(), 2));
    let _ = drust::storage::tenant_db::open_write(&data, tenant).unwrap();
    drust::mcp::server::McpRegistry::new(tr)
        .get_or_create(tenant)
        .await
        .unwrap()
}

fn fld(name: &str, ty: &str) -> drust::mcp::tools::schema::FieldSpec {
    drust::mcp::tools::schema::FieldSpec {
        name: name.into(),
        sql_type: ty.into(),
        nullable: true,
        unique: false,
        default_value: None,
        foreign_key: None,
        dim: None,
        description: None,
        ..Default::default()
    }
}

// Edge-function/MCP path: MCP service write → service actor.
#[tokio::test]
async fn mcp_service_write_captures_service_actor() {
    let d = tempfile::tempdir().unwrap();
    let svc = mcp_svc(&d, "mcphist").await;
    drust::mcp::tools::schema::create_collection(&svc, "notes", &[fld("body", "text")])
        .await
        .unwrap();
    drust::mcp::tools::write::insert_record(&svc, "notes", serde_json::json!({"body": "x"}))
        .await
        .unwrap();
    let ak: String = svc
        .inner()
        .pool
        .with_reader(|c| {
            c.query_row("SELECT actor_kind FROM _system_record_history", [], |r| {
                r.get(0)
            })
        })
        .await
        .unwrap();
    assert_eq!(ak, "service");
}

// enforced_insert with AuthCtx::User → actor_kind='user', actor_id=user_id.
#[tokio::test]
async fn enforced_user_write_captures_user_actor() {
    let d = tempfile::tempdir().unwrap();
    let svc = mcp_svc(&d, "mcphist").await;
    drust::mcp::tools::schema::create_collection(&svc, "notes", &[fld("body", "text")])
        .await
        .unwrap();
    // default user_caps = [select] → grant insert so the cap gate passes.
    drust::mcp::tools::schema::set_user_caps(
        &svc,
        "notes",
        &[
            drust::storage::schema::DmlVerb::Select,
            drust::storage::schema::DmlVerb::Insert,
        ],
    )
    .await
    .unwrap();
    let ctx = drust::auth::middleware::AuthCtx::User {
        user_id: "u9".into(),
        token_hash: "x".into(),
    };
    drust::functions::enforce::enforced_insert(
        &svc,
        &ctx,
        "notes",
        serde_json::json!({"body": "y"}),
    )
    .await
    .unwrap();
    let (ak, ai): (String, String) = svc
        .inner()
        .pool
        .with_reader(|c| {
            c.query_row(
                "SELECT actor_kind, actor_id FROM _system_record_history",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
        })
        .await
        .unwrap();
    assert_eq!(ak, "user");
    assert_eq!(ai, "u9");
}

// ── delete_user owner cascade (shared capture_owner_cascade, both sites) ─────

use drust::storage::pool::SharedTenantPool;

/// Owner-scoped `tasks` collection with 2 rows owned by `owner` and 1 by
/// `other`. The meta row is created by the `set_owner_field` upsert, so
/// `audit_enabled` sits at the column DEFAULT 1 (gate ON) unless a test
/// flips it off explicitly.
async fn seed_owned_tasks(pool: &SharedTenantPool, owner: &str, other: &str) {
    let owner = owner.to_string();
    let other = other.to_string();
    pool.with_writer(move |c| {
        c.execute_batch(
            "CREATE TABLE tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                body TEXT,
                owner TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );",
        )?;
        drust::storage::schema::set_owner_field(c, "tasks", Some("owner"), Some("own"))?;
        c.execute(
            "INSERT INTO tasks (body, owner) VALUES ('a1', ?1)",
            rusqlite::params![owner],
        )?;
        c.execute(
            "INSERT INTO tasks (body, owner) VALUES ('a2', ?1)",
            rusqlite::params![owner],
        )?;
        c.execute(
            "INSERT INTO tasks (body, owner) VALUES ('b1', ?1)",
            rusqlite::params![other],
        )?;
        Ok::<_, rusqlite::Error>(())
    })
    .await
    .unwrap();
}

/// All op='delete' history rows: (collection, record_id, old_json, new_json,
/// actor_kind), insertion order.
type DeleteHistRow = (String, i64, Option<String>, Option<String>, String);

async fn delete_history(pool: &SharedTenantPool) -> Vec<DeleteHistRow> {
    pool.with_reader(|c| {
        let mut stmt = c.prepare(
            "SELECT collection, record_id, old_json, new_json, actor_kind \
             FROM _system_record_history WHERE op = 'delete' ORDER BY id",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    })
    .await
    .unwrap()
}

// Site 1 — MCP tools::user::delete_user: the owner cascade must emit one
// op=delete history row PER deleted row (old populated, new NULL, service
// actor), and must not touch or capture other users' rows.
#[tokio::test]
async fn mcp_delete_user_cascade_captures_per_row_history() {
    let (pool, _d, uid) = helpers::seed_user_for_mcp("cas1").await;
    seed_owned_tasks(&pool, &uid, "u-other").await;

    let out = drust::mcp::tools::user::delete_user(&pool, uid.clone(), None)
        .await
        .unwrap();
    assert_eq!(out["deleted_records"]["tasks"], 2);

    let rows = delete_history(&pool).await;
    assert_eq!(rows.len(), 2, "one history row per cascaded delete");
    let mut record_ids: Vec<i64> = rows.iter().map(|r| r.1).collect();
    record_ids.sort();
    assert_eq!(record_ids, vec![1, 2], "only the owned rows are captured");
    for (coll, _id, old, new, actor) in &rows {
        assert_eq!(coll.as_str(), "tasks");
        assert_eq!(actor.as_str(), "service");
        assert!(new.is_none(), "delete has no post-image");
        let old: serde_json::Value =
            serde_json::from_str(old.as_deref().expect("old_json present")).unwrap();
        assert_eq!(old["owner"], uid.as_str(), "pre-image carries the owner");
        assert!(
            old["body"] == "a1" || old["body"] == "a2",
            "pre-image carries the row fields: {old}"
        );
    }
    // The other user's row survives, uncaptured.
    let (n, owner_left): (i64, String) = pool
        .with_reader(|c| {
            c.query_row("SELECT COUNT(*), MAX(owner) FROM tasks", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
        })
        .await
        .unwrap();
    assert_eq!(n, 1, "foreign row untouched by the cascade");
    assert_eq!(owner_left, "u-other");
}

// Site 2 — REST admin delete_user_handler: same cascade, same capture
// contract (both sites route through the shared capture_owner_cascade).
#[tokio::test]
async fn rest_admin_delete_user_cascade_captures_per_row_history() {
    use axum::extract::{Path, State};
    use drust::auth::middleware::ServiceTid;
    use std::collections::HashMap;

    let (auth_state, dir, uid) = helpers::auth_state_with_seeded_user("cas2").await;
    let pool = helpers::grab_pool("cas2", &dir).await;
    seed_owned_tasks(&pool, &uid, "u-other").await;

    let mut params = HashMap::new();
    params.insert("tenant".to_string(), "cas2".to_string());
    params.insert("uid".to_string(), uid.clone());
    let resp = drust::tenant::admin_user_routes::delete_user_handler(
        State(auth_state),
        ServiceTid("cas2".to_string()),
        Path(params),
    )
    .await;
    assert!(resp.status().is_success());

    let rows = delete_history(&pool).await;
    assert_eq!(rows.len(), 2, "one history row per cascaded delete");
    for (coll, _id, old, new, actor) in &rows {
        assert_eq!(coll.as_str(), "tasks");
        assert_eq!(actor.as_str(), "service");
        assert!(new.is_none(), "delete has no post-image");
        let old: serde_json::Value =
            serde_json::from_str(old.as_deref().expect("old_json present")).unwrap();
        assert_eq!(old["owner"], uid.as_str());
    }
    let n: i64 = pool
        .with_reader(|c| c.query_row("SELECT COUNT(*) FROM tasks", [], |r| r.get(0)))
        .await
        .unwrap();
    assert_eq!(n, 1, "foreign row untouched by the cascade");
}

// ── §11 capture atomicity: forced write failure → no history row ─────────────

/// Constrained `people` collection (integer `age`, max 150 → inline native
/// CHECK) created through the canonical MCP `create_collection` — same
/// FieldSpec shape as tests/check_constraints_writepath.rs — over the SAME
/// tenant dir the REST router serves. The meta row it writes stamps the
/// default-ON audit gate.
async fn seed_constrained_people(d: &tempfile::TempDir) {
    let svc = mcp_svc(d, "hist").await;
    drust::mcp::tools::schema::create_collection(
        &svc,
        "people",
        &[drust::mcp::tools::schema::FieldSpec {
            name: "age".into(),
            sql_type: "integer".into(),
            nullable: true,
            min: Some(0.0),
            max: Some(150.0),
            ..Default::default()
        }],
    )
    .await
    .unwrap();
}

// Spec §11 — capture atomicity, INSERT path: a CHECK-constraint violation
// inside the writer transaction (records.rs create_handler has no app-layer
// pre-check; the native CHECK raises in-tx) surfaces as the typed 400 and
// rolls back BOTH the row and any history capture.
#[tokio::test]
async fn rest_insert_check_violation_leaves_no_history() {
    let (app, tok, d) = spin_up_tenant("hist").await;
    seed_constrained_people(&d).await;

    let r = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/t/hist/records/people")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"data":{"age":999}}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    let b = axum::body::to_bytes(r.into_body(), 65_536).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(v["error_code"], "CHECK_CONSTRAINT_FAILED", "typed: {v}");

    assert_eq!(
        history_total(&d).await,
        0,
        "failed INSERT must leave no history row"
    );
    let pool = grab_pool("hist", &d).await;
    let n: i64 = pool
        .with_reader(|c| c.query_row("SELECT COUNT(*) FROM people", [], |r| r.get(0)))
        .await
        .unwrap();
    assert_eq!(n, 0, "the INSERT itself rolled back");
}

// Spec §11 — capture atomicity, policy-CHECK path: the in-tx insert policy
// CHECK (write.rs insert_record_checked) fires AFTER the INSERT and BEFORE
// the capture call, so a rejected row rolls back the already-executed INSERT
// and leaves zero history rows. Policy shape mirrors enforce.rs
// policy_check_fail_rolls_back (`n > 10`).
#[tokio::test]
async fn policy_check_failure_leaves_no_history() {
    let d = tempfile::tempdir().unwrap();
    let svc = mcp_svc(&d, "polhist").await;
    drust::mcp::tools::schema::create_collection(&svc, "items", &[fld("n", "integer")])
        .await
        .unwrap();
    // default user_caps = [select] → grant insert so the cap gate passes and
    // the policy CHECK is what rejects.
    drust::mcp::tools::schema::set_user_caps(
        &svc,
        "items",
        &[
            drust::storage::schema::DmlVerb::Select,
            drust::storage::schema::DmlVerb::Insert,
        ],
    )
    .await
    .unwrap();
    drust::mcp::tools::policy::set_policy(
        &svc,
        "items",
        "insert",
        None,
        Some(serde_json::json!({ "n": { "gt": 10 } })),
    )
    .await
    .unwrap();

    let ctx = drust::auth::middleware::AuthCtx::User {
        user_id: "u9".into(),
        token_hash: "x".into(),
    };
    let err = drust::functions::enforce::enforced_insert(
        &svc,
        &ctx,
        "items",
        serde_json::json!({"n": 5}),
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string().contains("POLICY_CHECK_FAILED"),
        "got: {err}"
    );

    let (hist, rows): (i64, i64) = svc
        .inner()
        .pool
        .with_reader(|c| {
            let hist: i64 =
                c.query_row("SELECT COUNT(*) FROM _system_record_history", [], |r| {
                    r.get(0)
                })?;
            let rows: i64 = c.query_row("SELECT COUNT(*) FROM items", [], |r| r.get(0))?;
            Ok::<_, rusqlite::Error>((hist, rows))
        })
        .await
        .unwrap();
    assert_eq!(hist, 0, "policy-rejected INSERT must leave no history row");
    assert_eq!(rows, 0, "the INSERT itself rolled back");
}

// Spec §11 — capture atomicity, UPDATE path: after one clean insert (exactly
// one history row), a CHECK-violating REST PATCH rolls back — no `update`
// history row appears, the total stays at 1, and the row keeps its
// pre-update value.
#[tokio::test]
async fn rest_update_check_violation_leaves_history_unchanged() {
    let (app, tok, d) = spin_up_tenant("hist").await;
    seed_constrained_people(&d).await;

    // Clean insert → 1 insert-history row.
    let r = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/t/hist/records/people")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"data":{"age":20}}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    let b = axum::body::to_bytes(r.into_body(), 65_536).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
    let id = v["id"].as_i64().unwrap();
    assert_eq!(history_total(&d).await, 1, "baseline: the insert captured");

    // Violating update → typed 400, rolled back.
    let r = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PATCH)
                .uri(format!("/t/hist/records/people/{id}"))
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"data":{"age":999}}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    let b = axum::body::to_bytes(r.into_body(), 65_536).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(v["error_code"], "CHECK_CONSTRAINT_FAILED", "typed: {v}");

    assert_eq!(
        history_total(&d).await,
        1,
        "failed UPDATE must not add a history row"
    );
    assert!(
        history_rows(&d, "update").await.is_empty(),
        "no op=update row after rollback"
    );
    // The row itself kept the pre-update value → the UPDATE rolled back too.
    let pool = grab_pool("hist", &d).await;
    let age: i64 = pool
        .with_reader(move |c| {
            c.query_row(
                "SELECT age FROM people WHERE id = ?1",
                rusqlite::params![id],
                |r| r.get(0),
            )
        })
        .await
        .unwrap();
    assert_eq!(age, 20, "row unchanged by the rolled-back UPDATE");
}

// audit_enabled=0 → the cascade still deletes but captures nothing.
#[tokio::test]
async fn delete_user_cascade_gate_off_captures_nothing() {
    let (pool, _d, uid) = helpers::seed_user_for_mcp("cas0").await;
    seed_owned_tasks(&pool, &uid, "u-other").await;
    pool.with_writer(|c| drust::storage::schema::write_audit_enabled(c, "tasks", false))
        .await
        .unwrap();

    drust::mcp::tools::user::delete_user(&pool, uid.clone(), None)
        .await
        .unwrap();

    let rows = delete_history(&pool).await;
    assert!(
        rows.is_empty(),
        "gate off → no history rows for the cascade"
    );
    let n: i64 = pool
        .with_reader(|c| c.query_row("SELECT COUNT(*) FROM tasks", [], |r| r.get(0)))
        .await
        .unwrap();
    assert_eq!(n, 1, "cascade still deleted the owned rows");
}
