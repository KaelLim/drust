//! v1.46 — record-history capture for write-mode stored RPCs.
//!
//! `run_write_rpc` (src/rpc/exec_write.rs) executes arbitrary
//! INSERT/UPDATE/DELETE under the writable authorizer; a scoped SQLite
//! preupdate hook buffers per-row old/new images and flushes them into
//! `_system_record_history` INSIDE the RPC savepoint, so history commits
//! (or rolls back) atomically with the mutation it records. These tests
//! drive the REST surface (`POST /t/<id>/rpc/<name>`), which shares the
//! executor with the admin playground — one site covers both callers.

mod helpers;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use serde_json::json;
use tower::ServiceExt;

fn req(
    method: &str,
    tid: &str,
    path: &str,
    body: Option<serde_json::Value>,
    token: &str,
) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(format!("/t/{tid}{path}"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"));
    if body.is_some() {
        b = b.header(header::CONTENT_TYPE, "application/json");
    }
    b.body(
        body.map(|v| Body::from(v.to_string()))
            .unwrap_or(Body::empty()),
    )
    .unwrap()
}

async fn read_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1_048_576)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// Create an RPC by writing directly to `_system_rpc` (same shape as
/// tests/rpc_v2_mutation.rs — bypasses config-time guards on purpose,
/// the runtime executor is what's under test).
async fn create_rpc(
    pool: &drust::storage::pool::SharedTenantPool,
    name: &str,
    sql: &str,
    params_json: &str,
    anon_callable: bool,
) {
    let name = name.to_string();
    let sql = sql.to_string();
    let params_json = params_json.to_string();
    pool.with_writer(move |c| {
        c.execute(
            "INSERT INTO _system_rpc \
             (name, sql, params_json, description, anon_callable, mode, \
              anon_calls, service_calls, last_called_at, created_at, updated_at) \
             VALUES (?1, ?2, ?3, '', ?4, 'write', 0, 0, NULL, \
                     datetime('now'), datetime('now'))",
            rusqlite::params![name, sql, params_json, anon_callable as i64],
        )
    })
    .await
    .unwrap();
}

async fn create_orders_table(pool: &drust::storage::pool::SharedTenantPool) {
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE orders (id INTEGER PRIMARY KEY AUTOINCREMENT, qty INTEGER, data BLOB);",
        )
    })
    .await
    .unwrap();
}

/// Seed rows OUTSIDE any RPC (direct pool write) — must never appear in
/// history (the hook only lives for the duration of a write-RPC run).
async fn seed_orders(pool: &drust::storage::pool::SharedTenantPool, qtys: &[i64]) {
    let qtys = qtys.to_vec();
    pool.with_writer(move |c| {
        for q in &qtys {
            c.execute("INSERT INTO orders (qty) VALUES (?1)", rusqlite::params![q])?;
        }
        Ok(())
    })
    .await
    .unwrap();
}

async fn orders_count(pool: &drust::storage::pool::SharedTenantPool) -> i64 {
    pool.with_reader(|c| c.query_row("SELECT COUNT(*) FROM orders", [], |r| r.get(0)))
        .await
        .unwrap()
}

/// One `_system_record_history` row projected for assertions.
#[derive(Debug)]
struct HistRow {
    op: String,
    record_id: i64,
    old_json: Option<String>,
    new_json: Option<String>,
    actor_kind: String,
    actor_id: Option<String>,
}

async fn history_rows(pool: &drust::storage::pool::SharedTenantPool) -> Vec<HistRow> {
    pool.with_reader(|c| {
        let mut stmt = c.prepare(
            "SELECT op, record_id, old_json, new_json, actor_kind, actor_id \
             FROM _system_record_history ORDER BY id",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(HistRow {
                    op: r.get(0)?,
                    record_id: r.get(1)?,
                    old_json: r.get(2)?,
                    new_json: r.get(3)?,
                    actor_kind: r.get(4)?,
                    actor_id: r.get(5)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    })
    .await
    .unwrap()
}

// ── INSERT: one history row, op=insert, old NULL, new carries the values
//    (BLOB → {"__blob_bytes": n}), record_id = the new rowid. ─────────────

#[tokio::test]
async fn write_rpc_insert_captures_history() {
    let (app, tid, svc, _anon, dir) = helpers::spin_up_dual_role_self_register("t-rh-ins").await;
    let pool = helpers::grab_pool(&tid, &dir).await;
    create_orders_table(&pool).await;
    create_rpc(
        &pool,
        "add_order",
        "INSERT INTO orders (qty, data) VALUES (:q, x'0102')",
        r#"[{"name":"q","type":"integer"}]"#,
        false,
    )
    .await;

    let r = app
        .oneshot(req(
            "POST",
            &tid,
            "/rpc/add_order",
            Some(json!({"q": 5})),
            &svc,
        ))
        .await
        .unwrap();
    let status = r.status();
    let v = read_json(r).await;
    assert!(status.is_success(), "{status} {v}");
    let new_id = v["last_insert_rowid"].as_i64().expect("last_insert_rowid");

    let rows = history_rows(&pool).await;
    assert_eq!(rows.len(), 1, "exactly one history row: {rows:?}");
    let row = &rows[0];
    assert_eq!(row.op, "insert");
    assert_eq!(row.record_id, new_id, "record_id = the inserted rowid");
    assert!(row.old_json.is_none(), "insert has no pre-image");
    assert_eq!(row.actor_kind, "service");
    let new: serde_json::Value =
        serde_json::from_str(row.new_json.as_deref().expect("new_json present")).unwrap();
    assert_eq!(new["qty"].as_i64(), Some(5));
    assert_eq!(new["id"].as_i64(), Some(new_id));
    assert_eq!(
        new["data"],
        json!({"__blob_bytes": 2}),
        "BLOB projects as __blob_bytes, same as materialize_row: {new}"
    );
}

// ── Multi-row UPDATE (no WHERE) on 3 rows → 3 history rows op=update with
//    the correct per-row old/new images. ──────────────────────────────────

#[tokio::test]
async fn write_rpc_multirow_update_captures_per_row() {
    let (app, tid, svc, _anon, dir) = helpers::spin_up_dual_role_self_register("t-rh-upd").await;
    let pool = helpers::grab_pool(&tid, &dir).await;
    create_orders_table(&pool).await;
    seed_orders(&pool, &[1, 2, 3]).await;

    create_rpc(
        &pool,
        "bump_all",
        "UPDATE orders SET qty = qty + 10",
        "[]",
        false,
    )
    .await;

    let r = app
        .oneshot(req("POST", &tid, "/rpc/bump_all", Some(json!({})), &svc))
        .await
        .unwrap();
    let status = r.status();
    let v = read_json(r).await;
    assert!(status.is_success(), "{status} {v}");
    assert_eq!(v["affected_rows"].as_i64(), Some(3));

    let rows = history_rows(&pool).await;
    assert_eq!(rows.len(), 3, "one history row per updated row: {rows:?}");
    let mut seen_ids: Vec<i64> = rows.iter().map(|r| r.record_id).collect();
    seen_ids.sort();
    assert_eq!(seen_ids, vec![1, 2, 3]);
    for row in &rows {
        assert_eq!(row.op, "update");
        assert_eq!(row.actor_kind, "service");
        let old: serde_json::Value =
            serde_json::from_str(row.old_json.as_deref().expect("old present")).unwrap();
        let new: serde_json::Value =
            serde_json::from_str(row.new_json.as_deref().expect("new present")).unwrap();
        // seeded qty == record_id (rows 1,2,3 carry qty 1,2,3).
        assert_eq!(
            old["qty"].as_i64(),
            Some(row.record_id),
            "old image per row: {old}"
        );
        assert_eq!(
            new["qty"].as_i64(),
            Some(row.record_id + 10),
            "new image per row: {new}"
        );
        assert_eq!(old["id"].as_i64(), Some(row.record_id));
        assert_eq!(new["id"].as_i64(), Some(row.record_id));
    }
}

// ── DELETE → op=delete, old populated, new NULL. ──────────────────────────

#[tokio::test]
async fn write_rpc_delete_captures_old() {
    let (app, tid, svc, _anon, dir) = helpers::spin_up_dual_role_self_register("t-rh-del").await;
    let pool = helpers::grab_pool(&tid, &dir).await;
    create_orders_table(&pool).await;
    seed_orders(&pool, &[7, 8]).await;

    create_rpc(&pool, "wipe", "DELETE FROM orders", "[]", false).await;

    let r = app
        .oneshot(req("POST", &tid, "/rpc/wipe", Some(json!({})), &svc))
        .await
        .unwrap();
    let status = r.status();
    let v = read_json(r).await;
    assert!(status.is_success(), "{status} {v}");
    assert_eq!(orders_count(&pool).await, 0);

    let rows = history_rows(&pool).await;
    assert_eq!(rows.len(), 2, "one history row per deleted row: {rows:?}");
    let mut qtys: Vec<i64> = rows
        .iter()
        .map(|r| {
            assert_eq!(r.op, "delete");
            assert!(r.new_json.is_none(), "delete has no post-image");
            let old: serde_json::Value =
                serde_json::from_str(r.old_json.as_deref().expect("old present")).unwrap();
            assert_eq!(old["id"].as_i64(), Some(r.record_id));
            old["qty"].as_i64().unwrap()
        })
        .collect();
    qtys.sort();
    assert_eq!(qtys, vec![7, 8], "pre-images carry the deleted values");
}

// ── audit_enabled=0 on the collection → same RPC → 0 history rows. ────────

#[tokio::test]
async fn audit_disabled_collection_captures_nothing() {
    let (app, tid, svc, _anon, dir) = helpers::spin_up_dual_role_self_register("t-rh-off").await;
    let pool = helpers::grab_pool(&tid, &dir).await;
    create_orders_table(&pool).await;
    pool.with_writer(|c| drust::storage::schema::write_audit_enabled(c, "orders", false))
        .await
        .unwrap();
    create_rpc(
        &pool,
        "add_one",
        "INSERT INTO orders (qty) VALUES (1)",
        "[]",
        false,
    )
    .await;

    let r = app
        .oneshot(req("POST", &tid, "/rpc/add_one", Some(json!({})), &svc))
        .await
        .unwrap();
    assert!(r.status().is_success());
    assert_eq!(orders_count(&pool).await, 1, "the write itself lands");
    assert!(
        history_rows(&pool).await.is_empty(),
        "gate off → no history rows"
    );
}

// ── dry_run=true → mutation rolled back AND 0 history rows. ───────────────

#[tokio::test]
async fn dry_run_persists_no_history() {
    let (app, tid, svc, _anon, dir) = helpers::spin_up_dual_role_self_register("t-rh-dry").await;
    let pool = helpers::grab_pool(&tid, &dir).await;
    create_orders_table(&pool).await;
    create_rpc(
        &pool,
        "add_one",
        "INSERT INTO orders (qty) VALUES (1)",
        "[]",
        false,
    )
    .await;

    let r = app
        .oneshot(req(
            "POST",
            &tid,
            "/rpc/add_one?dry_run=true",
            Some(json!({})),
            &svc,
        ))
        .await
        .unwrap();
    let status = r.status();
    let v = read_json(r).await;
    assert!(status.is_success(), "{status} {v}");
    assert_eq!(v["dry_run"].as_bool(), Some(true));
    assert_eq!(orders_count(&pool).await, 0, "dry_run persists nothing");
    assert!(
        history_rows(&pool).await.is_empty(),
        "dry_run must not persist history"
    );
}

// ── failing RPC (second statement errors) → savepoint rollback → 0 history
//    rows and 0 data changes. Capture atomicity invariant. ─────────────────

#[tokio::test]
async fn failing_rpc_rolls_back_history_and_data() {
    let (app, tid, svc, _anon, dir) = helpers::spin_up_dual_role_self_register("t-rh-fail").await;
    let pool = helpers::grab_pool(&tid, &dir).await;
    create_orders_table(&pool).await;
    create_rpc(
        &pool,
        "bad_pair",
        "INSERT INTO orders (qty) VALUES (1); SELECT * FROM does_not_exist;",
        "[]",
        false,
    )
    .await;

    let r = app
        .oneshot(req("POST", &tid, "/rpc/bad_pair", Some(json!({})), &svc))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    assert_eq!(orders_count(&pool).await, 0, "mutation rolled back");
    assert!(
        history_rows(&pool).await.is_empty(),
        "history rolled back with the mutation"
    );
}

// ── Two sequential RPC runs → exactly one capture per run; a leaked hook
//    from run 1 must not double-capture run 2 (or vice versa). ─────────────

#[tokio::test]
async fn sequential_runs_do_not_double_capture() {
    let (app, tid, svc, _anon, dir) = helpers::spin_up_dual_role_self_register("t-rh-seq").await;
    let pool = helpers::grab_pool(&tid, &dir).await;
    create_orders_table(&pool).await;
    create_rpc(
        &pool,
        "add_one",
        "INSERT INTO orders (qty) VALUES (1)",
        "[]",
        false,
    )
    .await;

    for _ in 0..2 {
        let r = app
            .clone()
            .oneshot(req("POST", &tid, "/rpc/add_one", Some(json!({})), &svc))
            .await
            .unwrap();
        assert!(r.status().is_success());
    }

    let rows = history_rows(&pool).await;
    assert_eq!(
        rows.len(),
        2,
        "exactly one history row per run — no double-capture: {rows:?}"
    );
    let mut ids: Vec<i64> = rows.iter().map(|r| r.record_id).collect();
    ids.sort();
    assert_eq!(ids, vec![1, 2]);

    // Belt and braces: a NON-RPC write after the runs must capture nothing
    // (the hook must not outlive the RPC savepoint).
    seed_orders(&pool, &[99]).await;
    assert_eq!(
        history_rows(&pool).await.len(),
        2,
        "direct pool write after the RPC runs adds no history row"
    );
}

// ── Trigger-driven preupdate events (canonical collections) ───────────────
//
// Every collection created through the CANONICAL create_collection path
// carries an AFTER UPDATE trigger `<name>_updated_at` that rewrites
// `updated_at`. SQLite fires the preupdate hook for trigger sub-statements
// too (query depth 1), so without depth handling one logical UPDATE would
// buffer TWO changes → two op=update history rows. The fix merges the
// trigger's fresh new-image into the pending depth-0 change, so exactly one
// row is written and its new_json equals the COMMITTED row (trigger-refreshed
// updated_at) — same fidelity contract the structured path gets from
// RETURNING * (v1.43 convergent-trigger note).

/// Create a collection through the CANONICAL create_collection path (same
/// shape as tests/record_history_capture.rs::mcp_svc) so the table carries
/// the `<name>_updated_at` trigger + the default-ON audit meta row.
async fn create_collection_canonical(
    dir: &tempfile::TempDir,
    tenant: &str,
    name: &str,
    fields: &[drust::mcp::tools::schema::FieldSpec],
) {
    let data = dir.path().to_path_buf();
    let tr = std::sync::Arc::new(drust::storage::pool::TenantRegistry::new(data, 2));
    let svc = drust::mcp::server::McpRegistry::new(tr)
        .get_or_create(tenant)
        .await
        .unwrap();
    drust::mcp::tools::schema::create_collection(&svc, name, fields)
        .await
        .unwrap();
}

fn fld(name: &str, ty: &str) -> drust::mcp::tools::schema::FieldSpec {
    drust::mcp::tools::schema::FieldSpec {
        name: name.into(),
        sql_type: ty.into(),
        nullable: true,
        ..Default::default()
    }
}

/// POST one record through the structured REST path; returns the new id.
async fn rest_insert(
    app: &axum::Router,
    tid: &str,
    tok: &str,
    coll: &str,
    data: serde_json::Value,
) -> i64 {
    let r = app
        .clone()
        .oneshot(req(
            "POST",
            tid,
            &format!("/records/{coll}"),
            Some(json!({ "data": data })),
            tok,
        ))
        .await
        .unwrap();
    let status = r.status();
    let v = read_json(r).await;
    assert_eq!(status, StatusCode::CREATED, "{status} {v}");
    v["id"].as_i64().unwrap()
}

async fn committed_updated_at(
    pool: &drust::storage::pool::SharedTenantPool,
    coll: &str,
    id: i64,
) -> String {
    let sql = format!("SELECT updated_at FROM \"{coll}\" WHERE id = ?1");
    pool.with_reader(move |c| c.query_row(&sql, rusqlite::params![id], |r| r.get(0)))
        .await
        .unwrap()
}

// One logical UPDATE via a write RPC on a canonical (triggered) collection →
// exactly ONE op=update history row, whose new_json carries the
// trigger-refreshed updated_at (== the committed row), not the stale depth-0
// image.
#[tokio::test]
async fn rpc_update_on_canonical_collection_captures_once() {
    let (app, tid, svc, _anon, dir) = helpers::spin_up_dual_role_self_register("t-rh-trig").await;
    create_collection_canonical(&dir, &tid, "items", &[fld("qty", "integer")]).await;
    let pool = helpers::grab_pool(&tid, &dir).await;

    let id = rest_insert(&app, &tid, &svc, "items", json!({"qty": 1})).await;

    // datetime('now') is second-resolution: sleep >1s so the trigger's
    // refreshed updated_at provably differs from the insert-time value.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

    create_rpc(
        &pool,
        "bump",
        "UPDATE items SET qty = qty + 1 WHERE id = :id",
        r#"[{"name":"id","type":"integer"}]"#,
        false,
    )
    .await;
    let r = app
        .oneshot(req(
            "POST",
            &tid,
            "/rpc/bump",
            Some(json!({"id": id})),
            &svc,
        ))
        .await
        .unwrap();
    let status = r.status();
    let v = read_json(r).await;
    assert!(status.is_success(), "{status} {v}");

    let rows = history_rows(&pool).await;
    let updates: Vec<&HistRow> = rows.iter().filter(|r| r.op == "update").collect();
    assert_eq!(
        updates.len(),
        1,
        "one logical UPDATE → exactly ONE op=update row (trigger event must merge, not duplicate): {rows:?}"
    );
    let row = updates[0];
    assert_eq!(row.record_id, id);
    let old: serde_json::Value =
        serde_json::from_str(row.old_json.as_deref().expect("old present")).unwrap();
    let new: serde_json::Value =
        serde_json::from_str(row.new_json.as_deref().expect("new present")).unwrap();
    assert_eq!(old["qty"].as_i64(), Some(1));
    assert_eq!(new["qty"].as_i64(), Some(2));

    let committed = committed_updated_at(&pool, "items", id).await;
    assert_eq!(
        new["updated_at"].as_str(),
        Some(committed.as_str()),
        "new_json carries the trigger-refreshed updated_at (== committed row): {new}"
    );
    assert_ne!(
        old["updated_at"], new["updated_at"],
        "trigger refresh actually changed updated_at — guards the equality \
         assertion above from passing vacuously"
    );
}

// Multi-row RPC UPDATE on a canonical collection: 3 rows → exactly 3
// op=update rows (trigger events merged per row, not doubled to 6).
#[tokio::test]
async fn rpc_multirow_update_on_canonical_collection_captures_per_row_once() {
    let (app, tid, svc, _anon, dir) = helpers::spin_up_dual_role_self_register("t-rh-trig3").await;
    create_collection_canonical(&dir, &tid, "items", &[fld("qty", "integer")]).await;
    let pool = helpers::grab_pool(&tid, &dir).await;

    for q in [1i64, 2, 3] {
        rest_insert(&app, &tid, &svc, "items", json!({ "qty": q })).await;
    }

    create_rpc(
        &pool,
        "bump_all",
        "UPDATE items SET qty = qty + 10",
        "[]",
        false,
    )
    .await;
    let r = app
        .oneshot(req("POST", &tid, "/rpc/bump_all", Some(json!({})), &svc))
        .await
        .unwrap();
    let status = r.status();
    let v = read_json(r).await;
    assert!(status.is_success(), "{status} {v}");
    assert_eq!(v["affected_rows"].as_i64(), Some(3));

    let rows = history_rows(&pool).await;
    let updates: Vec<&HistRow> = rows.iter().filter(|r| r.op == "update").collect();
    assert_eq!(
        updates.len(),
        3,
        "3 updated rows → exactly 3 op=update rows: {rows:?}"
    );
    let mut ids: Vec<i64> = updates.iter().map(|r| r.record_id).collect();
    ids.sort();
    assert_eq!(ids, vec![1, 2, 3], "one merged row per updated record");
    for row in &updates {
        let old: serde_json::Value =
            serde_json::from_str(row.old_json.as_deref().expect("old present")).unwrap();
        let new: serde_json::Value =
            serde_json::from_str(row.new_json.as_deref().expect("new present")).unwrap();
        assert_eq!(old["qty"].as_i64(), Some(row.record_id));
        assert_eq!(new["qty"].as_i64(), Some(row.record_id + 10));
    }
}

// INSERT ... ON CONFLICT DO UPDATE hitting an existing row: the update arm
// fires the trigger too → still exactly ONE op=update history row.
#[tokio::test]
async fn rpc_upsert_update_arm_on_canonical_collection_captures_once() {
    let (app, tid, svc, _anon, dir) = helpers::spin_up_dual_role_self_register("t-rh-ups").await;
    create_collection_canonical(
        &dir,
        &tid,
        "items",
        &[
            drust::mcp::tools::schema::FieldSpec {
                name: "sku".into(),
                sql_type: "text".into(),
                nullable: true,
                unique: true,
                ..Default::default()
            },
            fld("qty", "integer"),
        ],
    )
    .await;
    let pool = helpers::grab_pool(&tid, &dir).await;

    let id = rest_insert(&app, &tid, &svc, "items", json!({"sku": "a", "qty": 1})).await;

    create_rpc(
        &pool,
        "upsert",
        "INSERT INTO items (sku, qty) VALUES (:s, :q) \
         ON CONFLICT(sku) DO UPDATE SET qty = excluded.qty",
        r#"[{"name":"s","type":"text"},{"name":"q","type":"integer"}]"#,
        false,
    )
    .await;
    let r = app
        .oneshot(req(
            "POST",
            &tid,
            "/rpc/upsert",
            Some(json!({"s": "a", "q": 99})),
            &svc,
        ))
        .await
        .unwrap();
    let status = r.status();
    let v = read_json(r).await;
    assert!(status.is_success(), "{status} {v}");

    let rows = history_rows(&pool).await;
    let updates: Vec<&HistRow> = rows.iter().filter(|r| r.op == "update").collect();
    assert_eq!(
        updates.len(),
        1,
        "upsert update arm → exactly ONE op=update row: {rows:?}"
    );
    assert_eq!(updates[0].record_id, id);
    let new: serde_json::Value =
        serde_json::from_str(updates[0].new_json.as_deref().expect("new present")).unwrap();
    assert_eq!(new["qty"].as_i64(), Some(99));
    // The conflicting INSERT never lands as a row change: only the REST
    // seed's op=insert row exists.
    let inserts = rows.iter().filter(|r| r.op == "insert").count();
    assert_eq!(inserts, 1, "no phantom op=insert from the upsert: {rows:?}");
}

// ── Anon-callable write RPC called with the anon bearer → actor_kind=anon. ─

#[tokio::test]
async fn anon_write_rpc_captures_anon_actor() {
    let (app, tid, _svc, anon, dir) = helpers::spin_up_dual_role_self_register("t-rh-anon").await;
    let pool = helpers::grab_pool(&tid, &dir).await;
    create_orders_table(&pool).await;
    create_rpc(
        &pool,
        "open_add",
        "INSERT INTO orders (qty) VALUES (1)",
        "[]",
        true, // anon_callable
    )
    .await;

    let r = app
        .oneshot(req("POST", &tid, "/rpc/open_add", Some(json!({})), &anon))
        .await
        .unwrap();
    let status = r.status();
    let v = read_json(r).await;
    assert!(status.is_success(), "{status} {v}");

    let rows = history_rows(&pool).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].actor_kind, "anon");
    assert!(rows[0].actor_id.is_none(), "anon carries no actor_id");
}

// ── User bearer on an anon-callable write RPC → actor_kind=user + id. ─────

#[tokio::test]
async fn user_write_rpc_captures_user_actor() {
    let (app, tid, _svc, _anon, dir) = helpers::spin_up_dual_role_self_register("t-rh-user").await;
    let pool = helpers::grab_pool(&tid, &dir).await;
    create_orders_table(&pool).await;
    create_rpc(
        &pool,
        "open_add",
        "INSERT INTO orders (qty) VALUES (1)",
        "[]",
        true, // anon_callable (covers User role too)
    )
    .await;

    let utok = helpers::register_and_login_via_app(&app, &tid, "u@x.com", "longpassword").await;
    let r = app
        .oneshot(req("POST", &tid, "/rpc/open_add", Some(json!({})), &utok))
        .await
        .unwrap();
    let status = r.status();
    let v = read_json(r).await;
    assert!(status.is_success(), "{status} {v}");

    let rows = history_rows(&pool).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].actor_kind, "user");
    assert!(
        rows[0].actor_id.is_some(),
        "user actor carries the user id: {rows:?}"
    );
}
