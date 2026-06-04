//! v1.30 — integration tests for write-mode RPC dispatch.
//!
//! The spec §8 cases (1..10) plus the §14 Q3 :user_id-inside-string-
//! literal proof. All tests spin up a tenant via the helpers in
//! `tests/helpers.rs`, write `_system_rpc` rows directly through the
//! pool writer (mirroring the auth_rpc.rs pattern), and call the RPC
//! through `app.oneshot(...)`.

mod helpers;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::safety::audit_db::{AuditWriter, open_audit_db_read, open_audit_db_write};
use serde_json::json;
use std::path::PathBuf;
use tempfile::tempdir;
use tower::ServiceExt;

/// Initialise the process-wide audit writer once and return the DB
/// path. v1.32.1 D1 — JSONL writer retired; tests read from the
/// global SQLite writer filtered by tenant id. Writer runs on a
/// dedicated std::thread so its task outlives individual #[tokio::test]
/// runtimes.
fn ensure_global_audit_writer() -> &'static PathBuf {
    static AUDIT_PATH: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    AUDIT_PATH.get_or_init(|| {
        let dir = Box::new(tempdir().unwrap());
        let path = dir.path().join("test_rpc_v2_mutation_audit.sqlite");
        let conn = open_audit_db_write(&path).unwrap();
        let (tx_ready, rx_ready) = std::sync::mpsc::channel::<()>();
        std::thread::Builder::new()
            .name("test-rpc-v2-audit-writer".into())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("build writer runtime");
                rt.block_on(async move {
                    let writer = AuditWriter::new(conn);
                    drust::safety::audit_db::init_globals(writer);
                    let _ = tx_ready.send(());
                    std::future::pending::<()>().await;
                });
            })
            .expect("spawn audit writer thread");
        rx_ready.recv().expect("audit writer init signal");
        let path_clone = path.clone();
        Box::leak(dir);
        path_clone
    })
}

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

/// Create an RPC by writing directly to `_system_rpc`. Mirrors the
/// helper in tests/auth_rpc.rs but takes a `mode` and writes it into
/// the row (the column is COALESCEd to 'read' on lookup so write-mode
/// is opt-in per row).
async fn create_rpc(
    pool: &drust::storage::pool::SharedTenantPool,
    name: &str,
    sql: &str,
    params_json: &str,
    anon_callable: bool,
    mode: &str,
) {
    let name = name.to_string();
    let sql = sql.to_string();
    let params_json = params_json.to_string();
    let mode = mode.to_string();
    pool.with_writer(move |c| {
        c.execute(
            "INSERT INTO _system_rpc \
             (name, sql, params_json, description, anon_callable, mode, \
              anon_calls, service_calls, last_called_at, created_at, updated_at) \
             VALUES (?1, ?2, ?3, '', ?4, ?5, 0, 0, NULL, \
                     datetime('now'), datetime('now'))",
            rusqlite::params![name, sql, params_json, anon_callable as i64, mode],
        )
    })
    .await
    .unwrap();
}

async fn create_orders_table(pool: &drust::storage::pool::SharedTenantPool) {
    pool.with_writer(|c| {
        c.execute_batch("CREATE TABLE orders (id INTEGER PRIMARY KEY AUTOINCREMENT, qty INTEGER);")
    })
    .await
    .unwrap();
}

async fn orders_count(pool: &drust::storage::pool::SharedTenantPool) -> i64 {
    pool.with_reader(|c| c.query_row("SELECT COUNT(*) FROM orders", [], |r| r.get(0)))
        .await
        .unwrap()
}

async fn orders_qty_sum(pool: &drust::storage::pool::SharedTenantPool) -> i64 {
    pool.with_reader(|c| c.query_row("SELECT COALESCE(SUM(qty), 0) FROM orders", [], |r| r.get(0)))
        .await
        .unwrap()
}

/// Best-effort: drain audit rows for `tenant` from the global SQLite
/// audit DB. Sleeps briefly so the async writer task (100ms batch
/// flush) has time to commit. v1.32.1 D1 — replaces the previous
/// JSONL-file scan. Flattens `extra` JSON into top-level keys so
/// assertions like `row["rpc_mode"]` work unchanged.
async fn read_audit_lines(tenant: &str) -> Vec<serde_json::Value> {
    let path = ensure_global_audit_writer();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let r = open_audit_db_read(path).unwrap();
    let _ = r.execute_batch("PRAGMA wal_checkpoint(PASSIVE);");
    let mut stmt = r
        .prepare(
            "SELECT tenant, status, op, extra \
             FROM audit WHERE tenant = ?1 ORDER BY id ASC",
        )
        .unwrap();
    stmt.query_map(rusqlite::params![tenant], |r| {
        let tenant: Option<String> = r.get(0)?;
        let status: Option<String> = r.get(1)?;
        let op: Option<String> = r.get(2)?;
        let extra_json: Option<String> = r.get(3)?;
        let mut map = serde_json::Map::new();
        if let Some(t) = tenant {
            map.insert("tenant".into(), serde_json::Value::String(t));
        }
        if let Some(s) = status {
            map.insert("status".into(), serde_json::Value::String(s));
        }
        if let Some(o) = op {
            map.insert("op".into(), serde_json::Value::String(o));
        }
        if let Some(extra_str) = extra_json {
            if let Ok(serde_json::Value::Object(extra_map)) =
                serde_json::from_str::<serde_json::Value>(&extra_str)
            {
                for (k, v) in extra_map {
                    map.entry(k).or_insert(v);
                }
            }
        }
        Ok(serde_json::Value::Object(map))
    })
    .unwrap()
    .filter_map(Result::ok)
    .collect()
}

// ────────────────────────────────────────────────────────────────────
// CASE 1 — read-mode RPC unchanged (regression guard for read arm)
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn case1_read_rpc_unchanged() {
    let (app, tid, svc, _anon, dir) = helpers::spin_up_dual_role_self_register("t-rpc-c1").await;
    let pool = helpers::grab_pool(&tid, &dir).await;
    create_rpc(&pool, "ping", "SELECT 1 AS x", "[]", false, "read").await;

    let r = app
        .oneshot(req("POST", &tid, "/rpc/ping", Some(json!({})), &svc))
        .await
        .unwrap();
    assert!(r.status().is_success());
    let v = read_json(r).await;

    // Read mode response must contain ONLY the v1.6 keys; write-mode
    // fields must not leak in.
    let obj = v.as_object().expect("object body");
    assert!(obj.contains_key("column_names"));
    assert!(obj.contains_key("rows"));
    assert!(obj.contains_key("row_count"));
    assert!(obj.contains_key("truncated"));
    assert!(
        !obj.contains_key("affected_rows"),
        "read-mode response leaked affected_rows: {v}"
    );
    assert!(
        !obj.contains_key("last_insert_rowid"),
        "read-mode response leaked last_insert_rowid: {v}"
    );
    assert!(
        !obj.contains_key("statement_count"),
        "read-mode response leaked statement_count: {v}"
    );
    assert!(
        !obj.contains_key("dry_run"),
        "read-mode response leaked dry_run: {v}"
    );
}

// ────────────────────────────────────────────────────────────────────
// CASE 2 — single INSERT commits + audit row has rpc_mode=write
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn case2_single_insert_commits_and_audits_affected_one() {
    ensure_global_audit_writer();
    let (app, tid, svc, _anon, dir) = helpers::spin_up_dual_role_self_register("t-rpc-c2").await;
    let pool = helpers::grab_pool(&tid, &dir).await;
    create_orders_table(&pool).await;
    create_rpc(
        &pool,
        "add_order",
        "INSERT INTO orders (qty) VALUES (:q)",
        r#"[{"name":"q","type":"integer"}]"#,
        false,
        "write",
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
    assert_eq!(v["affected_rows"].as_i64(), Some(1));
    assert_eq!(orders_count(&pool).await, 1);
    assert_eq!(orders_qty_sum(&pool).await, 5);

    let lines = read_audit_lines(&tid).await;
    let row = lines
        .iter()
        .find(|l| l["op"].as_str().unwrap_or("").contains("/rpc/add_order"))
        .expect("audit row for /rpc/add_order");
    assert_eq!(
        row["rpc_mode"].as_str(),
        Some("write"),
        "audit must carry rpc_mode='write': {row}"
    );
    assert_eq!(
        row["rpc_affected_rows"].as_i64(),
        Some(1),
        "audit must carry rpc_affected_rows=1: {row}"
    );
}

// ────────────────────────────────────────────────────────────────────
// CASE 3 — multi-statement commits both
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn case3_multi_statement_commits_both() {
    let (app, tid, svc, _anon, dir) = helpers::spin_up_dual_role_self_register("t-rpc-c3").await;
    let pool = helpers::grab_pool(&tid, &dir).await;
    create_orders_table(&pool).await;
    create_rpc(
        &pool,
        "two_step",
        "INSERT INTO orders (qty) VALUES (1); UPDATE orders SET qty = qty + 10 WHERE qty = 1;",
        "[]",
        false,
        "write",
    )
    .await;

    let r = app
        .oneshot(req("POST", &tid, "/rpc/two_step", Some(json!({})), &svc))
        .await
        .unwrap();
    let status = r.status();
    let v = read_json(r).await;
    assert!(status.is_success(), "{status} {v}");
    assert_eq!(
        v["affected_rows"].as_i64(),
        Some(2),
        "INSERT(1) + UPDATE(1) = 2 affected: {v}"
    );
    assert_eq!(v["statement_count"].as_i64(), Some(2));
    assert_eq!(orders_count(&pool).await, 1);
    assert_eq!(
        orders_qty_sum(&pool).await,
        11,
        "row must have qty=11 after UPDATE"
    );
}

// ────────────────────────────────────────────────────────────────────
// CASE 4 — second statement fails, whole tx rolls back
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn case4_multi_statement_failure_rolls_all_back() {
    let (app, tid, svc, _anon, dir) = helpers::spin_up_dual_role_self_register("t-rpc-c4").await;
    let pool = helpers::grab_pool(&tid, &dir).await;
    create_orders_table(&pool).await;
    create_rpc(
        &pool,
        "bad_pair",
        "INSERT INTO orders (qty) VALUES (1); SELECT * FROM does_not_exist;",
        "[]",
        false,
        "write",
    )
    .await;

    let r = app
        .oneshot(req("POST", &tid, "/rpc/bad_pair", Some(json!({})), &svc))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    let v = read_json(r).await;
    assert_eq!(
        v["error_code"].as_str(),
        Some("RPC_STATEMENT_FAILED"),
        "expected RPC_STATEMENT_FAILED, got: {v}"
    );
    assert_eq!(
        v["statement_index"].as_i64(),
        Some(2),
        "statement_index must be 1-based and point at the failing SELECT: {v}"
    );
    assert_eq!(
        orders_count(&pool).await,
        0,
        "ROLLBACK TO must have undone the prior INSERT"
    );
}

// ────────────────────────────────────────────────────────────────────
// CASE 5 — dry_run persists nothing
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn case5_dry_run_persists_nothing() {
    let (app, tid, svc, _anon, dir) = helpers::spin_up_dual_role_self_register("t-rpc-c5").await;
    let pool = helpers::grab_pool(&tid, &dir).await;
    create_orders_table(&pool).await;
    create_rpc(
        &pool,
        "add_one",
        "INSERT INTO orders (qty) VALUES (1)",
        "[]",
        false,
        "write",
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
    assert_eq!(v["would_commit"].as_bool(), Some(true));
    assert_eq!(
        v["affected_rows"].as_i64(),
        Some(1),
        "dry_run reports what WOULD happen"
    );
    assert_eq!(
        orders_count(&pool).await,
        0,
        "dry_run must NOT persist any row"
    );
}

// ────────────────────────────────────────────────────────────────────
// CASE 6 — write-mode anon_callable=false → 403 RPC_DENIED for anon
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn case6_anon_with_anon_callable_false_403_rpc_denied() {
    let (app, tid, _svc, anon, dir) = helpers::spin_up_dual_role_self_register("t-rpc-c6").await;
    let pool = helpers::grab_pool(&tid, &dir).await;
    create_orders_table(&pool).await;
    create_rpc(
        &pool,
        "private_add",
        "INSERT INTO orders (qty) VALUES (1)",
        "[]",
        false, // anon_callable = false
        "write",
    )
    .await;

    let r = app
        .oneshot(req(
            "POST",
            &tid,
            "/rpc/private_add",
            Some(json!({})),
            &anon,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let v = read_json(r).await;
    assert_eq!(
        v["error_code"].as_str(),
        Some("RPC_DENIED"),
        "write-mode anon-deny must emit RPC_DENIED (not ANON_DENIED): {v}"
    );
    assert_eq!(
        orders_count(&pool).await,
        0,
        "denied call must not have written anything"
    );
}

// ────────────────────────────────────────────────────────────────────
// CASE 7 — :user_id declared, anon caller → 403 USER_ID_BINDING_REQUIRED
//          (pre-SQL; no mutation should land)
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn case7_user_id_param_with_anon_caller_403_before_sql() {
    let (app, tid, _svc, anon, dir) = helpers::spin_up_dual_role_self_register("t-rpc-c7").await;
    let pool = helpers::grab_pool(&tid, &dir).await;
    // orders carries a user_id column so the bind would succeed if it
    // got to SQL — but the pre-flight reject must fire first.
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE orders (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT, qty INTEGER);",
        )
    })
    .await
    .unwrap();
    create_rpc(
        &pool,
        "user_add",
        "INSERT INTO orders (user_id, qty) VALUES (:user_id, 1)",
        r#"[{"name":"user_id","type":"text"}]"#,
        true, // anon_callable so the role check passes
        "write",
    )
    .await;

    let r = app
        .oneshot(req("POST", &tid, "/rpc/user_add", Some(json!({})), &anon))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let v = read_json(r).await;
    assert_eq!(
        v["error_code"].as_str(),
        Some("USER_ID_BINDING_REQUIRED"),
        "anon + :user_id must reject pre-SQL: {v}"
    );
    assert_eq!(
        orders_count(&pool).await,
        0,
        "pre-flight reject must not have written anything"
    );
}

// ────────────────────────────────────────────────────────────────────
// CASE 8 — owner_field collection + write-mode RPC: user A INSERTs
// their own row; user A's UPDATE on user B's row must not mutate B.
// drust does NOT apply owner_field to RPC SQL (auth_rpc.rs test 3 is
// the precedent), so the test here proves user-bound :user_id IS
// auto-injected and the SQL itself is the gate.
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn case8_owner_field_collection_owner_match_succeeds_and_mismatch_blocked() {
    let (app, tid, svc, _anon, dir) = helpers::spin_up_dual_role_self_register("t-rpc-c8").await;
    let pool = helpers::grab_pool(&tid, &dir).await;
    // No FK to _system_users — the writable authorizer denies Read on
    // _system_users (it's a protected collection), which would trip
    // when SQLite enforces the FK during INSERT. The test's invariant
    // (per-user UPDATE only mutates the caller's row) does not depend
    // on FK enforcement; the column carries the user_id verbatim.
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT,
                qty INTEGER
             );",
        )
    })
    .await
    .unwrap();
    let _ = svc; // owner_field not used — INSERT writes user_id verbatim from :user_id

    let ta = helpers::register_and_login_via_app(&app, &tid, "a@x.com", "longpassword").await;
    let tb = helpers::register_and_login_via_app(&app, &tid, "b@x.com", "longpassword").await;

    // RPC: each user inserts a row tagged with their own user_id.
    create_rpc(
        &pool,
        "my_add",
        "INSERT INTO orders (user_id, qty) VALUES (:user_id, :q)",
        r#"[{"name":"user_id","type":"text"},{"name":"q","type":"integer"}]"#,
        true,
        "write",
    )
    .await;

    // A inserts a row.
    let r = app
        .clone()
        .oneshot(req(
            "POST",
            &tid,
            "/rpc/my_add",
            Some(json!({"q": 10})),
            &ta,
        ))
        .await
        .unwrap();
    assert!(r.status().is_success(), "A INSERT must succeed");
    // B inserts a row.
    let r = app
        .clone()
        .oneshot(req(
            "POST",
            &tid,
            "/rpc/my_add",
            Some(json!({"q": 20})),
            &tb,
        ))
        .await
        .unwrap();
    assert!(r.status().is_success(), "B INSERT must succeed");

    assert_eq!(orders_count(&pool).await, 2);

    // UPDATE RPC that only mutates rows for the calling user.
    create_rpc(
        &pool,
        "my_bump",
        "UPDATE orders SET qty = qty + 1 WHERE user_id = :user_id",
        r#"[{"name":"user_id","type":"text"}]"#,
        true,
        "write",
    )
    .await;

    // A calls bump — only their row should change.
    let r = app
        .clone()
        .oneshot(req("POST", &tid, "/rpc/my_bump", Some(json!({})), &ta))
        .await
        .unwrap();
    let status = r.status();
    let v = read_json(r).await;
    assert!(status.is_success(), "{status} {v}");
    assert_eq!(
        v["affected_rows"].as_i64(),
        Some(1),
        "A's UPDATE must only touch A's row: {v}"
    );

    // B's row must still be qty=20; A's row must now be 11.
    let qtys: Vec<(String, i64)> = pool
        .with_reader(|c| {
            let mut stmt = c
                .prepare("SELECT user_id, qty FROM orders ORDER BY id")
                .unwrap();
            let rows = stmt
                .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
                .unwrap()
                .map(|r| r.unwrap())
                .collect::<Vec<_>>();
            Ok(rows)
        })
        .await
        .unwrap();
    assert_eq!(qtys.len(), 2);
    assert_eq!(qtys[0].1, 11, "A's row bumped to 11: {qtys:?}");
    assert_eq!(qtys[1].1, 20, "B's row untouched at 20: {qtys:?}");
}

// ────────────────────────────────────────────────────────────────────
// CASE 9 — INSERT ... RETURNING produces SELECT-shaped rows
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn case9_returning_clause_shape_matches_select() {
    let (app, tid, svc, _anon, dir) = helpers::spin_up_dual_role_self_register("t-rpc-c9").await;
    let pool = helpers::grab_pool(&tid, &dir).await;
    create_orders_table(&pool).await;
    create_rpc(
        &pool,
        "add_returning",
        "INSERT INTO orders (qty) VALUES (:q) RETURNING id, qty",
        r#"[{"name":"q","type":"integer"}]"#,
        false,
        "write",
    )
    .await;

    let r = app
        .oneshot(req(
            "POST",
            &tid,
            "/rpc/add_returning",
            Some(json!({"q": 7})),
            &svc,
        ))
        .await
        .unwrap();
    let status = r.status();
    let v = read_json(r).await;
    assert!(status.is_success(), "{status} {v}");
    let cols = v["column_names"].as_array().expect("column_names");
    assert_eq!(cols.len(), 2);
    assert_eq!(cols[0].as_str(), Some("id"));
    assert_eq!(cols[1].as_str(), Some("qty"));
    let rows = v["rows"].as_array().expect("rows");
    assert_eq!(rows.len(), 1);
    let inserted_id = rows[0][0].as_i64().expect("returned id");
    assert_eq!(rows[0][1].as_i64(), Some(7));
    assert_eq!(v["row_count"].as_i64(), Some(1));
    assert_eq!(v["affected_rows"].as_i64(), Some(1));
    assert_eq!(v["last_insert_rowid"].as_i64(), Some(inserted_id));
    assert_eq!(v["statement_count"].as_i64(), Some(1));
}

// ────────────────────────────────────────────────────────────────────
// CASE 10 — audit row carries all 4 new fields
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn case10_audit_extra_carries_all_four_new_fields() {
    ensure_global_audit_writer();
    let (app, tid, svc, _anon, dir) = helpers::spin_up_dual_role_self_register("t-rpc-c10").await;
    let pool = helpers::grab_pool(&tid, &dir).await;
    create_orders_table(&pool).await;
    create_rpc(
        &pool,
        "add_one",
        "INSERT INTO orders (qty) VALUES (1)",
        "[]",
        false,
        "write",
    )
    .await;

    let r = app
        .oneshot(req("POST", &tid, "/rpc/add_one", Some(json!({})), &svc))
        .await
        .unwrap();
    assert!(r.status().is_success());

    let lines = read_audit_lines(&tid).await;
    let row = lines
        .iter()
        .find(|l| l["op"].as_str().unwrap_or("").contains("/rpc/add_one"))
        .expect("audit row");
    assert_eq!(row["rpc_mode"].as_str(), Some("write"), "{row}");
    assert_eq!(row["rpc_affected_rows"].as_i64(), Some(1), "{row}");
    assert_eq!(row["rpc_dry_run"].as_bool(), Some(false), "{row}");
    assert_eq!(row["rpc_statement_count"].as_i64(), Some(1), "{row}");
}

// ────────────────────────────────────────────────────────────────────
// CASE 10b — read-mode RPC tags its audit row with rpc_mode:"read" and
// MUST NOT carry the write-mode-only fields. Locks in v1.30 C7's
// read-arm AuditExtra insertion against regression.
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn case10b_read_rpc_audit_has_rpc_mode_read_no_write_fields() {
    ensure_global_audit_writer();
    let (app, tid, svc, _anon, dir) = helpers::spin_up_dual_role_self_register("t-rpc-c10b").await;
    let pool = helpers::grab_pool(&tid, &dir).await;
    create_rpc(&pool, "ping", "SELECT 1 AS x", "[]", false, "read").await;

    let r = app
        .oneshot(req("POST", &tid, "/rpc/ping", Some(json!({})), &svc))
        .await
        .unwrap();
    assert!(r.status().is_success());

    let lines = read_audit_lines(&tid).await;
    let row = lines
        .iter()
        .find(|l| l["op"].as_str().unwrap_or("").contains("/rpc/ping"))
        .expect("audit row");
    assert_eq!(row["rpc_mode"].as_str(), Some("read"), "{row}");
    assert!(
        row.get("rpc_affected_rows").is_none(),
        "read-mode audit must not carry rpc_affected_rows: {row}"
    );
    assert!(
        row.get("rpc_dry_run").is_none(),
        "read-mode audit must not carry rpc_dry_run: {row}"
    );
    assert!(
        row.get("rpc_statement_count").is_none(),
        "read-mode audit must not carry rpc_statement_count: {row}"
    );
    assert!(
        row.get("rpc_statement_index").is_none(),
        "read-mode audit must not carry rpc_statement_index: {row}"
    );
}

// ────────────────────────────────────────────────────────────────────
// Q3 — :user_id inside a string literal is NOT auto-bound; the SQLite
// lexer does not recognise `:user_id` as a bind token inside `'...'`.
// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn q3_user_id_inside_string_literal_not_autobound() {
    let (app, tid, _svc, _anon, dir) = helpers::spin_up_dual_role_self_register("t-rpc-q3").await;
    let pool = helpers::grab_pool(&tid, &dir).await;
    pool.with_writer(|c| {
        c.execute_batch("CREATE TABLE logs (id INTEGER PRIMARY KEY AUTOINCREMENT, msg TEXT);")
    })
    .await
    .unwrap();

    // The body declares no params at all; the :user_id substring is
    // inside a SQL string literal so the lexer ignores it. With the
    // anon_callable flag on and a User caller, the auto-bind path must
    // skip the literal (params.is_empty() ⇒ no declared user_id ⇒ no
    // auto-bind attempted).
    create_rpc(
        &pool,
        "echo_literal",
        "INSERT INTO logs (msg) VALUES (':user_id was here')",
        "[]",
        true,
        "write",
    )
    .await;

    let utok = helpers::register_and_login_via_app(&app, &tid, "u@x.com", "longpassword").await;
    let r = app
        .oneshot(req(
            "POST",
            &tid,
            "/rpc/echo_literal",
            Some(json!({})),
            &utok,
        ))
        .await
        .unwrap();
    let status = r.status();
    let v = read_json(r).await;
    assert!(status.is_success(), "{status} {v}");
    assert_eq!(v["affected_rows"].as_i64(), Some(1));

    let stored: String = pool
        .with_reader(|c| c.query_row("SELECT msg FROM logs WHERE id = 1", [], |r| r.get(0)))
        .await
        .unwrap();
    assert_eq!(
        stored, ":user_id was here",
        "literal `:user_id` must survive untouched (lexer ignores binds inside string literals)"
    );
}
