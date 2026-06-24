//! WS2 Task 2.2 — parity oracle for the REST `create_handler` / `update_handler`
//! RETURNING refactor. The read-back `SELECT *` collapses into
//! `INSERT/UPDATE ... RETURNING *`, but every behavior that runs on the
//! returned row must be unchanged:
//!
//!   * the insert/update policy CHECK still rolls back → `403 POLICY_CHECK_FAILED`
//!     with no row persisted (it now evaluates the RETURNING-derived row),
//!   * the update USING pre-flight `SELECT 1` still 404s a filtered target
//!     (it is a PRE-image gate, NOT collapsible into RETURNING),
//!   * the `n == 0` / missing-row arm still 404s,
//!   * declared vector columns are still stripped from the returned row.
//!
//! Written first per TDD so these needles are locked before the body changes.

#[path = "helpers.rs"]
mod helpers;

use axum::body::Body;
use axum::http::{Request, header};
use drust::storage::schema::DmlVerb;
use helpers::{grab_pool, spin_up_dual_role_self_register, spin_up_tenant};
use serde_json::{Value, json};
use tower::ServiceExt;

// ── Helpers ───────────────────────────────────────────────────────────

/// `posts(status TEXT)` with anon `select`+`insert` caps, no owner_field.
async fn seed_status_posts(dir: &tempfile::TempDir, tenant: &str, caps_json: &str) {
    let pool = grab_pool(tenant, dir).await;
    let caps = caps_json.to_string();
    pool.with_writer(move |c| {
        c.execute_batch(&format!(
            "CREATE TABLE posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
             );
             INSERT INTO _system_collection_meta
                  (collection_name, anon_caps_json)
                  VALUES ('posts', '{caps}')
                  ON CONFLICT(collection_name) DO UPDATE SET
                    anon_caps_json = '{caps}';"
        ))
    })
    .await
    .unwrap();
}

/// Write a policy for `op` directly + invalidate the cache.
async fn set_policy(
    dir: &tempfile::TempDir,
    tenant: &str,
    coll: &str,
    op: DmlVerb,
    policy_json: Value,
) {
    let pool = grab_pool(tenant, dir).await;
    let policy: drust::query::policy::Policy = serde_json::from_value(policy_json).unwrap();
    let coll_owned = coll.to_string();
    pool.with_writer(move |c| {
        drust::storage::schema::write_policy(c, &coll_owned, op, Some(&policy))
    })
    .await
    .unwrap();
    pool.schema_cache.invalidate(coll);
}

async fn insert_status(app: &axum::Router, tid: &str, tok: &str, status: &str) -> u16 {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{tid}/records/posts"))
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({"data": {"status": status}}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    resp.status().as_u16()
}

/// Service insert → the new row's id from the 201 body.
async fn insert_status_returning_id(app: &axum::Router, tid: &str, tok: &str, status: &str) -> i64 {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{tid}/records/posts"))
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({"data": {"status": status}}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        201,
        "service insert {status} failed"
    );
    let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    v["id"].as_i64().expect("create body has numeric id")
}

async fn update_status(app: &axum::Router, tid: &str, tok: &str, id: i64, status: &str) -> u16 {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/t/{tid}/records/posts/{id}"))
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({"data": {"status": status}}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    resp.status().as_u16()
}

async fn count_posts(dir: &tempfile::TempDir, tenant: &str) -> i64 {
    let pool = grab_pool(tenant, dir).await;
    pool.with_reader(|c| c.query_row("SELECT count(*) FROM posts", [], |r| r.get(0)))
        .await
        .unwrap()
}

// ── Tests ─────────────────────────────────────────────────────────────

/// Insert CHECK policy still rolls back (no row) with RETURNING; a compliant
/// insert returns the row + id. This is the WS2 parity oracle for the policy
/// CHECK running on the RETURNING-derived row.
#[tokio::test]
async fn insert_check_policy_still_rolls_back_with_returning() {
    let (app, tid, _svc, anon, dir) =
        spin_up_dual_role_self_register("ws2-rest-insert-check").await;
    seed_status_posts(&dir, &tid, "[\"select\",\"insert\"]").await;
    // CHECK: new rows must be status="draft".
    set_policy(
        &dir,
        &tid,
        "posts",
        DmlVerb::Insert,
        json!({"check": {"status": "draft"}}),
    )
    .await;

    // A published row fails the CHECK → rolled back → 403, no row persisted.
    let bad = insert_status(&app, &tid, &anon, "published").await;
    assert_eq!(bad, 403, "CHECK must reject status=published");
    assert_eq!(count_posts(&dir, &tid).await, 0, "rolled back — no row");

    // A draft passes the CHECK → 201, row persisted.
    let ok = insert_status(&app, &tid, &anon, "draft").await;
    assert_eq!(ok, 201, "draft insert must pass the CHECK");
    assert_eq!(count_posts(&dir, &tid).await, 1);
}

/// Update USING pre-flight (the PRE-image `SELECT 1` gate, NOT collapsible into
/// RETURNING) still 404s a filtered target.
#[tokio::test]
async fn update_using_preflight_still_404s_with_returning() {
    let (app, tid, svc, anon, dir) = spin_up_dual_role_self_register("ws2-rest-upd-using").await;
    seed_status_posts(&dir, &tid, "[\"select\",\"update\"]").await;
    // update USING: only rows where status != "locked" may be updated.
    set_policy(
        &dir,
        &tid,
        "posts",
        DmlVerb::Update,
        json!({"using": {"status": {"$ne": "locked"}}}),
    )
    .await;
    let id = insert_status_returning_id(&app, &tid, &svc, "locked").await;

    let st = update_status(&app, &tid, &anon, id, "open").await;
    assert_eq!(
        st, 404,
        "locked row is not an updatable target (USING pre-flight)"
    );
}

/// Update post-image CHECK still rolls back → 403 with RETURNING.
#[tokio::test]
async fn update_check_policy_still_rolls_back_with_returning() {
    let (app, tid, svc, anon, dir) = spin_up_dual_role_self_register("ws2-rest-upd-check").await;
    seed_status_posts(&dir, &tid, "[\"select\",\"update\"]").await;
    // CHECK: status must never become "published" via update.
    set_policy(
        &dir,
        &tid,
        "posts",
        DmlVerb::Update,
        json!({"check": {"status": {"$ne": "published"}}}),
    )
    .await;
    let id = insert_status_returning_id(&app, &tid, &svc, "draft").await;

    // status=open passes the CHECK → 200.
    assert_eq!(update_status(&app, &tid, &anon, id, "open").await, 200);
    // status=published fails the CHECK → rolled back → 403.
    assert_eq!(update_status(&app, &tid, &anon, id, "published").await, 403);
}

/// Missing-row update still 404s (the `n == 0` / no-RETURNING-row arm).
#[tokio::test]
async fn update_missing_row_404s_with_returning() {
    let (app, tok, dir) = spin_up_tenant("ws2-rest-upd-missing").await;
    seed_status_posts(&dir, "ws2-rest-upd-missing", "[\"select\"]").await;
    let st = update_status(&app, "ws2-rest-upd-missing", &tok, 999_999, "x").await;
    assert_eq!(st, 404, "missing id must 404");
}

// ── Vector-hide parity (service token, no policy) ──────────────────────

async fn seed_vec_docs(dir: &tempfile::TempDir, tenant: &str) {
    let pool = grab_pool(tenant, dir).await;
    pool.with_writer(|c| -> rusqlite::Result<()> {
        c.execute_batch(
            "CREATE TABLE docs (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                title       TEXT,
                embedding   BLOB,
                created_at  TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TRIGGER docs_updated_at AFTER UPDATE ON docs
              BEGIN UPDATE docs SET updated_at = datetime('now') WHERE id = OLD.id; END;",
        )?;
        c.execute(
            "INSERT INTO _system_collection_meta \
                (collection_name, anon_caps_json, vector_fields_json, updated_at) \
             VALUES ('docs', '[\"select\"]', \
                     '[{\"name\":\"embedding\",\"dim\":3}]', datetime('now'))",
            [],
        )?;
        Ok(())
    })
    .await
    .unwrap();
}

/// The returned row on create AND update strips the declared vector column
/// (no `embedding`, no leaked `__blob_bytes`).
#[tokio::test]
async fn create_and_update_strip_vector_column_on_returning() {
    let (app, tok, dir) = spin_up_tenant("ws2-rest-vec").await;
    seed_vec_docs(&dir, "ws2-rest-vec").await;

    // Create with an embedding.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/t/ws2-rest-vec/records/docs")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"data": {"title": "a", "embedding": [0.1, 0.2, 0.3]}}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 201);
    let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    let id = v["id"].as_i64().unwrap();
    let rec = &v["record"];
    assert_eq!(rec["title"], "a");
    assert!(
        rec.get("embedding").is_none(),
        "vector hidden on create RETURNING"
    );
    assert!(
        v.to_string().find("__blob_bytes").is_none(),
        "BLOB must not leak as __blob_bytes"
    );

    // Update the title; vector stays hidden.
    let uresp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/t/ws2-rest-vec/records/docs/{id}"))
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({"data": {"title": "b"}}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(uresp.status().as_u16(), 200);
    let ubytes = axum::body::to_bytes(uresp.into_body(), 65536)
        .await
        .unwrap();
    let uv: Value = serde_json::from_slice(&ubytes).unwrap();
    let urec = &uv["record"];
    assert_eq!(urec["title"], "b");
    assert!(
        urec.get("embedding").is_none(),
        "vector hidden on update RETURNING"
    );
    assert!(uv.to_string().find("__blob_bytes").is_none());
}
