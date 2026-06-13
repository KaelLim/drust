//! RLS Phase 5 (Write) — explicit-policy CHECK / USING enforcement on the
//! mutating record handlers (`create_handler` / `update_handler` /
//! `delete_handler`).
//!
//! Task 12 covers the INSERT CHECK: an `insert` policy
//! `{"check":{"status":"draft"}}` is evaluated against the persisted
//! (read-back) row inside the writer transaction; a row that fails the
//! predicate rolls the INSERT back and surfaces as
//! `403 POLICY_CHECK_FAILED`. Service tokens bypass policy entirely
//! (`effective_policy_check` returns `None` for `AuthCtx::Service`), so the
//! scenario runs on a non-owner collection with the anon `insert` cap.
//!
//! Until Task 17 (the REST `set_policy`) lands, policies are written
//! directly via `storage::schema::write_policy` + `schema_cache.invalidate`
//! per the plan's Test Harness appendix.

#[path = "helpers.rs"]
mod helpers;

use axum::body::Body;
use axum::http::{Request, header};
use drust::storage::schema::DmlVerb;
use helpers::{grab_pool, spin_up_dual_role_self_register};
use serde_json::{Value, json};
use tower::ServiceExt;

// ── Fixtures ──────────────────────────────────────────────────────────

/// `posts(status TEXT)` with anon `select`+`insert` caps, no owner_field.
async fn seed_status_posts_insertable(dir: &tempfile::TempDir, tenant: &str) {
    let pool = grab_pool(tenant, dir).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
             );
             INSERT INTO _system_collection_meta
                  (collection_name, anon_caps_json)
                  VALUES ('posts', '[\"select\",\"insert\"]')
                  ON CONFLICT(collection_name) DO UPDATE SET
                    anon_caps_json = '[\"select\",\"insert\"]';",
        )
    })
    .await
    .unwrap();
}

/// Write a policy for `op` directly (pre-Task-17) + invalidate the cache.
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

/// `posts(status TEXT)` with anon `select`+`update` caps, no owner_field.
async fn seed_status_posts_updatable(dir: &tempfile::TempDir, tenant: &str) {
    let pool = grab_pool(tenant, dir).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
             );
             INSERT INTO _system_collection_meta
                  (collection_name, anon_caps_json)
                  VALUES ('posts', '[\"select\",\"update\"]')
                  ON CONFLICT(collection_name) DO UPDATE SET
                    anon_caps_json = '[\"select\",\"update\"]';",
        )
    })
    .await
    .unwrap();
}

/// `posts(status TEXT)` with anon `select`+`delete` caps, no owner_field.
async fn seed_status_posts_deletable(dir: &tempfile::TempDir, tenant: &str) {
    let pool = grab_pool(tenant, dir).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
             );
             INSERT INTO _system_collection_meta
                  (collection_name, anon_caps_json)
                  VALUES ('posts', '[\"select\",\"delete\"]')
                  ON CONFLICT(collection_name) DO UPDATE SET
                    anon_caps_json = '[\"select\",\"delete\"]';",
        )
    })
    .await
    .unwrap();
}

/// `DELETE /t/<id>/records/posts/<id>` → just the HTTP status.
async fn delete_status(app: &axum::Router, tid: &str, tok: &str, id: i64) -> u16 {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/t/{tid}/records/posts/{id}"))
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    resp.status().as_u16()
}

/// `POST /t/<id>/records/posts` with `{data:{status}}` → just the HTTP status.
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

/// `POST /t/<id>/records/posts` (service) → the new row's `id` from the 201 body.
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
    assert_eq!(resp.status().as_u16(), 201, "service insert {status} failed");
    let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    v["id"].as_i64().expect("create body has numeric id")
}

/// `PATCH /t/<id>/records/posts/<id>` with `{data:{status}}` → just the HTTP status.
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

// ── Tests ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn insert_rejected_by_check() {
    let (app, tid, _svc, anon, dir) = spin_up_dual_role_self_register("rls-write-insert").await;
    seed_status_posts_insertable(&dir, &tid).await;
    // CHECK: new rows must be status="draft".
    set_policy(
        &dir,
        &tid,
        "posts",
        DmlVerb::Insert,
        json!({"check": {"status": "draft"}}),
    )
    .await;

    // A draft passes the CHECK → 201.
    let ok = insert_status(&app, &tid, &anon, "draft").await;
    assert_eq!(ok, 201, "draft insert must pass the CHECK");

    // A published row fails the CHECK → rolled back → 403.
    let bad = insert_status(&app, &tid, &anon, "published").await;
    assert_eq!(bad, 403, "CHECK must reject status=published");
}

#[tokio::test]
async fn update_target_filtered_by_using() {
    let (app, tid, svc, anon, dir) = spin_up_dual_role_self_register("rls-write-upd-using").await;
    seed_status_posts_updatable(&dir, &tid).await;
    // update USING: only rows where status != "locked" may be updated.
    // Written to disk BEFORE the cache-populating service insert so the app's
    // schema_cache picks up the policy on first load (the test's grab_pool uses
    // a separate registry/cache and cannot invalidate the running app's cache).
    set_policy(
        &dir,
        &tid,
        "posts",
        DmlVerb::Update,
        json!({"using": {"status": {"$ne": "locked"}}}),
    )
    .await;
    // Service inserts a locked row (service bypasses policy on the insert).
    let id = insert_status_returning_id(&app, &tid, &svc, "locked").await;

    let st = update_status(&app, &tid, &anon, id, "open").await;
    assert_eq!(st, 404, "locked row is not an updatable target");
}

#[tokio::test]
async fn update_post_image_check() {
    let (app, tid, svc, anon, dir) = spin_up_dual_role_self_register("rls-write-upd-check").await;
    seed_status_posts_updatable(&dir, &tid).await;
    // CHECK: status must never become "published" via update. Written to disk
    // before the cache-populating service insert (see USING test rationale).
    set_policy(
        &dir,
        &tid,
        "posts",
        DmlVerb::Update,
        json!({"check": {"status": {"$ne": "published"}}}),
    )
    .await;
    // Service inserts a draft row.
    let id = insert_status_returning_id(&app, &tid, &svc, "draft").await;

    // status=open passes the CHECK → 200.
    assert_eq!(update_status(&app, &tid, &anon, id, "open").await, 200);
    // status=published fails the CHECK → rolled back → 403.
    assert_eq!(update_status(&app, &tid, &anon, id, "published").await, 403);
}

#[tokio::test]
async fn delete_target_filtered_by_using() {
    let (app, tid, svc, anon, dir) = spin_up_dual_role_self_register("rls-write-del-using").await;
    seed_status_posts_deletable(&dir, &tid).await;
    // delete USING: only rows where status != "locked" may be deleted.
    // Written to disk BEFORE the cache-populating service insert so the app's
    // schema_cache picks up the policy on first load (the test's grab_pool uses
    // a separate registry/cache and cannot invalidate the running app's cache).
    set_policy(
        &dir,
        &tid,
        "posts",
        DmlVerb::Delete,
        json!({"using": {"status": {"$ne": "locked"}}}),
    )
    .await;
    // Service inserts a locked row (service bypasses policy on the insert).
    let id = insert_status_returning_id(&app, &tid, &svc, "locked").await;

    let st = delete_status(&app, &tid, &anon, id).await;
    assert_eq!(st, 404, "locked row is not a deletable target");
}
