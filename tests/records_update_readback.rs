//! E9 — an anon/user `PATCH /t/<id>/records/<c>/<id>` returns the updated row
//! only where that caller could READ it (the same cap/owner matrix `/list`
//! uses, plus the select policy evaluated on the post-image). Otherwise the
//! body is `{"record": {"id": <id>}}`; the write itself still commits with 200.
//! Service, and every INSERT response, are unchanged.
//!
//! Ordering rule for every test here: `grab_pool` opens a NEW pool, so its
//! `schema_cache.invalidate` never reaches the app's own pool. All direct-DB
//! config (table, caps, policies) is therefore written BEFORE the app's first
//! request that touches `posts`.

#[path = "helpers.rs"]
mod helpers;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::storage::schema::{DmlVerb, write_anon_caps, write_policy, write_user_caps};
use helpers::{grab_pool, register_and_login_via_app, spin_up_dual_role_self_register};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use tower::ServiceExt;

fn req(method: &str, tid: &str, path: &str, body: Option<Value>, token: &str) -> Request<Body> {
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

async fn read_json(resp: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 65_536)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

async fn send(app: &axum::Router, r: Request<Body>) -> axum::response::Response {
    app.clone().oneshot(r).await.unwrap()
}

fn caps(verbs: &[DmlVerb]) -> BTreeSet<DmlVerb> {
    verbs.iter().copied().collect()
}

/// Non-owner-scoped `posts(status, note)` with the given anon/user caps.
async fn seed_posts(
    dir: &tempfile::TempDir,
    tid: &str,
    anon_caps: &[DmlVerb],
    user_caps: &[DmlVerb],
) {
    let pool = grab_pool(tid, dir).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                status TEXT NOT NULL,
                note TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
             );",
        )
    })
    .await
    .unwrap();
    let ac = caps(anon_caps);
    let uc = caps(user_caps);
    pool.with_writer(move |c| {
        write_anon_caps(c, "posts", &ac)?;
        write_user_caps(c, "posts", &uc)
    })
    .await
    .unwrap();
}

/// Write a policy directly (bypasses `validate_policy`, so a legacy
/// clause-less select policy can be stored). Must run before the app first
/// touches `posts`.
async fn set_policy(dir: &tempfile::TempDir, tid: &str, op: DmlVerb, policy_json: Value) {
    let pool = grab_pool(tid, dir).await;
    let policy: drust::query::policy::Policy = serde_json::from_value(policy_json).unwrap();
    pool.with_writer(move |c| write_policy(c, "posts", op, Some(&policy)))
        .await
        .unwrap();
}

/// Owner-scoped `posts(user_id FK, title)` with the given `read_scope`, set
/// through the app's own `POST /owner-field` (which invalidates the app's cache).
async fn seed_owner_scoped(
    app: &axum::Router,
    tid: &str,
    svc: &str,
    dir: &tempfile::TempDir,
    read_scope: &str,
) {
    let pool = grab_pool(tid, dir).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE posts (
                 id         INTEGER PRIMARY KEY AUTOINCREMENT,
                 user_id    TEXT REFERENCES _system_users(id) ON DELETE RESTRICT,
                 title      TEXT,
                 created_at TEXT DEFAULT (datetime('now')),
                 updated_at TEXT DEFAULT (datetime('now'))
             );",
        )
    })
    .await
    .unwrap();
    let r = send(
        app,
        req(
            "POST",
            tid,
            "/collections/posts/owner-field",
            Some(json!({"field": "user_id", "read_scope": read_scope})),
            svc,
        ),
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK, "set owner-field failed");
}

async fn write_caps_user(dir: &tempfile::TempDir, tid: &str, verbs: &[DmlVerb]) {
    let pool = grab_pool(tid, dir).await;
    let uc = caps(verbs);
    pool.with_writer(move |c| write_user_caps(c, "posts", &uc))
        .await
        .unwrap();
}

async fn db_status(dir: &tempfile::TempDir, tid: &str, id: i64) -> String {
    grab_pool(tid, dir)
        .await
        .with_reader(move |c| {
            c.query_row("SELECT status FROM posts WHERE id = ?1", [id], |r| {
                r.get::<_, String>(0)
            })
        })
        .await
        .unwrap()
}

/// Create a row as `token`; returns the 201 body.
async fn create(app: &axum::Router, tid: &str, token: &str, data: Value) -> Value {
    let r = send(
        app,
        req(
            "POST",
            tid,
            "/records/posts",
            Some(json!({"data": data})),
            token,
        ),
    )
    .await;
    assert_eq!(r.status(), StatusCode::CREATED, "create failed");
    read_json(r).await
}

async fn create_id(app: &axum::Router, tid: &str, token: &str, data: Value) -> i64 {
    create(app, tid, token, data).await["id"].as_i64().unwrap()
}

/// PATCH as `token`; asserts 200 and returns the body.
async fn patch_ok(app: &axum::Router, tid: &str, token: &str, id: i64, data: Value) -> Value {
    let r = send(
        app,
        req(
            "PATCH",
            tid,
            &format!("/records/posts/{id}"),
            Some(json!({"data": data})),
            token,
        ),
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK, "PATCH must still succeed");
    read_json(r).await
}

// ── anon ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn anon_update_without_select_cap_returns_id_only() {
    let (app, tid, svc, anon, dir) = spin_up_dual_role_self_register("t-e9-a1").await;
    seed_posts(&dir, &tid, &[DmlVerb::Update], &[DmlVerb::Select]).await;
    let id = create_id(
        &app,
        &tid,
        &svc,
        json!({"status": "draft", "note": "private"}),
    )
    .await;
    let body = patch_ok(&app, &tid, &anon, id, json!({"status": "open"})).await;
    assert_eq!(body, json!({"record": {"id": id}}));
    assert_eq!(db_status(&dir, &tid, id).await, "open", "write committed");
}

#[tokio::test]
async fn anon_update_with_select_cap_returns_full_row() {
    let (app, tid, svc, anon, dir) = spin_up_dual_role_self_register("t-e9-a2").await;
    seed_posts(
        &dir,
        &tid,
        &[DmlVerb::Select, DmlVerb::Update],
        &[DmlVerb::Select],
    )
    .await;
    let id = create_id(
        &app,
        &tid,
        &svc,
        json!({"status": "draft", "note": "private"}),
    )
    .await;
    let body = patch_ok(&app, &tid, &anon, id, json!({"status": "open"})).await;
    let rec = &body["record"];
    assert_eq!(rec["status"], "open", "{body}");
    assert_eq!(rec["note"], "private", "{body}");
    assert!(rec.get("created_at").is_some(), "{body}");
    assert!(rec.get("updated_at").is_some(), "{body}");
}

#[tokio::test]
async fn anon_update_row_hidden_by_select_policy_returns_id_only() {
    let (app, tid, svc, anon, dir) = spin_up_dual_role_self_register("t-e9-a3").await;
    seed_posts(
        &dir,
        &tid,
        &[DmlVerb::Select, DmlVerb::Update],
        &[DmlVerb::Select],
    )
    .await;
    set_policy(
        &dir,
        &tid,
        DmlVerb::Select,
        json!({"using": {"status": {"$ne": "secret"}}}),
    )
    .await;
    let id = create_id(&app, &tid, &svc, json!({"status": "secret", "note": "n"})).await;
    let body = patch_ok(&app, &tid, &anon, id, json!({"note": "x"})).await;
    assert_eq!(body, json!({"record": {"id": id}}));
    // Oracle: the same caller cannot GET the row either.
    let g = send(
        &app,
        req("GET", &tid, &format!("/records/posts/{id}"), None, &anon),
    )
    .await;
    assert_eq!(g.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn anon_update_that_hides_the_row_returns_id_only() {
    let (app, tid, svc, anon, dir) = spin_up_dual_role_self_register("t-e9-a4").await;
    seed_posts(
        &dir,
        &tid,
        &[DmlVerb::Select, DmlVerb::Update],
        &[DmlVerb::Select],
    )
    .await;
    set_policy(
        &dir,
        &tid,
        DmlVerb::Select,
        json!({"using": {"status": {"$ne": "secret"}}}),
    )
    .await;
    let id = create_id(&app, &tid, &svc, json!({"status": "draft", "note": "n"})).await;
    let body = patch_ok(&app, &tid, &anon, id, json!({"status": "secret"})).await;
    assert_eq!(
        body,
        json!({"record": {"id": id}}),
        "decided on the post-image"
    );
    assert_eq!(db_status(&dir, &tid, id).await, "secret", "write committed");
}

#[tokio::test]
async fn anon_update_visible_under_policy_returns_full_row() {
    let (app, tid, svc, anon, dir) = spin_up_dual_role_self_register("t-e9-a5").await;
    seed_posts(
        &dir,
        &tid,
        &[DmlVerb::Select, DmlVerb::Update],
        &[DmlVerb::Select],
    )
    .await;
    set_policy(
        &dir,
        &tid,
        DmlVerb::Select,
        json!({"using": {"status": {"$ne": "secret"}}}),
    )
    .await;
    let id = create_id(&app, &tid, &svc, json!({"status": "draft", "note": "n"})).await;
    let body = patch_ok(&app, &tid, &anon, id, json!({"status": "open"})).await;
    assert_eq!(body["record"]["status"], "open", "{body}");
    assert_eq!(body["record"]["note"], "n", "{body}");
}

#[tokio::test]
async fn anon_update_clause_less_select_policy_returns_id_only() {
    let (app, tid, svc, anon, dir) = spin_up_dual_role_self_register("t-e9-a6").await;
    seed_posts(
        &dir,
        &tid,
        &[DmlVerb::Select, DmlVerb::Update],
        &[DmlVerb::Select],
    )
    .await;
    set_policy(&dir, &tid, DmlVerb::Select, json!({})).await;
    let id = create_id(&app, &tid, &svc, json!({"status": "draft", "note": "n"})).await;
    let body = patch_ok(&app, &tid, &anon, id, json!({"status": "open"})).await;
    assert_eq!(body, json!({"record": {"id": id}}));
}

// ── user ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn user_update_without_user_caps_select_returns_id_only() {
    let (app, tid, svc, _anon, dir) = spin_up_dual_role_self_register("t-e9-u1").await;
    seed_posts(&dir, &tid, &[DmlVerb::Select], &[DmlVerb::Update]).await;
    let ut = register_and_login_via_app(&app, &tid, "a@x.com", "longpassword").await;
    let id = create_id(
        &app,
        &tid,
        &svc,
        json!({"status": "draft", "note": "private"}),
    )
    .await;
    let body = patch_ok(&app, &tid, &ut, id, json!({"status": "open"})).await;
    assert_eq!(body, json!({"record": {"id": id}}));
    assert_eq!(db_status(&dir, &tid, id).await, "open", "write committed");
}

#[tokio::test]
async fn user_update_read_scope_own_returns_full_row() {
    let (app, tid, svc, _anon, dir) = spin_up_dual_role_self_register("t-e9-u2").await;
    seed_owner_scoped(&app, &tid, &svc, &dir, "own").await;
    let ut = register_and_login_via_app(&app, &tid, "a@x.com", "longpassword").await;
    let created = create(&app, &tid, &ut, json!({"title": "t"})).await;
    let id = created["id"].as_i64().unwrap();
    let me = created["record"]["user_id"].clone();
    assert!(me.is_string(), "owner stamped: {created}");
    let body = patch_ok(&app, &tid, &ut, id, json!({"title": "t2"})).await;
    assert_eq!(body["record"]["title"], "t2", "{body}");
    assert_eq!(body["record"]["user_id"], me, "{body}");
}

#[tokio::test]
async fn user_update_read_scope_all_without_select_cap_returns_id_only() {
    let (app, tid, svc, _anon, dir) = spin_up_dual_role_self_register("t-e9-u3").await;
    seed_owner_scoped(&app, &tid, &svc, &dir, "all").await;
    write_caps_user(&dir, &tid, &[]).await;
    let ut = register_and_login_via_app(&app, &tid, "a@x.com", "longpassword").await;
    let id = create_id(&app, &tid, &ut, json!({"title": "t"})).await;
    let body = patch_ok(&app, &tid, &ut, id, json!({"title": "t2"})).await;
    assert_eq!(body, json!({"record": {"id": id}}));
    // Oracle: the same user cannot GET the row either.
    let g = send(
        &app,
        req("GET", &tid, &format!("/records/posts/{id}"), None, &ut),
    )
    .await;
    assert_eq!(g.status(), StatusCode::FORBIDDEN);
}

// ── unchanged faces ─────────────────────────────────────────────────────

#[tokio::test]
async fn service_update_returns_full_row_regardless_of_caps_and_policy() {
    let (app, tid, svc, _anon, dir) = spin_up_dual_role_self_register("t-e9-s1").await;
    seed_posts(&dir, &tid, &[], &[]).await;
    set_policy(&dir, &tid, DmlVerb::Select, json!({})).await;
    let id = create_id(
        &app,
        &tid,
        &svc,
        json!({"status": "draft", "note": "private"}),
    )
    .await;
    let body = patch_ok(&app, &tid, &svc, id, json!({"status": "open"})).await;
    assert_eq!(body["record"]["status"], "open", "{body}");
    assert_eq!(body["record"]["note"], "private", "{body}");
}

#[tokio::test]
async fn anon_insert_only_create_still_returns_record() {
    let (app, tid, _svc, anon, dir) = spin_up_dual_role_self_register("t-e9-i1").await;
    seed_posts(&dir, &tid, &[DmlVerb::Insert], &[DmlVerb::Select]).await;
    let body = create(&app, &tid, &anon, json!({"status": "draft", "note": "n"})).await;
    assert!(body["id"].as_i64().is_some(), "{body}");
    assert_eq!(body["record"]["status"], "draft", "{body}");
    assert_eq!(body["record"]["note"], "n", "{body}");
}
