//! audit3 (2026-06-23) F1 — `read_scope="all"` on an owner-scoped collection
//! must NOT bypass `user_caps` on reads, and must NOT let a user write another
//! user's row.
//!
//! Before the fix, `has_dml_cap` short-circuited on `owner_field.is_some()` for
//! ALL verbs while `compute_owner_filter` only emitted the owner clause for
//! `read_scope="own"`. So under `read_scope="all"`:
//!   • GET /records and POST /search returned every row even with user_caps=[]
//!     (divergent from POST /list, which already gated on user_caps[select]);
//!   • PATCH/DELETE became ID-only → a user could mutate/delete another user's
//!     row, violating "UPDATE/DELETE foreign rows → 404".
//!
//! The fix: reads under read_scope="all" are gated by user_caps[select] (parity
//! with /list); writes always carry the owner clause regardless of read_scope.

#[path = "helpers.rs"]
mod helpers;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::storage::schema::{DmlVerb, write_user_caps};
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

/// posts(user_id FK) owner-scoped with `read_scope="all"`, two registered users.
/// Returns (app, tid, dir, svc, anon, alice, bob).
async fn setup_all(
    tname: &str,
) -> (
    axum::Router,
    String,
    tempfile::TempDir,
    String,
    String,
    String,
    String,
) {
    let (app, tid, svc, anon, dir) = helpers::spin_up_dual_role_self_register(tname).await;
    let pool = helpers::grab_pool(&tid, &dir).await;
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
    let r = app
        .clone()
        .oneshot(req(
            "POST",
            &tid,
            "/collections/posts/owner-field",
            Some(json!({"field": "user_id", "read_scope": "all"})),
            &svc,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK, "set owner-field failed");
    let ta = helpers::register_and_login_via_app(&app, &tid, "a@x.com", "longpassword").await;
    let tb = helpers::register_and_login_via_app(&app, &tid, "b@x.com", "longpassword").await;
    (app, tid, dir, svc, anon, ta, tb)
}

async fn set_user_caps(dir: &tempfile::TempDir, tid: &str, verbs: &[DmlVerb]) {
    let pool = helpers::grab_pool(tid, dir).await;
    let uc: BTreeSet<DmlVerb> = verbs.iter().copied().collect();
    pool.with_writer(move |c| write_user_caps(c, "posts", &uc))
        .await
        .unwrap();
    pool.schema_cache.invalidate("posts");
}

async fn create_post(app: &axum::Router, tid: &str, title: &str, token: &str) -> i64 {
    let r = app
        .clone()
        .oneshot(req(
            "POST",
            tid,
            "/records/posts",
            Some(json!({"data": {"title": title}})),
            token,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED, "create_post should 201");
    read_json(r).await["id"].as_i64().unwrap()
}

// ── reads ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn read_scope_all_without_select_cap_is_denied() {
    // user_caps=[] → read_scope="all" GET must be 403 (parity with /list), not
    // a free read of every row via the owner short-circuit.
    let (app, tid, dir, _svc, _anon, ta, _tb) = setup_all("t-a3-readdeny").await;
    set_user_caps(&dir, &tid, &[]).await;
    let r = app
        .oneshot(req("GET", &tid, "/records/posts", None, &ta))
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::FORBIDDEN,
        "read_scope=all + user_caps=[] must deny the user read (audit3 F1)"
    );
}

#[tokio::test]
async fn read_scope_all_list_endpoint_also_denied_without_select_cap() {
    // Lockstep proof: POST /list already denied this; /records must match.
    let (app, tid, dir, _svc, _anon, ta, _tb) = setup_all("t-a3-listdeny").await;
    set_user_caps(&dir, &tid, &[]).await;
    let r = app
        .oneshot(req(
            "POST",
            &tid,
            "/collections/posts/list",
            Some(json!({})),
            &ta,
        ))
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::FORBIDDEN,
        "/list must also deny read_scope=all + user_caps=[] (lockstep)"
    );
}

#[tokio::test]
async fn read_scope_all_with_select_cap_sees_everyones_rows() {
    // Regression: the intended read-all behavior still works with the default
    // user_caps=[select].
    let (app, tid, _dir, _svc, _anon, ta, tb) = setup_all("t-a3-readall").await;
    create_post(&app, &tid, "alice-1", &ta).await;
    create_post(&app, &tid, "bob-1", &tb).await;
    let r = app
        .oneshot(req("GET", &tid, "/records/posts", None, &ta))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let v = read_json(r).await;
    assert_eq!(
        v["records"].as_array().unwrap().len(),
        2,
        "read_scope=all + user_caps=[select] should still see all rows"
    );
}

// ── writes (owner clause always applied) ───────────────────────────────────

#[tokio::test]
async fn read_scope_all_user_cannot_delete_foreign_row() {
    let (app, tid, _dir, _svc, _anon, ta, tb) = setup_all("t-a3-delforeign").await;
    let _aid = create_post(&app, &tid, "alice-1", &ta).await;
    let bid = create_post(&app, &tid, "bob-1", &tb).await;
    // Alice tries to delete Bob's row → must 404 (owner clause), not 204.
    let r = app
        .clone()
        .oneshot(req(
            "DELETE",
            &tid,
            &format!("/records/posts/{bid}"),
            None,
            &ta,
        ))
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::NOT_FOUND,
        "user must not delete another user's row under read_scope=all (audit3 F1)"
    );
    // Bob's row must still exist.
    let g = app
        .oneshot(req(
            "GET",
            &tid,
            &format!("/records/posts/{bid}"),
            None,
            &tb,
        ))
        .await
        .unwrap();
    assert_eq!(g.status(), StatusCode::OK, "bob's row must survive");
}

#[tokio::test]
async fn read_scope_all_user_cannot_patch_foreign_row() {
    let (app, tid, _dir, _svc, _anon, ta, tb) = setup_all("t-a3-patchforeign").await;
    let _aid = create_post(&app, &tid, "alice-1", &ta).await;
    let bid = create_post(&app, &tid, "bob-1", &tb).await;
    let r = app
        .oneshot(req(
            "PATCH",
            &tid,
            &format!("/records/posts/{bid}"),
            Some(json!({"data": {"title": "hijacked"}})),
            &ta,
        ))
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::NOT_FOUND,
        "user must not patch another user's row under read_scope=all (audit3 F1)"
    );
}

#[tokio::test]
async fn read_scope_all_user_can_still_modify_own_row() {
    // Regression: own-row writes still work under read_scope=all.
    let (app, tid, _dir, _svc, _anon, ta, _tb) = setup_all("t-a3-ownwrite").await;
    let aid = create_post(&app, &tid, "alice-1", &ta).await;
    let r = app
        .clone()
        .oneshot(req(
            "PATCH",
            &tid,
            &format!("/records/posts/{aid}"),
            Some(json!({"data": {"title": "alice-edited"}})),
            &ta,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK, "own-row patch must work");
    let r = app
        .oneshot(req(
            "DELETE",
            &tid,
            &format!("/records/posts/{aid}"),
            None,
            &ta,
        ))
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::NO_CONTENT,
        "own-row delete must work"
    );
}
