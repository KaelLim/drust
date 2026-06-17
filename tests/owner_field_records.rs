/// Integration tests for Tasks 20 + 21: row-level owner filter on
/// SELECT (list + get-by-id) and INSERT/UPDATE/DELETE enforcement.
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
    let bytes = axum::body::to_bytes(resp.into_body(), 65_536)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// Set up a tenant with:
///   - a `posts` table with `user_id TEXT REFERENCES _system_users(id)`
///   - owner_field set to `user_id` with the given `read_scope`
///   - self-registration enabled
///   - two registered users (alice = ta, bob = tb)
///
/// Returns `(app, tid, dir, svc_token, anon_token, ta, tb)`.
async fn setup(
    scope: &str,
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

    // Create posts table via direct pool write.
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

    // Set owner-field via REST (service token).
    let r = app
        .clone()
        .oneshot(req(
            "POST",
            &tid,
            "/collections/posts/owner-field",
            Some(json!({"field": "user_id", "read_scope": scope})),
            &svc,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK, "set owner-field failed");

    // Register two users.
    let ta = helpers::register_and_login_via_app(&app, &tid, "a@x.com", "longpassword").await;
    let tb = helpers::register_and_login_via_app(&app, &tid, "b@x.com", "longpassword").await;

    (app, tid, dir, svc, anon, ta, tb)
}

// ──────────────────────────────────────────────────────────────────────────────
// Task 20: SELECT filter
// ──────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn read_own_user_only_sees_own_records() {
    let (app, tid, _d, _svc, _anon, ta, tb) = setup("own", "t-rec1").await;
    // Alice creates a record (user token → auto-fills user_id).
    let _ = app
        .clone()
        .oneshot(req(
            "POST",
            &tid,
            "/records/posts",
            Some(json!({"data": {"title": "alice-1"}})),
            &ta,
        ))
        .await
        .unwrap();
    // Bob creates a record.
    let _ = app
        .clone()
        .oneshot(req(
            "POST",
            &tid,
            "/records/posts",
            Some(json!({"data": {"title": "bob-1"}})),
            &tb,
        ))
        .await
        .unwrap();
    // Alice lists → should see only her record.
    let resp = app
        .oneshot(req("GET", &tid, "/records/posts", None, &ta))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = read_json(resp).await;
    let arr = v["records"].as_array().unwrap();
    assert_eq!(
        arr.len(),
        1,
        "alice should see exactly 1 record, got: {arr:?}"
    );
    assert!(
        arr.iter()
            .all(|r| r["title"].as_str().unwrap().starts_with("alice-")),
        "alice got wrong records: {arr:?}"
    );
}

#[tokio::test]
async fn read_all_user_sees_everyones_records() {
    let (app, tid, _d, _svc, _anon, ta, tb) = setup("all", "t-rec2").await;
    let _ = app
        .clone()
        .oneshot(req(
            "POST",
            &tid,
            "/records/posts",
            Some(json!({"data": {"title": "alice-1"}})),
            &ta,
        ))
        .await
        .unwrap();
    let _ = app
        .clone()
        .oneshot(req(
            "POST",
            &tid,
            "/records/posts",
            Some(json!({"data": {"title": "bob-1"}})),
            &tb,
        ))
        .await
        .unwrap();
    // Alice lists → read_scope=all, so she sees both.
    let resp = app
        .oneshot(req("GET", &tid, "/records/posts", None, &ta))
        .await
        .unwrap();
    let v = read_json(resp).await;
    assert_eq!(
        v["records"].as_array().unwrap().len(),
        2,
        "read_scope=all should return all records"
    );
}

#[tokio::test]
async fn service_token_bypasses_read_filter() {
    let (app, tid, _d, svc, _anon, ta, tb) = setup("own", "t-rec3").await;
    // Service inserts records for both users with explicit user_id.
    // First get the user IDs by having them each register; ta and tb are their
    // session tokens, but we need the user_id.  Insert via service with
    // explicit user_id strings (they start with "u-" per the system).
    // Simpler: just let users insert their own posts via user tokens.
    let _ = app
        .clone()
        .oneshot(req(
            "POST",
            &tid,
            "/records/posts",
            Some(json!({"data": {"title": "alice-post"}})),
            &ta,
        ))
        .await
        .unwrap();
    let _ = app
        .clone()
        .oneshot(req(
            "POST",
            &tid,
            "/records/posts",
            Some(json!({"data": {"title": "bob-post"}})),
            &tb,
        ))
        .await
        .unwrap();
    // Service lists → no owner filter → sees all 2 records.
    let resp = app
        .oneshot(req("GET", &tid, "/records/posts", None, &svc))
        .await
        .unwrap();
    let v = read_json(resp).await;
    assert_eq!(
        v["records"].as_array().unwrap().len(),
        2,
        "service should bypass owner filter"
    );
}

#[tokio::test]
async fn get_by_id_foreign_returns_404() {
    let (app, tid, _d, _svc, _anon, ta, tb) = setup("own", "t-rec-getid").await;
    // Alice creates a post.
    let r = app
        .clone()
        .oneshot(req(
            "POST",
            &tid,
            "/records/posts",
            Some(json!({"data": {"title": "alice"}})),
            &ta,
        ))
        .await
        .unwrap();
    let v = read_json(r).await;
    let pid = v["id"].as_i64().unwrap();
    // Bob tries to get Alice's post by id → 404 (no enumeration leak).
    let r = app
        .oneshot(req(
            "GET",
            &tid,
            &format!("/records/posts/{pid}"),
            None,
            &tb,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
}

// ──────────────────────────────────────────────────────────────────────────────
// Task 21: INSERT auto-fill + UPDATE/DELETE foreign-row 404
// ──────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn insert_overrides_client_supplied_owner_field() {
    let (app, tid, _d, _svc, _anon, ta, tb) = setup("own", "t-rec4").await;
    // Alice tries to claim ownership for a fake user_id.
    let r = app
        .clone()
        .oneshot(req(
            "POST",
            &tid,
            "/records/posts",
            Some(json!({"data": {"title": "phishy", "user_id": "u-00000000-fake"}})),
            &ta,
        ))
        .await
        .unwrap();
    assert!(
        r.status().is_success(),
        "insert should succeed: {:?}",
        r.status()
    );

    // Alice sees her phishy post.
    let v = read_json(
        app.clone()
            .oneshot(req("GET", &tid, "/records/posts", None, &ta))
            .await
            .unwrap(),
    )
    .await;
    assert!(
        v["records"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["title"] == "phishy"),
        "alice should see her own post"
    );

    // Bob does NOT see Alice's post.
    let v = read_json(
        app.oneshot(req("GET", &tid, "/records/posts", None, &tb))
            .await
            .unwrap(),
    )
    .await;
    assert!(
        v["records"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["title"] != "phishy"),
        "bob should not see alice's post"
    );
}

#[tokio::test]
async fn update_foreign_row_returns_404_not_403() {
    let (app, tid, _d, _svc, _anon, ta, tb) = setup("own", "t-rec5").await;
    let r = app
        .clone()
        .oneshot(req(
            "POST",
            &tid,
            "/records/posts",
            Some(json!({"data": {"title": "alice"}})),
            &ta,
        ))
        .await
        .unwrap();
    let v = read_json(r).await;
    let pid = v["id"].as_i64().unwrap();
    // Bob tries to update Alice's record.
    let r = app
        .oneshot(req(
            "PATCH",
            &tid,
            &format!("/records/posts/{pid}"),
            Some(json!({"data": {"title": "hijacked"}})),
            &tb,
        ))
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::NOT_FOUND,
        "cross-user UPDATE should be 404"
    );
}

#[tokio::test]
async fn delete_foreign_row_returns_404() {
    let (app, tid, _d, _svc, _anon, ta, tb) = setup("own", "t-rec6").await;
    let r = app
        .clone()
        .oneshot(req(
            "POST",
            &tid,
            "/records/posts",
            Some(json!({"data": {"title": "alice"}})),
            &ta,
        ))
        .await
        .unwrap();
    let v = read_json(r).await;
    let pid = v["id"].as_i64().unwrap();
    // Bob tries to delete Alice's record.
    let r = app
        .oneshot(req(
            "DELETE",
            &tid,
            &format!("/records/posts/{pid}"),
            None,
            &tb,
        ))
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::NOT_FOUND,
        "cross-user DELETE should be 404"
    );
}

#[tokio::test]
async fn anon_blocked_from_owner_scoped_writes() {
    let (app, tid, _d, _svc, anon, _ta, _tb) = setup("own", "t-rec7").await;
    let r = app
        .oneshot(req(
            "POST",
            &tid,
            "/records/posts",
            Some(json!({"data": {"title": "anonpost"}})),
            &anon,
        ))
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::FORBIDDEN,
        "anon should be blocked on owner-scoped collection"
    );
    let bytes = axum::body::to_bytes(r.into_body(), 65_536).await.unwrap();
    assert!(
        String::from_utf8_lossy(&bytes).contains("ANON_FORBIDDEN_OWNER_SCOPED"),
        "wrong error code, body: {}",
        String::from_utf8_lossy(&bytes)
    );
}

#[tokio::test]
async fn service_required_to_pass_owner_field_on_insert() {
    let (app, tid, _d, svc, _anon, _ta, _tb) = setup("own", "t-rec8").await;
    // Service token omits the owner field → 409 OWNER_FIELD_REQUIRED.
    let r = app
        .oneshot(req(
            "POST",
            &tid,
            "/records/posts",
            Some(json!({"data": {"title": "svcpost"}})),
            &svc,
        ))
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::CONFLICT,
        "service omitting owner_field should get 409"
    );
    let bytes = axum::body::to_bytes(r.into_body(), 65_536).await.unwrap();
    assert!(
        String::from_utf8_lossy(&bytes).contains("OWNER_FIELD_REQUIRED"),
        "wrong error code, body: {}",
        String::from_utf8_lossy(&bytes)
    );
}

// === Regression tests for review fixes ===

#[tokio::test]
async fn anon_blocked_from_owner_scoped_read_when_scope_own() {
    // Anon has no user_id to match against; the SELECT filter would
    // produce an empty list silently. We want a loud 403 instead.
    let (app, tid, _d, _svc, anon, _ta, _tb) = setup("own", "t-rec-anonread").await;
    let r = app
        .oneshot(req("GET", &tid, "/records/posts", None, &anon))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let bytes = axum::body::to_bytes(r.into_body(), 65_536).await.unwrap();
    assert!(
        String::from_utf8_lossy(&bytes).contains("ANON_FORBIDDEN_OWNER_SCOPED"),
        "wrong error code: {}",
        String::from_utf8_lossy(&bytes)
    );
}

#[tokio::test]
async fn user_cannot_transfer_ownership_via_patch_user_id() {
    // PATCH with a {user_id: other-uid} payload must NOT change ownership.
    // The strip-owner-field guard removes it from the SET clause.
    let (app, tid, _d, _svc, _anon, ta, tb) = setup("own", "t-rec-transfer").await;
    let r = app
        .clone()
        .oneshot(req(
            "POST",
            &tid,
            "/records/posts",
            Some(json!({"data": {"title": "mine"}})),
            &ta,
        ))
        .await
        .unwrap();
    let pid = read_json(r).await["id"].as_i64().unwrap();
    // Alice tries to set user_id to bob's id (we don't know bob's id, but
    // any non-alice value triggers the bug if strip is missing).
    let r = app
        .clone()
        .oneshot(req(
            "PATCH",
            &tid,
            &format!("/records/posts/{pid}"),
            Some(json!({"data": {"title": "edited", "user_id": "u-someone-else"}})),
            &ta,
        ))
        .await
        .unwrap();
    assert!(
        r.status().is_success(),
        "patch should succeed: {}",
        r.status()
    );
    // Alice can still see + update the row (still owns it).
    let resp = app
        .clone()
        .oneshot(req("GET", &tid, "/records/posts", None, &ta))
        .await
        .unwrap();
    let v = read_json(resp).await;
    let arr = v["records"].as_array().unwrap();
    assert_eq!(arr.len(), 1, "alice should still own the row");
    assert_eq!(arr[0]["title"].as_str().unwrap(), "edited");
    // Bob still doesn't see it.
    let resp = app
        .oneshot(req("GET", &tid, "/records/posts", None, &tb))
        .await
        .unwrap();
    let v = read_json(resp).await;
    assert_eq!(v["records"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn user_governed_by_user_caps_on_non_owner_scoped() {
    // v1.41: the User role is governed by its OWN user_caps on a
    // non-owner-scoped collection — it no longer inherits anon_caps. Here
    // user_caps='[]' locks the user out of SELECT (independent of anon_caps,
    // which is also '[]' but irrelevant to the User gate now).
    let (app, tid, _svc, _anon, _dir) =
        helpers::spin_up_dual_role_self_register("t-rec-userfall").await;
    let pool = helpers::grab_pool(&tid, &_dir).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                body TEXT,
                created_at TEXT DEFAULT (datetime('now')),
                updated_at TEXT DEFAULT (datetime('now'))
            );
            INSERT INTO _system_collection_meta
                (collection_name, anon_caps_json, user_caps_json, updated_at)
                VALUES ('notes', '[]', '[]', datetime('now'));",
        )
    })
    .await
    .unwrap();
    let token = helpers::register_and_login_via_app(&app, &tid, "u@x.com", "longpassword").await;
    // User token tries to SELECT a collection where user_caps=[] — denied.
    let r = app
        .oneshot(req("GET", &tid, "/records/notes", None, &token))
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::FORBIDDEN,
        "user must be governed by user_caps (=[]) on non-owner-scoped collection"
    );
}

#[tokio::test]
async fn user_can_read_but_not_write_when_anon_caps_is_select_only() {
    // Non-owner-scoped collection with no meta row → default user_caps=[select]
    // (v1.41). User token: SELECT succeeds via user_caps[select], INSERT denied
    // (user_caps lacks insert) — independent of anon_caps.
    let (app, tid, _svc, _anon, _dir) =
        helpers::spin_up_dual_role_self_register("t-rec-userselect").await;
    let pool = helpers::grab_pool(&tid, &_dir).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE tags (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                label TEXT,
                created_at TEXT DEFAULT (datetime('now')),
                updated_at TEXT DEFAULT (datetime('now'))
            );",
        )
    })
    .await
    .unwrap();
    // No _system_collection_meta row → default anon_caps = [select]
    let token = helpers::register_and_login_via_app(&app, &tid, "u@x.com", "longpassword").await;
    // GET succeeds (select in caps)
    let r = app
        .clone()
        .oneshot(req("GET", &tid, "/records/tags", None, &token))
        .await
        .unwrap();
    assert!(
        r.status().is_success(),
        "user GET should pass via user_caps[select]: {}",
        r.status()
    );
    // POST denied (insert not in caps)
    let r = app
        .oneshot(req(
            "POST",
            &tid,
            "/records/tags",
            Some(json!({"data": {"label": "rust"}})),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let bytes = axum::body::to_bytes(r.into_body(), 65_536).await.unwrap();
    assert!(String::from_utf8_lossy(&bytes).contains("ANON_CAP_DENIED"));
}
