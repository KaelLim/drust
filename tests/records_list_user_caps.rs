//! v1.41 — `POST /t/<id>/collections/<c>/list` User-role cap source.
//!
//! Group 4 (the `/list` lockstep). Proves the two User cap-check branches
//! in `src/tenant/records_list.rs` consult `user_caps` (NOT `anon_caps`):
//!   - the non-owner-scoped User branch (records_list.rs:~115), and
//!   - the owner_field + read_scope="all" User branch (records_list.rs:~104),
//!     which keeps its own select-cap requirement despite owner_field
//!     (pre-existing divergence from has_dml_cap's owner short-circuit — see
//!     spec §5.3 / the lockstep cross-ref comment in records_list.rs).
//!
//! Parity: for a non-owner-scoped collection, /list and /records GET-list
//! and /search must give the SAME allow/deny for a User token under the
//! same user_caps (all three route the User-non-owner case to user_caps —
//! /records + /search via has_dml_cap, /list via its own matrix).

#[path = "helpers.rs"]
mod helpers;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use helpers::{grab_pool, register_and_login_via_app, spin_up_dual_role_self_register};
use serde_json::{Value, json};
use tower::ServiceExt;

// ── Fixtures ──────────────────────────────────────────────────────────

/// Plain (non-owner-scoped) `posts` with explicit anon_caps + user_caps so
/// the two columns can diverge in tests.
async fn seed_plain_posts_caps(
    dir: &tempfile::TempDir,
    tenant: &str,
    anon_caps: &str,
    user_caps: &str,
) {
    let pool = grab_pool(tenant, dir).await;
    let sql = format!(
        "CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            score INTEGER DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
         );
         INSERT INTO _system_collection_meta
              (collection_name, anon_caps_json, user_caps_json)
              VALUES ('posts', '{anon_caps}', '{user_caps}')
              ON CONFLICT(collection_name) DO UPDATE SET
                anon_caps_json = '{anon_caps}',
                user_caps_json = '{user_caps}';"
    );
    pool.with_writer(move |c| c.execute_batch(&sql))
        .await
        .unwrap();
}

/// owner_field set + read_scope="all" `posts` with explicit anon_caps +
/// user_caps. read_scope="all" means the User sees everyone's rows but the
/// /list branch STILL requires the select cap (records_list.rs:~104).
async fn seed_owner_all_posts_caps(
    dir: &tempfile::TempDir,
    tenant: &str,
    anon_caps: &str,
    user_caps: &str,
) {
    let pool = grab_pool(tenant, dir).await;
    let sql = format!(
        "CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            score INTEGER DEFAULT 0,
            owner_id TEXT REFERENCES _system_users(id),
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
         );
         INSERT INTO _system_collection_meta
              (collection_name, anon_caps_json, user_caps_json, owner_field, read_scope)
              VALUES ('posts', '{anon_caps}', '{user_caps}', 'owner_id', 'all')
              ON CONFLICT(collection_name) DO UPDATE SET
                anon_caps_json = '{anon_caps}',
                user_caps_json = '{user_caps}',
                owner_field = 'owner_id',
                read_scope = 'all';"
    );
    pool.with_writer(move |c| c.execute_batch(&sql))
        .await
        .unwrap();
}

async fn insert_post(app: &axum::Router, tid: &str, tok: &str, title: &str, score: i64) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{tid}/records/posts"))
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"data": {"title": title, "score": score}}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED, "insert {title} failed");
}

/// Service-insert a row into an owner-scoped collection, supplying `owner_id`
/// explicitly. Production requires service tokens to populate `owner_field` on
/// owner-scoped INSERT (`409 OWNER_FIELD_REQUIRED` otherwise — see
/// `src/tenant/records.rs`), independent of column nullability.
async fn insert_post_owned(
    app: &axum::Router,
    tid: &str,
    tok: &str,
    title: &str,
    score: i64,
    owner_id: &str,
) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{tid}/records/posts"))
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"data": {"title": title, "score": score, "owner_id": owner_id}})
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED, "insert {title} failed");
}

/// Look up a registered user's `_system_users.id` by email so a service
/// token can stamp `owner_id` to a real, FK-valid user.
async fn user_id_for_email(dir: &tempfile::TempDir, tenant: &str, email: &str) -> String {
    let pool = grab_pool(tenant, dir).await;
    let email = email.to_string();
    pool.with_reader(move |c| {
        c.query_row(
            "SELECT id FROM _system_users WHERE email = ?1",
            rusqlite::params![email],
            |r| r.get::<_, String>(0),
        )
    })
    .await
    .unwrap()
}

async fn post_list(
    app: &axum::Router,
    tid: &str,
    tok: &str,
    coll: &str,
    body: Value,
) -> (StatusCode, Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{tid}/collections/{coll}/list"))
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

async fn records_get_list(
    app: &axum::Router,
    tid: &str,
    tok: &str,
    coll: &str,
) -> (StatusCode, Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/t/{tid}/records/{coll}"))
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

// ──────────────────────────────────────────────────────────────────────
// (1) Non-owner-scoped /list gated by user_caps[select]
// ──────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn user_list_non_owner_denied_when_user_caps_lacks_select() {
    // anon_caps=[select] (broad), user_caps=[] (no select for User).
    // The User must be DENIED on /list — proving /list reads user_caps,
    // not anon_caps (the old code would have ALLOWED via anon_caps[select]).
    let (app, tid, svc, _anon, dir) = spin_up_dual_role_self_register("ucaps-list-deny").await;
    seed_plain_posts_caps(&dir, &tid, "[\"select\"]", "[]").await;
    insert_post(&app, &tid, &svc, "row-1", 1).await;
    let user_a = register_and_login_via_app(&app, &tid, "u@x.com", "longpassword").await;
    let (status, v) = post_list(&app, &tid, &user_a, "posts", json!({})).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{v:?}");
    assert_eq!(v["error_code"], "ANON_CAP_DENIED");
    // Site-A′ role-aware message: must NOT say "inherits anon"; must point
    // the user at user_caps.
    let msg = v["message"].as_str().unwrap_or("");
    assert!(
        msg.contains("user role") && msg.contains("user_caps") && !msg.contains("inherit"),
        "deny message not reworded for user_caps: {v:?}"
    );
}

#[tokio::test]
async fn user_list_non_owner_allowed_when_user_caps_has_select() {
    // user_caps=[select] grants the User read even though anon_caps=[].
    // Proves user_caps is the deciding gate (anon_caps=[] would have
    // denied under the old anon-inherit code).
    let (app, tid, svc, _anon, dir) = spin_up_dual_role_self_register("ucaps-list-allow").await;
    seed_plain_posts_caps(&dir, &tid, "[]", "[\"select\"]").await;
    insert_post(&app, &tid, &svc, "row-1", 1).await;
    let user_a = register_and_login_via_app(&app, &tid, "u@x.com", "longpassword").await;
    let (status, v) = post_list(&app, &tid, &user_a, "posts", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{v:?}");
    assert_eq!(v["total"], 1);
}

// ──────────────────────────────────────────────────────────────────────
// (2) owner_field + read_scope="all" /list gated by user_caps[select], NOT anon_caps
// ──────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn user_list_owner_all_denied_by_user_caps_not_anon_caps() {
    // owner_field set + read_scope="all". anon_caps=[select] (broad),
    // user_caps=[] (empty). The read_scope="all" /list branch keeps its
    // own select-cap requirement (it does NOT use has_dml_cap's owner
    // short-circuit) — so the User must be DENIED, gated by user_caps,
    // and the swap means anon_caps no longer rescues them.
    let (app, tid, _svc, _anon, dir) = spin_up_dual_role_self_register("ucaps-all-deny").await;
    seed_owner_all_posts_caps(&dir, &tid, "[\"select\"]", "[]").await;
    let user_a = register_and_login_via_app(&app, &tid, "a@x.com", "longpassword").await;
    let (status, v) = post_list(&app, &tid, &user_a, "posts", json!({})).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{v:?}");
    assert_eq!(v["error_code"], "ANON_CAP_DENIED");
    let msg = v["message"].as_str().unwrap_or("");
    assert!(
        msg.contains("user role") && msg.contains("user_caps") && !msg.contains("inherit"),
        "owner_all deny message not reworded: {v:?}"
    );
}

#[tokio::test]
async fn user_list_owner_all_allowed_when_user_caps_has_select() {
    // Same owner+all shape, but user_caps=[select] and anon_caps=[].
    // The User is ALLOWED (gated by user_caps), and with read_scope="all"
    // sees every row (no per-user filter).
    let (app, tid, svc, _anon, dir) = spin_up_dual_role_self_register("ucaps-all-allow").await;
    seed_owner_all_posts_caps(&dir, &tid, "[]", "[\"select\"]").await;
    // Register the user first, then service-insert a row owned by that user.
    // Production requires service tokens to supply owner_field on owner-scoped
    // INSERT (409 OWNER_FIELD_REQUIRED otherwise — see src/tenant/records.rs),
    // regardless of column nullability.
    let user_a = register_and_login_via_app(&app, &tid, "a@x.com", "longpassword").await;
    let uid = user_id_for_email(&dir, &tid, "a@x.com").await;
    insert_post_owned(&app, &tid, &svc, "shared-1", 1, &uid).await;
    let (status, v) = post_list(&app, &tid, &user_a, "posts", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{v:?}");
    assert_eq!(v["total"], 1, "read_scope=all sees all rows: {v:?}");
}

// ──────────────────────────────────────────────────────────────────────
// (3) Parity: /list vs /records GET-list — same allow/deny for User
//     (non-owner-scoped common case)
// ──────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn user_list_and_records_getlist_parity_deny() {
    // user_caps=[] → BOTH /list and /records GET-list deny the User with
    // ANON_CAP_DENIED. (/records routes through has_dml_cap's User arm —
    // Group 1's swap; /list through its own matrix — Group 4's swap. The
    // parity test kills any lockstep divergence between the two sites.)
    let (app, tid, svc, _anon, dir) = spin_up_dual_role_self_register("ucaps-parity-deny").await;
    seed_plain_posts_caps(&dir, &tid, "[\"select\"]", "[]").await;
    insert_post(&app, &tid, &svc, "row-1", 1).await;
    let user_a = register_and_login_via_app(&app, &tid, "u@x.com", "longpassword").await;

    let (list_status, lv) = post_list(&app, &tid, &user_a, "posts", json!({})).await;
    let (rec_status, rv) = records_get_list(&app, &tid, &user_a, "posts").await;

    assert_eq!(list_status, StatusCode::FORBIDDEN, "/list: {lv:?}");
    assert_eq!(rec_status, StatusCode::FORBIDDEN, "/records: {rv:?}");
    assert_eq!(lv["error_code"], "ANON_CAP_DENIED");
    assert_eq!(rv["error_code"], "ANON_CAP_DENIED");
}

#[tokio::test]
async fn user_list_and_records_getlist_parity_allow() {
    // user_caps=[select] → BOTH /list and /records GET-list allow the User.
    let (app, tid, svc, _anon, dir) = spin_up_dual_role_self_register("ucaps-parity-allow").await;
    seed_plain_posts_caps(&dir, &tid, "[]", "[\"select\"]").await;
    insert_post(&app, &tid, &svc, "row-1", 1).await;
    let user_a = register_and_login_via_app(&app, &tid, "u@x.com", "longpassword").await;

    let (list_status, lv) = post_list(&app, &tid, &user_a, "posts", json!({})).await;
    let (rec_status, rv) = records_get_list(&app, &tid, &user_a, "posts").await;

    assert_eq!(list_status, StatusCode::OK, "/list: {lv:?}");
    assert_eq!(rec_status, StatusCode::OK, "/records: {rv:?}");
}
