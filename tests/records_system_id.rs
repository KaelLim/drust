//! E1′ — anon and user tokens may not choose a row's `id` on INSERT nor change
//! it on UPDATE (REST `create_handler` / `update_handler`); service is unchanged.
//!
//! Every collection is `id INTEGER PRIMARY KEY AUTOINCREMENT`. One INSERT of
//! `id = i64::MAX` pins `sqlite_sequence` at the max and every later auto-id
//! INSERT on that table fails with SQLITE_FULL; an UPDATE to `i64::MAX - 1`
//! reaches the same end on the next ordinary insert. The function under test
//! is validate-only, so accepted requests (no id, INSERT `"id": null`, UPDATE
//! echoing the row's own id) must behave exactly as before.

#[path = "helpers.rs"]
mod helpers;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::storage::schema::{DmlVerb, write_anon_caps, write_user_caps};
use helpers::{grab_pool, register_and_login_via_app, spin_up_dual_role_self_register};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use tower::ServiceExt;

const MAX: i64 = i64::MAX;

// ── tiny request/response helpers (mirror tests/user_caps.rs) ──

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

fn caps(verbs: &[DmlVerb]) -> BTreeSet<DmlVerb> {
    verbs.iter().copied().collect()
}

/// Plain non-owner-scoped `notes(body TEXT)` with the given anon/user caps.
async fn seed_notes(
    dir: &tempfile::TempDir,
    tenant: &str,
    anon_caps: &[DmlVerb],
    user_caps: &[DmlVerb],
) {
    let pool = grab_pool(tenant, dir).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                body TEXT,
                created_at TEXT DEFAULT (datetime('now')),
                updated_at TEXT DEFAULT (datetime('now'))
            );",
        )
    })
    .await
    .unwrap();
    let ac = caps(anon_caps);
    let uc = caps(user_caps);
    pool.with_writer(move |c| {
        write_anon_caps(c, "notes", &ac)?;
        write_user_caps(c, "notes", &uc)
    })
    .await
    .unwrap();
    pool.schema_cache.invalidate("notes");
}

/// Owner-scoped `posts` (owner_field=user_id, read_scope="own", user_caps={}):
/// the owner short-circuit, not the caps, lets the User write.
async fn seed_owner_posts(dir: &tempfile::TempDir, tenant: &str) {
    let pool = grab_pool(tenant, dir).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE posts (
                 id         INTEGER PRIMARY KEY AUTOINCREMENT,
                 user_id    TEXT REFERENCES _system_users(id) ON DELETE RESTRICT,
                 title      TEXT,
                 created_at TEXT DEFAULT (datetime('now')),
                 updated_at TEXT DEFAULT (datetime('now'))
             );
             INSERT INTO _system_collection_meta
                  (collection_name, anon_caps_json, owner_field, read_scope)
                  VALUES ('posts', '[\"select\"]', 'user_id', 'own')
                  ON CONFLICT(collection_name) DO UPDATE SET
                    owner_field = 'user_id', read_scope = 'own';",
        )
    })
    .await
    .unwrap();
    pool.with_writer(|c| write_user_caps(c, "posts", &BTreeSet::new()))
        .await
        .unwrap();
    pool.schema_cache.invalidate("posts");
}

async fn notes_seq(dir: &tempfile::TempDir, tenant: &str) -> i64 {
    grab_pool(tenant, dir)
        .await
        .with_reader(|c| {
            c.query_row(
                "SELECT seq FROM sqlite_sequence WHERE name='notes'",
                [],
                |r| r.get::<_, i64>(0),
            )
        })
        .await
        .unwrap()
}

async fn send(app: &axum::Router, r: Request<Body>) -> axum::response::Response {
    app.clone().oneshot(r).await.unwrap()
}

async fn assert_readonly(resp: axum::response::Response, what: &str) {
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "{what}: expected 400"
    );
    let v = read_json(resp).await;
    assert_eq!(v["error_code"], "SYSTEM_FIELD_READONLY", "{what}: {v}");
    assert!(
        v["suggested_fix"].as_str().is_some_and(|s| !s.is_empty()),
        "{what}: suggested_fix must be present: {v}"
    );
}

/// User creates a note and GETs it back; returns `(id, whole record)`.
async fn user_note(app: &axum::Router, tid: &str, user: &str) -> (i64, Value) {
    let r = send(
        app,
        req(
            "POST",
            tid,
            "/records/notes",
            Some(json!({"data": {"body": "orig"}})),
            user,
        ),
    )
    .await;
    assert_eq!(r.status(), StatusCode::CREATED);
    let id = read_json(r).await["id"].as_i64().unwrap();
    let r = send(
        app,
        req("GET", tid, &format!("/records/notes/{id}"), None, user),
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK);
    let rec = read_json(r).await["record"].clone();
    (id, rec)
}

// R1
#[tokio::test]
async fn anon_insert_with_explicit_id_is_rejected_and_table_stays_writable() {
    let (app, tid, _svc, anon, dir) = spin_up_dual_role_self_register("sid-r1").await;
    seed_notes(&dir, &tid, &[DmlVerb::Select, DmlVerb::Insert], &[]).await;

    let r = send(
        &app,
        req(
            "POST",
            &tid,
            "/records/notes",
            Some(json!({"data": {"id": MAX, "body": "x"}})),
            &anon,
        ),
    )
    .await;
    assert_readonly(r, "anon insert id=MAX").await;

    let r = send(
        &app,
        req(
            "POST",
            &tid,
            "/records/notes",
            Some(json!({"data": {"body": "y"}})),
            &anon,
        ),
    )
    .await;
    assert_eq!(
        r.status(),
        StatusCode::CREATED,
        "auto-id insert must still work"
    );
    assert!(
        notes_seq(&dir, &tid).await < MAX,
        "sqlite_sequence not pinned"
    );
}

// R2
#[tokio::test]
async fn anon_insert_with_null_id_is_auto_assigned() {
    let (app, tid, _svc, anon, dir) = spin_up_dual_role_self_register("sid-r2").await;
    seed_notes(&dir, &tid, &[DmlVerb::Select, DmlVerb::Insert], &[]).await;

    let r = send(
        &app,
        req(
            "POST",
            &tid,
            "/records/notes",
            Some(json!({"data": {"id": null, "body": "x"}})),
            &anon,
        ),
    )
    .await;
    assert_eq!(r.status(), StatusCode::CREATED);
    let v = read_json(r).await;
    let id = v["id"].as_i64().unwrap();
    assert!(id > 0, "{v}");
    assert_eq!(v["record"]["id"].as_i64(), Some(id), "{v}");
}

// R3
#[tokio::test]
async fn user_insert_with_explicit_id_is_rejected() {
    let (app, tid, svc, _anon, dir) = spin_up_dual_role_self_register("sid-r3").await;
    seed_notes(&dir, &tid, &[], &[DmlVerb::Select, DmlVerb::Insert]).await;
    let user = register_and_login_via_app(&app, &tid, "u@x.com", "longpassword").await;

    let r = send(
        &app,
        req(
            "POST",
            &tid,
            "/records/notes",
            Some(json!({"data": {"id": 500, "body": "x"}})),
            &user,
        ),
    )
    .await;
    assert_readonly(r, "user insert id=500").await;

    let r = send(&app, req("GET", &tid, "/records/notes/500", None, &svc)).await;
    assert_eq!(
        r.status(),
        StatusCode::NOT_FOUND,
        "no row must exist at 500"
    );
}

// R4
#[tokio::test]
async fn user_insert_with_explicit_id_on_owner_scoped_is_rejected() {
    let (app, tid, _svc, _anon, dir) = spin_up_dual_role_self_register("sid-r4").await;
    seed_owner_posts(&dir, &tid).await;
    let user = register_and_login_via_app(&app, &tid, "u@x.com", "longpassword").await;

    let r = send(
        &app,
        req(
            "POST",
            &tid,
            "/records/posts",
            Some(json!({"data": {"id": 500, "title": "t"}})),
            &user,
        ),
    )
    .await;
    assert_readonly(r, "user owner-scoped insert id=500").await;
}

// R5
#[tokio::test]
async fn user_patch_echoing_the_whole_record_is_unchanged() {
    let (app, tid, _svc, _anon, dir) = spin_up_dual_role_self_register("sid-r5").await;
    seed_notes(
        &dir,
        &tid,
        &[],
        &[DmlVerb::Select, DmlVerb::Insert, DmlVerb::Update],
    )
    .await;
    let user = register_and_login_via_app(&app, &tid, "u@x.com", "longpassword").await;
    let (id, rec) = user_note(&app, &tid, &user).await;

    // Whole record echoed back (id, created_at, updated_at included).
    let mut body = rec.clone();
    body["body"] = json!("edited");
    let r = send(
        &app,
        req(
            "PATCH",
            &tid,
            &format!("/records/notes/{id}"),
            Some(json!({"data": body})),
            &user,
        ),
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK, "echoed whole-record PATCH");
    let v = read_json(r).await;
    assert_eq!(v["record"]["id"].as_i64(), Some(id), "{v}");
    assert_eq!(v["record"]["body"], "edited", "{v}");

    // Same, with the id echoed as a numeric string.
    let mut body = rec;
    body["body"] = json!("edited2");
    body["id"] = json!(id.to_string());
    let r = send(
        &app,
        req(
            "PATCH",
            &tid,
            &format!("/records/notes/{id}"),
            Some(json!({"data": body})),
            &user,
        ),
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK, "string-id whole-record PATCH");
    let v = read_json(r).await;
    assert_eq!(v["record"]["id"].as_i64(), Some(id), "{v}");
    assert_eq!(v["record"]["body"], "edited2", "{v}");
}

// R6
#[tokio::test]
async fn user_patch_changing_id_is_rejected_and_row_stays() {
    let (app, tid, svc, _anon, dir) = spin_up_dual_role_self_register("sid-r6").await;
    seed_notes(
        &dir,
        &tid,
        &[],
        &[DmlVerb::Select, DmlVerb::Insert, DmlVerb::Update],
    )
    .await;
    let user = register_and_login_via_app(&app, &tid, "u@x.com", "longpassword").await;
    let (id, _rec) = user_note(&app, &tid, &user).await;
    let moved = id + 1000;

    let r = send(
        &app,
        req(
            "PATCH",
            &tid,
            &format!("/records/notes/{id}"),
            Some(json!({"data": {"id": moved, "body": "z"}})),
            &user,
        ),
    )
    .await;
    assert_readonly(r, "user patch changing id").await;

    let r = send(
        &app,
        req("GET", &tid, &format!("/records/notes/{id}"), None, &svc),
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK, "row must stay at its id");
    assert_eq!(read_json(r).await["record"]["body"], "orig");
    let r = send(
        &app,
        req("GET", &tid, &format!("/records/notes/{moved}"), None, &svc),
    )
    .await;
    assert_eq!(r.status(), StatusCode::NOT_FOUND, "no row at the new id");
}

// R7
#[tokio::test]
async fn anon_patch_to_near_max_id_is_rejected_and_next_insert_is_normal() {
    let (app, tid, _svc, anon, dir) = spin_up_dual_role_self_register("sid-r7").await;
    seed_notes(
        &dir,
        &tid,
        &[DmlVerb::Select, DmlVerb::Insert, DmlVerb::Update],
        &[],
    )
    .await;
    let r = send(
        &app,
        req(
            "POST",
            &tid,
            "/records/notes",
            Some(json!({"data": {"body": "a"}})),
            &anon,
        ),
    )
    .await;
    assert_eq!(r.status(), StatusCode::CREATED);
    let id = read_json(r).await["id"].as_i64().unwrap();

    let r = send(
        &app,
        req(
            "PATCH",
            &tid,
            &format!("/records/notes/{id}"),
            Some(json!({"data": {"id": MAX - 1}})),
            &anon,
        ),
    )
    .await;
    assert_readonly(r, "anon patch id=MAX-1").await;

    for body in ["b", "c"] {
        let r = send(
            &app,
            req(
                "POST",
                &tid,
                "/records/notes",
                Some(json!({"data": {"body": body}})),
                &anon,
            ),
        )
        .await;
        assert_eq!(r.status(), StatusCode::CREATED, "insert {body}");
        let new_id = read_json(r).await["id"].as_i64().unwrap();
        assert!(new_id < 1000, "auto id stays small, got {new_id}");
    }
}

// R8
#[tokio::test]
async fn user_patch_with_only_the_same_id_is_unchanged() {
    let (app, tid, _svc, _anon, dir) = spin_up_dual_role_self_register("sid-r8").await;
    seed_notes(
        &dir,
        &tid,
        &[],
        &[DmlVerb::Select, DmlVerb::Insert, DmlVerb::Update],
    )
    .await;
    let user = register_and_login_via_app(&app, &tid, "u@x.com", "longpassword").await;
    let (id, _rec) = user_note(&app, &tid, &user).await;

    let r = send(
        &app,
        req(
            "PATCH",
            &tid,
            &format!("/records/notes/{id}"),
            Some(json!({"data": {"id": id}})),
            &user,
        ),
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK, "same-id-only PATCH stays 200");
    let v = read_json(r).await;
    assert_eq!(v["record"]["id"].as_i64(), Some(id), "{v}");
    assert_eq!(v["record"]["body"], "orig", "{v}");
}

// R9
#[tokio::test]
async fn service_insert_with_explicit_id_is_unchanged() {
    let (app, tid, svc, _anon, dir) = spin_up_dual_role_self_register("sid-r9").await;
    seed_notes(&dir, &tid, &[], &[]).await;

    let r = send(
        &app,
        req(
            "POST",
            &tid,
            "/records/notes",
            Some(json!({"data": {"id": 500, "body": "x"}})),
            &svc,
        ),
    )
    .await;
    assert_eq!(r.status(), StatusCode::CREATED);
    assert_eq!(read_json(r).await["id"].as_i64(), Some(500));
}

// R10
#[tokio::test]
async fn service_patch_changing_id_is_unchanged() {
    let (app, tid, svc, _anon, dir) = spin_up_dual_role_self_register("sid-r10").await;
    seed_notes(&dir, &tid, &[], &[]).await;
    let r = send(
        &app,
        req(
            "POST",
            &tid,
            "/records/notes",
            Some(json!({"data": {"body": "x"}})),
            &svc,
        ),
    )
    .await;
    assert_eq!(r.status(), StatusCode::CREATED);
    let id = read_json(r).await["id"].as_i64().unwrap();

    let r = send(
        &app,
        req(
            "PATCH",
            &tid,
            &format!("/records/notes/{id}"),
            Some(json!({"data": {"id": id + 1000}})),
            &svc,
        ),
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(read_json(r).await["record"]["id"].as_i64(), Some(id + 1000));
}

// R11
#[tokio::test]
async fn anon_without_insert_cap_still_gets_cap_denied_first() {
    let (app, tid, _svc, anon, dir) = spin_up_dual_role_self_register("sid-r11").await;
    seed_notes(&dir, &tid, &[DmlVerb::Select], &[]).await;

    let r = send(
        &app,
        req(
            "POST",
            &tid,
            "/records/notes",
            Some(json!({"data": {"id": 5, "body": "x"}})),
            &anon,
        ),
    )
    .await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    assert_eq!(read_json(r).await["error_code"], "ANON_CAP_DENIED");
}
