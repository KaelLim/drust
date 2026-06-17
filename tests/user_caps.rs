//! v1.41.0 — per-collection `user_caps` for the User role (drust_user_*).
//!
//! End-to-end coverage:
//!   (1) User POST/PATCH/DELETE /records → 201/200/204 when the verb is in
//!       user_caps, 403 ANON_CAP_DENIED (alias retained) when not.
//!   (2) The deny MESSAGE names the *user* role, not anon (regression guard
//!       for the Group-3 role-aware message fix).
//!   (3) Anon-independence: widening user_caps to [insert,update,delete] does
//!       NOT open those verbs to an Anon token (separate column + branch).
//!   (4) owner_field short-circuit unchanged: on a read_scope="own" owner_field
//!       collection, a User has full CRUD on own rows regardless of user_caps,
//!       while Anon → ANON_FORBIDDEN_OWNER_SCOPED.
//!   (5) Must-stay-denied: a User with full user_caps still gets 403 on
//!       /query, /query/explain, /mcp, and SSE subscribe.

#[path = "helpers.rs"]
mod helpers;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use drust::storage::schema::{DmlVerb, write_user_caps};
use helpers::{
    grab_pool, register_and_login_via_app, spin_up_dual_role_self_register,
    spin_up_tenant_self_register,
};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use tower::ServiceExt;

// ── tiny request/response helpers (mirror tests/owner_field_records.rs) ──

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

/// Seed a plain non-owner-scoped `notes(body TEXT)` collection (no owner_field)
/// with the given `user_caps`. Anon caps stay at the default ([select]) unless
/// overridden separately. Mirrors the direct-pool seeding in
/// tests/token_roles.rs (write_anon_caps) — here using write_user_caps.
async fn seed_notes(dir: &tempfile::TempDir, tenant: &str, user_caps: &[DmlVerb]) {
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
    let uc = caps(user_caps);
    pool.with_writer(move |c| write_user_caps(c, "notes", &uc))
        .await
        .unwrap();
    // write_user_caps upserts a _system_collection_meta row; invalidate so the
    // schema_cache reloads it on the next request.
    pool.schema_cache.invalidate("notes");
}

// ── (1) User CRUD allowed when verb ∈ user_caps ─────────────────────────

#[tokio::test]
async fn user_full_caps_can_create_update_delete() {
    let tid = "uc-crud";
    let (app, _svc, dir) = spin_up_tenant_self_register(tid).await;
    seed_notes(
        &dir,
        tid,
        &[
            DmlVerb::Select,
            DmlVerb::Insert,
            DmlVerb::Update,
            DmlVerb::Delete,
        ],
    )
    .await;
    let user = register_and_login_via_app(&app, tid, "u@x.com", "longpassword").await;

    // POST → 201
    let r = app
        .clone()
        .oneshot(req(
            "POST",
            tid,
            "/records/notes",
            Some(json!({"data": {"body": "hello"}})),
            &user,
        ))
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::CREATED,
        "user insert should pass with user_caps"
    );
    let pid = read_json(r).await["id"].as_i64().unwrap();

    // PATCH → 200
    let r = app
        .clone()
        .oneshot(req(
            "PATCH",
            tid,
            &format!("/records/notes/{pid}"),
            Some(json!({"data": {"body": "edited"}})),
            &user,
        ))
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::OK,
        "user update should pass with user_caps"
    );

    // DELETE → 204
    let r = app
        .oneshot(req(
            "DELETE",
            tid,
            &format!("/records/notes/{pid}"),
            None,
            &user,
        ))
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::NO_CONTENT,
        "user delete should pass with user_caps"
    );
}

// ── (1)+(2) deny when verb absent, and the MESSAGE names the user role ──

#[tokio::test]
async fn user_select_only_denied_on_insert_with_user_role_message() {
    let tid = "uc-deny-msg";
    let (app, _svc, dir) = spin_up_tenant_self_register(tid).await;
    // user_caps = [select] (default-equivalent) → insert must be denied.
    seed_notes(&dir, tid, &[DmlVerb::Select]).await;
    let user = register_and_login_via_app(&app, tid, "u@x.com", "longpassword").await;

    let r = app
        .oneshot(req(
            "POST",
            tid,
            "/records/notes",
            Some(json!({"data": {"body": "nope"}})),
            &user,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let v = read_json(r).await;
    // Back-compat error_code + alias retained.
    assert_eq!(v["error_code"], "ANON_CAP_DENIED");
    // Regression guard for the Group-3 role-aware message fix: the human text
    // must name the *user* role and point at user_caps — NOT say "anon".
    let msg = v["message"].as_str().unwrap_or("");
    assert!(
        msg.contains("user role") && msg.contains("user_caps"),
        "deny message should name the user role + user_caps, got: {msg:?} (full: {v})"
    );
    assert!(
        !msg.contains("anon role"),
        "deny message must NOT say 'anon role' for a logged-in user, got: {msg:?}"
    );
}

// ── (3) Anon-independence: widening user_caps does not open anon ────────

#[tokio::test]
async fn widening_user_caps_does_not_open_anon_writes() {
    let tid = "uc-anon-indep";
    let (app, _tid, _svc, anon, dir) = spin_up_dual_role_self_register(tid).await;
    // user_caps wide open; anon_caps left at default ([select]).
    seed_notes(
        &dir,
        tid,
        &[
            DmlVerb::Select,
            DmlVerb::Insert,
            DmlVerb::Update,
            DmlVerb::Delete,
        ],
    )
    .await;

    // Seed one row via service-equivalent? Simpler: anon insert/update/delete
    // must all be 403 regardless of the widened user_caps.
    for (method, path, body) in [
        (
            Method::POST,
            "/records/notes".to_string(),
            Some(json!({"data": {"body": "a"}})),
        ),
        (
            Method::PATCH,
            "/records/notes/1".to_string(),
            Some(json!({"data": {"body": "b"}})),
        ),
        (Method::DELETE, "/records/notes/1".to_string(), None),
    ] {
        let r = app
            .clone()
            .oneshot(req(method.as_str(), tid, &path, body, &anon))
            .await
            .unwrap();
        assert_eq!(
            r.status(),
            StatusCode::FORBIDDEN,
            "anon must stay denied on {method} {path} even with wide user_caps"
        );
        let v = read_json(r).await;
        assert_eq!(v["error_code"], "ANON_CAP_DENIED");
    }
}

// ── (4) owner_field short-circuit unchanged ─────────────────────────────

/// owner-scoped posts (owner_field=user_id, read_scope="own"). Deliberately
/// leave user_caps EMPTY so we prove the owner_field.is_some() short-circuit
/// (not user_caps) is what lets the User write.
async fn seed_owner_posts_empty_user_caps(dir: &tempfile::TempDir, tenant: &str) {
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
    // user_caps = {} — the short-circuit, not the caps, must carry the write.
    pool.with_writer(|c| write_user_caps(c, "posts", &BTreeSet::new()))
        .await
        .unwrap();
    pool.schema_cache.invalidate("posts");
}

#[tokio::test]
async fn owner_scoped_user_has_full_crud_regardless_of_user_caps() {
    let tid = "uc-owner";
    let (app, _tid, _svc, _anon, dir) = spin_up_dual_role_self_register(tid).await;
    seed_owner_posts_empty_user_caps(&dir, tid).await;
    let user = register_and_login_via_app(&app, tid, "a@x.com", "longpassword").await;

    // INSERT (auto-fills user_id) — passes via owner_field short-circuit even
    // though user_caps is empty.
    let r = app
        .clone()
        .oneshot(req(
            "POST",
            tid,
            "/records/posts",
            Some(json!({"data": {"title": "mine"}})),
            &user,
        ))
        .await
        .unwrap();
    assert!(
        r.status().is_success(),
        "owner insert should pass: {}",
        r.status()
    );
    let pid = read_json(r).await["id"].as_i64().unwrap();

    // UPDATE own row — passes.
    let r = app
        .clone()
        .oneshot(req(
            "PATCH",
            tid,
            &format!("/records/posts/{pid}"),
            Some(json!({"data": {"title": "edited"}})),
            &user,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK, "owner update should pass");

    // DELETE own row — passes.
    let r = app
        .oneshot(req(
            "DELETE",
            tid,
            &format!("/records/posts/{pid}"),
            None,
            &user,
        ))
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::NO_CONTENT,
        "owner delete should pass"
    );
}

#[tokio::test]
async fn owner_scoped_anon_forbidden() {
    let tid = "uc-owner-anon";
    let (app, _tid, _svc, anon, dir) = spin_up_dual_role_self_register(tid).await;
    seed_owner_posts_empty_user_caps(&dir, tid).await;

    let r = app
        .oneshot(req(
            "POST",
            tid,
            "/records/posts",
            Some(json!({"data": {"title": "anon"}})),
            &anon,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let v = read_json(r).await;
    assert_eq!(v["error_code"], "ANON_FORBIDDEN_OWNER_SCOPED");
}

// ── (5) must-stay-denied: /query, /query/explain, /mcp, SSE subscribe ───

#[tokio::test]
async fn user_with_full_caps_still_denied_on_query_mcp_sse() {
    let tid = "uc-mustdeny";
    let (app, _svc, dir) = spin_up_tenant_self_register(tid).await;
    // Full user_caps must NOT open any of these surfaces.
    seed_notes(
        &dir,
        tid,
        &[
            DmlVerb::Select,
            DmlVerb::Insert,
            DmlVerb::Update,
            DmlVerb::Delete,
        ],
    )
    .await;
    let user = register_and_login_via_app(&app, tid, "u@x.com", "longpassword").await;

    // /query → QUERY_USER_DENIED
    let r = app
        .clone()
        .oneshot(req(
            "POST",
            tid,
            "/query",
            Some(json!({"sql": "SELECT 1"})),
            &user,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    assert!(
        String::from_utf8_lossy(&axum::body::to_bytes(r.into_body(), 65_536).await.unwrap())
            .contains("QUERY_USER_DENIED")
    );

    // /query/explain → QUERY_USER_DENIED
    let r = app
        .clone()
        .oneshot(req(
            "POST",
            tid,
            "/query/explain",
            Some(json!({"sql": "SELECT 1"})),
            &user,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    assert!(
        String::from_utf8_lossy(&axum::body::to_bytes(r.into_body(), 65_536).await.unwrap())
            .contains("QUERY_USER_DENIED")
    );

    // /mcp → MCP_USER_DENIED
    let r = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{tid}/mcp"))
                .header(header::AUTHORIZATION, format!("Bearer {user}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","method":"tools/list","id":1}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    assert!(
        String::from_utf8_lossy(&axum::body::to_bytes(r.into_body(), 65_536).await.unwrap())
            .contains("MCP_USER_DENIED")
    );

    // SSE subscribe → SSE_USER_DENIED
    let r = app
        .oneshot(
            Request::builder()
                .uri(format!("/t/{tid}/records/notes/subscribe"))
                .header(header::AUTHORIZATION, format!("Bearer {user}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let v = read_json(r).await;
    assert_eq!(v["error_code"], "SSE_USER_DENIED");
}
