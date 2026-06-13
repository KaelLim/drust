//! RLS Phase 9 (Goldens) — Task 21.
//!
//! Two safety nets that must hold for the whole RLS feature:
//!
//! 1. **owner_field is byte-identical to pre-RLS when NO explicit policy is
//!    set.** Adding the policy machinery must not perturb the existing
//!    `owner_field` / `read_scope` behaviour: a user only sees / mutates their
//!    own rows (foreign rows → 404, no enumeration leak), and anon is loudly
//!    `403`ed on an own-scoped collection (the pre-existing cap-gate), never
//!    silently empty-filtered.
//!
//! 2. **Security: an explicit `select` policy cannot be bypassed via the raw
//!    `/query` surface.** drust cannot row-filter un-rewritable SQL, so once a
//!    collection carries a policy the anon `/query` caller is DENIED (`403`),
//!    not silently filtered — while the structured `/list` path (drust builds
//!    the SQL with `?` binds) returns exactly the policy-passing rows.
//!
//! Real boilerplate (per the plan's Test Harness appendix): the axum `Router`
//! is driven via `oneshot` with bare `/t/<id>/…` paths (Caddy bypassed). The
//! `select` policy in golden 2 is set through the **service** REST surface
//! `PUT /t/<id>/collections/<c>/policies` (Task 17), which invalidates the
//! running app's `schema_cache` for us.

#[path = "helpers.rs"]
mod helpers;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use helpers::{grab_pool, register_and_login_via_app, spin_up_dual_role_self_register};
use serde_json::{Value, json};
use tower::ServiceExt;

// ── Drivers ───────────────────────────────────────────────────────────

fn req(method: &str, tid: &str, path: &str, body: Option<Value>, tok: &str) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(format!("/t/{tid}{path}"))
        .header(header::AUTHORIZATION, format!("Bearer {tok}"));
    if body.is_some() {
        b = b.header(header::CONTENT_TYPE, "application/json");
    }
    b.body(
        body.map(|v| Body::from(v.to_string()))
            .unwrap_or(Body::empty()),
    )
    .unwrap()
}

async fn status(app: &axum::Router, r: Request<Body>) -> u16 {
    app.clone().oneshot(r).await.unwrap().status().as_u16()
}

/// `POST /records/<coll>` (service or user) → the new row's `id`.
async fn insert_returning_id(
    app: &axum::Router,
    tid: &str,
    tok: &str,
    coll: &str,
    data: Value,
) -> i64 {
    let resp = app
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
    assert_eq!(resp.status(), StatusCode::CREATED, "insert into {coll} failed");
    let bytes = axum::body::to_bytes(resp.into_body(), 65_536).await.unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    v["id"].as_i64().expect("create body has numeric id")
}

/// `POST /collections/<coll>/list` → the `records` array (asserts 200).
async fn list_records(app: &axum::Router, tid: &str, tok: &str, coll: &str) -> Vec<Value> {
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            tid,
            &format!("/collections/{coll}/list"),
            Some(json!({})),
            tok,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "list {coll} non-OK");
    let bytes = axum::body::to_bytes(resp.into_body(), 65_536).await.unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    v["records"].as_array().cloned().unwrap_or_default()
}

/// `POST /query` → just the HTTP status.
async fn query_status(app: &axum::Router, tid: &str, tok: &str, sql: &str) -> u16 {
    status(
        app,
        req("POST", tid, "/query", Some(json!({ "sql": sql })), tok),
    )
    .await
}

// ── Golden 1: owner_field behaviour is byte-identical to pre-RLS ───────

#[tokio::test]
async fn owner_field_unchanged_when_no_policy() {
    let (app, tid, svc, anon, dir) =
        spin_up_dual_role_self_register("t-rls-bc-owner").await;

    // `notes(body TEXT, owner_id TEXT REFERENCES _system_users(id))`. No
    // explicit policy is ever set — only owner_field — so this exercises the
    // unchanged owner clause in isolation.
    let pool = grab_pool(&tid, &dir).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE notes (
                 id         INTEGER PRIMARY KEY AUTOINCREMENT,
                 owner_id   TEXT REFERENCES _system_users(id) ON DELETE RESTRICT,
                 body       TEXT,
                 created_at TEXT NOT NULL DEFAULT (datetime('now')),
                 updated_at TEXT NOT NULL DEFAULT (datetime('now'))
             );",
        )
    })
    .await
    .unwrap();
    drop(pool);

    // owner_field via the service REST route (invalidates the running cache).
    assert_eq!(
        status(
            &app,
            req(
                "POST",
                &tid,
                "/collections/notes/owner-field",
                Some(json!({"field": "owner_id", "read_scope": "own"})),
                &svc,
            ),
        )
        .await,
        200,
        "set owner-field failed",
    );

    // Two users; A inserts (owner stamped), B must not see / touch A's row.
    let a = register_and_login_via_app(&app, &tid, "a@b.com", "longpassword").await;
    let b = register_and_login_via_app(&app, &tid, "c@d.com", "longpassword").await;

    let id = insert_returning_id(&app, &tid, &a, "notes", json!({"body": "x"})).await;

    // User B: foreign-row GET / UPDATE → 404 (own-scope filter, no leak).
    assert_eq!(
        status(&app, req("GET", &tid, &format!("/records/notes/{id}"), None, &b)).await,
        404,
        "user B must not see A's row",
    );
    assert_eq!(
        status(
            &app,
            req(
                "PATCH",
                &tid,
                &format!("/records/notes/{id}"),
                Some(json!({"data": {"body": "y"}})),
                &b,
            ),
        )
        .await,
        404,
        "user B must not update A's row",
    );

    // Anon read of an own-scoped collection is a loud 403 (pre-existing
    // cap-gate), NOT a silent empty filter.
    assert_eq!(
        status(&app, req("GET", &tid, &format!("/records/notes/{id}"), None, &anon)).await,
        403,
        "anon GET-one on own-scoped must be 403",
    );
    // Anon `/records` list on own-scoped is likewise 403.
    assert_eq!(
        status(&app, req("GET", &tid, "/records/notes", None, &anon)).await,
        403,
        "anon list on own-scoped must be 403",
    );
}

// ── Golden 2: an explicit select policy cannot be bypassed via /query ──

#[tokio::test]
async fn anon_cannot_bypass_via_query() {
    let (app, tid, svc, anon, dir) =
        spin_up_dual_role_self_register("t-rls-bc-query").await;

    // `posts(status TEXT)` with the default `[select]` anon cap. Created via
    // the pool; the running app loads its schema fresh on first touch.
    let pool = grab_pool(&tid, &dir).await;
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
                  VALUES ('posts', '[\"select\"]')
                  ON CONFLICT(collection_name) DO UPDATE SET
                    anon_caps_json = '[\"select\"]';",
        )
    })
    .await
    .unwrap();
    drop(pool);

    // Service inserts a non-published ("secret") row.
    insert_returning_id(&app, &tid, &svc, "posts", json!({"status": "secret"})).await;

    // Set the select policy through the service REST surface (Task 17), which
    // invalidates the running app's schema_cache for `posts`.
    assert_eq!(
        status(
            &app,
            req(
                "PUT",
                &tid,
                "/collections/posts/policies",
                Some(json!({"select": {"using": {"status": "published"}}})),
                &svc,
            ),
        )
        .await,
        200,
        "PUT select policy failed",
    );

    // Anon `/query` is DENIED (403) — not silently filtered — because drust
    // cannot row-rewrite raw SQL on a policy-protected collection.
    assert_eq!(
        query_status(&app, &tid, &anon, "SELECT * FROM posts").await,
        403,
        "anon /query on a policy-protected collection must be denied, not filtered",
    );

    // The structured `/list` path enforces the policy: anon sees no
    // non-published rows.
    let listed = list_records(&app, &tid, &anon, "posts").await;
    assert!(
        listed.is_empty(),
        "anon must see no non-published rows via /list, got: {listed:?}",
    );

    // Service bypasses the policy entirely → still sees the secret row.
    let svc_rows = list_records(&app, &tid, &svc, "posts").await;
    assert_eq!(svc_rows.len(), 1, "service bypasses the select policy");
}
