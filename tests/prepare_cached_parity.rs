//! WS4 (prepare_cached on hot reads) parity oracle.
//!
//! These results MUST be identical before/after switching the list/count/get
//! reads from `conn.prepare` to `conn.prepare_cached`, and after converting the
//! owner clause on `get_handler` from an inlined LITERAL to a `?`-bind. The
//! owner-scoped single-record GET must STILL 404 a foreign row — that proves the
//! owner clause moved to a bind without weakening enforcement.
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

/// Owner-scoped `posts` table with `read_scope="own"`, self-register on, two
/// registered users (alice = ta, bob = tb). Returns `(app, tid, dir, svc, ta, tb)`.
async fn setup(
    tname: &str,
) -> (
    axum::Router,
    String,
    tempfile::TempDir,
    String,
    String,
    String,
) {
    let (app, tid, svc, _anon, dir) = helpers::spin_up_dual_role_self_register(tname).await;

    let pool = helpers::grab_pool(&tid, &dir).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE posts (
                 id         INTEGER PRIMARY KEY AUTOINCREMENT,
                 user_id    TEXT REFERENCES _system_users(id) ON DELETE RESTRICT,
                 label      TEXT,
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
            Some(json!({"field": "user_id", "read_scope": "own"})),
            &svc,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK, "set owner-field failed");

    let ta = helpers::register_and_login_via_app(&app, &tid, "a@x.com", "longpassword").await;
    let tb = helpers::register_and_login_via_app(&app, &tid, "b@x.com", "longpassword").await;

    (app, tid, dir, svc, ta, tb)
}

#[tokio::test]
async fn list_and_owner_get_unchanged_after_prepare_cached() {
    let (app, tid, _dir, _svc, ta, tb) = setup("t-prepcache").await;

    // Alice creates a record (owner = alice via auto-fill).
    let r = app
        .clone()
        .oneshot(req(
            "POST",
            &tid,
            "/records/posts",
            Some(json!({"data": {"label": "x"}})),
            &ta,
        ))
        .await
        .unwrap();
    assert!(
        r.status().is_success(),
        "alice insert failed: {}",
        r.status()
    );
    let id = read_json(r).await["id"].as_i64().unwrap();

    // Owner-scoped single-record GET: alice reads her row (200), bob 404s it.
    // The 404 proves the owner clause is still enforced after the literal→bind
    // conversion + prepare_cached.
    let ra = app
        .clone()
        .oneshot(req("GET", &tid, &format!("/records/posts/{id}"), None, &ta))
        .await
        .unwrap();
    assert_eq!(ra.status(), StatusCode::OK, "alice must read her own row");

    let rb = app
        .clone()
        .oneshot(req("GET", &tid, &format!("/records/posts/{id}"), None, &tb))
        .await
        .unwrap();
    assert_eq!(
        rb.status(),
        StatusCode::NOT_FOUND,
        "bob must 404 a foreign owner-scoped row"
    );

    // POST /list: alice sees the row (total 1), bob sees none (total 0).
    let list = |tok: String| {
        let app = app.clone();
        let tid = tid.clone();
        async move {
            let resp = app
                .oneshot(req(
                    "POST",
                    &tid,
                    "/collections/posts/list",
                    Some(json!({})),
                    &tok,
                ))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            read_json(resp).await
        }
    };
    let va = list(ta).await;
    assert_eq!(va["total"], 1, "alice /list must see her row: {va:?}");
    let vb = list(tb).await;
    assert_eq!(vb["total"], 0, "bob /list must see nothing: {vb:?}");
}
