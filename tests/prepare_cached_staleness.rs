//! WS4 regression: `prepare_cached` on a `SELECT *` read MUST NOT serve a
//! stale column set after a DDL change.
//!
//! `get_handler` (single-record GET) and `list_bound_rows` (legacy list) cache
//! a `SELECT * FROM "<coll>" WHERE ...` statement on a long-lived reader
//! connection. rusqlite keys its per-connection statement cache by SQL text,
//! and that text is stable across `add_field`/`drop_field`, so a cached
//! statement's pre-step `column_names()` goes stale: after `add_field` the new
//! column is silently omitted from the response; after `drop_field` the
//! out-of-range index 500s. A DDL path only invalidates the drust schema cache
//! and SSE bus, NOT the reader's rusqlite statement cache, so these `SELECT *`
//! reads must use plain `prepare` (recompiled per call), never `prepare_cached`.
mod helpers;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;

fn req(method: &str, tid: &str, path: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(format!("/t/{tid}{path}"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

async fn read_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 65_536)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// After `add_field` adds a column, a single-record GET on the same long-lived
/// reader connection must reflect the new column — not the stale cached
/// `column_names()` from before the ALTER.
#[tokio::test]
async fn get_by_id_reflects_added_column_not_stale_cache() {
    let (app, tid, svc, _anon, dir) =
        helpers::spin_up_dual_role_self_register("t-prepcache-stale").await;
    let pool = helpers::grab_pool(&tid, &dir).await;

    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE widgets (
                 id         INTEGER PRIMARY KEY AUTOINCREMENT,
                 name       TEXT,
                 created_at TEXT DEFAULT (datetime('now')),
                 updated_at TEXT DEFAULT (datetime('now'))
             );
             INSERT INTO widgets (id, name) VALUES (1, 'gizmo');",
        )
    })
    .await
    .unwrap();

    // Warm the get_handler `prepare_cached` on a reader connection.
    let r1 = app
        .clone()
        .oneshot(req("GET", &tid, "/records/widgets/1", &svc))
        .await
        .unwrap();
    assert_eq!(r1.status(), StatusCode::OK, "warm GET should 200");
    let v1 = read_json(r1).await;
    assert!(
        v1["record"].get("name").is_some(),
        "warm GET should carry name: {v1:?}"
    );
    assert!(
        v1["record"].as_object().unwrap().get("color").is_none(),
        "color not added yet"
    );

    // ALTER on the WRITER connection — the reader pool's statement cache is NOT
    // flushed by this (only schema_cache + SSE bus are invalidated elsewhere).
    pool.with_writer(|c| c.execute("ALTER TABLE widgets ADD COLUMN color TEXT", []))
        .await
        .unwrap();

    // GET again — same reader, stale cached statement. Must still reflect the
    // new column.
    let r2 = app
        .clone()
        .oneshot(req("GET", &tid, "/records/widgets/1", &svc))
        .await
        .unwrap();
    assert_eq!(r2.status(), StatusCode::OK, "post-ALTER GET should 200");
    let v2 = read_json(r2).await;
    assert!(
        v2["record"].as_object().unwrap().contains_key("color"),
        "get-by-id must include the newly added column; a stale prepare_cached \
         statement omitted it: {v2:?}"
    );
}
