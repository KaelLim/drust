//! Regression (sibling of the get_handler H1 fix): the stored-RPC / named-exec
//! read path must NOT serve a stale column set after a DDL change. A read RPC
//! whose body is `SELECT *` caches its statement on a long-lived reader
//! connection and reads `column_names()` before stepping, so a column added
//! afterward must appear in the RPC result — not be silently dropped by a stale
//! cached `column_names()`. (DDL flushes only the drust schema cache + SSE bus,
//! never rusqlite's per-connection statement cache, so this path must use plain
//! `prepare`, like the non-named query variant.)
mod helpers;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use serde_json::json;
use tower::ServiceExt;

fn req(tid: &str, path: &str, body: serde_json::Value, token: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!("/t/{tid}{path}"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn read_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 65_536)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

async fn create_rpc(pool: &drust::storage::pool::SharedTenantPool, name: &str, sql: &str) {
    let name = name.to_string();
    let sql = sql.to_string();
    pool.with_writer(move |c| {
        c.execute(
            "INSERT INTO _system_rpc \
             (name, sql, params_json, description, anon_callable, \
              anon_calls, service_calls, last_called_at, created_at, updated_at) \
             VALUES (?1, ?2, '[]', '', 0, 0, 0, NULL, datetime('now'), datetime('now'))",
            rusqlite::params![name, sql],
        )
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn rpc_select_star_reflects_added_column_not_stale_cache() {
    let (app, tid, svc, _anon, dir) = helpers::spin_up_dual_role_self_register("t-rpc-stale").await;
    let pool = helpers::grab_pool(&tid, &dir).await;

    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE widgets (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT);
             INSERT INTO widgets (id, name) VALUES (1, 'gizmo');",
        )
    })
    .await
    .unwrap();
    create_rpc(&pool, "list_widgets", "SELECT * FROM widgets").await;

    // Warm the named-exec prepare_cached on a reader connection.
    let r1 = app
        .clone()
        .oneshot(req(&tid, "/rpc/list_widgets", json!({}), &svc))
        .await
        .unwrap();
    assert_eq!(r1.status(), StatusCode::OK, "warm RPC call should 200");
    let v1 = read_json(r1).await;
    let cols1: Vec<String> = v1["column_names"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap().to_string())
        .collect();
    assert!(cols1.contains(&"name".to_string()) && !cols1.contains(&"color".to_string()));

    // ALTER on the writer connection — reader statement cache is NOT flushed.
    pool.with_writer(|c| c.execute("ALTER TABLE widgets ADD COLUMN color TEXT", []))
        .await
        .unwrap();

    // Call again — must reflect the new column.
    let r2 = app
        .clone()
        .oneshot(req(&tid, "/rpc/list_widgets", json!({}), &svc))
        .await
        .unwrap();
    assert_eq!(
        r2.status(),
        StatusCode::OK,
        "post-ALTER RPC call should 200"
    );
    let v2 = read_json(r2).await;
    let cols2: Vec<String> = v2["column_names"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap().to_string())
        .collect();
    assert!(
        cols2.contains(&"color".to_string()),
        "stored-RPC SELECT * must reflect the newly added column; a stale \
         prepare_cached statement omitted it: {cols2:?}"
    );
}
