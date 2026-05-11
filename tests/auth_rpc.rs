/// Integration tests for Task 26: RPC user token gating + auto-bind :user_id (S4).
///
/// * User tokens may call anon_callable RPCs; denied otherwise.
/// * drust auto-binds :user_id from AuthCtx when (a) param declared, (b) caller
///   is User, (c) body did NOT supply user_id.
/// * RPC SQL is run verbatim — owner_field/read_scope do NOT apply (S4).
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

/// Create an RPC by writing directly to _system_rpc via pool writer.
/// Avoids dependence on an admin REST endpoint that may not exist.
async fn create_rpc(
    pool: &drust::storage::pool::SharedTenantPool,
    name: &str,
    sql: &str,
    params_json: &str,
    anon_callable: bool,
) {
    let name = name.to_string();
    let sql = sql.to_string();
    let params_json = params_json.to_string();
    pool.with_writer(move |c| {
        c.execute(
            "INSERT INTO _system_rpc \
             (name, sql, params_json, description, anon_callable, \
              anon_calls, service_calls, last_called_at, created_at, updated_at) \
             VALUES (?1, ?2, ?3, '', ?4, 0, 0, NULL, datetime('now'), datetime('now'))",
            rusqlite::params![name, sql, params_json, anon_callable as i64],
        )
    })
    .await
    .unwrap();
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. User CAN call an anon_callable RPC
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn user_can_call_anon_callable_rpc() {
    let (app, tid, _svc, _anon, dir) =
        helpers::spin_up_dual_role_self_register("t-rpc1").await;
    let pool = helpers::grab_pool(&tid, &dir).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE items (id INTEGER PRIMARY KEY AUTOINCREMENT, label TEXT);
             INSERT INTO items (label) VALUES ('a'), ('b');",
        )
    })
    .await
    .unwrap();
    create_rpc(&pool, "list_items", "SELECT * FROM items", "[]", true).await;

    let utok =
        helpers::register_and_login_via_app(&app, &tid, "u@x.com", "longpassword").await;
    let r = app
        .oneshot(req("POST", &tid, "/rpc/list_items", Some(json!({})), &utok))
        .await
        .unwrap();
    let status = r.status();
    let v = read_json(r).await;
    assert!(
        status.is_success(),
        "user must be able to call anon_callable RPC: {} {:?}",
        status, v
    );
    let rows = v["rows"].as_array().expect("rows array");
    assert_eq!(rows.len(), 2);
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. User CANNOT call a non-anon_callable RPC
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn user_cannot_call_non_anon_rpc() {
    let (app, tid, _svc, _anon, dir) =
        helpers::spin_up_dual_role_self_register("t-rpc2").await;
    let pool = helpers::grab_pool(&tid, &dir).await;
    pool.with_writer(|c| {
        c.execute_batch("CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT);")
    })
    .await
    .unwrap();
    create_rpc(&pool, "private_list", "SELECT * FROM items", "[]", false).await;

    let utok =
        helpers::register_and_login_via_app(&app, &tid, "u@x.com", "longpassword").await;
    let r = app
        .oneshot(req(
            "POST",
            &tid,
            "/rpc/private_list",
            Some(json!({})),
            &utok,
        ))
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::FORBIDDEN,
        "user must be denied on non-anon_callable RPC"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. RPC does NOT apply owner_field filter (S4)
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn rpc_does_not_apply_owner_field_filter() {
    // RPC SQL is run verbatim; drust does NOT inject a WHERE owner_field=user_id.
    let (app, tid, svc, _anon, dir) =
        helpers::spin_up_dual_role_self_register("t-rpc3").await;
    let pool = helpers::grab_pool(&tid, &dir).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT REFERENCES _system_users(id),
                title TEXT,
                created_at TEXT DEFAULT (datetime('now')),
                updated_at TEXT DEFAULT (datetime('now'))
            );",
        )
    })
    .await
    .unwrap();

    // Set owner-field on the collection (read_scope = own).
    let _ = app
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

    let ta =
        helpers::register_and_login_via_app(&app, &tid, "a@x.com", "longpassword").await;
    let tb =
        helpers::register_and_login_via_app(&app, &tid, "b@x.com", "longpassword").await;

    // Each user inserts one post (auto-sets user_id via owner_field logic).
    let _ = app
        .clone()
        .oneshot(req(
            "POST",
            &tid,
            "/records/posts",
            Some(json!({"data": {"title": "a"}})),
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
            Some(json!({"data": {"title": "b"}})),
            &tb,
        ))
        .await
        .unwrap();

    // RPC returns ALL posts, regardless of who calls it.
    create_rpc(&pool, "all_posts", "SELECT title FROM posts", "[]", true).await;
    let r = app
        .oneshot(req(
            "POST",
            &tid,
            "/rpc/all_posts",
            Some(json!({})),
            &ta,
        ))
        .await
        .unwrap();
    let status = r.status();
    let v = read_json(r).await;
    assert!(status.is_success(), "got {}: {:?}", status, v);
    let rows = v["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 2, "RPC must NOT apply owner_field filter (S4)");
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. :user_id is auto-bound from AuthCtx when declared and not supplied
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn rpc_auto_binds_user_id_param() {
    let (app, tid, svc, _anon, dir) =
        helpers::spin_up_dual_role_self_register("t-rpc4").await;
    let pool = helpers::grab_pool(&tid, &dir).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT REFERENCES _system_users(id),
                title TEXT,
                created_at TEXT DEFAULT (datetime('now')),
                updated_at TEXT DEFAULT (datetime('now'))
            );",
        )
    })
    .await
    .unwrap();

    // Set owner-field so INSERT auto-sets user_id.
    let _ = app
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

    let ta =
        helpers::register_and_login_via_app(&app, &tid, "a@x.com", "longpassword").await;
    let tb =
        helpers::register_and_login_via_app(&app, &tid, "b@x.com", "longpassword").await;

    let _ = app
        .clone()
        .oneshot(req(
            "POST",
            &tid,
            "/records/posts",
            Some(json!({"data": {"title": "a"}})),
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
            Some(json!({"data": {"title": "b"}})),
            &tb,
        ))
        .await
        .unwrap();

    // RPC declares :user_id param; drust auto-binds from caller's AuthCtx.
    create_rpc(
        &pool,
        "my_posts",
        "SELECT title FROM posts WHERE user_id = :user_id",
        r#"[{"name":"user_id","type":"text"}]"#,
        true,
    )
    .await;

    let r = app
        .oneshot(req(
            "POST",
            &tid,
            "/rpc/my_posts",
            Some(json!({})), // user does NOT supply user_id manually
            &ta,
        ))
        .await
        .unwrap();
    let status = r.status();
    let v = read_json(r).await;
    assert!(status.is_success(), "got {}: {:?}", status, v);
    let rows = v["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 1, "auto-bind must filter to caller's own posts");
    // rows[0] is an array of column values (column_names: ["title"])
    let title = rows[0][0].as_str().unwrap_or_else(|| {
        rows[0]["title"].as_str().unwrap_or("")
    });
    assert_eq!(title, "a");
}
