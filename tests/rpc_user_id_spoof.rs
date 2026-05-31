/// v1.32 A1 regression tests — RPC :user_id spoof close.
///
/// A User token MUST NOT be able to override :user_id by supplying it in the
/// request body. drust must always overwrite :user_id from the bearer-bound
/// identity, ignoring any caller-supplied value.
///
/// An Anon token has NO bearer-bound user_id. When the RPC declares :user_id,
/// Anon callers MUST be rejected categorically — even if they supply user_id
/// in the body. This closes the residual hole where Anon could spoof any
/// user_id by simply including it in the request body.
///
/// Four tests:
///   1. Read-mode RPC: Alice sends {"user_id": bob_id} — must get back Alice's rows.
///   2. Write-mode RPC: Alice sends {"user_id": bob_id} — inserted row must carry alice_id.
///   3. Read-mode RPC: Anon sends {"user_id": any_id} — must get 403, no rows returned.
///   4. Write-mode RPC: Anon sends {"user_id": any_id} — must get 403, no row inserted.
mod helpers;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
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

/// Create a read-mode RPC.
async fn create_read_rpc(
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

/// Create a write-mode RPC.
async fn create_write_rpc(
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
             (name, sql, params_json, description, anon_callable, mode, \
              anon_calls, service_calls, last_called_at, created_at, updated_at) \
             VALUES (?1, ?2, ?3, '', ?4, 'write', 0, 0, NULL, \
                     datetime('now'), datetime('now'))",
            rusqlite::params![name, sql, params_json, anon_callable as i64],
        )
    })
    .await
    .unwrap();
}

/// Call GET /me with a user token and return the user's id.
async fn get_my_user_id(app: &axum::Router, tid: &str, token: &str) -> String {
    let r = app
        .clone()
        .oneshot(req("GET", tid, "/me", None, token))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK, "GET /me must succeed");
    let v = read_json(r).await;
    v["id"]
        .as_str()
        .expect("/me response must have id field")
        .to_string()
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 1: Read-mode RPC — user token cannot spoof user_id
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn user_token_cannot_spoof_user_id_via_body_read_rpc() {
    let (app, tid, svc, _anon, dir) =
        helpers::spin_up_dual_role_self_register("t-spoof-read").await;
    let pool = helpers::grab_pool(&tid, &dir).await;

    // Set up posts table with user_id column.
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                title TEXT NOT NULL
            );",
        )
    })
    .await
    .unwrap();

    // Register Alice and Bob; resolve their bearer-bound user IDs via /me.
    let alice_tok =
        helpers::register_and_login_via_app(&app, &tid, "alice@x.com", "longpassword").await;
    let bob_tok =
        helpers::register_and_login_via_app(&app, &tid, "bob@x.com", "longpassword").await;

    let alice_id = get_my_user_id(&app, &tid, &alice_tok).await;
    let bob_id = get_my_user_id(&app, &tid, &bob_tok).await;

    // Seed rows directly so we control user_id without depending on owner-field.
    // Alice has one post; Bob has one post.
    let a_id = alice_id.clone();
    let b_id = bob_id.clone();
    pool.with_writer(move |c| {
        c.execute(
            "INSERT INTO posts (user_id, title) VALUES (?1, 'alice-post')",
            rusqlite::params![a_id],
        )
    })
    .await
    .unwrap();
    pool.with_writer(move |c| {
        c.execute(
            "INSERT INTO posts (user_id, title) VALUES (?1, 'bob-post')",
            rusqlite::params![b_id],
        )
    })
    .await
    .unwrap();
    let _ = svc; // not needed further

    // Create a read RPC that returns all posts matching :user_id.
    create_read_rpc(
        &pool,
        "my_rows",
        "SELECT id, user_id, title FROM posts WHERE user_id = :user_id",
        r#"[{"name":"user_id","type":"text"}]"#,
        true,
    )
    .await;

    // Alice calls my_rows with body {"user_id": bob_id} — trying to spoof.
    // v1.32 A1: drust must OVERWRITE user_id with alice's bearer-bound id.
    // All returned rows must have user_id = alice_id, NOT bob_id.
    let r = app
        .oneshot(req(
            "POST",
            &tid,
            "/rpc/my_rows",
            Some(json!({"user_id": bob_id})),
            &alice_tok,
        ))
        .await
        .unwrap();
    let status = r.status();
    let v = read_json(r).await;
    assert!(status.is_success(), "RPC call failed: {} {:?}", status, v);

    let rows = v["rows"].as_array().expect("must have rows array");
    // Must get exactly Alice's row.
    assert_eq!(
        rows.len(),
        1,
        "Expected exactly 1 row (Alice's), got {}: {:?}",
        rows.len(),
        v
    );

    // column_names: ["id", "user_id", "title"] — user_id is index 1.
    let col_names = v["column_names"].as_array().expect("column_names array");
    let uid_idx = col_names
        .iter()
        .position(|c| c.as_str() == Some("user_id"))
        .expect("user_id column must be present");

    let row_user_id = rows[0][uid_idx].as_str().expect("user_id value");
    assert_eq!(
        row_user_id, alice_id,
        "SPOOF DETECTED: row user_id={row_user_id} but expected alice_id={alice_id}. \
         Caller supplied bob_id={bob_id} in body but bearer must win."
    );
    assert_ne!(
        row_user_id, bob_id,
        "Returned Bob's row — user_id spoof succeeded (should be impossible)"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 2: Write-mode RPC — user token cannot spoof user_id
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn user_token_cannot_spoof_user_id_via_body_write_rpc() {
    let (app, tid, svc, _anon, dir) =
        helpers::spin_up_dual_role_self_register("t-spoof-write").await;
    let pool = helpers::grab_pool(&tid, &dir).await;

    // Set up posts table with user_id column.
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                title TEXT NOT NULL
            );",
        )
    })
    .await
    .unwrap();

    // Register Alice and Bob.
    let alice_tok =
        helpers::register_and_login_via_app(&app, &tid, "alice@x.com", "longpassword").await;
    let bob_tok =
        helpers::register_and_login_via_app(&app, &tid, "bob@x.com", "longpassword").await;
    let _ = svc; // not needed for this test

    let alice_id = get_my_user_id(&app, &tid, &alice_tok).await;
    let bob_id = get_my_user_id(&app, &tid, &bob_tok).await;

    // Create a write RPC that inserts a post with :user_id and :title.
    create_write_rpc(
        &pool,
        "insert_post",
        "INSERT INTO posts (user_id, title) VALUES (:user_id, :title)",
        r#"[{"name":"user_id","type":"text"},{"name":"title","type":"text"}]"#,
        true,
    )
    .await;

    // Alice calls insert_post with body {"user_id": bob_id, "title": "spoof"}.
    // v1.32 A1: drust must OVERWRITE user_id with alice's bearer-bound id.
    let r = app
        .clone()
        .oneshot(req(
            "POST",
            &tid,
            "/rpc/insert_post",
            Some(json!({"user_id": bob_id, "title": "spoof-attempt"})),
            &alice_tok,
        ))
        .await
        .unwrap();
    let status = r.status();
    let v = read_json(r).await;
    assert!(status.is_success(), "insert_post RPC failed: {} {:?}", status, v);
    assert_eq!(
        v["affected_rows"].as_i64(),
        Some(1),
        "expected 1 affected row: {:?}",
        v
    );

    // Read the inserted row from the DB directly and confirm user_id = alice_id.
    let (stored_user_id, stored_title): (String, String) = pool
        .with_reader(|c| {
            c.query_row(
                "SELECT user_id, title FROM posts WHERE title = 'spoof-attempt'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
        })
        .await
        .unwrap();

    assert_eq!(
        stored_user_id, alice_id,
        "SPOOF DETECTED: inserted user_id={stored_user_id} but expected alice_id={alice_id}. \
         Caller supplied bob_id={bob_id} in body but bearer must win."
    );
    assert_ne!(
        stored_user_id, bob_id,
        "Inserted row has Bob's id — user_id spoof on write succeeded (should be impossible)"
    );
    assert_eq!(stored_title, "spoof-attempt");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 3: Read-mode RPC — anon token cannot spoof user_id via body
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn anon_token_cannot_spoof_user_id_via_body_read_rpc() {
    let (app, tid, _svc, anon_tok, dir) =
        helpers::spin_up_dual_role_self_register("t-anon-spoof-read").await;
    let pool = helpers::grab_pool(&tid, &dir).await;

    // Set up posts table with user_id column.
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                title TEXT NOT NULL
            );",
        )
    })
    .await
    .unwrap();

    // Seed a row with a known user_id directly so Anon has something to
    // attempt to retrieve.
    let victim_id = "00000000-dead-beef-dead-000000000001".to_string();
    let v = victim_id.clone();
    pool.with_writer(move |c| {
        c.execute(
            "INSERT INTO posts (user_id, title) VALUES (?1, 'victim-post')",
            rusqlite::params![v],
        )
    })
    .await
    .unwrap();

    // Create an anon_callable read RPC that filters by :user_id.
    create_read_rpc(
        &pool,
        "anon_my_rows",
        "SELECT id, user_id, title FROM posts WHERE user_id = :user_id",
        r#"[{"name":"user_id","type":"text"}]"#,
        true, // anon_callable = true so Anon can even attempt the call
    )
    .await;

    // Anon token tries to call the RPC with body {"user_id": victim_id}.
    // v1.32 A1 residual fix: Anon has no bearer-bound user_id — must be
    // rejected with 403 USER_ID_BINDING_REQUIRED, not served with rows.
    let r = app
        .oneshot(req(
            "POST",
            &tid,
            "/rpc/anon_my_rows",
            Some(json!({"user_id": victim_id})),
            &anon_tok,
        ))
        .await
        .unwrap();
    let status = r.status();
    let v = read_json(r).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "Anon should be rejected with 403 when RPC declares :user_id, got {} {:?}",
        status,
        v
    );
    assert_eq!(
        v["error_code"].as_str(),
        Some("USER_ID_BINDING_REQUIRED"),
        "Expected USER_ID_BINDING_REQUIRED error_code, got: {:?}",
        v
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 4: Write-mode RPC — anon token cannot spoof user_id via body
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn anon_token_cannot_spoof_user_id_via_body_write_rpc() {
    let (app, tid, _svc, anon_tok, dir) =
        helpers::spin_up_dual_role_self_register("t-anon-spoof-write").await;
    let pool = helpers::grab_pool(&tid, &dir).await;

    // Set up posts table with user_id column.
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                title TEXT NOT NULL
            );",
        )
    })
    .await
    .unwrap();

    let spoofed_id = "00000000-dead-beef-dead-000000000002".to_string();

    // Create an anon_callable write RPC that inserts with :user_id.
    create_write_rpc(
        &pool,
        "anon_insert_post",
        "INSERT INTO posts (user_id, title) VALUES (:user_id, :title)",
        r#"[{"name":"user_id","type":"text"},{"name":"title","type":"text"}]"#,
        true, // anon_callable = true so Anon can even attempt the call
    )
    .await;

    // Anon token tries to call the write RPC with body {"user_id": spoofed_id}.
    // v1.32 A1 residual fix: Anon has no bearer-bound user_id — must be
    // rejected with 403 USER_ID_BINDING_REQUIRED before any mutation.
    let r = app
        .clone()
        .oneshot(req(
            "POST",
            &tid,
            "/rpc/anon_insert_post",
            Some(json!({"user_id": spoofed_id, "title": "anon-spoof-attempt"})),
            &anon_tok,
        ))
        .await
        .unwrap();
    let status = r.status();
    let v = read_json(r).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "Anon should be rejected with 403 when RPC declares :user_id, got {} {:?}",
        status,
        v
    );
    assert_eq!(
        v["error_code"].as_str(),
        Some("USER_ID_BINDING_REQUIRED"),
        "Expected USER_ID_BINDING_REQUIRED error_code, got: {:?}",
        v
    );

    // Verify no row was inserted.
    let count: i64 = pool
        .with_reader(|c| {
            c.query_row(
                "SELECT COUNT(*) FROM posts WHERE title = 'anon-spoof-attempt'",
                [],
                |row| row.get(0),
            )
        })
        .await
        .unwrap();
    assert_eq!(
        count, 0,
        "A row was inserted despite 403 rejection — Anon user_id spoof on write succeeded"
    );
}
