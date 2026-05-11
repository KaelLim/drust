/// Integration tests for Task 23: /admin/users CRUD + cascade delete + revoke-sessions.
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

#[tokio::test]
async fn create_list_get_user_via_service_token() {
    let (app, tid, svc, _anon, _dir) =
        helpers::spin_up_dual_role_self_register("t-au1").await;

    // Create user
    let r = app
        .clone()
        .oneshot(req(
            "POST",
            &tid,
            "/admin/users",
            Some(json!({"email": "a@b.com", "password": "longpassword"})),
            &svc,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED, "create user should return 201");
    let v = read_json(r).await;
    let uid = v["user_id"].as_str().expect("user_id in response").to_string();
    assert_eq!(v["email"].as_str().unwrap(), "a@b.com");

    // List users
    let r = app
        .clone()
        .oneshot(req("GET", &tid, "/admin/users", None, &svc))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let v = read_json(r).await;
    assert_eq!(v["total"].as_i64().unwrap(), 1);
    assert_eq!(v["users"].as_array().unwrap().len(), 1);

    // Get one user
    let r = app
        .oneshot(req("GET", &tid, &format!("/admin/users/{uid}"), None, &svc))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let v = read_json(r).await;
    assert_eq!(v["email"].as_str().unwrap(), "a@b.com");
    // password_hash must NOT be exposed
    assert!(v.get("password_hash").is_none(), "password_hash must not be in response");
}

#[tokio::test]
async fn update_user_changes_email_and_verified() {
    let (app, tid, svc, _anon, _dir) =
        helpers::spin_up_dual_role_self_register("t-au-upd").await;

    // Create
    let r = app
        .clone()
        .oneshot(req(
            "POST",
            &tid,
            "/admin/users",
            Some(json!({"email": "orig@b.com", "password": "longpassword"})),
            &svc,
        ))
        .await
        .unwrap();
    let v = read_json(r).await;
    let uid = v["user_id"].as_str().unwrap().to_string();

    // Update email + verified
    let r = app
        .clone()
        .oneshot(req(
            "PATCH",
            &tid,
            &format!("/admin/users/{uid}"),
            Some(json!({"email": "new@b.com", "verified": true})),
            &svc,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK, "PATCH should return 200");
    let v = read_json(r).await;
    assert_eq!(v["email"].as_str().unwrap(), "new@b.com");
    assert!(v["verified"].as_bool().unwrap(), "verified should be true");
}

#[tokio::test]
async fn delete_user_cascades_records() {
    let (app, tid, svc, _anon, dir) =
        helpers::spin_up_dual_role_self_register("t-au2").await;

    // Create posts collection with owner_field via pool
    let pool = helpers::grab_pool(&tid, &dir).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE posts (
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

    // Set owner-field via REST
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

    // Create user via admin endpoint
    let r = app
        .clone()
        .oneshot(req(
            "POST",
            &tid,
            "/admin/users",
            Some(json!({"email": "a@b.com", "password": "longpassword"})),
            &svc,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    let v = read_json(r).await;
    let uid = v["user_id"].as_str().unwrap().to_string();

    // Service inserts 3 posts owned by uid
    for i in 0..3 {
        let r = app
            .clone()
            .oneshot(req(
                "POST",
                &tid,
                "/records/posts",
                Some(json!({"data": {"user_id": &uid, "title": format!("t-{i}")}})),
                &svc,
            ))
            .await
            .unwrap();
        assert!(r.status().is_success(), "insert post {i} failed: {}", r.status());
    }

    // Delete user
    let r = app
        .oneshot(req(
            "DELETE",
            &tid,
            &format!("/admin/users/{uid}"),
            None,
            &svc,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let v = read_json(r).await;
    assert_eq!(
        v["deleted_records"]["posts"].as_i64().unwrap(),
        3,
        "cascade delete should report 3 deleted posts"
    );
}

#[tokio::test]
async fn admin_users_rejects_non_service() {
    let (app, tid, _svc, anon, _dir) =
        helpers::spin_up_dual_role_self_register("t-au3").await;

    let r = app
        .oneshot(req("GET", &tid, "/admin/users", None, &anon))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let bytes = axum::body::to_bytes(r.into_body(), 65_536).await.unwrap();
    assert!(
        String::from_utf8_lossy(&bytes).contains("SERVICE_ONLY"),
        "wrong error code, body: {}",
        String::from_utf8_lossy(&bytes)
    );
}

#[tokio::test]
async fn revoke_sessions_kicks_all_user_tokens() {
    let (app, tid, svc, _anon, _dir) =
        helpers::spin_up_dual_role_self_register("t-au4").await;

    // Register + login via app
    let token = helpers::register_and_login_via_app(&app, &tid, "a@b.com", "longpassword").await;

    // Get the user ID via /me
    let r = app
        .clone()
        .oneshot(req("GET", &tid, "/me", None, &token))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let v = read_json(r).await;
    let uid = v["id"].as_str().unwrap().to_string();

    // Revoke all sessions for this user
    let r = app
        .clone()
        .oneshot(req(
            "POST",
            &tid,
            &format!("/admin/users/{uid}/revoke-sessions"),
            None,
            &svc,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let v = read_json(r).await;
    assert!(v["revoked"].as_i64().unwrap() >= 1, "at least 1 session should be revoked");

    // /me now 401
    let r = app
        .oneshot(req("GET", &tid, "/me", None, &token))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "/me should now be 401");
}

#[tokio::test]
async fn create_user_duplicate_email_returns_409() {
    let (app, tid, svc, _anon, _dir) =
        helpers::spin_up_dual_role_self_register("t-au5").await;

    let create_req = || {
        req(
            "POST",
            &tid,
            "/admin/users",
            Some(json!({"email": "dup@b.com", "password": "longpassword"})),
            &svc,
        )
    };
    let r = app.clone().oneshot(create_req()).await.unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    let r = app.oneshot(create_req()).await.unwrap();
    assert_eq!(r.status(), StatusCode::CONFLICT, "duplicate email should be 409");
    let bytes = axum::body::to_bytes(r.into_body(), 65_536).await.unwrap();
    assert!(
        String::from_utf8_lossy(&bytes).contains("EMAIL_EXISTS"),
        "wrong error code: {}",
        String::from_utf8_lossy(&bytes)
    );
}

#[tokio::test]
async fn get_nonexistent_user_returns_404() {
    let (app, tid, svc, _anon, _dir) =
        helpers::spin_up_dual_role_self_register("t-au6").await;

    let r = app
        .oneshot(req(
            "GET",
            &tid,
            "/admin/users/u-00000000-0000-0000-0000-000000000000",
            None,
            &svc,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
}
