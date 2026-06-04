use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use serde_json::json;
use tower::ServiceExt;

mod helpers;

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

async fn read_body(resp: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Create a `posts` table with `user_id TEXT REFERENCES _system_users(id)` via
/// the pool writer (there is no REST POST /collections endpoint).
async fn make_posts_with_user_fk(dir: &tempfile::TempDir, tenant_name: &str) {
    let pool = helpers::grab_pool(tenant_name, dir).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE IF NOT EXISTS posts (
                 id         INTEGER PRIMARY KEY AUTOINCREMENT,
                 user_id    TEXT REFERENCES _system_users(id) ON DELETE RESTRICT,
                 title      TEXT
             );",
        )
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn set_owner_field_happy() {
    let (app, tok, dir) = helpers::spin_up_tenant_with_role("t-of1", "service").await;
    make_posts_with_user_fk(&dir, "t-of1").await;
    let r = app
        .oneshot(req(
            "POST",
            "t-of1",
            "/collections/posts/owner-field",
            Some(json!({"field": "user_id", "read_scope": "own"})),
            &tok,
        ))
        .await
        .unwrap();
    let status = r.status();
    let body = read_body(r).await;
    assert_eq!(status, StatusCode::OK, "body={body}");
}

#[tokio::test]
async fn set_owner_field_unknown_column_returns_409() {
    let (app, tok, dir) = helpers::spin_up_tenant_with_role("t-of2", "service").await;
    make_posts_with_user_fk(&dir, "t-of2").await;
    let r = app
        .oneshot(req(
            "POST",
            "t-of2",
            "/collections/posts/owner-field",
            Some(json!({"field": "ghost_col", "read_scope": "own"})),
            &tok,
        ))
        .await
        .unwrap();
    let status = r.status();
    let body = read_body(r).await;
    assert_eq!(status, StatusCode::CONFLICT, "body={body}");
    assert!(body.contains("OWNER_FIELD_INVALID_COLUMN"), "body={body}");
}

#[tokio::test]
async fn set_owner_field_non_fk_returns_409() {
    let (app, tok, dir) = helpers::spin_up_tenant_with_role("t-of3", "service").await;
    // Create a notes table with an `owner` column that is NOT a FK.
    let pool = helpers::grab_pool("t-of3", &dir).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE IF NOT EXISTS notes (
                 id    INTEGER PRIMARY KEY AUTOINCREMENT,
                 owner TEXT
             );",
        )
    })
    .await
    .unwrap();
    let r = app
        .oneshot(req(
            "POST",
            "t-of3",
            "/collections/notes/owner-field",
            Some(json!({"field": "owner", "read_scope": "own"})),
            &tok,
        ))
        .await
        .unwrap();
    let status = r.status();
    let body = read_body(r).await;
    assert_eq!(status, StatusCode::CONFLICT, "body={body}");
    assert!(body.contains("OWNER_FIELD_NOT_FK"), "body={body}");
}

#[tokio::test]
async fn set_owner_field_rejects_anon_token() {
    let (app, tok, _dir) = helpers::spin_up_tenant_with_role("t-of4", "anon").await;
    // The handler checks role before touching the collection, so 403
    // fires even when the collection doesn't exist.
    let r = app
        .oneshot(req(
            "POST",
            "t-of4",
            "/collections/posts/owner-field",
            Some(json!({"field": "user_id", "read_scope": "own"})),
            &tok,
        ))
        .await
        .unwrap();
    let status = r.status();
    let body = read_body(r).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body={body}");
    assert!(body.contains("SERVICE_ONLY"), "body={body}");
}

#[tokio::test]
async fn set_owner_field_invalid_read_scope_returns_422() {
    let (app, tok, dir) = helpers::spin_up_tenant_with_role("t-of5", "service").await;
    make_posts_with_user_fk(&dir, "t-of5").await;
    let r = app
        .oneshot(req(
            "POST",
            "t-of5",
            "/collections/posts/owner-field",
            Some(json!({"field": "user_id", "read_scope": "weird"})),
            &tok,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn clear_owner_field_via_delete() {
    let (app, tok, dir) = helpers::spin_up_tenant_with_role("t-of6", "service").await;
    make_posts_with_user_fk(&dir, "t-of6").await;
    // Set first
    let _ = app
        .clone()
        .oneshot(req(
            "POST",
            "t-of6",
            "/collections/posts/owner-field",
            Some(json!({"field": "user_id", "read_scope": "own"})),
            &tok,
        ))
        .await
        .unwrap();
    // Clear via DELETE
    let r = app
        .oneshot(req(
            "DELETE",
            "t-of6",
            "/collections/posts/owner-field",
            None,
            &tok,
        ))
        .await
        .unwrap();
    let status = r.status();
    let body = read_body(r).await;
    assert_eq!(status, StatusCode::OK, "body={body}");
}
