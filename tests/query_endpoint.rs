mod helpers;
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use helpers::{grab_pool, spin_up_tenant};
use tower::ServiceExt;

async fn seed(dir: &tempfile::TempDir) {
    let pool = grab_pool("blog", dir).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE posts (id INTEGER PRIMARY KEY, title TEXT, views INTEGER);
             INSERT INTO posts VALUES (1,'a',10),(2,'b',20),(3,'c',30);",
        )
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn ok_path() {
    let (app, tok, d) = spin_up_tenant("blog").await;
    seed(&d).await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/t/blog/query")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"sql":"SELECT id FROM posts ORDER BY id"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let b = axum::body::to_bytes(resp.into_body(), 65_536).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(v["rows"].as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn forbidden() {
    let (app, tok, d) = spin_up_tenant("blog").await;
    seed(&d).await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/t/blog/query")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"sql":"DROP TABLE posts"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn sql_too_big() {
    let (app, tok, _d) = spin_up_tenant("blog").await;
    let big = "SELECT 1 /* ".to_string() + &"x".repeat(17_000) + " */";
    let body = format!(r#"{{"sql":{}}}"#, serde_json::to_string(&big).unwrap());
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/t/blog/query")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}
