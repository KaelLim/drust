use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use drust::tenant::router::TenantRef;
use tower::ServiceExt;

mod helpers;
use helpers::spin_up_tenant;

#[tokio::test]
async fn list_collections_empty() {
    let (app, tok, _d) = spin_up_tenant("blog").await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/t/blog/collections")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["collections"], serde_json::json!([]));
    let _: TenantRef; // keep import
}

#[tokio::test]
async fn describe_after_manual_create() {
    let (app, tok, _d) = spin_up_tenant("blog").await;
    // Manually create a table on the writer conn
    let pool = helpers::grab_pool("blog", &_d).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE posts (id INTEGER PRIMARY KEY, title TEXT NOT NULL);
             INSERT INTO posts (title) VALUES ('a');",
        )
    })
    .await
    .unwrap();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/t/blog/collections/posts")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["name"], "posts");
    assert_eq!(v["row_count"], 1);
}

#[tokio::test]
async fn describe_missing_404() {
    let (app, tok, _d) = spin_up_tenant("blog").await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/t/blog/collections/ghost")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
