mod helpers;
use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use helpers::{grab_pool, spin_up_tenant};
use tower::ServiceExt;

async fn seed_posts(dir: &tempfile::TempDir) {
    let pool = grab_pool("blog", dir).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                views INTEGER DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );",
        )
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn create_then_list() {
    let (app, tok, d) = spin_up_tenant("blog").await;
    seed_posts(&d).await;
    // Create
    let r = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/t/blog/records/posts")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"data":{"title":"hello","views":5}}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    // List
    let r2 = app
        .oneshot(
            Request::builder()
                .uri("/t/blog/records/posts")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r2.status(), StatusCode::OK);
    let body = axum::body::to_bytes(r2.into_body(), 65_536).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["records"].as_array().unwrap().len(), 1);
    assert_eq!(v["total"], 1);
}

#[tokio::test]
async fn update_then_get() {
    let (app, tok, d) = spin_up_tenant("blog").await;
    seed_posts(&d).await;
    let r = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/t/blog/records/posts")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"data":{"title":"a"}}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    let b = axum::body::to_bytes(r.into_body(), 65_536).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
    let id = v["id"].as_i64().unwrap();
    let r2 = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PATCH)
                .uri(format!("/t/blog/records/posts/{id}"))
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"data":{"title":"b"}}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r2.status(), StatusCode::OK);
    let r3 = app
        .oneshot(
            Request::builder()
                .uri(format!("/t/blog/records/posts/{id}"))
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let b = axum::body::to_bytes(r3.into_body(), 65_536).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(v["record"]["title"], "b");
}

#[tokio::test]
async fn delete_record() {
    let (app, tok, d) = spin_up_tenant("blog").await;
    seed_posts(&d).await;
    let r = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/t/blog/records/posts")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"data":{"title":"x"}}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    let b = axum::body::to_bytes(r.into_body(), 65_536).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
    let id = v["id"].as_i64().unwrap();
    let r2 = app
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!("/t/blog/records/posts/{id}"))
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r2.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn list_with_filter() {
    let (app, tok, d) = spin_up_tenant("blog").await;
    seed_posts(&d).await;
    for t in ["a", "b", "c"] {
        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/t/blog/records/posts")
                    .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(format!(r#"{{"data":{{"title":"{t}"}}}}"#)))
                    .unwrap(),
            )
            .await
            .unwrap();
    }
    let r = app
        .oneshot(
            Request::builder()
                .uri("/t/blog/records/posts?filter=title='b'")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let b = axum::body::to_bytes(r.into_body(), 65_536).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(v["records"].as_array().unwrap().len(), 1);
    assert_eq!(v["records"][0]["title"], "b");
}
