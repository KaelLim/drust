mod helpers;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use helpers::{grab_pool, spin_up_tenant};
use tower::ServiceExt;

#[tokio::test]
async fn full_lifecycle() {
    let (app, tok, d) = spin_up_tenant("app1").await;
    // Create collection via direct pool (as an approximation; MCP create_collection tested elsewhere)
    let pool = grab_pool("app1", &d).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                price REAL,
                created_at TEXT DEFAULT (datetime('now')),
                updated_at TEXT DEFAULT (datetime('now'))
            );",
        )
    })
    .await
    .unwrap();

    // Insert via REST
    for (n, p) in [("a", 1.0), ("b", 2.5), ("c", 9.9)] {
        let body = format!(r#"{{"data":{{"name":"{n}","price":{p}}}}}"#);
        let r = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/t/app1/records/items")
                    .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::CREATED);
    }

    // List with filter
    let r = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/t/app1/records/items?filter=price%3E1")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let b = axum::body::to_bytes(r.into_body(), 65_536).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(v["records"].as_array().unwrap().len(), 2);

    // Complex query
    let r2 = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/t/app1/query")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"sql":"SELECT COUNT(*) AS n, AVG(price) AS avg FROM items"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let b = axum::body::to_bytes(r2.into_body(), 65_536).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(v["rows"][0][0], 3);
}
