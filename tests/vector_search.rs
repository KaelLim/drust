//! /search end-to-end: happy path + metrics + k cap + filter + errors.
//! See tests/vector_storage.rs for INSERT/UPDATE/list shape.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;

mod helpers;
use helpers::spin_up_tenant;

/// Seed a 3-dim collection with three rows whose embeddings sit at the
/// unit axes. Mirrors the create_collection DDL + meta row write.
async fn seed_axes_collection(dir: &tempfile::TempDir, app: &axum::Router, tok: &str) {
    let pool = helpers::grab_pool("blog", dir).await;
    pool.with_writer(|c| -> rusqlite::Result<()> {
        c.execute_batch(
            "CREATE TABLE docs (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                title       TEXT,
                category    TEXT,
                embedding   BLOB,
                created_at  TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TRIGGER docs_updated_at AFTER UPDATE ON docs
              BEGIN UPDATE docs SET updated_at = datetime('now') WHERE id = OLD.id; END;",
        )?;
        c.execute(
            "INSERT INTO _system_collection_meta \
                (collection_name, anon_caps_json, vector_fields_json, updated_at) \
             VALUES ('docs', '[\"select\"]',
                     '[{\"name\":\"embedding\",\"dim\":3}]',
                     datetime('now'))",
            [],
        )?;
        Ok(())
    })
    .await
    .unwrap();
    // Three rows, three unit-axis vectors.
    for (title, cat, v) in &[
        ("alpha", "docs", [1.0f32, 0.0, 0.0]),
        ("beta", "blog", [0.0, 1.0, 0.0]),
        ("gamma", "docs", [0.0, 0.0, 1.0]),
    ] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/t/blog/records/docs")
                    .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "data": {"title": title, "category": cat, "embedding": v}
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }
}

async fn search(
    app: &axum::Router,
    tok: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/t/blog/collections/docs/search")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, v)
}

#[tokio::test]
async fn search_returns_k_nearest_cosine() {
    let (app, tok, dir) = spin_up_tenant("blog").await;
    seed_axes_collection(&dir, &app, &tok).await;
    let (status, v) = search(
        &app,
        &tok,
        serde_json::json!({
            "field": "embedding",
            "vector": [1.0, 0.0, 0.0],
            "k": 2
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {v}");
    let rows = v["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    // alpha sits exactly at [1,0,0] → distance = 0.
    assert_eq!(rows[0]["title"], "alpha");
    assert!((rows[0]["_distance"].as_f64().unwrap()).abs() < 1e-6);
    // embedding column should NOT be projected by default.
    assert!(rows[0].get("embedding").is_none());
}

#[tokio::test]
async fn search_with_metric_l2() {
    let (app, tok, dir) = spin_up_tenant("blog").await;
    seed_axes_collection(&dir, &app, &tok).await;
    let (status, v) = search(
        &app,
        &tok,
        serde_json::json!({
            "field": "embedding",
            "vector": [1.0, 0.0, 0.0],
            "k": 3,
            "metric": "l2"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["metric"], "l2");
    let rows = v["rows"].as_array().unwrap();
    assert_eq!(rows[0]["title"], "alpha");
}

#[tokio::test]
async fn search_invalid_metric_400() {
    let (app, tok, dir) = spin_up_tenant("blog").await;
    seed_axes_collection(&dir, &app, &tok).await;
    let (status, v) = search(
        &app,
        &tok,
        serde_json::json!({
            "field": "embedding",
            "vector": [1.0, 0.0, 0.0],
            "k": 1,
            "metric": "hamming"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(v["error_code"], "INVALID_METRIC");
}

#[tokio::test]
async fn search_k_cap_enforced() {
    let (app, tok, dir) = spin_up_tenant("blog").await;
    seed_axes_collection(&dir, &app, &tok).await;
    for k in [0u32, 1001, 100_000] {
        let (status, v) = search(
            &app,
            &tok,
            serde_json::json!({"field": "embedding", "vector": [1.0, 0.0, 0.0], "k": k}),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "for k={k}");
        assert_eq!(v["error_code"], "K_OUT_OF_RANGE", "for k={k}");
    }
}

#[tokio::test]
async fn search_vector_field_not_found_404() {
    let (app, tok, dir) = spin_up_tenant("blog").await;
    seed_axes_collection(&dir, &app, &tok).await;
    let (status, v) = search(
        &app,
        &tok,
        serde_json::json!({"field": "ghost", "vector": [1.0, 0.0, 0.0], "k": 1}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(v["error_code"], "VECTOR_FIELD_NOT_FOUND");
}

#[tokio::test]
async fn search_query_dim_mismatch_422() {
    let (app, tok, dir) = spin_up_tenant("blog").await;
    seed_axes_collection(&dir, &app, &tok).await;
    let (status, v) = search(
        &app,
        &tok,
        serde_json::json!({"field": "embedding", "vector": [1.0, 0.0], "k": 1}),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(v["error_code"], "VECTOR_DIM_MISMATCH");
}

#[tokio::test]
async fn search_filter_eq_shorthand() {
    let (app, tok, dir) = spin_up_tenant("blog").await;
    seed_axes_collection(&dir, &app, &tok).await;
    let (status, v) = search(
        &app,
        &tok,
        serde_json::json!({
            "field": "embedding",
            "vector": [1.0, 0.0, 0.0],
            "k": 10,
            "where": {"category": "docs"}
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let rows = v["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    for r in rows {
        assert_eq!(r["category"], "docs");
    }
}

#[tokio::test]
async fn search_filter_unknown_field_400() {
    let (app, tok, dir) = spin_up_tenant("blog").await;
    seed_axes_collection(&dir, &app, &tok).await;
    let (status, v) = search(
        &app,
        &tok,
        serde_json::json!({
            "field": "embedding",
            "vector": [1.0, 0.0, 0.0],
            "k": 1,
            "where": {"ghost": "x"}
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(v["error_code"], "FILTER_UNKNOWN_FIELD");
}

#[tokio::test]
async fn search_filter_vector_field_400() {
    let (app, tok, dir) = spin_up_tenant("blog").await;
    seed_axes_collection(&dir, &app, &tok).await;
    let (status, v) = search(
        &app,
        &tok,
        serde_json::json!({
            "field": "embedding",
            "vector": [1.0, 0.0, 0.0],
            "k": 1,
            "where": {"embedding": "anything"}
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(v["error_code"], "FILTER_VECTOR_FIELD");
}

#[tokio::test]
async fn search_filter_and_or_not() {
    let (app, tok, dir) = spin_up_tenant("blog").await;
    seed_axes_collection(&dir, &app, &tok).await;
    let (status, v) = search(
        &app,
        &tok,
        serde_json::json!({
            "field": "embedding",
            "vector": [1.0, 0.0, 0.0],
            "k": 10,
            "where": {
                "and": [
                    {"or": [{"category": "docs"}, {"category": "blog"}]},
                    {"not": {"title": "beta"}}
                ]
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {v}");
    let rows = v["rows"].as_array().unwrap();
    let titles: Vec<&str> = rows.iter().map(|r| r["title"].as_str().unwrap()).collect();
    assert!(!titles.contains(&"beta"), "beta should be filtered: {titles:?}");
    // alpha + gamma remain (both category=docs).
    assert!(titles.contains(&"alpha"));
    assert!(titles.contains(&"gamma"));
}
