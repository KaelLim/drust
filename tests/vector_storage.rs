//! Vector field storage integration: INSERT pre-encodes JSON → BLOB,
//! list/get exclude vector fields by default (v1: no opt-in mechanism).

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;

mod helpers;
use helpers::spin_up_tenant;

/// Build the table + meta row directly via the writer pool, mirroring
/// what `mcp::tools::schema::create_collection` would do. This avoids
/// depending on an MCP route in the integration test harness — the
/// /collections HTTP surface is GET-only.
async fn seed_docs_collection(dir: &tempfile::TempDir) {
    let pool = helpers::grab_pool("blog", dir).await;
    pool.with_writer(|c| -> rusqlite::Result<()> {
        c.execute_batch(
            "CREATE TABLE docs (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                title       TEXT,
                embedding   BLOB,
                created_at  TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TRIGGER docs_updated_at AFTER UPDATE ON docs
              BEGIN UPDATE docs SET updated_at = datetime('now') WHERE id = OLD.id; END;",
        )?;
        // Seed the meta row with the vector field declaration so
        // describe_collection populates schema.vector_fields correctly.
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
}

#[tokio::test]
async fn insert_packs_vector_and_excludes_from_response() {
    let (app, tok, dir) = spin_up_tenant("blog").await;
    seed_docs_collection(&dir).await;

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
                        "data": {"title": "hi", "embedding": [1.0, 0.0, 0.0]}
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let rec = &v["record"];
    assert_eq!(rec["title"], "hi");
    assert!(
        rec.get("embedding").is_none(),
        "embedding should be excluded from insert response, got {v}"
    );

    // GET single record — same default-hide behavior.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/t/blog/records/docs/1")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        v["record"].get("embedding").is_none(),
        "GET response leaked embedding: {v}"
    );

    // Verify the BLOB is actually stored at the SQLite level with the
    // right packed-f32 bytes.
    let pool = helpers::grab_pool("blog", &dir).await;
    let bytes: Vec<u8> = pool
        .with_reader(|c| c.query_row("SELECT embedding FROM docs WHERE id = 1", [], |r| r.get(0)))
        .await
        .unwrap();
    assert_eq!(bytes.len(), 12); // 3 dim × 4 bytes
    let f0 = f32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let f1 = f32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let f2 = f32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    assert!((f0 - 1.0).abs() < 1e-6);
    assert!(f1.abs() < 1e-6);
    assert!(f2.abs() < 1e-6);
}

#[tokio::test]
async fn insert_dim_mismatch_returns_422() {
    let (app, tok, dir) = spin_up_tenant("blog").await;
    seed_docs_collection(&dir).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/t/blog/records/docs")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "data": {"embedding": [1.0, 0.0]}  // dim=2 against declared dim=3
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["error_code"], "VECTOR_DIM_MISMATCH");
}

#[tokio::test]
async fn list_excludes_vector_field_by_default() {
    let (app, tok, dir) = spin_up_tenant("blog").await;
    seed_docs_collection(&dir).await;
    // Insert 2 rows.
    for i in 0..2 {
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
                            "data": {"title": format!("d{i}"), "embedding": [i as f32, 0.0, 0.0]}
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/t/blog/records/docs")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let records = v["records"].as_array().unwrap();
    assert_eq!(records.len(), 2);
    for r in records {
        assert!(r.get("embedding").is_none(), "list leaked embedding: {r}");
    }
}
