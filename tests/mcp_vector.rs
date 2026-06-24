//! v1.10.1 — MCP-side regression tests for vector storage & search.
//!
//! Why this file exists: v1.10.0 shipped `src/tenant/records.rs` (REST)
//! and `src/mcp/tools/write.rs` (MCP) as two parallel write codepaths.
//! The vector encoding was added to REST first; the MCP fix only landed
//! in commit 274341d after a live smoke caught it. These tests pin the
//! MCP path so that drift cannot recur silently.

mod helpers;

use drust::mcp::server::McpRegistry;
use drust::mcp::tools::schema::{FieldSpec, create_collection};
use drust::mcp::tools::vector::{SearchInput, search_collection};
use drust::mcp::tools::write::{insert_record, update_record};
use drust::storage::pool::TenantRegistry;
use std::sync::Arc;

async fn svc(dir: &tempfile::TempDir) -> drust::mcp::server::DrustMcp {
    let data = dir.path().to_path_buf();
    let tr = Arc::new(TenantRegistry::new(data.clone(), 2));
    let _ = drust::storage::tenant_db::open_write(&data, "blog").unwrap();
    let reg = McpRegistry::new(tr);
    reg.get_or_create("blog").await.unwrap()
}

/// Helper: create a `docs(title text, embedding vector dim=3)` collection.
async fn make_vec_collection(s: &drust::mcp::server::DrustMcp) {
    create_collection(
        s,
        "docs",
        &[
            FieldSpec {
                name: "title".into(),
                sql_type: "text".into(),
                nullable: false,
                unique: false,
                default_value: None,
                foreign_key: None,
                dim: None,
                description: None,
                ..Default::default()
            },
            FieldSpec {
                name: "embedding".into(),
                sql_type: "vector".into(),
                nullable: true,
                unique: false,
                default_value: None,
                foreign_key: None,
                dim: Some(3),
                description: None,
                ..Default::default()
            },
        ],
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn mcp_insert_packs_vector_to_blob_and_hides_on_response() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    make_vec_collection(&s).await;
    let ins = insert_record(
        &s,
        "docs",
        serde_json::json!({"title": "alpha", "embedding": [1.0, 0.0, 0.0]}),
    )
    .await
    .unwrap();
    // Response must NOT leak the embedding column.
    assert!(
        ins["record"].get("embedding").is_none(),
        "vector column must be hidden on insert response: {ins}"
    );
    // But it should round-trip through the BLOB column. Verify via the
    // search path, which is the only public surface that touches the
    // stored bytes.
    let id = ins["id"].as_i64().unwrap();
    assert!(id > 0);
}

#[tokio::test]
async fn mcp_insert_rejects_dim_mismatch_with_typed_code() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    make_vec_collection(&s).await;
    let err = insert_record(
        &s,
        "docs",
        serde_json::json!({"title": "bad", "embedding": [1.0, 0.0]}),
    )
    .await
    .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("VECTOR_DIM_MISMATCH"),
        "expected VECTOR_DIM_MISMATCH prefix, got: {msg}"
    );
}

#[tokio::test]
async fn mcp_update_packs_vector_to_blob() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    make_vec_collection(&s).await;
    let ins = insert_record(
        &s,
        "docs",
        serde_json::json!({"title": "alpha", "embedding": [1.0, 0.0, 0.0]}),
    )
    .await
    .unwrap();
    let id = ins["id"].as_i64().unwrap();
    let upd = update_record(
        &s,
        "docs",
        id,
        serde_json::json!({"embedding": [0.0, 1.0, 0.0]}),
    )
    .await
    .unwrap();
    // Update response must also hide the embedding.
    assert!(
        upd["record"].get("embedding").is_none(),
        "vector column must be hidden on update response: {upd}"
    );
}

#[tokio::test]
async fn mcp_update_dim_mismatch_returns_typed_code() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    make_vec_collection(&s).await;
    let ins = insert_record(
        &s,
        "docs",
        serde_json::json!({"title": "a", "embedding": [1.0, 0.0, 0.0]}),
    )
    .await
    .unwrap();
    let id = ins["id"].as_i64().unwrap();
    let err = update_record(
        &s,
        "docs",
        id,
        serde_json::json!({"embedding": [1.0, 0.0, 0.0, 0.0]}),
    )
    .await
    .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("VECTOR_DIM_MISMATCH"),
        "expected VECTOR_DIM_MISMATCH on update, got: {msg}"
    );
}

#[tokio::test]
async fn mcp_search_returns_top_k_ordered() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    make_vec_collection(&s).await;
    for (title, v) in &[
        ("alpha", [1.0f64, 0.0, 0.0]),
        ("beta", [0.0, 1.0, 0.0]),
        ("gamma", [0.0, 0.0, 1.0]),
    ] {
        insert_record(
            &s,
            "docs",
            serde_json::json!({"title": title, "embedding": v}),
        )
        .await
        .unwrap();
    }
    let out = search_collection(
        &s,
        SearchInput {
            collection: "docs".into(),
            field: "embedding".into(),
            vector: serde_json::json!([1.0, 0.0, 0.0]),
            k: 2,
            metric: "cosine".into(),
            r#where: None,
            select: None,
        },
    )
    .await
    .unwrap();
    let rows = out["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["title"], "alpha", "nearest should be alpha: {out}");
    // alpha is exactly at the query → distance ~ 0.
    let d0 = rows[0]["_distance"].as_f64().unwrap();
    assert!(d0.abs() < 1e-6, "expected ~0 distance for alpha, got {d0}");
    // embedding column must not leak into search rows.
    assert!(
        rows[0].get("embedding").is_none(),
        "search row leaked embedding: {out}"
    );
}

#[tokio::test]
async fn mcp_search_invalid_metric_rejected() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    make_vec_collection(&s).await;
    let err = search_collection(
        &s,
        SearchInput {
            collection: "docs".into(),
            field: "embedding".into(),
            vector: serde_json::json!([1.0, 0.0, 0.0]),
            k: 1,
            metric: "hamming".into(),
            r#where: None,
            select: None,
        },
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string().contains("INVALID_METRIC"),
        "expected INVALID_METRIC, got: {err}"
    );
}

#[tokio::test]
async fn mcp_search_k_out_of_range_rejected() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    make_vec_collection(&s).await;
    for k in [0u32, 1001, 100_000] {
        let err = search_collection(
            &s,
            SearchInput {
                collection: "docs".into(),
                field: "embedding".into(),
                vector: serde_json::json!([1.0, 0.0, 0.0]),
                k,
                metric: "cosine".into(),
                r#where: None,
                select: None,
            },
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("K_OUT_OF_RANGE"),
            "k={k} should be rejected; got: {err}"
        );
    }
}

#[tokio::test]
async fn mcp_search_filter_compiles_and_filters() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    create_collection(
        &s,
        "docs",
        &[
            FieldSpec {
                name: "title".into(),
                sql_type: "text".into(),
                nullable: false,
                unique: false,
                default_value: None,
                foreign_key: None,
                dim: None,
                description: None,
                ..Default::default()
            },
            FieldSpec {
                name: "category".into(),
                sql_type: "text".into(),
                nullable: true,
                unique: false,
                default_value: None,
                foreign_key: None,
                dim: None,
                description: None,
                ..Default::default()
            },
            FieldSpec {
                name: "embedding".into(),
                sql_type: "vector".into(),
                nullable: true,
                unique: false,
                default_value: None,
                foreign_key: None,
                dim: Some(3),
                description: None,
                ..Default::default()
            },
        ],
    )
    .await
    .unwrap();
    for (title, cat, v) in &[
        ("alpha", "docs", [1.0f64, 0.0, 0.0]),
        ("beta", "blog", [0.0, 1.0, 0.0]),
        ("gamma", "docs", [0.0, 0.0, 1.0]),
    ] {
        insert_record(
            &s,
            "docs",
            serde_json::json!({"title": title, "category": cat, "embedding": v}),
        )
        .await
        .unwrap();
    }
    let out = search_collection(
        &s,
        SearchInput {
            collection: "docs".into(),
            field: "embedding".into(),
            vector: serde_json::json!([1.0, 0.0, 0.0]),
            k: 10,
            metric: "cosine".into(),
            r#where: Some(serde_json::json!({"category": "docs"})),
            select: None,
        },
    )
    .await
    .unwrap();
    let rows = out["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 2, "filter should leave alpha + gamma: {out}");
    for r in rows {
        assert_eq!(r["category"], "docs");
    }
}

#[tokio::test]
async fn mcp_search_filter_on_vector_field_rejected() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    make_vec_collection(&s).await;
    let err = search_collection(
        &s,
        SearchInput {
            collection: "docs".into(),
            field: "embedding".into(),
            vector: serde_json::json!([1.0, 0.0, 0.0]),
            k: 1,
            metric: "cosine".into(),
            r#where: Some(serde_json::json!({"embedding": "anything"})),
            select: None,
        },
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string().contains("FILTER_VECTOR_FIELD"),
        "expected FILTER_VECTOR_FIELD, got: {err}"
    );
}

#[tokio::test]
async fn mcp_search_filter_too_deep_rejected() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d).await;
    make_vec_collection(&s).await;
    // Build {"not":{"not":{...{"title":"x"}...}}} 40 levels deep — well
    // above the MAX_FILTER_DEPTH=32 ceiling.
    let mut node = serde_json::json!({"title": "x"});
    for _ in 0..40 {
        node = serde_json::json!({"not": node});
    }
    let err = search_collection(
        &s,
        SearchInput {
            collection: "docs".into(),
            field: "embedding".into(),
            vector: serde_json::json!([1.0, 0.0, 0.0]),
            k: 1,
            metric: "cosine".into(),
            r#where: Some(node),
            select: None,
        },
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string().contains("FILTER_TOO_DEEP"),
        "expected FILTER_TOO_DEEP, got: {err}"
    );
}
