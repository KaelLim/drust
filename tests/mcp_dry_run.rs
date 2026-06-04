//! v1.26 dry_run mode: delete_record / drop_collection / drop_index
//! must short-circuit before mutating storage, audit, or webhook
//! state, and must return a blast-radius preview.

#[path = "helpers.rs"]
mod test_helpers;

use drust::storage::blast_radius::*;

mod helpers {
    use tempfile::tempdir;

    pub fn make_tenant_with_posts() -> (drust::storage::pool::SharedTenantPool, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let data_dir = dir.path().to_path_buf();
        let writer = drust::storage::tenant_db::open_write(&data_dir, "acme").unwrap();
        writer.execute_batch(
            "CREATE TABLE posts (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT);
             CREATE TABLE comments (id INTEGER PRIMARY KEY, post_id INTEGER REFERENCES posts(id) ON DELETE RESTRICT);
             INSERT INTO posts (id, title) VALUES (1, 'hello');
             INSERT INTO comments (id, post_id) VALUES (1, 1), (2, 1);"
        ).unwrap();
        let registry = drust::storage::pool::TenantRegistry::new(data_dir, 2);
        let pool = registry.get_or_open("acme").unwrap();
        (pool, dir)
    }
}

#[tokio::test]
async fn delete_blast_radius_lists_fk_blockers() {
    let (pool, _dir) = helpers::make_tenant_with_posts();
    let br = delete_blast_radius(&pool, "posts", 1).await.unwrap();
    assert!(br.would_delete);
    assert_eq!(br.id, 1);
    assert_eq!(br.fk_blocks.len(), 1);
    let block = &br.fk_blocks[0];
    assert_eq!(block.collection, "comments");
    assert_eq!(block.via_field, "post_id");
    assert_eq!(block.count, 2);
}

#[tokio::test]
async fn drop_collection_blast_radius_lists_reverse_fks() {
    let (pool, _dir) = helpers::make_tenant_with_posts();
    let br = drop_collection_blast_radius(&pool, "posts").await.unwrap();
    assert!(br.would_drop);
    assert_eq!(br.row_count, 1);
    assert_eq!(br.reverse_fks.len(), 1);
    assert_eq!(br.reverse_fks[0].collection, "comments");
}

/// REST surface check: `?dry_run=true` on DELETE must return the
/// blast-radius JSON and leave the row in place.
#[tokio::test]
async fn rest_delete_dry_run_does_not_delete() {
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, header};
    use tower::ServiceExt;

    let (app, svc_token, dir) = test_helpers::spin_up_tenant_with_role("acme", "service").await;

    // Seed a `posts` collection with one row by going through the same pool.
    let pool = test_helpers::grab_pool("acme", &dir).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE posts (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL);
             INSERT INTO posts (id, title) VALUES (1, 'hello');",
        )
    })
    .await
    .unwrap();

    let req = Request::builder()
        .method("DELETE")
        .uri("/t/acme/records/posts/1?dry_run=true")
        .header(header::AUTHORIZATION, format!("Bearer {svc_token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let bytes = to_bytes(resp.into_body(), 4096).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["would_delete"], true);
    assert_eq!(v["id"], 1);

    // Row must still exist.
    let count: i64 = pool
        .with_reader(|c| c.query_row("SELECT COUNT(*) FROM posts WHERE id = 1", [], |r| r.get(0)))
        .await
        .unwrap();
    assert_eq!(count, 1, "dry_run must not delete the row");
}

#[tokio::test]
async fn drop_collection_dry_run_does_not_drop() {
    let (pool, _dir) = helpers::make_tenant_with_posts();
    let br = drop_collection_blast_radius(&pool, "posts").await.unwrap();
    assert_eq!(br.row_count, 1);
    let still_there: i64 = pool
        .with_reader(|c| {
            c.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='posts'",
                [],
                |r| r.get(0),
            )
        })
        .await
        .unwrap();
    assert_eq!(still_there, 1, "posts table must still exist after dry_run");
}

#[tokio::test]
async fn drop_index_dry_run_unknown_returns_error() {
    let (pool, _dir) = helpers::make_tenant_with_posts();
    let r = drop_index_blast_radius(&pool, "idx_does_not_exist").await;
    let err = r.unwrap_err();
    let msg = err.to_string();
    assert!(msg.starts_with("INDEX_NOT_FOUND"), "got: {msg}");
}

#[tokio::test]
async fn rest_drop_index_dry_run_does_not_drop() {
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, header};
    use tower::ServiceExt;

    let (app, svc_token, dir) = test_helpers::spin_up_tenant_with_role("acme", "service").await;

    // Seed a `posts` table and create an index via the pool writer.
    let pool = test_helpers::grab_pool("acme", &dir).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE posts (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL);
             INSERT INTO posts (id, title) VALUES (1, 'hello');
             CREATE INDEX idx_posts_title ON posts(title);",
        )
    })
    .await
    .unwrap();

    // Hit the dry_run endpoint — should return blast-radius JSON without dropping.
    let req = Request::builder()
        .method("DELETE")
        .uri("/t/acme/collections/posts/indexes/idx_posts_title?dry_run=true")
        .header(header::AUTHORIZATION, format!("Bearer {svc_token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let bytes = to_bytes(resp.into_body(), 4096).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["would_drop"], true);
    assert_eq!(v["name"], "idx_posts_title");

    // Index must still exist.
    let still_there: i64 = pool
        .with_reader(|c| {
            c.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_posts_title'",
                [],
                |r| r.get(0),
            )
        })
        .await
        .unwrap();
    assert_eq!(still_there, 1, "dry_run must not drop the index");
}
