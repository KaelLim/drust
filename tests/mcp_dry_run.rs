//! v1.26 dry_run mode: delete_record / drop_collection / drop_index
//! must short-circuit before mutating storage, audit, or webhook
//! state, and must return a blast-radius preview.

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
