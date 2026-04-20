use drust::storage::schema::{describe_collection, list_collections};
use drust::storage::tenant_db::open_write;
use tempfile::tempdir;

fn seed() -> (tempfile::TempDir, rusqlite::Connection) {
    let d = tempdir().unwrap();
    let conn = open_write(d.path(), "t1").unwrap();
    conn.execute_batch(
        "CREATE TABLE posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            views INTEGER DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
         );
         CREATE INDEX idx_posts_views ON posts(views);
         INSERT INTO posts (title) VALUES ('a'), ('b'), ('c');",
    )
    .unwrap();
    (d, conn)
}

#[test]
fn list_returns_user_tables_only() {
    let (_d, conn) = seed();
    let cols = list_collections(&conn).unwrap();
    assert_eq!(cols.iter().map(|c| &c.name).collect::<Vec<_>>(), vec!["posts"]);
    assert_eq!(cols[0].row_count, 3);
}

#[test]
fn describe_returns_fields_and_indexes() {
    let (_d, conn) = seed();
    let s = describe_collection(&conn, "posts").unwrap().expect("exists");
    let names: Vec<_> = s.fields.iter().map(|f| f.name.clone()).collect();
    assert_eq!(names, vec!["id", "title", "views", "created_at"]);
    let title = s.fields.iter().find(|f| f.name == "title").unwrap();
    assert!(!title.nullable);
    let id_field = s.fields.iter().find(|f| f.name == "id").unwrap();
    assert!(id_field.pk);
    assert!(s.indices.iter().any(|i| i.name == "idx_posts_views"));
    assert_eq!(s.row_count, 3);
}

#[test]
fn describe_missing_returns_none() {
    let (_d, conn) = seed();
    assert!(describe_collection(&conn, "ghost").unwrap().is_none());
}
