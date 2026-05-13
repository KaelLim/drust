// Acceptance: sqlite-vec functions are reachable on a fresh tenant
// connection. This validates the auto-extension install path. Other
// /search-specific tests live in vector_search_*.rs.
use drust::storage::tenant_db::open_write;
use tempfile::TempDir;

#[test]
fn vec_distance_function_is_registered() {
    let tmp = TempDir::new().unwrap();
    let conn = open_write(tmp.path(), "vecsmoke").unwrap();
    // vec_distance_cosine returns a float between -1 and 1 for two
    // 1-element f32 vectors packed as 4-byte BLOBs.
    let a: [u8; 4] = 1.0f32.to_le_bytes();
    let b: [u8; 4] = 1.0f32.to_le_bytes();
    let d: f64 = conn
        .query_row(
            "SELECT vec_distance_cosine(?1, ?2)",
            rusqlite::params![&a[..], &b[..]],
            |r| r.get(0),
        )
        .expect("vec_distance_cosine should be registered");
    // Identical vectors → distance = 0 (cosine).
    assert!((d.abs()) < 1e-6, "expected ~0, got {d}");
}
