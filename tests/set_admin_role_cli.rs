//! Test the set_admin_role binary by spawning it as a subprocess against
//! a temporary meta DB.
use std::process::Command;
use tempfile::TempDir;

#[test]
fn promotes_member_to_owner() {
    let tmp = TempDir::new().unwrap();
    let meta_path = tmp.path().join("meta.sqlite");
    let conn = rusqlite::Connection::open(&meta_path).unwrap();
    conn.execute_batch(
        "CREATE TABLE admins (
           id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
           password_hash TEXT NOT NULL, email TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now')),
           role TEXT NOT NULL DEFAULT 'member'
         );
         INSERT INTO admins (username, password_hash, email, role) VALUES ('kael', 'h', 'k@x', 'member');"
    ).unwrap();
    drop(conn);

    let exe = env!("CARGO_BIN_EXE_set_admin_role");
    // set_admin_password.rs uses DRUST_DATA_DIR; set_admin_role mirrors that convention.
    // We pass the directory containing meta.sqlite.
    let out = Command::new(exe)
        .env("DRUST_DATA_DIR", tmp.path())
        .args(&["--email", "k@x", "--role", "owner"])
        .output().unwrap();
    assert!(out.status.success(), "stderr={}", String::from_utf8_lossy(&out.stderr));

    let conn = rusqlite::Connection::open(&meta_path).unwrap();
    let role: String = conn.query_row("SELECT role FROM admins WHERE email='k@x'", [], |r| r.get(0)).unwrap();
    assert_eq!(role, "owner");
}
