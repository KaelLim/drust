use drust::storage::meta::{bootstrap_admin, open_meta};
use drust::storage::tenant_db::open_write;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn backup_roundtrip() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    std::fs::create_dir_all(data.join("backups")).unwrap();
    let mut meta = open_meta(&data.join("meta.sqlite")).unwrap();
    bootstrap_admin(&mut meta, "root", "pw").unwrap();
    meta.execute("INSERT INTO tenants (id, name) VALUES ('blog', 'Blog')", [])
        .unwrap();
    drop(meta);
    let tc = open_write(data, "blog").unwrap();
    tc.execute_batch("CREATE TABLE posts (id INTEGER); INSERT INTO posts VALUES (1),(2);")
        .unwrap();
    drop(tc);

    // Run backup script with DATA_DIR override
    let script = std::fs::canonicalize("deploy/drust-backup.sh").unwrap();
    let status = Command::new("bash")
        .arg(&script)
        .env("DRUST_DATA_DIR", data)
        .status()
        .expect("script runs");
    assert!(status.success());

    let files: Vec<_> = std::fs::read_dir(data.join("backups"))
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().ends_with(".tar.zst"))
        .collect();
    assert_eq!(files.len(), 1);
}
