use drust::safety::audit::{AuditEntry, AuditLog};
use tempfile::tempdir;

#[tokio::test]
async fn writes_jsonl_and_rolls_by_date() {
    let dir = tempdir().unwrap();
    let log = AuditLog::new(dir.path().to_path_buf());
    log.append(
        AuditEntry::success("t1", "drust_abc", "insert_record", 12).with_collection("posts"),
    )
    .await
    .unwrap();
    log.append(AuditEntry::failure(
        "t1",
        "drust_abc",
        "query",
        5001,
        "QUERY_TIMEOUT",
        "timed out",
    ))
    .await
    .unwrap();
    let files: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.file_name().into_string().unwrap())
        .collect();
    assert_eq!(files.len(), 1);
    let content = std::fs::read_to_string(dir.path().join(&files[0])).unwrap();
    let lines: Vec<_> = content.lines().collect();
    assert_eq!(lines.len(), 2);
    let v1: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(v1["status"], "ok");
    assert_eq!(v1["op"], "insert_record");
    assert_eq!(v1["collection"], "posts");
    let v2: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(v2["status"], "error");
    assert_eq!(v2["error_code"], "QUERY_TIMEOUT");
}
