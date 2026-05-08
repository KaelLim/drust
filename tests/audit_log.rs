use drust::safety::audit::{AuditEntry, AuditLog};
use tempfile::tempdir;

#[tokio::test]
async fn writes_jsonl_and_rolls_by_date() {
    let dir = tempdir().unwrap();
    let (log, handle) = AuditLog::start(dir.path().to_path_buf());
    log.append(
        AuditEntry::success("t1", "drust_abc", "insert_record", 12).with_collection("posts"),
    );
    log.append(AuditEntry::failure(
        "t1",
        "drust_abc",
        "query",
        5001,
        "QUERY_TIMEOUT",
        "timed out",
    ));
    // Close the channel so the writer drains and exits before we read.
    drop(log);
    handle.join().await;

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

#[tokio::test]
async fn with_extra_flattens_into_top_level_json() {
    use drust::safety::audit::AuditEntry;

    let entry = AuditEntry::success("t1", "drust_abc", "POST /collections/foo/indexes", 42)
        .with_collection("foo")
        .with_extra(serde_json::json!({
            "index_name":   "idx_foo_bar",
            "index_fields": ["bar"],
            "row_count":    18432,
            "force_used":   false
        }));

    let line = serde_json::to_string(&entry).unwrap();
    let v: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(v["index_name"], "idx_foo_bar");
    assert_eq!(v["index_fields"], serde_json::json!(["bar"]));
    assert_eq!(v["row_count"], 18432);
    assert_eq!(v["force_used"], false);
    // Existing keys still present.
    assert_eq!(v["status"], "ok");
    assert_eq!(v["collection"], "foo");
}

#[test]
fn with_extra_ignores_non_object_value() {
    use drust::safety::audit::AuditEntry;
    let entry = AuditEntry::success("t1", "h", "op", 0)
        .with_extra(serde_json::json!("not an object"));
    let line = serde_json::to_string(&entry).unwrap();
    // No surprise top-level keys leaked from the ignored input.
    assert!(!line.contains("not an object"));
}
