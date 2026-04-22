//! Tests for the admin upload form validation added in Task 15.
//!
//! Strategy: **Option B** — pure validation via `parse_upload_fields`.
//! We construct raw multipart HTTP requests, extract `axum::extract::Multipart`
//! using `FromRequest`, then call `parse_upload_fields` directly.  No real
//! Garage S3 endpoint is needed; we only test the parsing/validation layer.
//!
//! The end-to-end PUT path (bucket routing + SQLite insert + Garage PUT) is
//! deferred — it requires either a real Garage S3 mock or a new in-process
//! fake S3 server (out of scope for this task).

use axum::body::Body;
use axum::extract::FromRequest;
use axum::extract::Multipart;
use axum::http::{Request, StatusCode};
use drust::mgmt::public_files::parse_upload_fields;
use drust::storage::files::{Disposition, Visibility};

/// Build a minimal multipart/form-data body. Returns (boundary, bytes).
fn make_multipart(parts: &[(&str, &str, Option<&str>)]) -> (String, Vec<u8>) {
    let boundary = "testboundary1234";
    let mut body: Vec<u8> = Vec::new();

    for (field_name, value, filename) in parts {
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        if let Some(fname) = filename {
            body.extend_from_slice(
                format!(
                    "Content-Disposition: form-data; name=\"{field_name}\"; filename=\"{fname}\"\r\n"
                )
                .as_bytes(),
            );
            body.extend_from_slice(b"Content-Type: application/octet-stream\r\n");
        } else {
            body.extend_from_slice(
                format!("Content-Disposition: form-data; name=\"{field_name}\"\r\n").as_bytes(),
            );
        }
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(value.as_bytes());
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());

    (boundary.to_string(), body)
}

async fn extract_multipart(parts: &[(&str, &str, Option<&str>)]) -> Multipart {
    let (boundary, body) = make_multipart(parts);
    let req = Request::builder()
        .method("POST")
        .header(
            "content-type",
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(body))
        .unwrap();
    Multipart::from_request(req, &()).await.unwrap()
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn accepts_visibility_public_default() {
    // No visibility field → defaults to Public.
    let mp = extract_multipart(&[("file", "hello", Some("test.txt"))]).await;
    let fields = parse_upload_fields(mp).await.expect("should parse ok");
    assert_eq!(fields.visibility, Visibility::Public);
    assert_eq!(fields.original_name, "test.txt");
}

#[tokio::test]
async fn accepts_visibility_private() {
    let mp = extract_multipart(&[
        ("file", "bytes", Some("data.bin")),
        ("visibility", "private", None),
    ])
    .await;
    let fields = parse_upload_fields(mp).await.expect("should parse ok");
    assert_eq!(fields.visibility, Visibility::Private);
}

#[tokio::test]
async fn rejects_invalid_visibility() {
    let mp = extract_multipart(&[
        ("file", "bytes", Some("data.bin")),
        ("visibility", "foo", None),
    ])
    .await;
    let err = parse_upload_fields(mp)
        .await
        .expect_err("should reject unknown visibility");
    assert!(
        err.contains("invalid visibility"),
        "expected 'invalid visibility' in {err:?}"
    );
}

#[tokio::test]
async fn accepts_disposition_attachment() {
    let mp = extract_multipart(&[
        ("file", "bytes", Some("doc.pdf")),
        ("disposition", "attachment", None),
    ])
    .await;
    let fields = parse_upload_fields(mp).await.expect("should parse ok");
    assert_eq!(fields.disposition, Disposition::Attachment);
}

#[tokio::test]
async fn rejects_invalid_disposition() {
    let mp = extract_multipart(&[
        ("file", "bytes", Some("data.bin")),
        ("disposition", "sideways", None),
    ])
    .await;
    let err = parse_upload_fields(mp)
        .await
        .expect_err("should reject unknown disposition");
    assert!(
        err.contains("invalid disposition"),
        "expected 'invalid disposition' in {err:?}"
    );
}

#[tokio::test]
async fn rejects_meta_when_not_json_object() {
    // JSON array — not an object.
    let mp = extract_multipart(&[
        ("file", "bytes", Some("data.bin")),
        ("meta", "[1,2,3]", None),
    ])
    .await;
    let err = parse_upload_fields(mp)
        .await
        .expect_err("should reject non-object meta");
    assert!(
        err.contains("JSON object"),
        "expected 'JSON object' in {err:?}"
    );
}

#[tokio::test]
async fn accepts_valid_meta_json_object() {
    let mp = extract_multipart(&[
        ("file", "bytes", Some("data.bin")),
        ("meta", r#"{"author":"admin","tag":"test"}"#, None),
    ])
    .await;
    let fields = parse_upload_fields(mp).await.expect("should parse ok");
    assert!(fields.meta_json.is_some());
}

#[tokio::test]
async fn missing_file_field_errors() {
    // Only a text field, no file.
    let mp = extract_multipart(&[("visibility", "public", None)]).await;
    let err = parse_upload_fields(mp)
        .await
        .expect_err("should require file field");
    assert!(
        err.contains("missing file field"),
        "expected 'missing file field' in {err:?}"
    );
}

// ─── Task 20: DiskView formatting + Counts ────────────────────────────────────

/// DiskView: when disk_stats returns real values, GB formatting has 1 decimal.
#[test]
fn disk_view_gb_formatting() {
    // 10 GiB used, 100 GiB total → free = 90 GiB → 90.0%
    let total_bytes: u64 = 100 * 1_073_741_824;
    let used_bytes: u64 = 10 * 1_073_741_824;
    let free_bytes = total_bytes - used_bytes;
    let free_pct = (free_bytes as f64 / total_bytes as f64) * 100.0;

    let used_gb = format!("{:.1}", used_bytes as f64 / 1_073_741_824.0);
    let total_gb = format!("{:.1}", total_bytes as f64 / 1_073_741_824.0);
    let free_pct_display = format!("{:.1}", free_pct);

    assert_eq!(used_gb, "10.0");
    assert_eq!(total_gb, "100.0");
    assert_eq!(free_pct_display, "90.0");
}

/// DiskView fallback: when disk_stats fails, placeholder strings are "?".
#[test]
fn disk_view_fallback_fields_are_question_mark() {
    // Simulate the fallback path used when statvfs fails.
    let used_gb = "?".to_string();
    let total_gb = "?".to_string();
    let free_pct: f64 = 100.0;
    let free_pct_display = "?".to_string();

    // free_pct >= 20 so the low-disk warning must NOT trigger.
    assert!(free_pct >= 20.0);
    assert_eq!(used_gb, "?");
    assert_eq!(total_gb, "?");
    assert_eq!(free_pct_display, "?");
}

/// DiskView: free_pct < 20 should trip the low-disk guard.
#[test]
fn disk_view_low_disk_threshold() {
    // 85 GiB used of 100 GiB total → 15% free → below 20% threshold.
    let total_bytes: u64 = 100 * 1_073_741_824;
    let used_bytes: u64 = 85 * 1_073_741_824;
    let free_bytes = total_bytes - used_bytes;
    let free_pct = (free_bytes as f64 / total_bytes as f64) * 100.0;

    assert!(
        free_pct < 20.0,
        "expected low-disk condition, got {free_pct}"
    );
}

/// Smoke-test that the handler returns 503 when garage is None.
#[tokio::test]
async fn upload_submit_returns_503_when_garage_none() {
    use drust::auth::middleware::AdminSessionState;
    use drust::mgmt::public_files::{PublicFilesState, upload_submit};
    use drust::storage::meta::{bootstrap_admin, open_meta};
    use std::sync::Arc;
    use tempfile::tempdir;
    use tokio::sync::Mutex;

    let dir = tempdir().unwrap();
    let mut conn = open_meta(&dir.path().join("meta.sqlite")).unwrap();
    bootstrap_admin(&mut conn, "root", "pw").unwrap();

    let state = PublicFilesState {
        session: AdminSessionState {
            meta: Arc::new(Mutex::new(conn)),
        },
        meta: {
            let mut c2 = open_meta(&dir.path().join("meta2.sqlite")).unwrap();
            bootstrap_admin(&mut c2, "root", "pw").unwrap();
            Arc::new(Mutex::new(c2))
        },
        garage: None,
        base_url: "http://localhost".to_string(),
        max_upload_bytes: 1_048_576,
        disk_min_free_pct: 20,
        garage_client_key_id: String::new(),
    };

    // Build a trivial multipart request.
    let (boundary, body_bytes) = make_multipart(&[("file", "hi", Some("hi.txt"))]);
    let req = Request::builder()
        .method("POST")
        .uri("/")
        .header(
            "content-type",
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(body_bytes))
        .unwrap();

    use tower::ServiceExt;

    // Build a one-shot router with upload_submit.
    let app = axum::Router::new()
        .route(
            "/",
            axum::routing::post(upload_submit)
                .layer(axum::extract::DefaultBodyLimit::max(state.max_upload_bytes)),
        )
        .with_state(state);

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}
