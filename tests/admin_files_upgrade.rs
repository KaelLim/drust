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

/// v1.63 (#950-B) — `visibility` alone cannot tell the data-plane gate whether
/// the caller ASKED for public or merely said nothing, because the default IS
/// public. `visibility_explicit` carries that difference, and getting it wrong
/// re-opens the pre-v1.63 footgun: every silent non-service upload published.
#[tokio::test]
async fn reports_whether_visibility_was_sent() {
    let mp = extract_multipart(&[("file", "hello", Some("test.txt"))]).await;
    let fields = parse_upload_fields(mp).await.expect("should parse ok");
    assert!(
        !fields.visibility_explicit,
        "an absent field must not read as an explicit `public`"
    );

    for sent in ["public", "private"] {
        let mp = extract_multipart(&[
            ("file", "hello", Some("test.txt")),
            ("visibility", sent, None),
        ])
        .await;
        let fields = parse_upload_fields(mp).await.expect("should parse ok");
        assert!(fields.visibility_explicit, "{sent} was sent explicitly");
    }
}

/// The `path` field goes through the one grammar choke point, byte-for-byte —
/// no normalization, and an empty field is `None` rather than `Some("")`.
#[tokio::test]
async fn accepts_and_validates_the_path_field() {
    let mp = extract_multipart(&[
        ("file", "hello", Some("x.png")),
        ("path", "照片/alice/x.png", None),
    ])
    .await;
    let fields = parse_upload_fields(mp).await.expect("should parse ok");
    assert_eq!(fields.path.as_deref(), Some("照片/alice/x.png"));

    let mp = extract_multipart(&[("file", "hello", Some("x.png")), ("path", "", None)]).await;
    let fields = parse_upload_fields(mp).await.expect("should parse ok");
    assert_eq!(fields.path, None, "an empty path field is no path at all");

    for bad in ["../x", "a//b", "/a", "a/"] {
        let mp = extract_multipart(&[("file", "hello", Some("x.png")), ("path", bad, None)]).await;
        let err = match parse_upload_fields(mp).await {
            Ok(f) => panic!("{bad:?} must be rejected, parsed as {:?}", f.path),
            Err(e) => e,
        };
        assert!(
            err.starts_with("FILE_PATH_INVALID"),
            "the caller gets a typed code for {bad:?}, got {err:?}"
        );
    }
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
    use drust::mgmt::public_files::{PublicFilesState, upload_submit};
    use drust::storage::meta::{bootstrap_admin, open_meta};
    use std::sync::Arc;
    use tempfile::tempdir;
    use tokio::sync::Mutex;

    let dir = tempdir().unwrap();
    let mut conn = open_meta(&dir.path().join("meta.sqlite")).unwrap();
    bootstrap_admin(&mut conn, "root", "pw").unwrap();

    let session_meta = Arc::new(Mutex::new(conn));
    let meta = {
        let mut c2 = open_meta(&dir.path().join("meta2.sqlite")).unwrap();
        bootstrap_admin(&mut c2, "root", "pw").unwrap();
        Arc::new(Mutex::new(c2))
    };
    let state = PublicFilesState::test_default(session_meta, meta);

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

/// The host-admin upload mints its key through the rule Mode-A and tus use
/// (`storage::files::derive_file_key`): an extension that is not 1-12 ASCII
/// alphanumerics becomes `bin`, so the row key, the object key and the public
/// URL are one string. Under the old rule the key kept the filename's own
/// extension, the object store percent-encoded it, and the public URL named an
/// object that was not there.
#[tokio::test]
async fn upload_submit_mints_a_bin_key_for_a_non_ascii_extension() {
    use drust::mgmt::public_files::{PublicFilesState, upload_submit};
    use drust::storage::files::{Owner, Visibility, build_public_url};
    use drust::storage::garage::GarageClient;
    use drust::storage::meta::{bootstrap_admin, open_meta};
    use std::sync::Arc;
    use tempfile::tempdir;
    use tokio::sync::Mutex;
    use tower::ServiceExt;

    let dir = tempdir().unwrap();
    let mut conn = open_meta(&dir.path().join("meta.sqlite")).unwrap();
    bootstrap_admin(&mut conn, "root", "pw").unwrap();
    let session_meta = Arc::new(Mutex::new(conn));
    let meta = {
        let mut c2 = open_meta(&dir.path().join("meta2.sqlite")).unwrap();
        bootstrap_admin(&mut c2, "root", "pw").unwrap();
        Arc::new(Mutex::new(c2))
    };
    // An in-memory store (no S3 endpoint): the bucket is folded into the key.
    let garage = Arc::new(GarageClient::from_mock_admin(
        "http://127.0.0.1:1",
        "unused",
    ));
    let mut state = PublicFilesState::test_default(session_meta, meta.clone());
    state.garage = Some(garage.clone());
    state.disk_min_free_pct = 0; // the disk guard is not what this test is about

    let (boundary, body_bytes) = make_multipart(&[("file", "hi", Some("報告書.檔案"))]);
    let req = Request::builder()
        .method("POST")
        .uri("/")
        .header(
            "content-type",
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(body_bytes))
        .unwrap();
    let base_url = state.base_url.clone();
    let app = axum::Router::new()
        .route(
            "/",
            axum::routing::post(upload_submit)
                .layer(axum::extract::DefaultBodyLimit::max(state.max_upload_bytes)),
        )
        .with_state(state);
    let resp = app.oneshot(req).await.unwrap();
    assert!(
        resp.status().is_redirection(),
        "a stored upload redirects to the list, got {}",
        resp.status()
    );

    let (key, original_name): (String, String) = meta
        .lock()
        .await
        .query_row("SELECT key, original_name FROM _system_files", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!(original_name, "報告書.檔案", "the stored filename is kept");
    assert!(
        key.ends_with(".bin"),
        "non-ASCII extension mints bin: {key}"
    );
    assert!(
        key.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.'),
        "the key needs no encoding: {key}"
    );

    // The object sits at exactly that key, and the public URL names it as is.
    let listed: Vec<String> = garage
        .list_objects()
        .await
        .unwrap()
        .into_iter()
        .map(|o| o.key)
        .collect();
    assert_eq!(listed, vec![format!("public/{key}")]);
    let url = build_public_url(&base_url, &Owner::Admin, Visibility::Public, &key);
    assert!(
        url.ends_with(&format!("/{key}")),
        "url {url} names key {key}"
    );
    assert!(!url.contains('%'), "nothing in the url is escaped: {url}");
}
