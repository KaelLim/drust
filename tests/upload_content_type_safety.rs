//! 2026-07-29 audit, finding P0-1 — stored XSS via a caller-supplied
//! `Content-Type` on a tenant file upload.
//!
//! Tenant objects are served from the SAME ORIGIN as the admin UI (Caddy fans
//! `/public/*` and `/drust/*` out of one site block, and drust itself streams
//! private bytes at `/drust/t/{id}/files/{key}/bytes`, a route also mounted
//! under `/drust/admin/...`). A file stored as `text/html` and served `inline`
//! therefore runs script in the admin plane's origin.
//!
//! Two layers are asserted here:
//!   * LAYER 1 (ingest) — the row PERSISTED by `tenant_files::upload` already
//!     carries `application/octet-stream` + `attachment`, so even a reader that
//!     bypasses drust (Caddy -> Garage web) gets safe object headers;
//!   * LAYER 2 (serve) — `stream_bytes` neutralizes what it read from the row,
//!     so a row written BEFORE this fix is served safely too, and every
//!     response carries `X-Content-Type-Options: nosniff`.
//!
//! Harness mirrors tests/tenant_quota_files.rs: real tenant sqlite in a
//! tempdir + an in-memory `GarageClient::from_store`.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::mgmt::tenant_files::{TenantFilesState, list, stream_bytes, upload};
use drust::storage::garage::GarageClient;
use drust::storage::pool::{SharedTenantPool, TenantRegistry};
use object_store::memory::InMemory;
use std::sync::Arc;
use tower::ServiceExt;

const TID: &str = "ctsafety-tenant";
const BOUNDARY: &str = "drustctboundary";

fn setup() -> (
    axum::Router,
    TenantFilesState,
    SharedTenantPool,
    tempfile::TempDir,
) {
    let dir = tempfile::tempdir().unwrap();
    drust::storage::tenant_db::open_write(dir.path(), TID).unwrap();
    let registry = Arc::new(TenantRegistry::new(dir.path().to_path_buf(), 2));
    let pool = registry.get_or_open(TID).unwrap();
    let garage = Arc::new(GarageClient::from_store(
        Arc::new(InMemory::new()),
        "public",
    ));
    let mut state =
        TenantFilesState::test_default(Some(garage), dir.path().to_path_buf(), registry);
    state.disk_min_free_pct = 0; // CI disk is frequently <20% free
    let app = axum::Router::new()
        .route("/t/{tenant}/files", axum::routing::post(upload).get(list))
        .route(
            "/t/{tenant}/files/{key}/bytes",
            axum::routing::get(stream_bytes),
        )
        .with_state(state.clone());
    (app, state, pool, dir)
}

/// One `file` part declaring `filename` + `Content-Type`, plus an explicit
/// `visibility=public` + `disposition=inline` (the attacker's best case).
fn multipart(filename: &str, ct: &str, bytes: &[u8]) -> Vec<u8> {
    let mut b: Vec<u8> = Vec::new();
    b.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
    b.extend_from_slice(
        format!("Content-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n")
            .as_bytes(),
    );
    b.extend_from_slice(format!("Content-Type: {ct}\r\n\r\n").as_bytes());
    b.extend_from_slice(bytes);
    b.extend_from_slice(b"\r\n");
    for (name, value) in [("visibility", "public"), ("disposition", "inline")] {
        b.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
        b.extend_from_slice(
            format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
        );
        b.extend_from_slice(value.as_bytes());
        b.extend_from_slice(b"\r\n");
    }
    b.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
    b
}

async fn do_upload(app: &axum::Router, filename: &str, ct: &str) -> serde_json::Value {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{TID}/files"))
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={BOUNDARY}"),
                )
                .body(Body::from(multipart(filename, ct, b"<script>1</script>")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "upload should succeed");
    let bytes = axum::body::to_bytes(resp.into_body(), 1_048_576)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// The `_system_files` row as the LIST endpoint returns it.
async fn list_row(app: &axum::Router, key: &str) -> serde_json::Value {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/t/{TID}/files"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 4_194_304)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    v["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["key"] == key)
        .unwrap_or_else(|| panic!("key {key} not in list"))
        .clone()
}

async fn get_bytes_headers(app: &axum::Router, key: &str) -> axum::http::HeaderMap {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/t/{TID}/files/{key}/bytes"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "bytes fetch should succeed");
    resp.headers().clone()
}

fn hdr(h: &axum::http::HeaderMap, name: &str) -> String {
    h.get(name)
        .unwrap_or_else(|| panic!("missing header {name}"))
        .to_str()
        .unwrap()
        .to_string()
}

// ───────────────────────────────────────────────────────────────────────────
// LAYER 1 — neutralize at ingest.
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn html_upload_is_stored_as_octet_stream_attachment() {
    let (app, _state, _pool, _dir) = setup();
    let up = do_upload(&app, "evil.html", "text/html").await;
    let key = up["key"].as_str().unwrap().to_string();

    let row = list_row(&app, &key).await;
    assert_eq!(
        row["content_type"], "application/octet-stream",
        "a text/html upload must NOT be stored as text/html"
    );
    assert_eq!(
        row["content_disposition"], "attachment",
        "a neutralized file must be stored as attachment even though the \
         caller asked for inline"
    );
}

#[tokio::test]
async fn svg_upload_is_stored_as_octet_stream_attachment() {
    let (app, _state, _pool, _dir) = setup();
    // No explicit part content type -> mime_guess infers image/svg+xml from
    // the extension. The extension route must be neutralized too.
    let up = do_upload(&app, "evil.svg", "application/octet-stream").await;
    let key = up["key"].as_str().unwrap().to_string();

    let row = list_row(&app, &key).await;
    assert_eq!(row["content_type"], "application/octet-stream");
    assert_eq!(row["content_disposition"], "attachment");
}

#[tokio::test]
async fn html_with_charset_parameter_is_neutralized() {
    let (app, _state, _pool, _dir) = setup();
    let up = do_upload(&app, "evil.bin", "text/html; charset=utf-8").await;
    let key = up["key"].as_str().unwrap().to_string();

    let row = list_row(&app, &key).await;
    assert_eq!(row["content_type"], "application/octet-stream");
    assert_eq!(row["content_disposition"], "attachment");
}

// ───────────────────────────────────────────────────────────────────────────
// LAYER 2 — neutralize at serve (+ nosniff).
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn html_upload_is_served_as_octet_stream_attachment_with_nosniff() {
    let (app, _state, _pool, _dir) = setup();
    let up = do_upload(&app, "evil.html", "text/html").await;
    let key = up["key"].as_str().unwrap().to_string();

    let h = get_bytes_headers(&app, &key).await;
    assert_eq!(hdr(&h, "content-type"), "application/octet-stream");
    assert!(
        hdr(&h, "content-disposition").starts_with("attachment;"),
        "expected attachment, got {}",
        hdr(&h, "content-disposition")
    );
    assert_eq!(hdr(&h, "x-content-type-options"), "nosniff");
}

/// A row written BEFORE this fix still says `text/html` + `inline`. The serve
/// layer must neutralize it independently of the ingest layer.
#[tokio::test]
async fn legacy_html_row_is_neutralized_at_serve_time() {
    let (app, _state, pool, _dir) = setup();
    let up = do_upload(&app, "innocent.png", "image/png").await;
    let key = up["key"].as_str().unwrap().to_string();

    // Rewrite the row the way a pre-fix upload would have persisted it.
    let key_w = key.clone();
    pool.with_writer(move |c| {
        c.execute(
            "UPDATE _system_files SET content_type='text/html', content_disposition='inline' \
             WHERE key=?1",
            rusqlite::params![key_w],
        )
        .map(|_| ())
    })
    .await
    .unwrap();

    let h = get_bytes_headers(&app, &key).await;
    assert_eq!(
        hdr(&h, "content-type"),
        "application/octet-stream",
        "a legacy text/html row must not be echoed back verbatim"
    );
    assert!(hdr(&h, "content-disposition").starts_with("attachment;"));
    assert_eq!(hdr(&h, "x-content-type-options"), "nosniff");
}

// ───────────────────────────────────────────────────────────────────────────
// No regression for ordinary files.
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn png_upload_round_trips_unchanged_as_inline() {
    let (app, _state, _pool, _dir) = setup();
    let up = do_upload(&app, "cat.png", "image/png").await;
    let key = up["key"].as_str().unwrap().to_string();

    let row = list_row(&app, &key).await;
    assert_eq!(row["content_type"], "image/png");
    assert_eq!(row["content_disposition"], "inline");

    let h = get_bytes_headers(&app, &key).await;
    assert_eq!(hdr(&h, "content-type"), "image/png");
    assert!(
        hdr(&h, "content-disposition").starts_with("inline;"),
        "got {}",
        hdr(&h, "content-disposition")
    );
    // nosniff is unconditional — it is what makes the passed-through type
    // authoritative instead of a sniffing hint.
    assert_eq!(hdr(&h, "x-content-type-options"), "nosniff");
}

#[tokio::test]
async fn javascript_upload_is_not_neutralized() {
    let (app, _state, _pool, _dir) = setup();
    let up = do_upload(&app, "app.js", "application/javascript").await;
    let key = up["key"].as_str().unwrap().to_string();

    let row = list_row(&app, &key).await;
    assert_eq!(
        row["content_type"], "application/javascript",
        "navigating to a .js URL does not execute it in the page origin — \
         neutralizing it would break legitimate asset hosting"
    );
    assert_eq!(row["content_disposition"], "inline");
}
