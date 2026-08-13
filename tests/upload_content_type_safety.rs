//! 2026-07-29 audit, finding P0-1 — stored XSS via a caller-supplied
//! `Content-Type` on a tenant file upload. Redesigned 2026-07-30.
//!
//! Tenant objects are served from the SAME ORIGIN as the admin UI (Caddy fans
//! `/public/*` and `/drust/*` out of one site block, and drust itself streams
//! private bytes at `/drust/t/{id}/files/{key}/bytes`, a route also mounted
//! under `/drust/admin/...`). A file stored as `text/html` and served `inline`
//! could therefore run script in the admin plane's origin.
//!
//! The v1.56.2 fix downgraded a script-executing type to
//! `application/octet-stream` + `attachment` at both ingest and serve — safe,
//! but it broke legitimate markup uploads (a Google-Docs-export-to-HTML
//! pipeline, SVG logos): they could only be downloaded, never viewed.
//!
//! The v1.56.3 redesign has two parts instead:
//!   * INGEST is untouched — the declared/sniffed content type and the
//!     caller's requested disposition are stored verbatim;
//!   * SERVE attaches `Content-Security-Policy: sandbox
//!     allow-top-navigation-by-user-activation` ([`SANDBOX_CSP`]) whenever the
//!     stored type is a script-executing one. Bare `sandbox` puts the
//!     rendered document in a unique opaque origin and disables scripts,
//!     forms, and popups; the `allow-top-navigation-by-user-activation` token
//!     only restores ordinary user-initiated hyperlink navigation. The
//!     decision is made fresh at every serve from the STORED type, so it
//!     covers a row from any point in time — before this file existed, after
//!     the v1.56.2 downgrade, or freshly uploaded under this design.
//!
//! `X-Content-Type-Options: nosniff` stays unconditional on every response —
//! it is the orthogonal defense against a browser sniffing a DIFFERENT
//! declared type back into HTML.
//!
//! Harness mirrors tests/tenant_quota_files.rs: real tenant sqlite in a
//! tempdir + an in-memory `GarageClient::from_store`.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::mgmt::tenant_files::{TenantFilesState, list, stream_bytes, upload};
use drust::storage::files::SANDBOX_CSP;
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
    let pool = registry.get_or_create(TID).unwrap();
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
        // v1.63 (#950-B) — the data-plane twins REQUIRE an identity, which
        // `bearer_auth_layer` supplies in production; without it they refuse
        // with 500 `AUTH_CTX_MISSING`. Service, because these tests upload
        // `visibility=public` on purpose (the attacker's best case) and a
        // service caller lands in the public bucket under every version of the
        // publish rule — this harness mounts no `file_caps_layer` to grant a
        // non-service caller the `upload` cap v1.63.1 requires.
        .layer(axum::Extension(drust::auth::middleware::AuthCtx::Service {
            admin_id: None,
        }))
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
// Ingest: declared type is stored as-is.
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn html_upload_is_stored_as_declared_type_inline() {
    let (app, _state, _pool, _dir) = setup();
    let up = do_upload(&app, "evil.html", "text/html").await;
    let key = up["key"].as_str().unwrap().to_string();

    let row = list_row(&app, &key).await;
    assert_eq!(
        row["content_type"], "text/html",
        "the declared type is stored verbatim — ingest no longer rewrites it"
    );
    assert_eq!(
        row["content_disposition"], "inline",
        "the caller's requested disposition is stored verbatim"
    );
}

#[tokio::test]
async fn svg_upload_is_stored_as_declared_type_inline() {
    let (app, _state, _pool, _dir) = setup();
    // No explicit part content type -> mime_guess infers image/svg+xml from
    // the extension.
    let up = do_upload(&app, "evil.svg", "application/octet-stream").await;
    let key = up["key"].as_str().unwrap().to_string();

    let row = list_row(&app, &key).await;
    assert!(
        row["content_type"].as_str().unwrap().contains("svg"),
        "got {:?}",
        row["content_type"]
    );
    assert_eq!(row["content_disposition"], "inline");
}

#[tokio::test]
async fn html_with_charset_parameter_is_stored_verbatim() {
    let (app, _state, _pool, _dir) = setup();
    let up = do_upload(&app, "evil.bin", "text/html; charset=utf-8").await;
    let key = up["key"].as_str().unwrap().to_string();

    let row = list_row(&app, &key).await;
    assert_eq!(row["content_type"], "text/html; charset=utf-8");
    assert_eq!(row["content_disposition"], "inline");
}

/// The Caddy `/public/*` response-header matcher can only do a plain,
/// case-SENSITIVE glob (Caddy 2.6.2 has no case-insensitive/regex option in
/// its response-matcher allowlist) — so ingest normalizes the essence to
/// lowercase, closing what would otherwise be a case-obfuscation bypass of
/// that layer (a browser still renders `TeXt/HtMl` as HTML; `nosniff` does
/// not help against an unambiguous-but-oddly-cased type).
#[tokio::test]
async fn uppercase_content_type_essence_is_normalized_to_lowercase() {
    let (app, _state, _pool, _dir) = setup();
    let up = do_upload(&app, "evil.bin", "TeXt/HtMl; charset=UTF-8").await;
    let key = up["key"].as_str().unwrap().to_string();

    // axum's multipart `Field::content_type()` is backed by the `mime` crate,
    // which already lowercases the essence and unquoted parameter values on
    // parse — so by the time `normalize_content_type_case` runs, `explicit_ct`
    // has arrived as "text/html; charset=utf-8". The unit tests on
    // `normalize_content_type_case` itself (src/storage/files.rs) pin its OWN
    // contract (params untouched) directly, bypassing this upstream parsing —
    // this integration test only needs to prove the essence is unsafe-flagged
    // and CSP-protected end to end regardless of the casing declared on the
    // wire, which is the actual property that matters here.
    let row = list_row(&app, &key).await;
    assert_eq!(row["content_type"], "text/html; charset=utf-8");

    let h = get_bytes_headers(&app, &key).await;
    assert_eq!(hdr(&h, "content-type"), "text/html; charset=utf-8");
    assert_eq!(
        hdr(&h, "content-security-policy"),
        SANDBOX_CSP,
        "is_unsafe_inline_type is already case-insensitive independent of \
         ingest normalization, so drust's own responder was never at risk — \
         this proves the STORED value drust hands to Garage is also safe for \
         the Caddy /public/* layer, which is not case-insensitive"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Serve: a script-executing type gets a sandbox CSP.
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn html_upload_is_served_inline_with_sandbox_csp_and_nosniff() {
    let (app, _state, _pool, _dir) = setup();
    let up = do_upload(&app, "evil.html", "text/html").await;
    let key = up["key"].as_str().unwrap().to_string();

    let h = get_bytes_headers(&app, &key).await;
    assert_eq!(hdr(&h, "content-type"), "text/html");
    assert!(
        hdr(&h, "content-disposition").starts_with("inline;"),
        "expected inline, got {}",
        hdr(&h, "content-disposition")
    );
    assert_eq!(hdr(&h, "x-content-type-options"), "nosniff");
    let csp = hdr(&h, "content-security-policy");
    assert_eq!(csp, SANDBOX_CSP, "csp must equal the pinned constant");
    assert!(csp.contains("sandbox"));
    assert!(!csp.contains("allow-same-origin"));
    assert!(!csp.contains("allow-scripts"));
}

/// A row from ANY point in time — before this file existed, after the
/// v1.56.2 downgrade, or freshly written under this design — gets the SAME
/// sandbox CSP treatment, because the decision is made fresh at every serve
/// from the stored type, never baked in.
#[tokio::test]
async fn legacy_html_row_is_served_with_sandbox_csp_not_neutralized() {
    let (app, _state, pool, _dir) = setup();
    let up = do_upload(&app, "innocent.png", "image/png").await;
    let key = up["key"].as_str().unwrap().to_string();

    // Rewrite the row to simulate a pre-existing `text/html` row.
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
        "text/html",
        "the stored type is served as declared, never rewritten"
    );
    assert!(hdr(&h, "content-disposition").starts_with("inline;"));
    assert_eq!(hdr(&h, "content-security-policy"), SANDBOX_CSP);
    assert_eq!(hdr(&h, "x-content-type-options"), "nosniff");
}

/// The 2026-07-29 adversarial review found `application/rss+xml` bypassing
/// the first exact-match blocklist. That finding is now closed by rendering
/// it SAFELY (sandbox CSP) instead of needing to keep expanding a blocklist.
#[tokio::test]
async fn rss_xml_upload_is_served_inline_with_sandbox_csp() {
    let (app, _state, _pool, _dir) = setup();
    let up = do_upload(&app, "feed.xml", "application/rss+xml").await;
    let key = up["key"].as_str().unwrap().to_string();

    let row = list_row(&app, &key).await;
    assert_eq!(row["content_type"], "application/rss+xml");
    assert_eq!(row["content_disposition"], "inline");

    let h = get_bytes_headers(&app, &key).await;
    assert_eq!(hdr(&h, "content-type"), "application/rss+xml");
    assert!(hdr(&h, "content-disposition").starts_with("inline;"));
    assert_eq!(hdr(&h, "content-security-policy"), SANDBOX_CSP);
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
    // A safe type must never get a spurious sandbox CSP.
    assert!(
        h.get("content-security-policy").is_none(),
        "safe type must not get a CSP header"
    );
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

    let h = get_bytes_headers(&app, &key).await;
    assert!(
        h.get("content-security-policy").is_none(),
        "application/javascript is not a script-executing DOCUMENT type — no CSP"
    );
}
