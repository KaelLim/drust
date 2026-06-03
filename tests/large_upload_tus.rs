//! Mode B (tus) large-upload tests. Direct handler calls with constructed
//! extractors (matches tests/tenant_files_rest.rs — no router auth harness).

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use drust::mgmt::tenant_files::TenantFilesState;
use drust::storage::pool::TenantRegistry;
use drust::tenant::router::{TenantRef, TokenRole};
use drust::tenant::uploads;
use std::sync::Arc;

fn setup(tid: &str) -> (tempfile::TempDir, TenantFilesState, TenantRef) {
    let dir = tempfile::tempdir().unwrap();
    drust::storage::tenant_db::open_write(dir.path(), tid).unwrap();
    let registry = Arc::new(TenantRegistry::new(dir.path().to_path_buf(), 2));
    let pool = registry.get_or_open(tid).unwrap();
    let state = TenantFilesState::test_default(None, dir.path().to_path_buf(), registry);
    let tref = TenantRef {
        tenant_id: tid.to_string(),
        token_hint: "svc".into(),
        pool,
        role: TokenRole::Service,
    };
    (dir, state, tref)
}

fn b64(s: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(s)
}

#[tokio::test]
async fn options_advertises_tus_capabilities() {
    let (_d, state, tref) = setup("t-opt");
    let resp = uploads::options(State(state), axum::Extension(tref),
        Path("t-opt".to_string())).await.into_response();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let h = resp.headers();
    assert_eq!(h.get("tus-version").unwrap(), "1.0.0");
    assert!(h.get("tus-extension").unwrap().to_str().unwrap().contains("creation"));
    assert!(h.get("tus-extension").unwrap().to_str().unwrap().contains("termination"));
    assert!(h.contains_key("tus-max-size"));
}

#[tokio::test]
async fn create_returns_201_with_prefixed_location() {
    let (_d, state, tref) = setup("t-cr");
    let mut headers = HeaderMap::new();
    headers.insert("upload-length", "1000".parse().unwrap());
    headers.insert("upload-metadata",
        format!("filename {},filetype {}", b64("a.pdf"), b64("application/pdf")).parse().unwrap());
    let resp = uploads::create(State(state), axum::Extension(tref),
        Path("t-cr".to_string()), headers).await.into_response();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let loc = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(loc.starts_with("/drust/t/t-cr/uploads/"),
        "Location must be /drust-prefixed for the browser-facing path, got: {loc}");
    assert!(resp.headers().contains_key("upload-expires"));
}

#[tokio::test]
async fn create_rejects_oversize_length() {
    let (_d, mut state, tref) = setup("t-big");
    state.large_upload_max_bytes = 500; // tiny cap
    let mut headers = HeaderMap::new();
    headers.insert("upload-length", "100000".parse().unwrap());
    let resp = uploads::create(State(state), axum::Extension(tref),
        Path("t-big".to_string()), headers).await.into_response();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn create_rejects_anon() {
    let (_d, state, mut tref) = setup("t-anon");
    tref.role = TokenRole::Anon;
    let mut headers = HeaderMap::new();
    headers.insert("upload-length", "1000".parse().unwrap());
    let resp = uploads::create(State(state), axum::Extension(tref),
        Path("t-anon".to_string()), headers).await.into_response();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
