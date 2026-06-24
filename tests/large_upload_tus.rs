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

fn caps() -> axum::Extension<drust::tenant::file_caps::TenantFileCaps> {
    axum::Extension(Default::default())
}

fn actx() -> axum::Extension<drust::auth::middleware::AuthCtx> {
    axum::Extension(drust::auth::middleware::AuthCtx::Service { admin_id: None })
}

#[tokio::test]
async fn options_advertises_tus_capabilities() {
    let (_d, state, tref) = setup("t-opt");
    let resp = uploads::options(
        State(state),
        axum::Extension(tref),
        Path("t-opt".to_string()),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let h = resp.headers();
    assert_eq!(h.get("tus-version").unwrap(), "1.0.0");
    assert!(
        h.get("tus-extension")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("creation")
    );
    assert!(
        h.get("tus-extension")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("termination")
    );
    assert!(h.contains_key("tus-max-size"));
}

#[tokio::test]
async fn create_returns_201_with_prefixed_location() {
    let (_d, state, tref) = setup("t-cr");
    let mut headers = HeaderMap::new();
    headers.insert("upload-length", "1000".parse().unwrap());
    headers.insert(
        "upload-metadata",
        format!(
            "filename {},filetype {}",
            b64("a.pdf"),
            b64("application/pdf")
        )
        .parse()
        .unwrap(),
    );
    let resp = uploads::create(
        State(state),
        axum::Extension(tref),
        caps(),
        actx(),
        Path("t-cr".to_string()),
        headers,
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let loc = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(
        loc.starts_with("/drust/t/t-cr/uploads/"),
        "Location must be /drust-prefixed for the browser-facing path, got: {loc}"
    );
    assert!(resp.headers().contains_key("upload-expires"));
}

#[tokio::test]
async fn create_rejects_oversize_length() {
    let (_d, mut state, tref) = setup("t-big");
    state.large_upload_max_bytes = 500; // tiny cap
    let mut headers = HeaderMap::new();
    headers.insert("upload-length", "100000".parse().unwrap());
    let resp = uploads::create(
        State(state),
        axum::Extension(tref),
        caps(),
        actx(),
        Path("t-big".to_string()),
        headers,
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn create_rejects_anon() {
    let (_d, state, mut tref) = setup("t-anon");
    tref.role = TokenRole::Anon;
    let mut headers = HeaderMap::new();
    headers.insert("upload-length", "1000".parse().unwrap());
    let resp = uploads::create(
        State(state),
        axum::Extension(tref),
        caps(),
        actx(),
        Path("t-anon".to_string()),
        headers,
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

async fn create_session(
    state: &TenantFilesState,
    tref: &TenantRef,
    tid: &str,
    len: usize,
) -> String {
    let mut headers = HeaderMap::new();
    headers.insert("upload-length", len.to_string().parse().unwrap());
    headers.insert(
        "upload-metadata",
        format!("filename {}", b64("f.bin")).parse().unwrap(),
    );
    let resp = uploads::create(
        State(state.clone()),
        axum::Extension(tref.clone()),
        caps(),
        actx(),
        Path(tid.to_string()),
        headers,
    )
    .await
    .into_response();
    let loc = resp
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    loc.rsplit('/').next().unwrap().to_string()
}

#[tokio::test]
async fn head_then_patch_advances_offset() {
    let (_d, state, tref) = setup("t-patch");
    let tok = create_session(&state, &tref, "t-patch", 5).await;

    // HEAD → offset 0.
    let resp = uploads::head(
        State(state.clone()),
        axum::Extension(tref.clone()),
        caps(),
        actx(),
        Path(("t-patch".into(), tok.clone())),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers().get("upload-offset").unwrap(), "0");
    assert_eq!(resp.headers().get("upload-length").unwrap(), "5");

    // PATCH "hel" at offset 0 → offset 3.
    let mut h = HeaderMap::new();
    h.insert("upload-offset", "0".parse().unwrap());
    let resp = uploads::patch(
        State(state.clone()),
        axum::Extension(tref.clone()),
        caps(),
        actx(),
        Path(("t-patch".into(), tok.clone())),
        h,
        axum::body::Bytes::from_static(b"hel"),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(resp.headers().get("upload-offset").unwrap(), "3");

    // Wrong-offset PATCH → 409.
    let mut h = HeaderMap::new();
    h.insert("upload-offset", "0".parse().unwrap());
    let resp = uploads::patch(
        State(state.clone()),
        axum::Extension(tref.clone()),
        caps(),
        actx(),
        Path(("t-patch".into(), tok.clone())),
        h,
        axum::body::Bytes::from_static(b"X"),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn patch_overrun_rejected() {
    let (_d, state, tref) = setup("t-over");
    let tok = create_session(&state, &tref, "t-over", 3).await;
    let mut h = HeaderMap::new();
    h.insert("upload-offset", "0".parse().unwrap());
    let resp = uploads::patch(
        State(state.clone()),
        axum::Extension(tref.clone()),
        caps(),
        actx(),
        Path(("t-over".into(), tok)),
        h,
        axum::body::Bytes::from_static(b"toolong"),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn full_upload_finalizes_into_system_files() {
    // Needs a Garage client → use the in-memory store via from_store.
    use drust::storage::garage::GarageClient;
    use object_store::memory::InMemory;
    let dir = tempfile::tempdir().unwrap();
    let tid = "t-fin";
    drust::storage::tenant_db::open_write(dir.path(), tid).unwrap();
    let registry = Arc::new(TenantRegistry::new(dir.path().to_path_buf(), 2));
    let pool = registry.get_or_open(tid).unwrap();
    // put_file_in (Task 3) branches on s3_endpoint.is_empty(): a from_store
    // client has an empty endpoint, so finalize streams into this InMemory
    // store directly — no real S3 needed.
    let garage = Arc::new(GarageClient::from_store(
        Arc::new(InMemory::new()),
        "private",
    ));
    let mut state =
        TenantFilesState::test_default(Some(garage), dir.path().to_path_buf(), registry);
    state.large_upload_chunk_max_bytes = 64 * 1024 * 1024;
    let tref = TenantRef {
        tenant_id: tid.into(),
        token_hint: "svc".into(),
        pool: pool.clone(),
        role: TokenRole::Service,
    };

    let tok = create_session(&state, &tref, tid, 5).await;
    let mut h = HeaderMap::new();
    h.insert("upload-offset", "0".parse().unwrap());
    let resp = uploads::patch(
        State(state.clone()),
        axum::Extension(tref.clone()),
        caps(),
        actx(),
        Path((tid.into(), tok.clone())),
        h,
        axum::body::Bytes::from_static(b"hello"),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(resp.headers().get("upload-offset").unwrap(), "5");

    // _system_files row now exists; session row gone.
    let n: i64 = pool
        .with_reader(|c| c.query_row("SELECT COUNT(*) FROM _system_files", [], |r| r.get(0)))
        .await
        .unwrap();
    assert_eq!(n, 1);
    let s: i64 = pool
        .with_reader(|c| {
            c.query_row("SELECT COUNT(*) FROM _system_upload_sessions", [], |r| {
                r.get(0)
            })
        })
        .await
        .unwrap();
    assert_eq!(s, 0);
}

#[tokio::test]
async fn delete_terminates_session() {
    let (_d, state, tref) = setup("t-del");
    let tok = create_session(&state, &tref, "t-del", 100).await;
    let resp = uploads::terminate(
        State(state.clone()),
        axum::Extension(tref.clone()),
        caps(),
        actx(),
        Path(("t-del".into(), tok.clone())),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    // gone
    let resp = uploads::head(
        State(state.clone()),
        axum::Extension(tref.clone()),
        caps(),
        actx(),
        Path(("t-del".into(), tok)),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn cross_tenant_token_is_404() {
    let (_da, state_a, tref_a) = setup("t-a");
    let tok = create_session(&state_a, &tref_a, "t-a", 10).await;
    // Tenant B's state/pool; same token string.
    let (_db, state_b, tref_b) = setup("t-b");
    let resp = uploads::head(
        State(state_b),
        axum::Extension(tref_b),
        caps(),
        actx(),
        Path(("t-b".into(), tok)),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn list_sessions_returns_in_flight() {
    let (_d, state, tref) = setup("t-list");
    let _ = create_session(&state, &tref, "t-list", 100).await;
    let _ = create_session(&state, &tref, "t-list", 200).await;
    let resp = uploads::list_sessions(
        State(state),
        axum::Extension(tref),
        Path("t-list".to_string()),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["sessions"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn create_rejects_over_session_cap() {
    let (_d, mut state, tref) = setup("t-cap");
    state.large_upload_max_sessions_per_tenant = 2;
    // Two succeed.
    for _ in 0..2 {
        let mut h = HeaderMap::new();
        h.insert("upload-length", "10".parse().unwrap());
        let resp = uploads::create(
            State(state.clone()),
            axum::Extension(tref.clone()),
            caps(),
            actx(),
            Path("t-cap".to_string()),
            h,
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }
    // Third exceeds the cap.
    let mut h = HeaderMap::new();
    h.insert("upload-length", "10".parse().unwrap());
    let resp = uploads::create(
        State(state.clone()),
        axum::Extension(tref.clone()),
        caps(),
        actx(),
        Path("t-cap".to_string()),
        h,
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
}

/// v1.42 per-bearer session binding: a session created by user "alice" cannot be
/// probed/resumed/aborted by a different user ("bob") — even same tenant, even
/// with the upload cap. The creator (alice) still reaches her own session.
#[tokio::test]
async fn tus_session_bound_to_creating_bearer() {
    use drust::auth::middleware::AuthCtx;
    use drust::storage::schema::FileVerb;
    use drust::tenant::file_caps::TenantFileCaps;

    let (_d, state, mut tref) = setup("t-bind");
    tref.role = TokenRole::User;
    let mut c = TenantFileCaps::default();
    c.user.insert(FileVerb::Upload); // grant upload so the cap gate passes for User
    let fc = axum::Extension(c);
    let alice = || {
        axum::Extension(AuthCtx::User {
            user_id: "alice".into(),
            token_hash: "ha".into(),
        })
    };
    let bob = || {
        axum::Extension(AuthCtx::User {
            user_id: "bob".into(),
            token_hash: "hb".into(),
        })
    };

    // alice creates a session.
    let mut headers = HeaderMap::new();
    headers.insert("upload-length", "5".parse().unwrap());
    headers.insert(
        "upload-metadata",
        format!("filename {}", b64("f.bin")).parse().unwrap(),
    );
    let resp = uploads::create(
        State(state.clone()),
        axum::Extension(tref.clone()),
        fc.clone(),
        alice(),
        Path("t-bind".to_string()),
        headers,
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let tok = resp
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_string();

    // bob (different user) must NOT see/resume alice's session → 404.
    let resp = uploads::head(
        State(state.clone()),
        axum::Extension(tref.clone()),
        fc.clone(),
        bob(),
        Path(("t-bind".into(), tok.clone())),
    )
    .await
    .into_response();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "bob must not see alice's in-flight session"
    );

    // alice CAN HEAD her own session → 200.
    let resp = uploads::head(
        State(state.clone()),
        axum::Extension(tref.clone()),
        fc.clone(),
        alice(),
        Path(("t-bind".into(), tok.clone())),
    )
    .await
    .into_response();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "alice must reach her own session"
    );
}
