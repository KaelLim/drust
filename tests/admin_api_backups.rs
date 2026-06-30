//! T8.4: GET /admin/api/backups + /admin/api/backups/{filename}/inspect — JSON
//! twins of the backups UI. `write_tiny_backup` mirrors the in-memory tar.zst
//! builder at src/mgmt/backups.rs:676-703.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::mgmt::routes::MgmtState;
use drust::storage::meta::{bootstrap_admin, open_meta};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::Mutex;
use tower::ServiceExt;

fn build_state(conn: rusqlite::Connection, data_dir: PathBuf, log_dir: PathBuf) -> MgmtState {
    let tenants = Arc::new(drust::storage::pool::TenantRegistry::new(
        data_dir.clone(),
        2,
    ));
    let bus = drust::tenant::events::EventBus::new();
    let mcp = Arc::new(drust::mcp::http_registry::McpHttpRegistry::new(Arc::new(
        drust::mcp::server::McpRegistry::new(tenants.clone()),
    )));
    let mut state = MgmtState::test_default(
        Arc::new(Mutex::new(conn)),
        data_dir,
        tenants,
        mcp,
        bus,
        drust::tenant::rooms::RoomBus::new(),
    );
    state.log_dir = log_dir;
    state
}

async fn spin_up() -> (axum::Router, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let log_dir = data_dir.join("audit");
    std::fs::create_dir_all(&log_dir).unwrap();
    let mut conn = open_meta(&data_dir.join("meta.sqlite")).unwrap();
    bootstrap_admin(&mut conn, "root", "hunter2").unwrap();
    drust::db::migrations::run_migrations(&conn, &data_dir).unwrap();
    let state = build_state(conn, data_dir.clone(), log_dir);
    let router = state.with_data_dir(data_dir);
    (router, dir)
}

async fn login(app: &axum::Router, username: &str, password: &str) -> String {
    let form = format!("username={username}&password={password}");
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "login failed");
    let sc = resp
        .headers()
        .get(header::SET_COOKIE)
        .expect("no Set-Cookie on login")
        .to_str()
        .unwrap();
    sc.split(';').next().unwrap().to_string()
}

async fn body_json(resp: axum::http::Response<Body>) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1_000_000)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

/// Build a tiny valid tar.zst with a meta.sqlite-shaped file + one tenant
/// data.sqlite (137 bytes). Mirrors backups.rs:676-703.
fn write_tiny_backup(archive: &Path) {
    let mut tar_buf: Vec<u8> = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_buf);
        let sqlite_header = b"SQLite format 3\0".to_vec();
        let mut header = tar::Header::new_gnu();
        header.set_path("meta.sqlite").unwrap();
        header.set_size(sqlite_header.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append(&header, sqlite_header.as_slice()).unwrap();

        let tdb = vec![0u8; 137];
        let mut th = tar::Header::new_gnu();
        th.set_path("tenants/abc/data.sqlite").unwrap();
        th.set_size(tdb.len() as u64);
        th.set_mode(0o644);
        th.set_cksum();
        builder.append(&th, tdb.as_slice()).unwrap();

        builder.finish().unwrap();
    }
    let compressed = zstd::encode_all(tar_buf.as_slice(), 0).unwrap();
    std::fs::write(archive, compressed).unwrap();
}

#[tokio::test]
async fn backups_json_list_and_inspect() {
    let (app, dir) = spin_up().await;
    let cookie = login(&app, "root", "hunter2").await;
    // write a tiny valid archive under <data_dir>/backups/
    let backups = dir.path().join("backups");
    std::fs::create_dir_all(&backups).unwrap();
    let archive = backups.join("drust-2026-01-01-000000.tar.zst");
    write_tiny_backup(&archive);

    let list = body_json(
        app.clone()
            .oneshot(
                Request::builder()
                    .uri("/admin/api/backups")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(list[0]["filename"], "drust-2026-01-01-000000.tar.zst");
    assert!(list[0]["size_bytes"].as_u64().unwrap() > 0);

    let insp = app
        .oneshot(
            Request::builder()
                .uri("/admin/api/backups/drust-2026-01-01-000000.tar.zst/inspect")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(insp.status(), StatusCode::OK);
    let ib = body_json(insp).await;
    assert_eq!(ib["filename"], "drust-2026-01-01-000000.tar.zst");
    assert!(ib["tenants"].is_array());
}
