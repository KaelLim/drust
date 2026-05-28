//! Integration tests: per-admin auto-MCP PAT ensure/remint endpoints.
//!
//! Covers:
//!   (a) ensure_mints_when_no_row_exists
//!   (b) ensure_is_idempotent_and_omits_token_after_first_mint
//!   (c) remint_revokes_previous_and_mints_new
//!   (d) ensure_requires_admin_session
//!   (e) ensure_writes_audit_row_with_kind_auto_mcp
//!
//! v1.29.2 — Task S3b.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::mgmt::routes::MgmtState;
use drust::safety::audit_db::{AuditWriter, open_audit_db_read, open_audit_db_write};
use drust::storage::meta::{bootstrap_admin, open_meta};
use rusqlite::params;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::Mutex;
use tower::ServiceExt;

// ─── helpers ─────────────────────────────────────────────────────────────────

fn build_state(conn: rusqlite::Connection, data_dir: PathBuf, log_dir: PathBuf) -> MgmtState {
    let tenants = Arc::new(drust::storage::pool::TenantRegistry::new(data_dir, 2));
    let bus = drust::tenant::events::EventBus::new();
    let mcp = Arc::new(drust::mcp::http_registry::McpHttpRegistry::new(Arc::new(
        drust::mcp::server::McpRegistry::new(tenants.clone()),
    )));
    MgmtState {
        meta: Arc::new(Mutex::new(conn)),
        audit_meta_read: Arc::new(Mutex::new(
            drust::safety::audit_db::open_audit_db_memory().unwrap(),
        )),
        session_ttl_days: 7,
        garage: None,
        public_base_url: "http://localhost:8793".to_string(),
        max_upload_bytes: 52_428_800,
        garage_client_key_id: String::new(),
        disk_min_free_pct: 20,
        log_dir,
        url_sign_secret: Arc::new([0u8; 32]),
        tenants,
        mcp,
        bus,
        index_large_table_rows: 1_000_000,
        public_url: String::new(),
        oauth_registry: Arc::new(drust::oauth::ProviderRegistry::from_env_empty()),
        admin_login_rl: Arc::new(drust::safety::rate_limit_ip::IpRateLimit::new(
            5,
            std::time::Duration::from_secs(60),
            4096,
        )),
        admin_oauth_callback_rl: Arc::new(drust::safety::rate_limit_ip::IpRateLimit::new(
            5,
            std::time::Duration::from_secs(60),
            4096,
        )),
    }
}

/// Spin up a mgmt router with one bootstrapped owner admin ("root" / "hunter2").
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

/// Insert an admin directly + create a session.  Returns `(admin_id, cookie_string)`.
fn insert_admin(dir: &tempfile::TempDir, email: &str, role: &str) -> (i64, String) {
    let meta_path = dir.path().join("meta.sqlite");
    let conn = rusqlite::Connection::open(&meta_path).unwrap();
    let username = email.split('@').next().unwrap_or("admin").to_string();
    conn.execute(
        "INSERT INTO admins (username, password_hash, email, role) VALUES (?1, '$oauth-only$', ?2, ?3)",
        params![username, email, role],
    )
    .unwrap();
    let admin_id = conn.last_insert_rowid();
    let session_token = {
        use base64::Engine;
        let mut bytes = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut bytes);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    };
    let expires_at = chrono::Utc::now() + chrono::Duration::days(7);
    conn.execute(
        "INSERT INTO sessions (token, admin_id, expires_at) VALUES (?1, ?2, ?3)",
        params![session_token, admin_id, expires_at.to_rfc3339()],
    )
    .unwrap();
    (admin_id, format!("drust_session={session_token}"))
}

async fn body_json(resp: axum::http::Response<Body>) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 65_536).await.unwrap();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

// ─── tests ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn ensure_mints_when_no_row_exists() {
    let (app, dir) = spin_up().await;
    let (_id, session) = insert_admin(&dir, "kael@x", "member");

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/me/mcp-pat/ensure")
                .header(header::COOKIE, &session)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK, "ensure should return 200");
    let body = body_json(resp).await;
    assert_eq!(body["just_minted"], true, "just_minted must be true on first call");
    let token = body["token"].as_str().expect("token must be present on first mint");
    assert!(token.starts_with("drust_pat_"), "token must start with drust_pat_");
}

#[tokio::test]
async fn ensure_is_idempotent_and_omits_token_after_first_mint() {
    let (app, dir) = spin_up().await;
    let (_id, session) = insert_admin(&dir, "kael@x", "member");

    // First ensure — mints.
    let resp1 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/me/mcp-pat/ensure")
                .header(header::COOKIE, &session)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp1.status(), StatusCode::OK);
    let body1 = body_json(resp1).await;
    assert_eq!(body1["just_minted"], true);

    // Second ensure — idempotent.
    let resp2 = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/me/mcp-pat/ensure")
                .header(header::COOKIE, &session)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp2.status(), StatusCode::OK);
    let body2 = body_json(resp2).await;
    assert_eq!(body2["just_minted"], false, "second ensure must be idempotent");
    assert!(body2["token"].is_null(), "token must be null on subsequent ensure");
    assert_eq!(body2["has_pat"], true, "has_pat must be true");
    let hp = body2["hash_prefix"].as_str().expect("hash_prefix must be present");
    assert_eq!(hp.len(), 8, "hash_prefix must be exactly 8 chars");
}

#[tokio::test]
async fn remint_revokes_previous_and_mints_new() {
    let (app, dir) = spin_up().await;
    let (_id, session) = insert_admin(&dir, "kael@x", "member");

    // Establish initial PAT via ensure.
    let resp1 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/me/mcp-pat/ensure")
                .header(header::COOKIE, &session)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body1 = body_json(resp1).await;
    let first_token = body1["token"].as_str().unwrap().to_string();

    // Remint — should always return a new plaintext token.
    let resp2 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/me/mcp-pat/remint")
                .header(header::COOKIE, &session)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp2.status(), StatusCode::OK, "remint should return 200");
    let body2 = body_json(resp2).await;
    assert_eq!(body2["just_minted"], true, "remint always returns just_minted=true");
    let reminted_token = body2["token"].as_str().expect("remint must return token");
    assert!(reminted_token.starts_with("drust_pat_"), "reminted token must have correct prefix");
    assert_ne!(reminted_token, first_token, "reminted token must differ from first");

    // Ensure after remint — should reflect the NEW token (no mint, has_pat=true).
    let resp3 = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/me/mcp-pat/ensure")
                .header(header::COOKIE, &session)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp3.status(), StatusCode::OK);
    let body3 = body_json(resp3).await;
    assert_eq!(body3["just_minted"], false, "ensure after remint must not re-mint");
    assert_eq!(body3["has_pat"], true, "has_pat must be true after remint");
}

#[tokio::test]
async fn ensure_requires_admin_session() {
    let (app, _dir) = spin_up().await;

    // No cookie — should get 401.
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/me/mcp-pat/ensure")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // admin_session_layer redirects unauthenticated requests to /drust/login
    // (303 See Other) rather than returning 401. This matches the behavior
    // of all other admin-protected endpoints in the mgmt router.
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "ensure without session must redirect to login (303)"
    );
}

/// Audit test: after `ensure` mints a new PAT, the global SQLite audit writer
/// (initialized via `init_globals` once per test-process) must have recorded
/// an `admin.token.mint` row with `extra` containing `"kind":"auto_mcp"` and
/// a non-null `actor_admin_id`.
///
/// Because `WRITER` is a process-level `OnceLock`, the writer is initialized
/// on the first call to `ensure_writes_audit_row_with_kind_auto_mcp` that
/// wins the OnceLock race.  Subsequent calls from within the same test binary
/// use the same writer, so the path must be kept alive for the duration of
/// the test binary run (which is why we use `Box::leak` for the TempDir).
#[tokio::test]
async fn ensure_writes_audit_row_with_kind_auto_mcp() {
    // ── Initialize the global writer once per process ─────────────────────
    // We leak the TempDir so its path remains valid for the lifetime of the
    // process; the writer task holds the write connection open, and the read
    // connection we open below must refer to the same on-disk file.
    static AUDIT_PATH: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    let audit_path = AUDIT_PATH.get_or_init(|| {
        let dir = Box::new(tempdir().unwrap());
        let path = dir.path().join("test_global_audit.sqlite");
        // Leak the TempDir so it lives for the duration of the test binary.
        let path_clone = path.clone();
        let conn = open_audit_db_write(&path).unwrap();
        let writer = AuditWriter::new(conn);
        drust::safety::audit_db::init_globals(writer);
        Box::leak(dir); // keep the directory alive
        path_clone
    });

    let (app, dir) = spin_up().await;
    let (admin_id, session) = insert_admin(&dir, "audit-test@x", "member");

    // Fire ensure → should mint and emit audit row.
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/me/mcp-pat/ensure")
                .header(header::COOKIE, &session)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["just_minted"], true, "must mint for audit attribution to fire");

    // Give the background writer ~250ms to drain.
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;

    // Read from the global audit DB and verify the row.
    let r = open_audit_db_read(audit_path).unwrap();
    let rows: Vec<(String, Option<i64>, Option<String>)> = {
        let mut stmt = r
            .prepare(
                "SELECT op, actor_admin_id, extra FROM audit \
                 WHERE op = 'admin.token.mint' \
                 ORDER BY id DESC LIMIT 10",
            )
            .unwrap();
        stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<i64>>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    };

    assert!(
        !rows.is_empty(),
        "expected at least one admin.token.mint audit row"
    );

    // Find the row that belongs to our admin.
    let matching = rows
        .iter()
        .find(|(_, aid, _)| *aid == Some(admin_id));

    let (_, _, extra) = matching.expect("must find audit row attributed to our admin_id");
    let extra_str = extra.as_deref().unwrap_or("");
    assert!(
        extra_str.contains(r#""kind":"auto_mcp""#)
            || extra_str.contains(r#""kind": "auto_mcp""#),
        "extra must contain kind=auto_mcp, got: {extra_str:?}"
    );
}
