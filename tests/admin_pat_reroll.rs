//! v1.29.3 — POST /drust/admin/settings/token/reroll integration tests.
//!
//! Covers:
//!   (a) reroll_returns_plaintext_and_revokes_previous
//!   (b) reroll_requires_admin_session
//!   (c) reroll_emits_revoke_and_mint_audit_rows

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
        bus_rooms: drust::tenant::rooms::RoomBus::new(),
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
    // run_migrations must come first: it creates _admin_tokens, which
    // bootstrap_admin (v1.29.3) inserts into.
    drust::db::migrations::run_migrations(&conn, &data_dir).unwrap();
    bootstrap_admin(&mut conn, "root", "hunter2").unwrap();
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
async fn reroll_returns_plaintext_and_revokes_previous() {
    let (app, dir) = spin_up().await;
    let (admin_id, session) = insert_admin(&dir, "kael@x", "member");

    // Seed an active PAT for the test admin (simulates the backfill that
    // run_migrations applies to pre-existing admins; insert_admin bypasses it).
    let meta_path = dir.path().join("meta.sqlite");
    {
        let conn = rusqlite::Connection::open(&meta_path).unwrap();
        conn.execute(
            "INSERT INTO _admin_tokens (admin_id, token_hash, plaintext) \
             VALUES (?1, 'fake_hash_seed_abc123', 'drust_pat_seed_placeholder')",
            params![admin_id],
        )
        .unwrap();
    }

    // Capture the initial active PAT token_hash.
    let initial_hash: String = {
        let conn = rusqlite::Connection::open(&meta_path).unwrap();
        conn.query_row(
            "SELECT token_hash FROM _admin_tokens WHERE admin_id = ?1 AND revoked_at IS NULL",
            params![admin_id],
            |r| r.get(0),
        )
        .expect("seeded PAT must be visible")
    };

    // Call reroll.
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/settings/token/reroll")
                .header(header::COOKIE, &session)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK, "reroll must return 200");
    let body = body_json(resp).await;
    let plaintext = body["plaintext"].as_str().expect("response must contain plaintext");
    assert!(
        plaintext.starts_with("drust_pat_"),
        "plaintext must start with drust_pat_, got: {plaintext:?}"
    );

    // Verify: old PAT is soft-revoked, exactly one active row.
    let conn2 = rusqlite::Connection::open(&meta_path).unwrap();
    let active_count: i64 = conn2
        .query_row(
            "SELECT COUNT(*) FROM _admin_tokens WHERE admin_id = ?1 AND revoked_at IS NULL",
            params![admin_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(active_count, 1, "exactly one active PAT after reroll");

    let new_hash: String = conn2
        .query_row(
            "SELECT token_hash FROM _admin_tokens WHERE admin_id = ?1 AND revoked_at IS NULL",
            params![admin_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_ne!(
        new_hash,
        initial_hash,
        "new PAT hash must differ from original"
    );

    let revoked_count: i64 = conn2
        .query_row(
            "SELECT COUNT(*) FROM _admin_tokens WHERE admin_id = ?1 AND revoked_at IS NOT NULL",
            params![admin_id],
            |r| r.get(0),
        )
        .unwrap();
    assert!(revoked_count >= 1, "at least one revoked row must exist");
}

#[tokio::test]
async fn reroll_requires_admin_session() {
    let (app, _dir) = spin_up().await;

    // No cookie — admin_session_layer should redirect to /drust/login (303).
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/settings/token/reroll")
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
        "reroll without session must redirect to login (303)"
    );
}

/// Audit test: after `reroll`, the global SQLite audit writer must have
/// recorded both an `admin.token.revoke` row and an `admin.token.mint` row
/// with a non-null `actor_admin_id`.
///
/// Because `WRITER` is a process-level `OnceLock`, the writer is initialized
/// on the first call that wins the OnceLock race. Subsequent calls from within
/// the same test binary use the same writer, so the path must be kept alive
/// for the duration of the test binary run (which is why we use `Box::leak`).
#[tokio::test]
async fn reroll_emits_revoke_and_mint_audit_rows() {
    // ── Initialize the global writer once per process ─────────────────────
    static AUDIT_PATH: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    let audit_path = AUDIT_PATH.get_or_init(|| {
        let dir = Box::new(tempdir().unwrap());
        let path = dir.path().join("test_global_audit_reroll.sqlite");
        let path_clone = path.clone();
        let conn = open_audit_db_write(&path).unwrap();
        let writer = AuditWriter::new(conn);
        drust::safety::audit_db::init_globals(writer);
        Box::leak(dir); // keep the directory alive
        path_clone
    });

    let (app, dir) = spin_up().await;
    let (admin_id, session) = insert_admin(&dir, "audit-reroll@x", "member");

    // Fire reroll → should emit admin.token.revoke + admin.token.mint.
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/settings/token/reroll")
                .header(header::COOKIE, &session)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "reroll must return 200 for audit test");

    // Give the background writer ~250ms to drain.
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;

    let r = open_audit_db_read(audit_path).unwrap();

    // Check admin.token.revoke row attributed to our admin.
    let revoke_rows: Vec<(String, Option<i64>)> = {
        let mut stmt = r
            .prepare(
                "SELECT op, actor_admin_id FROM audit \
                 WHERE op = 'admin.token.revoke' \
                 ORDER BY id DESC LIMIT 20",
            )
            .unwrap();
        stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<i64>>(1)?,
            ))
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    };

    let matching_revoke = revoke_rows
        .iter()
        .find(|(_, aid)| *aid == Some(admin_id));
    assert!(
        matching_revoke.is_some(),
        "must find admin.token.revoke row for admin_id={admin_id}"
    );

    // Check admin.token.mint row attributed to our admin.
    let mint_rows: Vec<(String, Option<i64>)> = {
        let mut stmt = r
            .prepare(
                "SELECT op, actor_admin_id FROM audit \
                 WHERE op = 'admin.token.mint' \
                 ORDER BY id DESC LIMIT 20",
            )
            .unwrap();
        stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<i64>>(1)?,
            ))
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    };

    let matching_mint = mint_rows
        .iter()
        .find(|(_, aid)| *aid == Some(admin_id));
    assert!(
        matching_mint.is_some(),
        "must find admin.token.mint row for admin_id={admin_id}"
    );
}
