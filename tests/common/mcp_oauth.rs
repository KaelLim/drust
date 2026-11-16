//! MA0 shared fixtures for the MCP OAuth authorization-server tests
//! (MA0-PLAN §3.9). Compiled into every harness that declares `mod common;`
//! (g_admin, g_tenant, g_storage), so: dev-dependencies only, no unused imports.

use std::sync::Arc;

use drust::mgmt::mcp_oauth::config::McpOauthConfig;
use drust::mgmt::mcp_oauth::tokens::{self, TokenKind};
use drust::mgmt::routes::MgmtState;
use rusqlite::params;
use tokio::sync::Mutex;

pub const PUBLIC_URL: &str = "https://drust.test";
pub const ISSUER: &str = "https://drust.test/drust";
pub const RESOURCE: &str = "https://drust.test/drust/mcp";
pub const CC_CLIENT_ID: &str = "https://claude.ai/oauth/claude-code-client-metadata";
pub const OWNER_USER: &str = "root";
pub const OWNER_PASS: &str = "hunter2";

pub struct McpOauthFixture {
    pub app: axum::Router,
    pub meta: Arc<Mutex<rusqlite::Connection>>,
    pub owner_id: i64,
    pub dir: tempfile::TempDir,
}

pub async fn fixture(enabled: bool) -> McpOauthFixture {
    fixture_with(if enabled {
        McpOauthConfig::for_tests(PUBLIC_URL)
    } else {
        McpOauthConfig::disabled()
    })
    .await
}

/// open_meta + bootstrap_admin + run_migrations + test_default + with_data_dir,
/// the same production-router shape as tests/admin_team_invariants.rs. The
/// router and `meta` share ONE connection, opened by `open_meta` with
/// `PRAGMA foreign_keys = ON`.
pub async fn fixture_with(cfg: McpOauthConfig) -> McpOauthFixture {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let log_dir = data_dir.join("audit");
    std::fs::create_dir_all(&log_dir).unwrap();
    let mut conn = drust::storage::meta::open_meta(&data_dir.join("meta.sqlite")).unwrap();
    drust::storage::meta::bootstrap_admin(&mut conn, OWNER_USER, OWNER_PASS).unwrap();
    drust::db::migrations::run_migrations(&conn, &data_dir).unwrap();
    let owner_id: i64 = conn
        .query_row(
            "SELECT id FROM admins WHERE username = ?1",
            params![OWNER_USER],
            |r| r.get(0),
        )
        .unwrap();
    let meta = Arc::new(Mutex::new(conn));
    let tenants = Arc::new(drust::storage::pool::TenantRegistry::new(
        data_dir.clone(),
        2,
    ));
    let mcp = Arc::new(drust::mcp::http_registry::McpHttpRegistry::new(Arc::new(
        drust::mcp::server::McpRegistry::new(tenants.clone()),
    )));
    let mut state = MgmtState::test_default(
        meta.clone(),
        data_dir.clone(),
        tenants,
        mcp,
        drust::tenant::events::EventBus::new(),
        drust::tenant::rooms::RoomBus::new(),
    );
    state.log_dir = log_dir; // remove_admin writes an audit file entry
    state.mcp_oauth = Arc::new(cfg);
    let app = state.with_data_dir(data_dir);
    McpOauthFixture {
        app,
        meta,
        owner_id,
        dir,
    }
}

/// Inserts an admin on the fixture's own (FK-ON) connection. An empty
/// `password` stores the `$oauth-only$` sentinel and skips argon2 — use it for
/// admins the test never logs in as.
pub async fn add_admin(fx: &McpOauthFixture, username: &str, password: &str, role: &str) -> i64 {
    let hash = if password.is_empty() {
        "$oauth-only$".to_string()
    } else {
        drust::auth::admin::hash_password(password).unwrap()
    };
    let conn = fx.meta.lock().await;
    conn.execute(
        "INSERT INTO admins (username, password_hash, email, role) VALUES (?1, ?2, ?3, ?4)",
        params![username, hash, format!("{username}@example.test"), role],
    )
    .unwrap();
    conn.last_insert_rowid()
}

pub fn count(conn: &rusqlite::Connection, sql: &str) -> i64 {
    conn.query_row(sql, [], |r| r.get(0)).unwrap()
}

/// idle/absolute are SQLite datetime modifiers, e.g. "+30 days", "-1 hour".
pub struct SeedGrant {
    pub admin_id: i64,
    pub idle: &'static str,
    pub absolute: &'static str,
    pub revoked: bool,
}

pub fn seed_grant(conn: &rusqlite::Connection, s: &SeedGrant) -> i64 {
    let n = conn
        .execute(
            "INSERT INTO _mcp_oauth_grants \
               (admin_id, admin_created_at, client_id, redirect_host, \
                idle_expires_at, absolute_expires_at, revoked_at, revoke_reason) \
             SELECT id, created_at, ?2, 'localhost', datetime('now', ?3), datetime('now', ?4), \
                    CASE WHEN ?5 THEN datetime('now') END, CASE WHEN ?5 THEN 'user' END \
               FROM admins WHERE id = ?1",
            params![s.admin_id, CC_CLIENT_ID, s.idle, s.absolute, s.revoked],
        )
        .unwrap();
    assert_eq!(n, 1, "seed_grant: admin {} does not exist", s.admin_id);
    conn.last_insert_rowid()
}

pub struct SeededTokens {
    pub access: String,
    pub refresh: String,
    pub refresh_id: i64,
}

/// One root refresh (parent_id NULL, expires_at = the grant's MIN(idle, absolute))
/// and one access pointing at it (refresh_id = that refresh, +3600 s).
pub fn seed_tokens(conn: &rusqlite::Connection, grant_id: i64) -> SeededTokens {
    let refresh = tokens::new_token(TokenKind::Refresh);
    let access = tokens::new_token(TokenKind::Access);
    let n = conn
        .execute(
            "INSERT INTO _mcp_oauth_refresh (grant_id, parent_id, token_hash, expires_at) \
             SELECT id, NULL, ?2, MIN(idle_expires_at, absolute_expires_at) \
               FROM _mcp_oauth_grants WHERE id = ?1",
            params![grant_id, tokens::hash(TokenKind::Refresh, &refresh)],
        )
        .unwrap();
    assert_eq!(n, 1, "seed_tokens: grant {grant_id} does not exist");
    let refresh_id = conn.last_insert_rowid();
    conn.execute(
        "INSERT INTO _mcp_oauth_access (token_hash, grant_id, refresh_id, expires_at) \
         VALUES (?1, ?2, ?3, datetime('now', '+3600 seconds'))",
        params![
            tokens::hash(TokenKind::Access, &access),
            grant_id,
            refresh_id
        ],
    )
    .unwrap();
    SeededTokens {
        access,
        refresh,
        refresh_id,
    }
}

/// An unredeemed code, expires in 300 s; returns the plaintext code.
pub fn seed_code(
    conn: &rusqlite::Connection,
    grant_id: i64,
    redirect_uri: &str,
    challenge: &str,
    resource: Option<&str>,
) -> String {
    let code = tokens::new_token(TokenKind::Code);
    let n = conn
        .execute(
            "INSERT INTO _mcp_oauth_codes \
               (code_hash, grant_id, client_id, redirect_uri, code_challenge, resource, expires_at) \
             SELECT ?1, id, client_id, ?2, ?3, ?4, datetime('now', '+300 seconds') \
               FROM _mcp_oauth_grants WHERE id = ?5",
            params![
                tokens::hash(TokenKind::Code, &code),
                redirect_uri,
                challenge,
                resource,
                grant_id
            ],
        )
        .unwrap();
    assert_eq!(n, 1, "seed_code: grant {grant_id} does not exist");
    code
}

// ─── HTTP helpers (MA0-4). Full paths only: this file compiles in three
// harnesses, and a file-level `use` that only these need would be unused there.

/// Sends one request through the production router.
pub async fn send(
    app: &axum::Router,
    req: axum::http::Request<axum::body::Body>,
) -> axum::http::Response<axum::body::Body> {
    use tower::ServiceExt;
    app.clone().oneshot(req).await.unwrap()
}

/// `GET <uri>` (a root path, never `/drust/...`) with the given `name=value` cookies.
pub async fn get(
    app: &axum::Router,
    uri: &str,
    cookies: &[&str],
) -> axum::http::Response<axum::body::Body> {
    let mut b = axum::http::Request::builder().method("GET").uri(uri);
    if !cookies.is_empty() {
        b = b.header(axum::http::header::COOKIE, cookies.join("; "));
    }
    send(app, b.body(axum::body::Body::empty()).unwrap()).await
}

/// `POST <uri>` with an `application/x-www-form-urlencoded` body built from
/// `pairs`, the given cookies, and `headers` appended as-is.
pub async fn post_form(
    app: &axum::Router,
    uri: &str,
    pairs: &[(&str, &str)],
    cookies: &[&str],
    headers: &[(&str, &str)],
) -> axum::http::Response<axum::body::Body> {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish();
    let mut b = axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header(
            axum::http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        );
    if !cookies.is_empty() {
        b = b.header(axum::http::header::COOKIE, cookies.join("; "));
    }
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    send(app, b.body(axum::body::Body::from(body)).unwrap()).await
}

pub async fn body_json(resp: axum::http::Response<axum::body::Body>) -> serde_json::Value {
    let b = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    serde_json::from_slice(&b).unwrap()
}

pub async fn body_text(resp: axum::http::Response<axum::body::Body>) -> String {
    let b = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    String::from_utf8(b.to_vec()).unwrap()
}
