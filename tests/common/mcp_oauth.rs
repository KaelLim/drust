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
    build_fixture(cfg, None, |_| {}).await
}

/// The one fixture builder. `owner_email` is written onto the bootstrap
/// admin; `edit` adjusts the state just before the router is built.
async fn build_fixture(
    cfg: McpOauthConfig,
    owner_email: Option<&str>,
    edit: impl FnOnce(&mut MgmtState),
) -> McpOauthFixture {
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
    if let Some(email) = owner_email {
        conn.execute(
            "UPDATE admins SET email = ?1 WHERE id = ?2",
            params![email, owner_id],
        )
        .unwrap();
    }
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
    edit(&mut state);
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

// ─── Authorize helpers (MA0-5). Full paths only, same reason as above.

/// `(verifier, challenge)` from the production PKCE generator.
pub fn pkce() -> (String, String) {
    drust::oauth::state::issue_pkce()
}

pub fn loopback_redirect(port: u16) -> String {
    format!("http://localhost:{port}/callback")
}

/// The MCP SDK's authorize query, in its order: response_type, client_id,
/// code_challenge, code_challenge_method, redirect_uri, state?, scope,
/// prompt=consent, resource?. Every value form-urlencoded.
pub fn authorize_query(
    challenge: &str,
    redirect_uri: &str,
    state: Option<&str>,
    resource: Option<&str>,
) -> String {
    let mut s = url::form_urlencoded::Serializer::new(String::new());
    s.append_pair("response_type", "code")
        .append_pair("client_id", CC_CLIENT_ID)
        .append_pair("code_challenge", challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("redirect_uri", redirect_uri);
    if let Some(st) = state {
        s.append_pair("state", st);
    }
    s.append_pair("scope", "mcp offline_access")
        .append_pair("prompt", "consent");
    if let Some(r) = resource {
        s.append_pair("resource", r);
    }
    s.finish()
}

/// The `Location` header; panics with a message when absent.
pub fn location(resp: &axum::http::Response<axum::body::Body>) -> String {
    match resp
        .headers()
        .get(axum::http::header::LOCATION)
        .map(|v| v.to_str())
    {
        Some(Ok(v)) => v.to_string(),
        other => panic!(
            "expected a Location header (status {}), got {other:?}",
            resp.status()
        ),
    }
}

/// The form-decoded value of `key` in the part after '?'; first match; None
/// when the key is absent.
pub fn query_param(url: &str, key: &str) -> Option<String> {
    let (_, q) = url.split_once('?')?;
    url::form_urlencoded::parse(q.as_bytes())
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
}

/// The full `Set-Cookie` line whose cookie name is `name`.
pub fn set_cookie(resp: &axum::http::Response<axum::body::Body>, name: &str) -> Option<String> {
    resp.headers()
        .get_all(axum::http::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|line| line.split_once('=').is_some_and(|(k, _)| k == name))
        .map(str::to_string)
}

// ─── Consent helpers (MA0-6). Full paths only, same reason as above.
//
// Two constraints on every caller, both from sharing a test binary:
// - Login budget: `test_default` gives `/login` and the admin OAuth callback
//   5 attempts per IP per 60 s each, and these requests carry no
//   X-Forwarded-For, so ONE fixture allows at most 5 password logins and 5
//   callbacks.
// - Audit rows: other g_admin members install the process-global audit writer
//   and `admin_oauth::oauth_audit_logged_on_success` reads the NEWEST
//   `oauth_google` success row, expecting `kael@example.com` / admin 1. So a
//   Google login here is always admin 1 with `kael@example.com`; any other
//   admin signs in by password or GitHub.

/// `POST /login` (at most 5 per fixture, see above); asserts 303 and returns
/// `"drust_session=<value>"`.
pub async fn login(app: &axum::Router, user: &str, pass: &str) -> String {
    let resp = post_form(
        app,
        "/login",
        &[("username", user), ("password", pass)],
        &[],
        &[],
    )
    .await;
    assert_eq!(
        resp.status(),
        axum::http::StatusCode::SEE_OTHER,
        "login {user}"
    );
    match set_cookie(&resp, "drust_session") {
        Some(line) => cookie_kv(&line),
        None => panic!("login {user}: no drust_session cookie"),
    }
}

/// The value of `<input type="hidden" name="{name}" value="…">`, HTML-unescaped.
pub fn hidden_field(html: &str, name: &str) -> Option<String> {
    let marker = format!("type=\"hidden\" name=\"{name}\" value=\"");
    let start = html.find(&marker)? + marker.len();
    let end = html[start..].find('"')? + start;
    Some(
        html[start..end]
            .replace("&#34;", "\"")
            .replace("&quot;", "\"")
            .replace("&#39;", "'")
            .replace("&#60;", "<")
            .replace("&lt;", "<")
            .replace("&#62;", ">")
            .replace("&gt;", ">")
            .replace("&#38;", "&")
            .replace("&amp;", "&"),
    )
}

/// `name=value` of a `Set-Cookie` line (everything before the first ';').
pub fn cookie_kv(set_cookie_line: &str) -> String {
    set_cookie_line
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_string()
}

/// `fixture(enabled)` plus one fake admin-login provider (`"google"` or
/// `"github"`) and `owner_email` on the bootstrap admin (id 1), the shape of
/// tests/admin_oauth.rs. Installs no audit writer.
pub async fn fixture_with_provider(
    enabled: bool,
    provider: &str,
    fake: &Arc<super::oauth_helpers::FakeProvider>,
    owner_email: &str,
) -> McpOauthFixture {
    use drust::oauth::provider::OauthProvider;
    let adapter: Arc<dyn OauthProvider> = match provider {
        "google" => Arc::new(drust::oauth::google::GoogleAdapter::new(
            "test-client-id".to_string(),
            "test-client-secret".to_string(),
            format!("{}/authorize", fake.base_url),
            format!("{}/token", fake.base_url),
        )),
        "github" => Arc::new(drust::oauth::github::GitHubAdapter::new(
            "test-client-id".to_string(),
            "test-client-secret".to_string(),
            format!("{}/login/oauth/authorize", fake.base_url),
            format!("{}/login/oauth/access_token", fake.base_url),
            fake.base_url.clone(),
        )),
        other => panic!("fixture_with_provider: unknown provider {other:?}"),
    };
    let name: &'static str = if provider == "google" {
        "google"
    } else {
        "github"
    };
    let mut providers: std::collections::HashMap<&'static str, Arc<dyn OauthProvider>> =
        std::collections::HashMap::new();
    providers.insert(name, adapter);
    let registry = drust::oauth::ProviderRegistry::from_providers(providers);
    let cfg = if enabled {
        McpOauthConfig::for_tests(PUBLIC_URL)
    } else {
        McpOauthConfig::disabled()
    };
    build_fixture(cfg, Some(owner_email), move |state| {
        state.public_url = "http://test".to_string();
        state.oauth_registry = Arc::new(registry);
    })
    .await
}

/// A 43-character S256 challenge (RFC 7636 appendix B).
pub const FIXED_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

/// An envelope for Claude Code with `FIXED_CHALLENGE` and no resource, sealed
/// at `now_unix`. `McpOauthConfig::for_tests` uses fixed keys, so an envelope
/// sealed with one `for_tests(PUBLIC_URL)` opens under the fixture's.
pub fn sealed_envelope(
    cfg: &McpOauthConfig,
    redirect_uri: &str,
    state: Option<&str>,
    now_unix: u64,
) -> String {
    let req = drust::mgmt::mcp_oauth::envelope::AuthzRequest {
        client_id: CC_CLIENT_ID.to_string(),
        redirect_uri: redirect_uri.to_string(),
        state: state.map(str::to_string),
        code_challenge: FIXED_CHALLENGE.to_string(),
        resource: None,
    };
    match drust::mgmt::mcp_oauth::envelope::seal(cfg, &req, now_unix) {
        Ok(w) => w,
        Err(e) => panic!("sealed_envelope: seal refused: {e:?}"),
    }
}

/// `Location` minus the base path, i.e. the root path the router serves.
pub fn router_path(location: &str) -> String {
    location
        .strip_prefix(drust::base_path::base_path())
        .unwrap_or(location)
        .to_string()
}

pub struct CodeGrant {
    pub code: String,
    pub verifier: String,
    pub redirect_uri: String,
    pub state: Option<String>,
    pub iss: String,
}

/// authorize (SDK shape, `resource = RESOURCE`) -> consent GET (session +
/// resume) -> approve (session + resume + csrf), asserting each status.
/// Takes a session; never logs in itself, so it spends no login budget.
pub async fn obtain_code(
    fx: &McpOauthFixture,
    session_cookie: &str,
    port: u16,
    state: Option<&str>,
) -> CodeGrant {
    use axum::http::StatusCode;
    let (verifier, challenge) = pkce();
    let redirect_uri = loopback_redirect(port);
    let q = authorize_query(&challenge, &redirect_uri, state, Some(RESOURCE));
    let resp = get(&fx.app, &format!("/oauth/authorize?{q}"), &[session_cookie]).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "authorize");
    let consent_uri = router_path(&location(&resp));
    let resume = cookie_kv(
        &set_cookie(&resp, drust::mgmt::mcp_oauth::envelope::RESUME_COOKIE)
            .expect("authorize sets the resume cookie"),
    );
    let resp = get(&fx.app, &consent_uri, &[session_cookie, &resume]).await;
    assert_eq!(resp.status(), StatusCode::OK, "consent page");
    let csrf_cookie = cookie_kv(
        &set_cookie(&resp, drust::mgmt::mcp_oauth::consent::CSRF_COOKIE)
            .expect("consent page sets the csrf cookie"),
    );
    let html = body_text(resp).await;
    let req = hidden_field(&html, "req").expect("req field");
    let csrf = hidden_field(&html, "csrf").expect("csrf field");
    let resp = post_form(
        &fx.app,
        "/oauth/consent/approve",
        &[("req", &req), ("csrf", &csrf)],
        &[session_cookie, &resume, &csrf_cookie],
        &[],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "approve");
    let loc = location(&resp);
    CodeGrant {
        code: query_param(&loc, "code").expect("code in the redirect"),
        verifier,
        redirect_uri,
        state: query_param(&loc, "state"),
        iss: query_param(&loc, "iss").expect("iss in the redirect"),
    }
}

// ─── Token helpers (MA0-7). Full paths only, same reason as above.

/// The MCP SDK's token request for a code, in its order: grant_type, code,
/// code_verifier, redirect_uri, client_id, resource (`RESOURCE`, as
/// `obtain_code` sent at authorize).
pub fn token_form_for(cg: &CodeGrant) -> Vec<(String, String)> {
    [
        ("grant_type", "authorization_code"),
        ("code", cg.code.as_str()),
        ("code_verifier", cg.verifier.as_str()),
        ("redirect_uri", cg.redirect_uri.as_str()),
        ("client_id", CC_CLIENT_ID),
        ("resource", RESOURCE),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect()
}

/// `POST /oauth/token` (a root path: the production router has no `/drust`)
/// with `token_form_for(cg)`.
pub async fn exchange(
    app: &axum::Router,
    cg: &CodeGrant,
) -> axum::http::Response<axum::body::Body> {
    let form = token_form_for(cg);
    let pairs: Vec<(&str, &str)> = form.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    post_form(app, "/oauth/token", &pairs, &[], &[]).await
}

pub struct Tokens {
    pub access: String,
    pub refresh: String,
    pub grant_id: i64,
}

/// `obtain_code` (port 53_682) -> `exchange` -> 200, with the grant id
/// resolved through `find_grant_by_access`.
pub async fn obtain_tokens(fx: &McpOauthFixture, session_cookie: &str) -> Tokens {
    let cg = obtain_code(fx, session_cookie, 53_682, None).await;
    let resp = exchange(&fx.app, &cg).await;
    assert_eq!(resp.status(), axum::http::StatusCode::OK, "token exchange");
    let v = body_json(resp).await;
    let access = v["access_token"]
        .as_str()
        .expect("access_token")
        .to_string();
    let refresh = v["refresh_token"]
        .as_str()
        .expect("refresh_token")
        .to_string();
    let conn = fx.meta.lock().await;
    let grant_id = drust::mgmt::mcp_oauth::store::find_grant_by_access(&conn, &access)
        .unwrap()
        .expect("the new access token resolves to its grant")
        .grant_id();
    Tokens {
        access,
        refresh,
        grant_id,
    }
}
