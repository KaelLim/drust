use crate::auth::admin::{dummy_hash, verify_password};
use crate::auth::middleware::{build_session_cookie, clear_session_cookie};
use crate::auth::session::{create_session, revoke_session};
use crate::mgmt::i18n::{Locale, LocaleHint, LocaleOption, Translator};
use askama::Template;
use axum::Router;
use axum::extract::{Form, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use rusqlite::Connection;
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct MgmtState {
    pub meta: Arc<Mutex<Connection>>,
    /// v1.24 — read-only connection to meta_logs.sqlite. Used by the
    /// admin audit page handler (Task 8 wires the SQL reader).
    pub audit_meta_read: std::sync::Arc<tokio::sync::Mutex<rusqlite::Connection>>,
    pub session_ttl_days: u64,
    pub garage: Option<Arc<crate::storage::garage::GarageClient>>,
    pub public_base_url: String,
    pub max_upload_bytes: usize,
    /// Garage S3 access-key-id for the drust-client key, used when granting
    /// per-tenant bucket access. Empty when garage is `None`.
    pub garage_client_key_id: String,
    /// Minimum free-disk percentage before uploads are refused (507).
    /// Sourced from `DRUST_DISK_MIN_FREE_PCT`; default 20.
    pub disk_min_free_pct: u8,
    /// Directory containing `audit-YYYY-MM-DD.jsonl` files. Sourced from
    /// `$DRUST_LOG_DIR` at boot; consumed by the admin audit UI.
    pub log_dir: std::path::PathBuf,
    /// 32-byte HMAC secret for drust-minted signed URLs. Generated at boot;
    /// signed URLs do not survive a restart.
    pub url_sign_secret: Arc<[u8; 32]>,
    /// Per-tenant pool registry. Admin handlers need this to invalidate
    /// the schema cache after writes (e.g. anon_caps mutation) so the
    /// next REST/MCP request through the tenant router sees the change
    /// without waiting for natural cache turnover.
    pub tenants: Arc<crate::storage::pool::TenantRegistry>,
    /// Per-tenant MCP service registry. soft_delete_tenant evicts the
    /// cached `DrustMcpService` for a tenant so its in-flight session
    /// state and `Arc<TenantPool>` clones release.
    pub mcp: Arc<crate::mcp::http_registry::McpHttpRegistry>,
    /// Per-(tenant, collection) SSE broadcast channels. soft_delete_tenant
    /// drops every channel keyed on the tenant so subscribers receive
    /// `Closed` instead of dangling forever.
    pub bus: crate::tenant::events::EventBus,
    /// v1.31 per-(tenant, room) broadcast channels for WebSocket multiplex
    /// rooms. Mirrors `bus`; `soft_delete_tenant` evicts both.
    pub bus_rooms: crate::tenant::rooms::RoomBus,
    /// Row count threshold above which index creation is considered "large
    /// table" and returns `LARGE_TABLE` unless `force=true`. Sourced from
    /// `DRUST_INDEX_LARGE_TABLE_ROWS` (default 1 000 000).
    pub index_large_table_rows: u64,
    /// External base URL used to build OAuth redirect URIs (e.g.
    /// `https://tool.tzuchi-org.tw`). Sourced from `DRUST_PUBLIC_URL`.
    /// Empty when unset, which disables OAuth login.
    pub public_url: String,
    /// Registered OAuth providers (Google / GitHub) keyed by short name.
    /// Cloned per request, so wrapped in `Arc`. When `enabled_names()` is
    /// empty, the admin login page hides the OAuth button.
    pub oauth_registry: std::sync::Arc<crate::oauth::ProviderRegistry>,
    /// Per-IP rate limiter for POST /drust/login admin password attempts.
    /// Default: 5 per 60 s. Same shape as tenant `login_rl` in
    /// `TenantAuthState`. Defends against parallel-thread argon2 grind.
    pub admin_login_rl: std::sync::Arc<crate::safety::rate_limit_ip::IpRateLimit>,
    /// Per-IP rate limiter for GET /drust/admin/oauth/{provider}/callback.
    /// Default: 5 per 60 s. Defends the provider-exchange path from being
    /// flooded with attacker-supplied (code, state) pairs.
    pub admin_oauth_callback_rl: std::sync::Arc<crate::safety::rate_limit_ip::IpRateLimit>,
    /// v1.33 — Mode B per-file ceiling (bytes). Forwarded to TenantFilesState.
    pub large_upload_max_bytes: usize,
    /// v1.33 — Mode B per-chunk body limit (bytes). Forwarded to TenantFilesState.
    pub large_upload_chunk_max_bytes: usize,
    /// v1.33 — max concurrent in-flight Mode B sessions per tenant.
    pub large_upload_max_sessions_per_tenant: u32,
    /// v1.33 — abandoned Mode B session TTL (seconds).
    pub large_upload_session_ttl_secs: u64,
    /// v1.35 — shared auth cache, threaded into `TenantsState` at router build.
    pub auth_cache: Arc<crate::tenant::auth_cache::AuthCache>,
    /// v1.36 — file.uploaded function dispatch, forwarded to the admin-side
    /// `TenantFilesState` so admin uploads trigger the same hooks.
    pub functions: Arc<crate::functions::dispatcher::FunctionDispatcher>,
    /// v1.36 — executor handle, forwarded to `TenantsState` so the admin
    /// `ƒ _functions` page can run a synchronous test-invoke.
    pub functions_exec: Arc<crate::functions::executor::Executor>,
    /// v1.36 — artifact root (same dir the tenant pools use), forwarded to
    /// `TenantsState` so the admin delete handler can GC the wasm blob.
    pub fn_data_root: std::path::PathBuf,
}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginPage {
    error: Option<String>,
    version: &'static str,
    oauth_providers: Vec<String>,
    oauth_error: Option<String>,
    t: Translator,
    palette_resolved: crate::mgmt::theme::ResolvedPalette,
    mascot_json_static: String,
    mascot_json_light: String,
    mascot_json_dark: String,
}

#[derive(Template)]
#[template(path = "design.html")]
struct DesignShowcase {
    version: &'static str,
    t: Translator,
    admin: crate::mgmt::admin_profile::AdminProfileExt,
    palette_resolved: crate::mgmt::theme::ResolvedPalette,
    mascot_json_static: String,
    mascot_json_light: String,
    mascot_json_dark: String,
}

async fn design_showcase(
    LocaleHint(locale): LocaleHint,
    crate::mgmt::theme::ThemeHint(theme): crate::mgmt::theme::ThemeHint,
    axum::Extension(admin): axum::Extension<crate::mgmt::admin_profile::AdminProfileExt>,
) -> Response {
    let trc = crate::mgmt::theme::ThemeRenderCtx::build(theme);
    Html(
        DesignShowcase {
            version: env!("CARGO_PKG_VERSION"),
            t: Translator::new(locale),
            admin,
            palette_resolved: trc.palette_resolved,
            mascot_json_static: trc.mascot_json_static,
            mascot_json_light: trc.mascot_json_light,
            mascot_json_dark: trc.mascot_json_dark,
        }
        .render()
        .unwrap_or_default(),
    )
    .into_response()
}

#[derive(Template)]
#[template(path = "settings.html")]
struct SettingsPage {
    version: &'static str,
    t: Translator,
    admin: crate::mgmt::admin_profile::AdminProfileExt,
    available_locales: Vec<LocaleOption>,
    available_themes: Vec<crate::mgmt::theme::ThemeOption>,
    theme: crate::mgmt::theme::Theme,
    palette_resolved: crate::mgmt::theme::ResolvedPalette,
    mascot_json_static: String,
    mascot_json_light: String,
    mascot_json_dark: String,
    /// v1.23 — all 3 palettes serialized as one JSON object for the
    /// settings page client-side live-preview. Consumed by inline JS in
    /// settings.html via `|safe`.
    all_themes_json: String,
    /// v1.29.3 — caller's active PAT plaintext for the Tokens card.
    pat_plaintext: Option<String>,
    /// First 8 chars of token_hash, shown as fingerprint regardless of plaintext.
    pat_hash_prefix: Option<String>,
    /// Caller's PAT last-used timestamp; `None` if the PAT has never authenticated.
    pat_last_used_at: Option<String>,
}

async fn settings_page(
    State(state): State<MgmtState>,
    LocaleHint(locale): LocaleHint,
    crate::mgmt::theme::ThemeHint(theme): crate::mgmt::theme::ThemeHint,
    axum::Extension(admin): axum::Extension<crate::mgmt::admin_profile::AdminProfileExt>,
    axum::Extension(crate::auth::middleware::AdminId(caller_id)): axum::Extension<
        crate::auth::middleware::AdminId,
    >,
) -> Response {
    let pat_row: Option<(Option<String>, String, Option<String>)> = {
        let conn = state.meta.lock().await;
        conn.query_row(
            "SELECT plaintext, token_hash, last_used_at FROM _admin_tokens \
             WHERE admin_id = ?1 AND revoked_at IS NULL",
            rusqlite::params![caller_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .ok()
    };

    let (pat_plaintext, pat_hash_prefix, pat_last_used_at) = match pat_row {
        Some((plain, hash, last)) => (plain, Some(hash.chars().take(8).collect::<String>()), last),
        None => (None, None, None),
    };

    let trc = crate::mgmt::theme::ThemeRenderCtx::build(theme);
    Html(
        SettingsPage {
            version: env!("CARGO_PKG_VERSION"),
            t: Translator::new(locale),
            admin,
            available_locales: Locale::options(),
            available_themes: crate::mgmt::theme::Theme::options(),
            theme,
            palette_resolved: trc.palette_resolved,
            mascot_json_static: trc.mascot_json_static,
            mascot_json_light: trc.mascot_json_light,
            mascot_json_dark: trc.mascot_json_dark,
            all_themes_json: crate::mgmt::script_json::escape_json_for_script(
                &crate::mgmt::theme::build_all_themes_json(),
            ),
            pat_plaintext,
            pat_hash_prefix,
            pat_last_used_at,
        }
        .render()
        .unwrap_or_default(),
    )
    .into_response()
}

#[derive(Debug, Deserialize)]
struct LocalePrefForm {
    locale: String,
}

/// `POST /admin/settings/locale` — persist the admin's UI language to
/// `admins.locale` and mirror it back as the `drust_locale` cookie so the
/// next render picks it up. Validation: only `en` / `zh-TW` accepted —
/// anything else returns 400 (the dropdown can't submit unknown values,
/// so this is purely defensive).
async fn settings_locale_save(
    State(state): State<MgmtState>,
    axum::Extension(crate::auth::middleware::AdminId(admin_id)): axum::Extension<
        crate::auth::middleware::AdminId,
    >,
    Form(form): Form<LocalePrefForm>,
) -> Response {
    let locale = match Locale::ALL.iter().find(|l| l.code() == form.locale) {
        Some(l) => *l,
        None => {
            return (StatusCode::BAD_REQUEST, "unsupported locale").into_response();
        }
    };
    {
        let conn = state.meta.lock().await;
        if let Err(e) = conn.execute(
            "UPDATE admins SET locale = ?1 WHERE id = ?2",
            rusqlite::params![locale.code(), admin_id],
        ) {
            return internal(format!("update locale: {e}"));
        }
    }
    let cookie = crate::mgmt::i18n::build_locale_cookie(locale);
    let mut resp = Redirect::to("/drust/admin/settings").into_response();
    resp.headers_mut()
        .insert(header::SET_COOKIE, cookie.parse().unwrap());
    resp
}

#[derive(Debug, serde::Deserialize)]
struct ThemePrefForm {
    theme: String,
}

/// `POST /admin/settings/theme` — persist the admin's UI theme to
/// `admins.theme` and mirror it back as the `drust_theme` cookie so the
/// next render picks it up. Validation: only codes in `Theme::ALL`
/// accepted; everything else returns 400 (the dropdown can't submit
/// unknown values, so this is purely defensive).
async fn settings_theme_save(
    State(state): State<MgmtState>,
    axum::Extension(crate::auth::middleware::AdminId(admin_id)): axum::Extension<
        crate::auth::middleware::AdminId,
    >,
    Form(form): Form<ThemePrefForm>,
) -> Response {
    let theme = match crate::mgmt::theme::Theme::ALL
        .iter()
        .find(|t| t.code() == form.theme)
    {
        Some(t) => *t,
        None => {
            return (StatusCode::BAD_REQUEST, "unsupported theme").into_response();
        }
    };
    {
        let conn = state.meta.lock().await;
        if let Err(e) = conn.execute(
            "UPDATE admins SET theme = ?1 WHERE id = ?2",
            rusqlite::params![theme.code(), admin_id],
        ) {
            return internal(format!("update theme: {e}"));
        }
    }
    let cookie = crate::mgmt::theme::build_theme_cookie(theme);
    let mut resp = Redirect::to("/drust/admin/settings").into_response();
    resp.headers_mut()
        .insert(header::SET_COOKIE, cookie.parse().unwrap());
    resp
}

#[derive(Debug, Deserialize)]
struct SettingsForm {
    locale: String,
    theme: String,
}

/// `POST /admin/settings` — combined save handler that updates BOTH
/// `admins.locale` and `admins.theme` in one round trip. Used by the
/// v1.23 settings page redesign that batches both changes behind a
/// single Save button (Save / Cancel pair sit at the bottom of the
/// Preferences card). The single-field endpoints
/// `/admin/settings/locale` and `/admin/settings/theme` are preserved
/// for any future sidebar quick-switcher.
async fn settings_combined_save(
    State(state): State<MgmtState>,
    axum::Extension(crate::auth::middleware::AdminId(admin_id)): axum::Extension<
        crate::auth::middleware::AdminId,
    >,
    Form(form): Form<SettingsForm>,
) -> Response {
    let locale = match Locale::ALL.iter().find(|l| l.code() == form.locale) {
        Some(l) => *l,
        None => return (StatusCode::BAD_REQUEST, "unsupported locale").into_response(),
    };
    let theme = match crate::mgmt::theme::Theme::ALL
        .iter()
        .find(|t| t.code() == form.theme)
    {
        Some(t) => *t,
        None => return (StatusCode::BAD_REQUEST, "unsupported theme").into_response(),
    };
    {
        let conn = state.meta.lock().await;
        if let Err(e) = conn.execute(
            "UPDATE admins SET locale = ?1, theme = ?2 WHERE id = ?3",
            rusqlite::params![locale.code(), theme.code(), admin_id],
        ) {
            return internal(format!("update settings: {e}"));
        }
    }
    let locale_cookie = crate::mgmt::i18n::build_locale_cookie(locale);
    let theme_cookie = crate::mgmt::theme::build_theme_cookie(theme);
    let mut resp = Redirect::to("/drust/admin/settings").into_response();
    resp.headers_mut()
        .insert(header::SET_COOKIE, locale_cookie.parse().unwrap());
    resp.headers_mut()
        .append(header::SET_COOKIE, theme_cookie.parse().unwrap());
    resp
}

#[derive(Debug, Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

#[derive(Debug, Default, Deserialize)]
struct LoginPageQuery {
    #[serde(default)]
    oauth_error: Option<String>,
}

async fn login_page(
    State(state): State<MgmtState>,
    LocaleHint(locale): LocaleHint,
    crate::mgmt::theme::ThemeHint(theme): crate::mgmt::theme::ThemeHint,
    Query(q): Query<LoginPageQuery>,
) -> Html<String> {
    let trc = crate::mgmt::theme::ThemeRenderCtx::build(theme);
    Html(
        LoginPage {
            error: None,
            version: env!("CARGO_PKG_VERSION"),
            oauth_providers: state
                .oauth_registry
                .enabled_names()
                .into_iter()
                .map(String::from)
                .collect(),
            oauth_error: q.oauth_error,
            t: Translator::new(locale),
            palette_resolved: trc.palette_resolved,
            mascot_json_static: trc.mascot_json_static,
            mascot_json_light: trc.mascot_json_light,
            mascot_json_dark: trc.mascot_json_dark,
        }
        .render()
        .unwrap(),
    )
}

async fn login_submit(
    State(state): State<MgmtState>,
    LocaleHint(locale): LocaleHint,
    crate::mgmt::theme::ThemeHint(theme): crate::mgmt::theme::ThemeHint,
    headers: axum::http::HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    let op = "POST /login";
    // v1.19.2 — per-IP rate limit. Same shape as tenant login_handler.
    let fallback_addr: std::net::SocketAddr = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
    let ip = crate::safety::ip::client_ip(&headers, fallback_addr);
    if !state.admin_login_rl.check(ip) {
        let mut entry =
            crate::safety::audit::AuditEntry::failure("-", "-", op, 0, "HTTP_429", "rate limited");
        entry.auth_method = Some("password".to_string());
        entry = entry.with_extra(serde_json::json!({ "auth_kind": "admin" }));
        crate::safety::audit::write_entry(&state.log_dir, &entry).await;
        let mut resp = axum::Json(serde_json::json!({
            "error_code": "RATE_LIMITED_IP",
            "message": "rate limited",
        }))
        .into_response();
        *resp.status_mut() = axum::http::StatusCode::TOO_MANY_REQUESTS;
        return resp;
    }
    let mut conn = state.meta.lock().await;
    let row: Option<(i64, String, Option<String>, Option<String>)> = conn
        .query_row(
            "SELECT id, password_hash, locale, theme FROM admins WHERE username = ?1",
            rusqlite::params![form.username],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .ok();
    let (admin_id, phc, admin_locale, admin_theme) = match row {
        Some((id, hash, loc, th)) => (id, hash, loc, th),
        None => {
            // S1: spend one argon2 verify so timing matches the wrong-password
            // path — prevents admin username existence leaking via wall-clock.
            let _ = verify_password(dummy_hash(), &form.password);
            let mut entry =
                crate::safety::audit::AuditEntry::failure("-", "-", op, 0, "HTTP_401", "");
            entry.auth_method = Some("password".to_string());
            entry = entry.with_extra(serde_json::json!({ "auth_kind": "admin" }));
            crate::safety::audit::write_entry(&state.log_dir, &entry).await;
            return unauthorized("Invalid credentials", &state, locale, theme);
        }
    };
    match verify_password(&phc, &form.password) {
        Ok(true) => {}
        _ => {
            let mut entry =
                crate::safety::audit::AuditEntry::failure("-", "-", op, 0, "HTTP_401", "");
            entry.auth_method = Some("password".to_string());
            entry = entry.with_extra(serde_json::json!({ "auth_kind": "admin" }));
            crate::safety::audit::write_entry(&state.log_dir, &entry).await;
            return unauthorized("Invalid credentials", &state, locale, theme);
        }
    }
    let ttl_secs = (state.session_ttl_days * 86_400) as i64;
    let token = match create_session(&mut conn, admin_id, ttl_secs) {
        Ok(t) => t,
        Err(e) => return internal(e.to_string()),
    };
    drop(conn);
    let mut entry = crate::safety::audit::AuditEntry::success("-", "-", op, 0)
        .with_extra(serde_json::json!({ "admin_id": admin_id, "auth_kind": "admin" }));
    entry.auth_method = Some("password".to_string());
    crate::safety::audit::write_entry(&state.log_dir, &entry).await;
    let cookie = build_session_cookie(&token, state.session_ttl_days * 86_400);
    let mut resp = Redirect::to("/drust/admin/tenants").into_response();
    resp.headers_mut()
        .insert(header::SET_COOKIE, cookie.parse().unwrap());
    // v1.28.1: expire any pre-v1.28.1 cookies that login wrote with `Path=/`.
    // Those bypassed the canonical Path=/drust path used by /admin/settings,
    // so after Save the browser would hold both copies and CookieJar::get
    // returned the stale Path=/ value — making Save look like a no-op.
    // Sending Max-Age=0 with the same Path the bad cookie was written under
    // deletes it from the browser jar; the new canonical cookie below then
    // takes over cleanly.
    let expire_legacy_locale = "drust_locale=; Path=/; Max-Age=0; SameSite=Lax";
    let expire_legacy_theme = "drust_theme=; Path=/; Max-Age=0; SameSite=Lax";
    resp.headers_mut()
        .append(header::SET_COOKIE, expire_legacy_locale.parse().unwrap());
    resp.headers_mut()
        .append(header::SET_COOKIE, expire_legacy_theme.parse().unwrap());

    // v1.22 — if this admin has a persisted locale, push it down as a cookie
    // so the next page renders in their preferred language regardless of
    // which device they signed in from. `append` not `insert` — must coexist
    // with the session cookie above. v1.28.1: route through the canonical
    // build_locale_cookie / build_theme_cookie helpers so attributes (Path,
    // Secure, SameSite) match what /admin/settings writes — otherwise the
    // two cookies coexist with different Paths and the Save-changed value
    // gets shadowed by the stale login-set one.
    if let Some(loc) = admin_locale.as_deref()
        && let Some(l) = crate::mgmt::i18n::Locale::from_tag(loc)
    {
        let locale_cookie = crate::mgmt::i18n::build_locale_cookie(l);
        resp.headers_mut()
            .append(header::SET_COOKIE, locale_cookie.parse().unwrap());
    }
    if let Some(th) = admin_theme.as_deref()
        && let Some(t) = crate::mgmt::theme::Theme::from_tag(th)
    {
        let theme_cookie = crate::mgmt::theme::build_theme_cookie(t);
        resp.headers_mut()
            .append(header::SET_COOKIE, theme_cookie.parse().unwrap());
    }
    resp
}

async fn logout_submit(State(state): State<MgmtState>, headers: axum::http::HeaderMap) -> Response {
    if let Some(c) = headers.get(header::COOKIE).and_then(|v| v.to_str().ok())
        && let Some(tok) = c.split(';').find_map(|p| {
            let t = p.trim();
            t.strip_prefix("drust_session=").map(|s| s.to_string())
        })
    {
        let mut conn = state.meta.lock().await;
        let _ = revoke_session(&mut conn, &tok);
    }
    let mut resp = Redirect::to("/drust/login").into_response();
    resp.headers_mut()
        .insert(header::SET_COOKIE, clear_session_cookie().parse().unwrap());
    resp
}

async fn root_redirect() -> Redirect {
    Redirect::to("/drust/admin/tenants")
}

fn unauthorized(
    msg: &str,
    state: &MgmtState,
    locale: Locale,
    theme: crate::mgmt::theme::Theme,
) -> Response {
    let trc = crate::mgmt::theme::ThemeRenderCtx::build(theme);
    let body = LoginPage {
        error: Some(msg.to_string()),
        version: env!("CARGO_PKG_VERSION"),
        oauth_providers: state
            .oauth_registry
            .enabled_names()
            .into_iter()
            .map(String::from)
            .collect(),
        oauth_error: None,
        t: Translator::new(locale),
        palette_resolved: trc.palette_resolved,
        mascot_json_static: trc.mascot_json_static,
        mascot_json_light: trc.mascot_json_light,
        mascot_json_dark: trc.mascot_json_dark,
    }
    .render()
    .unwrap();
    let mut r = Html(body).into_response();
    *r.status_mut() = StatusCode::UNAUTHORIZED;
    r
}

fn internal(msg: String) -> Response {
    let mut r = msg.into_response();
    *r.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    r
}

async fn legacy_files_redirect() -> Response {
    let mut resp = "".into_response();
    *resp.status_mut() = StatusCode::MOVED_PERMANENTLY;
    resp.headers_mut()
        .insert(header::LOCATION, "/admin/files".parse().unwrap());
    resp
}

async fn legacy_reconcile_redirect() -> Response {
    let mut resp = "".into_response();
    *resp.status_mut() = StatusCode::MOVED_PERMANENTLY;
    resp.headers_mut()
        .insert(header::LOCATION, "/admin/files/reconcile".parse().unwrap());
    resp
}

pub fn build_mgmt_router(state: MgmtState) -> Router {
    // v1.22 — `init_bundles` is idempotent (OnceLock::get_or_init). Calling
    // it here means every code path that materialises an admin router gets
    // the i18n bundles loaded, including integration tests that bypass
    // `main.rs`. Production main also calls this directly; the second call
    // is a cheap no-op.
    crate::mgmt::i18n::init_bundles();
    // build_mgmt_router covers only the unauthenticated mini-router
    // (/login, /logout, root redirect) — no AdminId ever in extensions here,
    // so outer (cookie-only) layer is correct.
    let theme_state = crate::mgmt::theme_layer::ThemeLayerState {
        meta: state.meta.clone(),
        allow_db_fallback: false,
    };
    Router::new()
        .route("/", get(root_redirect))
        .route("/login", get(login_page).post(login_submit))
        .route("/logout", post(logout_submit))
        .layer(axum::middleware::from_fn(
            crate::mgmt::locale_layer::locale_layer,
        ))
        .layer(axum::middleware::from_fn_with_state(
            theme_state,
            crate::mgmt::theme_layer::theme_layer,
        ))
        .with_state(state)
}

#[cfg(any(test, debug_assertions))]
impl MgmtState {
    /// Test/debug-only constructor. Mirrors `TenantsState::test_default`:
    /// callers pass the inputs that vary per test; everything else defaults to
    /// production-equivalent values. Override a `pub` field post-construction
    /// for the rare non-default case.
    pub fn test_default(
        meta: Arc<Mutex<Connection>>,
        data_dir: std::path::PathBuf,
        tenants: Arc<crate::storage::pool::TenantRegistry>,
        mcp: Arc<crate::mcp::http_registry::McpHttpRegistry>,
        bus: crate::tenant::events::EventBus,
        bus_rooms: crate::tenant::rooms::RoomBus,
    ) -> Self {
        let audit_meta_read = Arc::new(tokio::sync::Mutex::new(
            crate::safety::audit_db::open_audit_db_memory().expect("in-memory audit DB for tests"),
        ));
        let log_dir = data_dir.join("logs");
        let (functions, functions_exec, _cfg) = crate::functions::test_stack_parts(tenants.clone());
        Self {
            meta,
            audit_meta_read,
            session_ttl_days: 7,
            garage: None,
            public_base_url: "http://localhost:8793".to_string(),
            max_upload_bytes: 52_428_800, // 50 MiB
            garage_client_key_id: String::new(),
            disk_min_free_pct: 20,
            log_dir,
            url_sign_secret: Arc::new([0u8; 32]),
            tenants,
            mcp,
            bus,
            bus_rooms,
            index_large_table_rows: 1_000_000,
            public_url: String::new(),
            oauth_registry: Arc::new(crate::oauth::ProviderRegistry::from_env_empty()),
            admin_login_rl: Arc::new(crate::safety::rate_limit_ip::IpRateLimit::new(
                5,
                std::time::Duration::from_secs(60),
                4096,
            )),
            admin_oauth_callback_rl: Arc::new(crate::safety::rate_limit_ip::IpRateLimit::new(
                5,
                std::time::Duration::from_secs(60),
                4096,
            )),
            large_upload_max_bytes: 2 * 1024 * 1024 * 1024, // 2 GiB
            large_upload_chunk_max_bytes: 64 * 1024 * 1024, // 64 MiB
            large_upload_max_sessions_per_tenant: 5,
            large_upload_session_ttl_secs: 86_400,
            auth_cache: Arc::new(crate::tenant::auth_cache::AuthCache::new(
                std::time::Duration::from_secs(10),
                200_000,
            )),
            functions,
            functions_exec,
            fn_data_root: data_dir,
        }
    }
}

impl MgmtState {
    pub fn with_data_dir(self, data_dir: std::path::PathBuf) -> Router {
        // v1.22 — idempotent (OnceLock::get_or_init). Production main also
        // calls this; tests that bypass main need it here.
        crate::mgmt::i18n::init_bundles();
        use crate::auth::middleware::{AdminSessionState, admin_session_layer};
        use crate::mgmt::public_files::{
            PublicFilesState, admin_sign_url, admin_stream_bytes, delete_submit,
            list_page as public_files_list_page, reconcile_apply, reconcile_page, upload_submit,
        };
        use crate::mgmt::tenant_files::{
            TenantFilesState, delete_one as tfiles_delete, set_visibility_admin as tfiles_set_vis,
            sign_url as tfiles_sign, stream_bytes as tfiles_stream, upload as tfiles_upload,
        };
        use crate::mgmt::tenants::{
            TenantsState, cmdk_tenants_json, create_tenant_form, create_tenant_json,
            get_publish_policy, list_page_axum, patch_publish_policy, soft_delete_tenant,
            soft_delete_tenant_form, tenant_files_admin_page, tenant_oauth_provider_delete,
            tenant_oauth_provider_upsert, tenant_oauth_providers_page, tenant_overview_page,
            tenant_webhook_create_form, tenant_webhook_delete_form, tenant_webhooks_page,
            toggle_self_register,
        };
        use axum::extract::DefaultBodyLimit;

        let session = AdminSessionState {
            meta: self.meta.clone(),
        };
        let tenants_state = TenantsState {
            session: session.clone(),
            data_dir: data_dir.clone(),
            garage: self.garage.clone(),
            garage_client_key_id: self.garage_client_key_id.clone(),
            max_upload_bytes: self.max_upload_bytes,
            disk_min_free_pct: self.disk_min_free_pct,
            public_base_url: self.public_base_url.clone(),
            tenants: self.tenants.clone(),
            mcp: self.mcp.clone(),
            bus: self.bus.clone(),
            bus_rooms: self.bus_rooms.clone(),
            log_dir: self.log_dir.clone(),
            audit_meta_read: self.audit_meta_read.clone(),
            index_large_table_rows: self.index_large_table_rows,
            auth_cache: self.auth_cache.clone(),
            functions: self.functions.clone(),
            functions_exec: self.functions_exec.clone(),
            fn_data_root: self.fn_data_root.clone(),
        };
        let public_files_state = PublicFilesState {
            session: session.clone(),
            meta: self.meta.clone(),
            garage: self.garage.clone(),
            base_url: self.public_base_url.clone(),
            max_upload_bytes: self.max_upload_bytes,
            disk_min_free_pct: self.disk_min_free_pct,
            garage_client_key_id: self.garage_client_key_id.clone(),
            url_sign_secret: self.url_sign_secret.clone(),
        };
        let tenant_files_state = TenantFilesState {
            garage: self.garage.clone(),
            data_root: data_dir.clone(),
            disk_min_free_pct: self.disk_min_free_pct,
            max_upload_bytes: self.max_upload_bytes,
            public_base_url: self.public_base_url.clone(),
            url_sign_secret: self.url_sign_secret.clone(),
            tenants: self.tenants.clone(),
            large_upload_max_bytes: self.large_upload_max_bytes,
            large_upload_chunk_max_bytes: self.large_upload_chunk_max_bytes,
            large_upload_max_sessions_per_tenant: self.large_upload_max_sessions_per_tenant,
            large_upload_session_ttl_secs: self.large_upload_session_ttl_secs,
            functions: self.functions.clone(),
        };
        let signed_bytes_state = crate::mgmt::signed_bytes::SignedBytesState {
            meta: self.meta.clone(),
            data_root: data_dir.clone(),
            garage: self.garage.clone(),
            url_sign_secret: self.url_sign_secret.clone(),
        };
        let backups_state = crate::mgmt::backups::BackupsState {
            data_dir: data_dir.clone(),
        };

        let public = Router::new()
            .route("/", get(root_redirect))
            .route("/login", get(login_page).post(login_submit))
            .route("/logout", post(logout_submit))
            .route(
                "/admin/oauth/{provider}/start",
                get(crate::mgmt::oauth_login::oauth_start),
            )
            .route(
                "/admin/oauth/{provider}/callback",
                get(crate::mgmt::oauth_login::oauth_callback),
            )
            .with_state(self.clone());

        // Legacy redirects (back-compat v1.4.0) — 301 to the new paths. These don't require
        // authentication since they're just static redirects.
        let legacy_redirects = Router::new()
            .route("/admin/public-files", get(legacy_files_redirect))
            .route(
                "/admin/public-files/reconcile",
                get(legacy_reconcile_redirect),
            );

        // Unauth public signed-bytes endpoints — token validates in the handler.
        let signed_router = Router::new()
            .route(
                "/s/admin/{key}",
                get(crate::mgmt::signed_bytes::admin_signed_bytes),
            )
            .route(
                "/s/t/{tenant}/{key}",
                get(crate::mgmt::signed_bytes::tenant_signed_bytes),
            )
            .with_state(signed_bytes_state);

        // Tenant admin sub-router (existing behaviour).
        let tenants_router = Router::new()
            .route("/admin/tenants", get(list_page_axum))
            .route("/admin/tenants/new", post(create_tenant_form))
            .route("/admin/api/tenants", post(create_tenant_json))
            .route("/admin/api/cmdk/tenants", get(cmdk_tenants_json))
            .route(
                "/admin/api/tenants/{id}",
                axum::routing::delete(soft_delete_tenant),
            )
            .route("/admin/tenants/{id}/delete", post(soft_delete_tenant_form))
            .route("/admin/tenants/{id}", get(super::tokens::detail_redirect))
            .route("/admin/tenants/{id}/_overview", get(tenant_overview_page))
            // v1.31 — broadcast room operations (drop hung subscribers).
            .route(
                "/admin/tenants/{id}/realtime/evict-all",
                post(super::admin_rooms::evict_all_rooms_handler),
            )
            .route(
                "/admin/tenants/{id}/realtime/rooms/{room}/evict",
                post(super::admin_rooms::evict_room_handler),
            )
            .route(
                "/admin/tenants/{id}/_api_keys",
                get(super::tokens::api_keys_page),
            )
            .route(
                "/admin/tenants/{id}/_broadcast",
                get(super::tenant_broadcast::broadcast_inspector_page),
            )
            .route("/admin/tenants/{id}/_rpc", get(super::rpc_admin::rpc_index))
            .route(
                "/admin/tenants/{id}/_rpc/new",
                get(super::rpc_admin::rpc_new_form).post(super::rpc_admin::rpc_save),
            )
            .route(
                "/admin/tenants/{id}/_rpc/{name}/edit",
                get(super::rpc_admin::rpc_edit_form),
            )
            .route(
                "/admin/tenants/{id}/_rpc/{name}/save",
                post(super::rpc_admin::rpc_save),
            )
            .route(
                "/admin/tenants/{id}/_rpc/{name}/delete",
                post(super::rpc_admin::rpc_delete),
            )
            .route(
                "/admin/tenants/{id}/_rpc/{name}/test",
                get(super::rpc_admin::rpc_test_form),
            )
            .route(
                "/admin/tenants/{id}/_rpc/{name}/test/run",
                post(super::rpc_admin::rpc_test_run),
            )
            .route(
                "/admin/api/tenants/{id}/tokens/{role}/reroll",
                post(super::tokens::reroll_token_json),
            )
            .route(
                "/admin/tenants/{id}/tokens/{role}/reroll",
                post(super::tokens::reroll_token_form),
            )
            .route("/admin/tenants/{id}/_files", get(tenant_files_admin_page))
            // Legacy alias: /files → 301 /_files. v1.32.7 renamed the page
            // URL for consistency with the other virtual sidebar entries
            // (_overview, _api_keys, _rpc, _broadcast, _oauth_providers,
            // _webhooks, _logs). Bookmarks + browser history under /files
            // still resolve via this redirect. Sub-routes (/files/upload,
            // /files/<key>, /files/<key>/sign, /files/<key>/bytes) stay on
            // /files because they're API/action endpoints — only the page
            // URL changed.
            .route(
                "/admin/tenants/{id}/files",
                get(super::tenant_files::redirect_legacy_files_page),
            )
            .route("/admin/_docs/changelog", get(super::docs::changelog_page))
            .route(
                "/admin/tenants/{id}/collections",
                get(super::browse::collections_page),
            )
            .route(
                "/admin/tenants/{id}/collections/{coll}",
                get(super::browse::collection_rows_page),
            )
            .route(
                "/admin/tenants/{id}/collections/{coll}/anon-caps",
                post(super::browse::update_anon_caps),
            )
            .route(
                "/admin/tenants/{id}/collections/{coll}/realtime",
                post(super::browse::update_realtime),
            )
            .route(
                "/admin/tenants/{id}/collections/{coll}/description",
                post(super::browse::admin_update_collection_description),
            )
            .route(
                "/admin/tenants/{id}/collections/{coll}/fields/{field}/description",
                post(super::browse::admin_update_field_description),
            )
            .route(
                "/admin/tenants/{id}/collections/{coll}/indexes/{index_name}/description",
                post(super::browse::admin_update_index_description),
            )
            .route(
                "/admin/tenants/{id}/collections/{coll}/_indexes",
                post(super::browse::create_index_admin),
            )
            .route(
                "/admin/tenants/{id}/collections/{coll}/_indexes/{name}",
                axum::routing::delete(super::browse::drop_index_admin),
            )
            .route(
                "/admin/tenants/{id}/collections/{coll}/_explain",
                post(super::browse::explain_admin),
            )
            .route(
                "/admin/tenants/{id}/collections/{coll}/policies",
                post(super::browse::admin_update_policies),
            )
            .route(
                "/admin/tenants/{id}/collections/{coll}/_list",
                post(super::collection_list::admin_list_handler),
            )
            .route("/admin/audit", get(super::audit::audit_host_page))
            .route(
                "/admin/tenants/{id}/_logs",
                get(super::audit::audit_tenant_page),
            )
            .route(
                "/admin/tenants/{id}/allow-self-register",
                post(toggle_self_register),
            )
            // v1.32.5 — publish-policy flags (allow_user_publish /
            // allow_anon_publish). PATCH partial-updates either or both;
            // GET reads current state. MCP `broadcast` ignores these.
            .route(
                "/admin/tenants/{id}/publish-policy",
                axum::routing::get(get_publish_policy).patch(patch_publish_policy),
            )
            // v1.12 per-tenant OAuth admin UI — virtual sidebar entry
            // `🔐 _oauth_providers`. GET renders the page; POST upserts a
            // provider (form-encoded); `<provider>/delete` removes one.
            .route(
                "/admin/tenants/{id}/_oauth_providers",
                get(tenant_oauth_providers_page).post(tenant_oauth_provider_upsert),
            )
            .route(
                "/admin/tenants/{id}/_oauth_providers/{provider}/delete",
                post(tenant_oauth_provider_delete),
            )
            // v1.13 outbound webhooks admin UI — virtual sidebar entry
            // `🔔 _webhooks`. GET renders the page; POST inserts a new
            // subscription + 303s with a short-lived secret-once cookie;
            // `<wid>/delete` removes one. The same `_system_webhooks` table
            // is also reachable via the service-only REST endpoints
            // (src/tenant/webhook_routes.rs) and the MCP tools — this is
            // the UI surface.
            .route(
                "/admin/tenants/{id}/_webhooks",
                get(tenant_webhooks_page).post(tenant_webhook_create_form),
            )
            .route(
                "/admin/tenants/{id}/_webhooks/{wid}/delete",
                post(tenant_webhook_delete_form),
            )
            // v1.36 edge-functions admin UI — virtual sidebar entry
            // `ƒ _functions`. GET renders the list + per-function logs + the
            // test-invoke form; `<name>/toggle` flips active; `<name>/delete`
            // removes the row + GCs the wasm artifact; `<name>/invoke` runs a
            // synchronous test-invoke and re-renders with the outcome inline.
            // Upload stays REST-only in v1 (the page shows the curl snippet).
            .route(
                "/admin/tenants/{id}/_functions",
                get(super::functions_admin::page),
            )
            .route(
                "/admin/tenants/{id}/_functions/{name}/toggle",
                post(super::functions_admin::toggle),
            )
            .route(
                "/admin/tenants/{id}/_functions/{name}/delete",
                post(super::functions_admin::delete),
            )
            .route(
                "/admin/tenants/{id}/_functions/{name}/invoke",
                post(super::functions_admin::invoke),
            )
            .with_state(tenants_state);

        // Backups sub-router — list + download snapshots produced by
        // drust-backup.timer. Read-only; restore is intentionally manual
        // (extract via `tar --zstd -xf`) until we add a guarded UI flow.
        let backups_router = Router::new()
            .route("/admin/backups", get(super::backups::list_page))
            .route(
                "/admin/backups/{filename}/download",
                get(super::backups::download_one),
            )
            .route(
                "/admin/backups/{filename}/inspect",
                get(super::backups::inspect),
            )
            .route(
                "/admin/backups/{filename}/restore",
                post(super::backups::restore_tenant),
            )
            .with_state(backups_state);

        // Public-files sub-router (new in v1.4.0). Upload route carries its
        // own DefaultBodyLimit so multipart payloads larger than the cap
        // return 413 without consuming memory.
        let public_files_router = Router::new()
            // Renamed routes (new in Y):
            .route("/admin/files", get(public_files_list_page))
            .route(
                "/admin/files/upload",
                post(upload_submit).layer(DefaultBodyLimit::max(self.max_upload_bytes)),
            )
            .route("/admin/files/{id}/delete", post(delete_submit))
            .route(
                "/admin/files/reconcile",
                get(reconcile_page).post(reconcile_apply),
            )
            .route("/admin/files/{key}/bytes", get(admin_stream_bytes))
            .route("/admin/files/{key}/sign", post(admin_sign_url))
            .with_state(public_files_state);

        // Admin-scoped tenant files sub-router — uploads land in the tenant's
        // own buckets (tenant-{id}-pub / tenant-{id}-prv) and its data.sqlite
        // _system_files. Reuses the tenant-side handlers unchanged; admin
        // auth is applied via `protected` below.
        let admin_tenant_files_router = Router::new()
            .route(
                "/admin/tenants/{id}/files/upload",
                post(tfiles_upload).layer(DefaultBodyLimit::max(self.max_upload_bytes)),
            )
            .route(
                "/admin/tenants/{id}/files/{key}",
                axum::routing::delete(tfiles_delete),
            )
            .route("/admin/tenants/{id}/files/{key}/sign", post(tfiles_sign))
            .route("/admin/tenants/{id}/files/{key}/bytes", get(tfiles_stream))
            .route(
                "/admin/tenants/{id}/files/{key}/visibility",
                post(tfiles_set_vis),
            )
            .with_state(tenant_files_state);

        // Internal design-system showcase. Renders every component class
        // from _styles.html in isolation. Admin-gated so it doesn't leak
        // into public crawl, but otherwise stateless.
        let design_router = Router::new().route("/admin/_design", get(design_showcase));

        // v1.32 C1 — Prometheus metrics endpoint. Admin-session-gated;
        // exposes operational counters for ISO/IEC 27001 A.8.16 compliance.
        let metrics_router = Router::new()
            .route("/admin/_metrics", get(super::metrics::handler))
            .with_state(self.clone());

        // Per-admin preferences hub. First section: locale switch (was on
        // the topbar pre-2026-05-22). Future home for keyboard shortcuts,
        // notifications, profile, etc. Save path writes through to
        // `admins.locale` so the choice follows the admin across devices;
        // the cookie is a per-device mirror of the same value.
        let settings_state = self.clone();
        let settings_router = Router::new()
            .route(
                "/admin/settings",
                get(settings_page).post(settings_combined_save),
            )
            .route("/admin/settings/locale", post(settings_locale_save))
            .route("/admin/settings/theme", post(settings_theme_save))
            .route(
                "/admin/settings/token/reroll",
                axum::routing::post(super::admin_pat::reroll),
            )
            .with_state(settings_state);

        // v1.29.0 — admin team management CRUD.
        let team_router = Router::new()
            .route(
                "/admin/team",
                get(super::admin_team::team_page_or_json).post(super::admin_team::invite_admin),
            )
            .route(
                "/admin/team/{id}",
                axum::routing::delete(super::admin_team::remove_admin),
            )
            .route(
                "/admin/team/{id}/role",
                axum::routing::patch(super::admin_team::change_role),
            )
            .with_state(self.clone());

        // v1.25 — inner theme layer: runs after admin_session_layer so
        // AdminId is in request extensions. Falls back cookie → DB → System.
        // Overwrites whatever the outer layer set. (F5/F6 from v1.23 review.)
        let inner_theme_state = crate::mgmt::theme_layer::ThemeLayerState {
            meta: self.meta.clone(),
            allow_db_fallback: true,
        };
        // v1.28.9 — admin profile layer: runs after admin_session_layer so
        // AdminId is in extensions, then loads display_name/email/picture_url
        // from admins and injects Extension<AdminProfileExt>. Sidebar
        // templates read this through every page struct's `pub admin` field.
        let profile_state = crate::mgmt::admin_profile::AdminProfileLayerState {
            meta: self.meta.clone(),
        };
        // v1.28.14 — axum's `.layer()` makes the LAST-applied layer the
        // OUTERMOST (runs FIRST on request descent). For profile/theme to
        // read `Extension<AdminId>` they must run AFTER session_layer sets
        // it — which means session must be applied LAST and the readers
        // applied FIRST. Previous order (session first, theme last) had
        // profile_layer always seeing an empty extensions map and falling
        // back to `placeholder()` → "??" + "admin" in the sidebar.
        let protected = tenants_router
            .merge(public_files_router)
            .merge(admin_tenant_files_router)
            .merge(backups_router)
            .merge(design_router)
            .merge(metrics_router)
            .merge(settings_router)
            .merge(team_router)
            .layer(axum::middleware::from_fn_with_state(
                inner_theme_state,
                crate::mgmt::theme_layer::theme_layer,
            ))
            .layer(axum::middleware::from_fn_with_state(
                profile_state,
                crate::mgmt::admin_profile::admin_profile_layer,
            ))
            .layer(axum::middleware::from_fn_with_state(
                session,
                admin_session_layer,
            ));

        // Outer theme layer: cookie-only (allow_db_fallback=false). Covers
        // unauthenticated routes (/login, OAuth callback) where AdminId is
        // not yet populated. Inner layer (above) overwrites this for
        // authenticated routes.
        let outer_theme_state = crate::mgmt::theme_layer::ThemeLayerState {
            meta: self.meta.clone(),
            allow_db_fallback: false,
        };
        public
            .merge(legacy_redirects)
            .merge(signed_router)
            .merge(protected)
            // v1.22 i18n — outermost layer so unauthenticated routes
            // (`/login`, `/admin/oauth/<provider>/callback`) also resolve
            // a locale and let users switch language before signing in.
            .layer(axum::middleware::from_fn(
                crate::mgmt::locale_layer::locale_layer,
            ))
            .layer(axum::middleware::from_fn_with_state(
                outer_theme_state,
                crate::mgmt::theme_layer::theme_layer,
            ))
    }
}
