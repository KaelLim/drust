use crate::auth::middleware::AdminSessionState;
use crate::mgmt::i18n::{Locale, LocaleHint, Translator};
use crate::storage::garage::GarageClient;
use askama::Template;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;

mod common;
mod crud;
mod files_page;
mod overview;

pub use crud::{
    cmdk_tenants_json, create_tenant_form, create_tenant_json, get_publish_policy,
    list_page_axum, patch_publish_policy, soft_delete_tenant, soft_delete_tenant_form,
    toggle_self_register,
};
pub use files_page::tenant_files_admin_page;
pub use overview::tenant_overview_page;

#[derive(Clone)]
pub struct TenantsState {
    pub session: AdminSessionState,
    pub data_dir: PathBuf,
    pub garage: Option<Arc<GarageClient>>,
    pub garage_client_key_id: String,
    /// Used by the admin tenant-files subpage to render disk banner + form cap.
    pub max_upload_bytes: usize,
    pub disk_min_free_pct: u8,
    pub public_base_url: String,
    /// Shared per-tenant pool registry. Admin handlers that mutate
    /// schema-cached state (e.g. the anon_caps editor) reach in here
    /// to invalidate the cache so REST/MCP requests pick up the change
    /// on the very next call.
    pub tenants: Arc<crate::storage::pool::TenantRegistry>,
    /// Per-tenant MCP service registry. Used by soft_delete_tenant to
    /// evict the cached `DrustMcpService` so in-flight sessions release.
    pub mcp: Arc<crate::mcp::http_registry::McpHttpRegistry>,
    /// SSE broadcast channels. Used by soft_delete_tenant to drop every
    /// channel keyed on the tenant.
    pub bus: crate::tenant::events::EventBus,
    /// v1.31 broadcast rooms bus. Mirrors `bus` for ad-hoc per-room
    /// WS multiplex channels. `soft_delete_tenant` evicts both.
    pub bus_rooms: crate::tenant::rooms::RoomBus,
    /// Directory containing `audit-YYYY-MM-DD.jsonl` files. Sourced from
    /// `$DRUST_LOG_DIR` at boot; consumed by the admin audit UI handlers
    /// mounted under tenants_router.
    pub log_dir: PathBuf,
    /// v1.24 — read-only connection to `meta_logs.sqlite`. Consumed by
    /// the admin audit UI (`audit_host_page` / `audit_tenant_page`) which
    /// now queries SQL directly instead of scanning JSONL.
    pub audit_meta_read: std::sync::Arc<tokio::sync::Mutex<rusqlite::Connection>>,
    /// Row count threshold above which index creation is considered "large
    /// table" and returns `LARGE_TABLE` unless `force=true`. Sourced from
    /// `DRUST_INDEX_LARGE_TABLE_ROWS` (default 1 000 000).
    pub index_large_table_rows: u64,
}

/// Test-only constructor available in debug builds.
///
/// Defaults:
/// - `garage`: `None` (no S3 client)
/// - `garage_client_key_id`: `""`
/// - `max_upload_bytes`: 1 MiB (1 048 576)
/// - `disk_min_free_pct`: 20
/// - `public_base_url`: `"http://localhost"`
/// - `log_dir`: `data_dir.join("logs")`
/// - `index_large_table_rows`: 1 000 000
///
/// `session` is derived from `meta` directly.
#[cfg(any(test, debug_assertions))]
impl TenantsState {
    pub fn test_default(
        meta: std::sync::Arc<tokio::sync::Mutex<rusqlite::Connection>>,
        data_dir: PathBuf,
        tenants: std::sync::Arc<crate::storage::pool::TenantRegistry>,
        mcp: std::sync::Arc<crate::mcp::http_registry::McpHttpRegistry>,
        bus: crate::tenant::events::EventBus,
        bus_rooms: crate::tenant::rooms::RoomBus,
    ) -> Self {
        use crate::auth::middleware::AdminSessionState;
        let log_dir = data_dir.join("logs");
        let audit_meta_read = std::sync::Arc::new(tokio::sync::Mutex::new(
            crate::safety::audit_db::open_audit_db_memory().expect("in-memory audit DB for tests"),
        ));
        Self {
            session: AdminSessionState { meta: meta.clone() },
            data_dir,
            garage: None,
            garage_client_key_id: String::new(),
            max_upload_bytes: 1024 * 1024,
            disk_min_free_pct: 20,
            public_base_url: "http://localhost".to_string(),
            tenants,
            mcp,
            bus,
            bus_rooms,
            log_dir,
            audit_meta_read,
            index_large_table_rows: 1_000_000,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateTenantJson {
    /// Optional — auto-generated UUID v4 when omitted.
    #[serde(default)]
    pub id: Option<String>,
    pub name: String,
    #[serde(default)]
    pub quota_db_mb: Option<i64>,
    #[serde(default)]
    pub quota_rows: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct CreateTenantForm {
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct CreatedResp {
    pub tenant: TenantInfo,
    /// Both initial keys, shown once only.
    pub initial_tokens: InitialTokens,
    /// Back-compat field: equals `initial_tokens.service`.
    pub initial_token: String,
}

#[derive(Debug, Serialize)]
pub struct InitialTokens {
    pub anon: String,
    pub service: String,
}

#[derive(Debug, Serialize)]
pub struct TenantInfo {
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub quota_db_mb: i64,
    pub quota_rows: i64,
}

pub fn valid_slug(s: &str) -> bool {
    let bytes = s.as_bytes();
    if !(3..=40).contains(&bytes.len()) {
        return false;
    }
    let first = bytes[0];
    let last = bytes[bytes.len() - 1];
    let is_lead = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    if !is_lead(first) || !is_lead(last) {
        return false;
    }
    bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

// ─── v1.12: per-tenant OAuth providers admin UI ──────────────────────────────

#[derive(Template)]
#[template(path = "tenant_oauth_providers.html")]
struct TenantOauthProvidersPage {
    version: &'static str,
    tenant_id: String,
    tenant_name: String,
    providers: Vec<TenantOauthProviderRow>,
    /// Driver list for `_collection_sidebar.html`.
    collections: Vec<crate::storage::schema::Collection>,
    /// Always `"_oauth_providers"` here — sidebar `.on` matching.
    active_coll: String,
    /// Surfaced after a failed upsert (validation / DB error). `None`
    /// on the plain GET render.
    error: Option<String>,
    t: Translator,
    admin: crate::mgmt::admin_profile::AdminProfileExt,
    palette_resolved: crate::mgmt::theme::ResolvedPalette,
    mascot_json_static: String,
    mascot_json_light: String,
    mascot_json_dark: String,
}

struct TenantOauthProviderRow {
    provider: String,
    client_id: String,
    /// First 12 chars + ellipsis when long enough; otherwise full id.
    client_id_short: String,
    allowed_redirect_uris: Vec<String>,
    updated_at: String,
}

impl TenantOauthProviderRow {
    fn from_config(cfg: crate::tenant::oauth_config::OauthProviderConfig) -> Self {
        let client_id_short = if cfg.client_id.chars().count() > 16 {
            let truncated: String = cfg.client_id.chars().take(12).collect();
            format!("{truncated}…")
        } else {
            cfg.client_id.clone()
        };
        Self {
            provider: cfg.provider,
            client_id: cfg.client_id,
            client_id_short,
            allowed_redirect_uris: cfg.allowed_redirect_uris,
            updated_at: cfg.updated_at,
        }
    }
}

#[derive(Debug, serde::Deserialize)]
pub struct OauthProviderUpsertForm {
    pub provider: String,
    pub client_id: String,
    pub client_secret: String,
    /// Newline-separated list — the handler splits + trims + drops empties.
    pub allowed_redirect_uris: String,
}

/// Render the page. Internal helper so the upsert handler can surface an
/// error inline without an extra round-trip.
async fn render_oauth_providers_page(
    state: &TenantsState,
    tenant_id: String,
    error: Option<String>,
    locale: Locale,
    theme: crate::mgmt::theme::Theme,
    admin: crate::mgmt::admin_profile::AdminProfileExt,
) -> Response {
    let (tenant_name, collections) = match common::load_tenant_shell(state, &tenant_id).await {
        Ok(t) => t,
        Err(r) => return r,
    };

    // Read the providers via the shared pool's reader (consistent with the
    // REST admin endpoints, and uses the same connection cache).
    let providers: Vec<TenantOauthProviderRow> = match state.tenants.get_or_open(&tenant_id) {
        Ok(pool) => match pool
            .with_reader(|c| crate::tenant::oauth_config::list(c))
            .await
        {
            Ok(rows) => rows
                .into_iter()
                .map(TenantOauthProviderRow::from_config)
                .collect(),
            Err(_) => vec![],
        },
        Err(_) => vec![],
    };

    let trc = crate::mgmt::theme::ThemeRenderCtx::build(theme);
    Html(
        TenantOauthProvidersPage {
            version: env!("CARGO_PKG_VERSION"),
            tenant_id,
            tenant_name,
            providers,
            collections,
            active_coll: "_oauth_providers".to_string(),
            error,
            t: Translator::new(locale),
            admin,
            palette_resolved: trc.palette_resolved,
            mascot_json_static: trc.mascot_json_static,
            mascot_json_light: trc.mascot_json_light,
            mascot_json_dark: trc.mascot_json_dark,
        }
        .render()
        .unwrap(),
    )
    .into_response()
}

/// `GET /admin/tenants/{id}/_oauth_providers`
pub async fn tenant_oauth_providers_page(
    State(state): State<TenantsState>,
    LocaleHint(locale): LocaleHint,
    crate::mgmt::theme::ThemeHint(theme): crate::mgmt::theme::ThemeHint,
    axum::Extension(admin): axum::Extension<crate::mgmt::admin_profile::AdminProfileExt>,
    Path(tenant_id): Path<String>,
) -> Response {
    render_oauth_providers_page(&state, tenant_id, None, locale, theme, admin).await
}

/// `POST /admin/tenants/{id}/_oauth_providers` — upsert. Splits the
/// textarea on newline, trims, drops empties, then calls the same
/// `oauth_config::upsert` helper the REST admin endpoint uses. On error
/// re-renders the page with the validation message in the inline banner;
/// on success 303s back to the GET so a refresh doesn't resubmit.
pub async fn tenant_oauth_provider_upsert(
    State(state): State<TenantsState>,
    LocaleHint(locale): LocaleHint,
    crate::mgmt::theme::ThemeHint(theme): crate::mgmt::theme::ThemeHint,
    axum::Extension(admin): axum::Extension<crate::mgmt::admin_profile::AdminProfileExt>,
    Path(tenant_id): Path<String>,
    Form(form): Form<OauthProviderUpsertForm>,
) -> Response {
    // Guard FIRST: a missing/soft-deleted tenant must not be re-materialised
    // by the writer-mutex below via get_or_open → open_write → create_dir_all.
    // GET path runs the same check via load_tenant_shell; DELETE and the
    // upsert error-leg need it too.
    if let Some(r) = common::ensure_tenant_exists(&state, &tenant_id).await {
        return r;
    }

    let uris: Vec<String> = form
        .allowed_redirect_uris
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    // Pre-validate so we can show the message inline without ever opening
    // the writer mutex.
    if let Err(e) = crate::tenant::oauth_config::validate_upsert(
        &form.provider,
        &form.client_id,
        &form.client_secret,
        &uris,
    ) {
        return render_oauth_providers_page(
            &state,
            tenant_id,
            Some(e.to_string()),
            locale,
            theme,
            admin.clone(),
        )
        .await;
    }

    let pool = match state.tenants.get_or_open(&tenant_id) {
        Ok(p) => p,
        Err(_) => return (StatusCode::NOT_FOUND, "no such tenant").into_response(),
    };
    let provider = form.provider.clone();
    let client_id = form.client_id.clone();
    let client_secret = form.client_secret.clone();
    let uris_owned = uris.clone();
    let res: Result<(), String> = pool
        .with_writer(move |c| {
            crate::tenant::oauth_config::upsert(
                c,
                &provider,
                &client_id,
                &client_secret,
                &uris_owned,
            )
            .map_err(|e| rusqlite::Error::InvalidParameterName(e.to_string()))
        })
        .await
        .map_err(|e| e.to_string());

    match res {
        Ok(()) => Redirect::to(&format!(
            "/drust/admin/tenants/{tenant_id}/_oauth_providers"
        ))
        .into_response(),
        Err(msg) => {
            render_oauth_providers_page(&state, tenant_id, Some(msg), locale, theme, admin).await
        }
    }
}

/// `POST /admin/tenants/{id}/_oauth_providers/{provider}/delete` —
/// idempotent delete. Always redirects back to the list (no error banner
/// needed; the row simply disappears).
pub async fn tenant_oauth_provider_delete(
    State(state): State<TenantsState>,
    Path((tenant_id, provider)): Path<(String, String)>,
) -> Response {
    // Guard FIRST: a missing/soft-deleted tenant must not be re-materialised
    // by get_or_open → open_write → create_dir_all. GET path runs the same
    // check via load_tenant_shell.
    if let Some(r) = common::ensure_tenant_exists(&state, &tenant_id).await {
        return r;
    }
    if let Ok(pool) = state.tenants.get_or_open(&tenant_id) {
        let provider2 = provider.clone();
        let _ = pool
            .with_writer(move |c| crate::tenant::oauth_config::delete(c, &provider2))
            .await;
    }
    Redirect::to(&format!(
        "/drust/admin/tenants/{tenant_id}/_oauth_providers"
    ))
    .into_response()
}

// ─── v1.13: outbound webhooks admin UI ────────────────────────────────────────

#[derive(Template)]
#[template(path = "tenant_webhooks_admin.html")]
struct TenantWebhooksPage {
    version: &'static str,
    tenant_id: String,
    tenant_name: String,
    webhooks: Vec<TenantWebhookRow>,
    /// Pre-computed counts for the stat-tile row.
    total_active: usize,
    total_with_failure: usize,
    collections: Vec<crate::storage::schema::Collection>,
    /// Always `"_webhooks"` here — sidebar `.on` matching.
    active_coll: String,
    /// Surfaced after a failed create (validation / DB error). `None` on the
    /// plain GET render.
    error: Option<String>,
    /// Sticky form values to re-populate after a validation failure. Empty
    /// strings on the plain GET render and after success.
    form_collection: String,
    form_events: String,
    form_url: String,
    /// Set once after a successful create — surfaces the raw secret in a
    /// banner. Sourced from the `drust_webhook_secret_once` cookie and
    /// cleared on the next response.
    secret_once: Option<WebhookSecretBanner>,
    t: Translator,
    admin: crate::mgmt::admin_profile::AdminProfileExt,
    palette_resolved: crate::mgmt::theme::ResolvedPalette,
    mascot_json_static: String,
    mascot_json_light: String,
    mascot_json_dark: String,
}

struct TenantWebhookRow {
    id: i64,
    collection: String,
    /// JSON-decoded from the DB `events` TEXT column.
    events: Vec<String>,
    url: String,
    active: bool,
    last_failure_at: Option<String>,
    last_failure_reason: Option<String>,
    created_at: String,
}

struct WebhookSecretBanner {
    id: i64,
    secret: String,
}

#[derive(Debug, Deserialize)]
pub struct WebhookCreateForm {
    pub collection: String,
    /// Comma-separated event names (e.g. `created,updated`).
    pub events: String,
    pub url: String,
}

const WEBHOOK_SECRET_ONCE_COOKIE: &str = "drust_webhook_secret_once";

/// Pull rows from the tenant's `_system_webhooks` table. Errors are swallowed
/// — the page just renders an empty table rather than 500-ing on a missing
/// fresh tenant DB.
async fn load_webhook_rows(state: &TenantsState, tenant_id: &str) -> Vec<TenantWebhookRow> {
    let pool = match state.tenants.get_or_open(tenant_id) {
        Ok(p) => p,
        Err(_) => return vec![],
    };
    pool.with_reader(|c| {
        let mut stmt = c.prepare(
            "SELECT id, collection, events, url, active, \
                    last_failure_at, last_failure_reason, created_at \
             FROM _system_webhooks \
             ORDER BY id DESC",
        )?;
        let rows: Vec<TenantWebhookRow> = stmt
            .query_map([], |r| {
                let events_raw: String = r.get(2)?;
                let events: Vec<String> = serde_json::from_str(&events_raw).unwrap_or_default();
                Ok(TenantWebhookRow {
                    id: r.get(0)?,
                    collection: r.get(1)?,
                    events,
                    url: r.get(3)?,
                    active: r.get::<_, i64>(4)? != 0,
                    last_failure_at: r.get::<_, Option<String>>(5)?,
                    last_failure_reason: r.get::<_, Option<String>>(6)?,
                    created_at: r.get(7)?,
                })
            })?
            .collect::<Result<_, _>>()?;
        Ok::<_, rusqlite::Error>(rows)
    })
    .await
    .unwrap_or_default()
}

/// Read the `drust_webhook_secret_once` cookie (set by the create handler)
/// from the inbound request and parse it as `{"id": <i64>, "secret": "<hex>"}`.
fn parse_secret_once_cookie(headers: &axum::http::HeaderMap) -> Option<WebhookSecretBanner> {
    let raw = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    let value = raw.split(';').find_map(|p| {
        let t = p.trim();
        t.strip_prefix(&format!("{WEBHOOK_SECRET_ONCE_COOKIE}="))
    })?;
    // Cookie value is JSON URL-encoded; decode once.
    let decoded = urlencoding::decode(value).ok()?.into_owned();
    let parsed: serde_json::Value = serde_json::from_str(&decoded).ok()?;
    let id = parsed.get("id")?.as_i64()?;
    let secret = parsed.get("secret")?.as_str()?.to_string();
    Some(WebhookSecretBanner { id, secret })
}

/// Build a `Set-Cookie` header value that clears the secret-once cookie
/// (Max-Age=0). Path matches the create handler's set so the browser drops
/// the right cookie.
fn clear_secret_once_cookie() -> axum::http::HeaderValue {
    // Body is static at compile time (only `const &str` interpolated), so we
    // can hand back a `HeaderValue::from_static` and skip the runtime parse.
    axum::http::HeaderValue::from_static(concat!(
        "drust_webhook_secret_once",
        "=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"
    ))
}

/// Build a `Set-Cookie` header value for a fresh secret-once banner. Short
/// TTL (120 s) so a refresh after the cookie expires stops showing the
/// banner. `HttpOnly` keeps it out of JS (the page renders the value
/// server-side); `SameSite=Lax` is fine since the request that sets the
/// cookie is a same-origin POST.
fn set_secret_once_cookie(id: i64, secret: &str) -> String {
    let payload = serde_json::json!({"id": id, "secret": secret}).to_string();
    let encoded = urlencoding::encode(&payload);
    format!("{WEBHOOK_SECRET_ONCE_COOKIE}={encoded}; Path=/; Max-Age=120; HttpOnly; SameSite=Lax")
}

/// Context bundle for `render_webhooks_page`. Defaults are all `None` /
/// empty so the GET path can spell out only what it has (typically just
/// `secret_once`), and the POST error paths construct the full set.
#[derive(Default)]
struct WebhookPageContext {
    error: Option<String>,
    form_collection: String,
    form_events: String,
    form_url: String,
    secret_once: Option<WebhookSecretBanner>,
}

/// Internal page render. Reused by GET, by the upsert error path, and
/// indirectly by the redirect target (which goes through GET on the next
/// request — not a direct call here).
async fn render_webhooks_page(
    state: &TenantsState,
    tenant_id: String,
    ctx: WebhookPageContext,
    extra_header: Option<(axum::http::HeaderName, axum::http::HeaderValue)>,
    locale: Locale,
    theme: crate::mgmt::theme::Theme,
    admin: crate::mgmt::admin_profile::AdminProfileExt,
) -> Response {
    let (tenant_name, collections) = match common::load_tenant_shell(state, &tenant_id).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    let webhooks = load_webhook_rows(state, &tenant_id).await;
    let total_active = webhooks.iter().filter(|w| w.active).count();
    let total_with_failure = webhooks
        .iter()
        .filter(|w| w.last_failure_at.is_some())
        .count();
    let trc = crate::mgmt::theme::ThemeRenderCtx::build(theme);
    let body = TenantWebhooksPage {
        version: env!("CARGO_PKG_VERSION"),
        tenant_id,
        tenant_name,
        webhooks,
        total_active,
        total_with_failure,
        collections,
        active_coll: "_webhooks".to_string(),
        error: ctx.error,
        form_collection: ctx.form_collection,
        form_events: ctx.form_events,
        form_url: ctx.form_url,
        secret_once: ctx.secret_once,
        t: Translator::new(locale),
        admin,
        palette_resolved: trc.palette_resolved,
        mascot_json_static: trc.mascot_json_static,
        mascot_json_light: trc.mascot_json_light,
        mascot_json_dark: trc.mascot_json_dark,
    }
    .render()
    .unwrap();
    let mut resp = Html(body).into_response();
    if let Some((name, value)) = extra_header {
        resp.headers_mut().append(name, value);
    }
    resp
}

/// `GET /admin/tenants/{id}/_webhooks` — render the management page.
/// Pops the secret-once cookie (if present) into the banner + clears it on
/// the response.
pub async fn tenant_webhooks_page(
    State(state): State<TenantsState>,
    LocaleHint(locale): LocaleHint,
    crate::mgmt::theme::ThemeHint(theme): crate::mgmt::theme::ThemeHint,
    axum::Extension(admin): axum::Extension<crate::mgmt::admin_profile::AdminProfileExt>,
    Path(tenant_id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    let secret_once = parse_secret_once_cookie(&headers);
    let clear = secret_once
        .as_ref()
        .map(|_| (axum::http::header::SET_COOKIE, clear_secret_once_cookie()));
    render_webhooks_page(
        &state,
        tenant_id,
        WebhookPageContext {
            secret_once,
            ..Default::default()
        },
        clear,
        locale,
        theme,
        admin,
    )
    .await
}

/// `POST /admin/tenants/{id}/_webhooks` — form submit. Splits the events
/// field on `,` + trims, validates via `webhook_routes::check_url` /
/// `check_events`, inserts the row with a generated 64-hex secret, then
/// 303s back to the GET with the secret in a short-lived `HttpOnly` cookie.
/// Referrer-Policy is also set on the redirect so the secret cannot leak
/// via `Referer` even though it never lives in the URL.
pub async fn tenant_webhook_create_form(
    State(state): State<TenantsState>,
    LocaleHint(locale): LocaleHint,
    crate::mgmt::theme::ThemeHint(theme): crate::mgmt::theme::ThemeHint,
    axum::Extension(admin): axum::Extension<crate::mgmt::admin_profile::AdminProfileExt>,
    Path(tenant_id): Path<String>,
    Form(form): Form<WebhookCreateForm>,
) -> Response {
    // Guard FIRST so a missing tenant doesn't re-materialise its dir.
    if let Some(r) = common::ensure_tenant_exists(&state, &tenant_id).await {
        return r;
    }
    let events: Vec<String> = form
        .events
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    // Validation — use the shared pure helpers from T7.
    if let Err((_, msg)) = crate::tenant::webhook_routes::check_url(&form.url) {
        return render_webhooks_page(
            &state,
            tenant_id,
            WebhookPageContext {
                error: Some(msg.to_string()),
                form_collection: form.collection,
                form_events: form.events,
                form_url: form.url,
                secret_once: None,
            },
            None,
            locale,
            theme,
            admin.clone(),
        )
        .await;
    }
    if let Err((_, msg)) = crate::tenant::webhook_routes::check_events(&events) {
        return render_webhooks_page(
            &state,
            tenant_id,
            WebhookPageContext {
                error: Some(msg.to_string()),
                form_collection: form.collection,
                form_events: form.events,
                form_url: form.url,
                secret_once: None,
            },
            None,
            locale,
            theme,
            admin.clone(),
        )
        .await;
    }
    let collection_trim = form.collection.trim().to_string();
    if collection_trim.is_empty() {
        return render_webhooks_page(
            &state,
            tenant_id,
            WebhookPageContext {
                error: Some("collection must not be empty".to_string()),
                form_collection: form.collection,
                form_events: form.events,
                form_url: form.url,
                secret_once: None,
            },
            None,
            locale,
            theme,
            admin.clone(),
        )
        .await;
    }

    let pool = match state.tenants.get_or_open(&tenant_id) {
        Ok(p) => p,
        Err(_) => {
            return (StatusCode::NOT_FOUND, "no such tenant").into_response();
        }
    };
    let events_json = match serde_json::to_string(&events) {
        Ok(s) => s,
        Err(_) => {
            return render_webhooks_page(
                &state,
                tenant_id,
                WebhookPageContext {
                    error: Some("failed to encode events".to_string()),
                    form_collection: form.collection,
                    form_events: form.events,
                    form_url: form.url,
                    secret_once: None,
                },
                None,
                locale,
                theme,
                admin.clone(),
            )
            .await;
        }
    };
    let secret = crate::tenant::webhook_routes::generate_secret();
    let secret_for_db = secret.clone();
    let url = form.url.clone();
    let coll = collection_trim.clone();
    let now = chrono::Utc::now().to_rfc3339();
    let res: rusqlite::Result<i64> = pool
        .with_writer(move |c| {
            c.execute(
                "INSERT INTO _system_webhooks \
                 (collection, events, url, secret, active, created_at) \
                 VALUES (?1, ?2, ?3, ?4, 1, ?5)",
                rusqlite::params![coll, events_json, url, secret_for_db, now],
            )?;
            Ok(c.last_insert_rowid())
        })
        .await;

    match res {
        Ok(id) => {
            // 303 See Other so a refresh of the resulting page doesn't
            // resubmit the form; carry the secret in a short-lived
            // HttpOnly cookie (not the URL — query-params would leak via
            // Referer + access logs).
            let location = format!("/drust/admin/tenants/{tenant_id}/_webhooks");
            let mut resp = Response::builder()
                .status(StatusCode::SEE_OTHER)
                .header(axum::http::header::LOCATION, &location)
                .header(axum::http::header::REFERRER_POLICY, "no-referrer")
                .header(
                    axum::http::header::SET_COOKIE,
                    set_secret_once_cookie(id, &secret),
                )
                .body(axum::body::Body::empty())
                .unwrap();
            // Stamp content-type for the empty body to keep clients happy.
            resp.headers_mut().insert(
                axum::http::header::CONTENT_TYPE,
                "text/html; charset=utf-8".parse().unwrap(),
            );
            resp
        }
        Err(e) => {
            render_webhooks_page(
                &state,
                tenant_id,
                WebhookPageContext {
                    error: Some(format!("insert failed: {e}")),
                    form_collection: form.collection,
                    form_events: form.events,
                    form_url: form.url,
                    secret_once: None,
                },
                None,
                locale,
                theme,
                admin,
            )
            .await
        }
    }
}

/// `POST /admin/tenants/{id}/_webhooks/{wid}/delete` — idempotent delete +
/// 303 back to the list.
pub async fn tenant_webhook_delete_form(
    State(state): State<TenantsState>,
    Path((tenant_id, wid)): Path<(String, i64)>,
) -> Response {
    if let Some(r) = common::ensure_tenant_exists(&state, &tenant_id).await {
        return r;
    }
    if let Ok(pool) = state.tenants.get_or_open(&tenant_id) {
        let _ = pool
            .with_writer(move |c| {
                c.execute(
                    "DELETE FROM _system_webhooks WHERE id = ?1",
                    rusqlite::params![wid],
                )
            })
            .await;
    }
    Redirect::to(&format!("/drust/admin/tenants/{tenant_id}/_webhooks")).into_response()
}
