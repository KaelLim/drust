use crate::auth::bearer::{generate_token, hash_token};
use crate::auth::middleware::AdminSessionState;
use crate::mgmt::i18n::{Locale, LocaleHint, Translator};
use crate::storage::garage::GarageClient;
use crate::storage::tenant_db::{open_read, open_write, tenant_dir, validate_tenant_id};
use askama::Template;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::{Form, Json};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;

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
    /// Directory containing `audit-YYYY-MM-DD.jsonl` files. Sourced from
    /// `$DRUST_LOG_DIR` at boot; consumed by the admin audit UI handlers
    /// mounted under tenants_router.
    pub log_dir: PathBuf,
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
    ) -> Self {
        use crate::auth::middleware::AdminSessionState;
        let log_dir = data_dir.join("logs");
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
            log_dir,
            index_large_table_rows: 1_000_000,
        }
    }
}

#[derive(Template)]
#[template(path = "tenants_list.html")]
struct TenantsListPage {
    tenants: Vec<TenantRow>,
    version: &'static str,
    disk: crate::mgmt::public_files::DiskView,
    /// Sampler refresh interval, displayed in the footer as "refresh every N min".
    stats_interval_min: u64,
    /// Human "N min ago" for the most recently re-sampled row in this batch
    /// (sampler iterates ORDER BY id, so `tenants[0]` is the most recent).
    /// Empty when no sampler tick has run yet on this boot.
    stats_age_display: String,
    t: Translator,
    palette_resolved: crate::mgmt::theme::ResolvedPalette,
    mascot_json_static: String,
    mascot_json_light: String,
    mascot_json_dark: String,
}

struct TenantRow {
    id: String,
    /// Short display of id (e.g. first 8 chars + "…" + last 4) for UI cells.
    id_short: String,
    name: String,
    /// First grapheme of name, uppercased — used as the avatar glyph.
    initial: String,
    created_at: String,
    /// Humanised data.sqlite size (e.g. "1.3 MB", "742 KB").
    db_display: String,
    /// Formatted string like "1.3 MB" or "0.0 MB" — _system_files SUM(size_bytes).
    files_display: String,
    /// Humanised db + files combined — at-a-glance "who's eating disk" signal.
    total_display: String,
}

use crate::mgmt::format::humanize_bytes;

fn short_id(id: &str) -> String {
    if id.len() <= 12 {
        return id.to_string();
    }
    format!("{}…{}", &id[..8], &id[id.len() - 4..])
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

pub async fn list_page_axum(
    State(state): State<TenantsState>,
    LocaleHint(locale): LocaleHint,
    crate::mgmt::theme::ThemeHint(theme): crate::mgmt::theme::ThemeHint,
) -> Response {
    // v1.15.0 — reads denormalized stats columns. Zero per-tenant SQLite
    // opens on the request path; the background sampler keeps them fresh.
    let mut latest_sample: Option<String> = None;
    let rows: Vec<TenantRow> = {
        let conn = state.session.meta.lock().await;
        let mut stmt = conn
            .prepare(
                "SELECT id, name, created_at, db_bytes, files_bytes, stats_updated_at \
                 FROM tenants WHERE deleted_at IS NULL ORDER BY id",
            )
            .unwrap();
        stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, Option<String>>(5)?,
            ))
        })
        .unwrap()
        .filter_map(Result::ok)
        .map(|(id, name, created_at, db_bytes, files_bytes, stats_at)| {
            // Track the freshest sample timestamp across the batch for the
            // footer; sampler updates each row at slightly different instants.
            if let Some(ref s) = stats_at {
                if latest_sample.as_deref().map_or(true, |cur| s.as_str() > cur) {
                    latest_sample = Some(s.clone());
                }
            }
            let initial = name
                .chars()
                .next()
                .map(|c| c.to_uppercase().to_string())
                .unwrap_or_else(|| "?".to_string());
            let db = db_bytes.max(0) as u64;
            let files = files_bytes.max(0) as u64;
            TenantRow {
                id_short: short_id(&id),
                id,
                initial,
                name,
                created_at,
                db_display: humanize_bytes(db),
                files_display: humanize_bytes(files),
                total_display: humanize_bytes(db + files),
            }
        })
        .collect()
    };
    let disk = crate::mgmt::public_files::build_disk_view();
    let stats_interval_min: u64 = std::env::var("DRUST_STATS_SAMPLE_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(300)
        / 60;
    let stats_age_display = humanize_age(latest_sample.as_deref());
    let trc = crate::mgmt::theme::ThemeRenderCtx::build(theme);
    Html(
        TenantsListPage {
            tenants: rows,
            version: env!("CARGO_PKG_VERSION"),
            disk,
            stats_interval_min,
            stats_age_display,
            t: Translator::new(locale),
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

/// Render an ISO-8601 timestamp as a coarse "N units ago" string for UI
/// footers. Returns empty string when input is `None` or unparseable.
fn humanize_age(iso: Option<&str>) -> String {
    let Some(s) = iso else {
        return String::new();
    };
    let Ok(then) = chrono::DateTime::parse_from_rfc3339(s) else {
        return String::new();
    };
    let secs = (chrono::Utc::now() - then.with_timezone(&chrono::Utc))
        .num_seconds()
        .max(0);
    match secs {
        0..=59 => format!("{}s ago", secs),
        60..=3599 => format!("{} min ago", secs / 60),
        3600..=86399 => format!("{}h ago", secs / 3600),
        _ => format!("{}d ago", secs / 86400),
    }
}

fn make_tenant_inner(
    conn: &mut rusqlite::Connection,
    data_dir: &std::path::Path,
    id: &str,
    name: &str,
    quota_mb: i64,
    quota_rows: i64,
) -> anyhow::Result<CreatedResp> {
    if let Err(e) = validate_tenant_id(id) {
        anyhow::bail!("invalid tenant id: {e}");
    }
    // A prior tenant with the same id may be soft-deleted. Treat the id as
    // free and hard-purge the old row + its tokens + on-disk data before
    // inserting. If the existing row is still active (deleted_at IS NULL),
    // reject with a clear error.
    let existing: Option<Option<String>> = conn
        .query_row(
            "SELECT deleted_at FROM tenants WHERE id = ?1",
            rusqlite::params![id],
            |r| r.get(0),
        )
        .ok();
    if let Some(deleted_at) = existing {
        if deleted_at.is_none() {
            anyhow::bail!("tenant '{id}' already exists");
        }
        tracing::info!(tenant_id = %id, "recycling id from soft-deleted tenant");
        conn.execute(
            "DELETE FROM tokens WHERE tenant_id = ?1",
            rusqlite::params![id],
        )?;
        conn.execute("DELETE FROM tenants WHERE id = ?1", rusqlite::params![id])?;
        let dir = tenant_dir(data_dir, id);
        if dir.exists() {
            let _ = std::fs::remove_dir_all(&dir);
        }
        // Clear any matching _trash/<id>-<ts> subdirs left from soft-delete.
        if let Ok(entries) = std::fs::read_dir(data_dir.join("_trash")) {
            let prefix = format!("{id}-");
            for entry in entries.flatten() {
                if let Some(n) = entry.file_name().to_str()
                    && n.starts_with(&prefix)
                {
                    let _ = std::fs::remove_dir_all(entry.path());
                }
            }
        }
    }
    conn.execute(
        "INSERT INTO tenants (id, name, quota_db_mb, quota_rows) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![id, name, quota_mb, quota_rows],
    )?;
    // Create directory + data.sqlite file
    let _ = open_write(data_dir, id)?;
    std::fs::write(
        tenant_dir(data_dir, id).join("meta.json"),
        serde_json::to_vec_pretty(&json!({
            "name": name,
            "created_at": Utc::now().to_rfc3339(),
            "quota_db_mb": quota_mb,
            "quota_rows": quota_rows,
        }))?,
    )?;
    // Issue both an anon and a service key on creation. Shown once.
    let service_token = generate_token();
    let anon_token = generate_token();
    conn.execute(
        "INSERT INTO tokens (tenant_id, token_hash, plaintext, label, role) \
         VALUES (?1, ?2, ?3, 'initial-service', 'service')",
        rusqlite::params![id, hash_token(&service_token), service_token],
    )?;
    conn.execute(
        "INSERT INTO tokens (tenant_id, token_hash, plaintext, label, role) \
         VALUES (?1, ?2, ?3, 'initial-anon', 'anon')",
        rusqlite::params![id, hash_token(&anon_token), anon_token],
    )?;
    Ok(CreatedResp {
        tenant: TenantInfo {
            id: id.to_string(),
            name: name.to_string(),
            created_at: Utc::now().to_rfc3339(),
            quota_db_mb: quota_mb,
            quota_rows,
        },
        initial_tokens: InitialTokens {
            anon: anon_token,
            service: service_token.clone(),
        },
        initial_token: service_token,
    })
}

/// Roll back everything `make_tenant_inner` did for `id`: delete token rows,
/// the tenant row, and the on-disk directory. Used when Garage provisioning
/// fails after local state has already been written.
pub async fn create_tenant_json(
    State(state): State<TenantsState>,
    Json(form): Json<CreateTenantJson>,
) -> Response {
    let mb = form.quota_db_mb.unwrap_or(500);
    let rows = form.quota_rows.unwrap_or(1_000_000);
    let id = form
        .id
        .clone()
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    let mut conn = state.session.meta.lock().await;
    let resp = match make_tenant_inner(&mut conn, &state.data_dir, &id, &form.name, mb, rows) {
        Ok(resp) => resp,
        Err(e) => {
            let msg = e.to_string();
            return if msg.contains("invalid tenant id") || msg.contains("UNIQUE") {
                (StatusCode::BAD_REQUEST, msg).into_response()
            } else {
                (StatusCode::INTERNAL_SERVER_ERROR, msg).into_response()
            };
        }
    };
    drop(conn);

    // v1.15.0 — immediate stats sample so the new row renders with real
    // numbers on the next dashboard load, without waiting for a sampler tick.
    crate::mgmt::stats::sample_one(&state.session.meta, &state.data_dir, &id).await;

    // Storage is fully shared (two buckets host-wide: `public` + `private`);
    // per-tenant bucket provisioning is no longer needed. The new tenant's
    // files will live under `<tenant-id>/<key>` inside those buckets.
    (StatusCode::CREATED, Json(resp)).into_response()
}

pub async fn create_tenant_form(
    State(state): State<TenantsState>,
    Form(form): Form<CreateTenantForm>,
) -> Response {
    // UUID v4 — user never types a slug. Display name is the human label.
    let id = uuid::Uuid::new_v4().to_string();
    let mut conn = state.session.meta.lock().await;
    let created = make_tenant_inner(&mut conn, &state.data_dir, &id, &form.name, 500, 1_000_000);
    drop(conn);

    match created {
        Ok(_) => {
            // v1.15.0 immediate sample so the new row renders with stats next load.
            crate::mgmt::stats::sample_one(&state.session.meta, &state.data_dir, &id).await;
            Redirect::to("/drust/admin/tenants").into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

pub async fn soft_delete_tenant(
    State(state): State<TenantsState>,
    Path(id): Path<String>,
) -> Response {
    // Delete the tenant's objects from shared Garage buckets first (outside
    // the meta lock). Iterate _system_files and DELETE each object. Admin
    // keeps its files — they live at the root of the shared buckets, not
    // under this tenant's prefix.
    if let Some(ref garage) = state.garage {
        let rows: Vec<(String, String)> =
            match crate::storage::tenant_db::open_read(&state.data_dir, &id) {
                Ok(conn) => {
                    match conn.prepare("SELECT key, visibility FROM _system_files") {
                        Ok(mut stmt) => stmt
                            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
                            .map(|it| it.filter_map(Result::ok).collect())
                            .unwrap_or_default(),
                        Err(_) => vec![], // table missing = no files to clean
                    }
                }
                Err(_) => vec![],
            };
        for (key, vis) in rows {
            let visibility = if vis == "public" {
                crate::storage::files::Visibility::Public
            } else {
                crate::storage::files::Visibility::Private
            };
            let bucket = crate::storage::files::bucket_for(visibility);
            let object_key = crate::storage::files::compose_key(
                &crate::storage::files::Owner::Tenant(id.clone()),
                &key,
            );
            if let Err(e) = garage.delete_object_in(bucket, &object_key).await {
                tracing::warn!(tenant = %id, key = %object_key, error = %e,
                    "soft-delete: object delete failed (ignored)");
            }
        }
    }

    // Now the synchronous SQLite + fs work — hold lock only over sync ops.
    {
        let conn = state.session.meta.lock().await;
        let affected = conn
            .execute(
                "UPDATE tenants SET deleted_at = datetime('now') WHERE id = ?1 AND deleted_at IS NULL",
                rusqlite::params![id],
            )
            .unwrap_or(0);
        if affected == 0 {
            return (StatusCode::NOT_FOUND, "no such tenant").into_response();
        }
        let ts = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let src = tenant_dir(&state.data_dir, &id);
        let dst = state.data_dir.join("_trash").join(format!("{id}-{ts}"));
        if let Some(parent) = dst.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if src.exists() {
            let _ = std::fs::rename(&src, &dst);
        }
    }
    // Eviction order matters: pools first (release rusqlite Connection FDs
    // on the rename target so the inode + disk space release immediately),
    // then MCP cache (drops its Arc<TenantPool> clones + session state),
    // then SSE channels (subscribers receive Closed on next recv).
    state.tenants.evict(&id);
    state.mcp.evict(&id);
    state.bus.evict_tenant(&id);
    StatusCode::NO_CONTENT.into_response()
}

pub async fn soft_delete_tenant_form(
    State(state): State<TenantsState>,
    Path(id): Path<String>,
) -> Response {
    let _ = soft_delete_tenant(State(state), Path(id)).await;
    Redirect::to("/drust/admin/tenants").into_response()
}

// ─── T28: allow_self_register toggle ─────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct ToggleSelfRegisterBody {
    pub enabled: bool,
}

/// `POST /admin/tenants/{id}/allow-self-register`
///
/// Flips `tenants.allow_self_register` for the given tenant. Body must be
/// `{"enabled": true|false}`. Returns `{"enabled": <bool>}` on success.
/// Requires an active admin session (enforced by `admin_session_layer`).
pub async fn toggle_self_register(
    State(state): State<TenantsState>,
    Path(tid): Path<String>,
    axum::Extension(_admin): axum::Extension<crate::auth::middleware::AdminId>,
    axum::Json(body): axum::Json<ToggleSelfRegisterBody>,
) -> Response {
    let conn = state.session.meta.lock().await;
    let v = if body.enabled { 1i64 } else { 0i64 };
    match conn.execute(
        "UPDATE tenants SET allow_self_register = ?1 WHERE id = ?2 AND deleted_at IS NULL",
        rusqlite::params![v, tid],
    ) {
        Ok(0) => (StatusCode::NOT_FOUND, "no such tenant").into_response(),
        Ok(_) => (
            StatusCode::OK,
            axum::Json(serde_json::json!({"enabled": body.enabled})),
        )
            .into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// ─── Admin tenant-files subpage (Task 21) ────────────────────────────────────

/// A single file row for the admin tenant-files view.
struct AdminTenantFileRow {
    key: String,
    original_name: String,
    content_type: String,
    size_human: String,
    visibility: String,
    uploaded_at: String,
    public_url: String,
}

#[derive(Template)]
#[template(path = "tenant_files_admin.html")]
struct TenantFilesAdminPage {
    version: &'static str,
    tenant_id: String,
    tenant_name: String,
    files: Vec<AdminTenantFileRow>,
    total_files: usize,
    used_mb_display: String,
    storage_available: bool,
    max_upload_mb: u64,
    disk: crate::mgmt::public_files::DiskView,
    /// Driver list for `_collection_sidebar.html`.
    collections: Vec<crate::storage::schema::Collection>,
    /// Always `"_system_files"` here — kept for sidebar `.on` matching.
    active_coll: String,
    page: u32,
    total_pages: u32,
    prev_url: Option<String>,
    next_url: Option<String>,
    per_page_options: Vec<TenantFilesPerPageOption>,
    t: Translator,
    palette_resolved: crate::mgmt::theme::ResolvedPalette,
    mascot_json_static: String,
    mascot_json_light: String,
    mascot_json_dark: String,
}

#[derive(Clone)]
pub struct TenantFilesPerPageOption {
    pub value: u32,
    pub selected: bool,
}

const TENANT_FILES_DEFAULT_PER_PAGE: u32 = 25;
const TENANT_FILES_PER_PAGE_OPTIONS: &[u32] = &[10, 25, 50, 100];

#[derive(Debug, serde::Deserialize, Default)]
pub struct TenantFilesListQs {
    #[serde(default)]
    pub page: Option<u32>,
    #[serde(default)]
    pub per_page: Option<u32>,
}

// ===== Cmd-K palette JSON endpoint (v1.14) =====
// Lightweight tenant list for the global ⌘K palette. Service-only? No —
// admin-session gated (same as the rest of /admin/*). Returns 0 rows
// rather than an error when no tenants exist so the palette renders
// "no matches" gracefully.

#[derive(Serialize)]
struct CmdkTenant {
    id: String,
    name: String,
}

/// `GET /admin/api/cmdk/tenants` — JSON `[{id, name}, ...]` used by the
/// cmd-K overlay to populate the tenant picker. Sorted by name (case-
/// insensitive). Excludes soft-deleted tenants.
pub async fn cmdk_tenants_json(State(state): State<TenantsState>) -> Response {
    let conn = state.session.meta.lock().await;
    let mut out: Vec<CmdkTenant> = Vec::new();
    if let Ok(mut stmt) = conn.prepare(
        "SELECT id, name FROM tenants WHERE deleted_at IS NULL \
         ORDER BY name COLLATE NOCASE",
    ) && let Ok(rows) = stmt.query_map([], |r| {
        Ok(CmdkTenant {
            id: r.get(0)?,
            name: r.get(1)?,
        })
    }) {
        out.extend(rows.flatten());
    }
    drop(conn);
    Json(out).into_response()
}

// ===== Overview page (v1.14, virtual sidebar entry `⌂ _overview`) =====

#[derive(Template)]
#[template(path = "tenant_overview.html")]
struct TenantOverviewPage {
    tenant_id: String,
    tenant_name: String,
    created_at: String,
    version: &'static str,
    collections: Vec<crate::storage::schema::Collection>,
    active_coll: String,
    collection_count: usize,
    total_records: i64,
    db_size_display: String,
    user_count: i64,
    rpc_count: i64,
    webhook_active_count: i64,
    webhook_total_count: i64,
    oauth_count: i64,
    token_count: i64,
    webhook_failures: Vec<WebhookFailureRow>,
    recent_audit: Vec<RecentAuditRow>,
    t: Translator,
    palette_resolved: crate::mgmt::theme::ResolvedPalette,
    mascot_json_static: String,
    mascot_json_light: String,
    mascot_json_dark: String,
}

struct WebhookFailureRow {
    #[allow(dead_code)]
    id: i64,
    collection: String,
    url: String,
    events: String,
    last_failure_at: String,
    last_failure_reason: String,
}

struct RecentAuditRow {
    /// "3m ago" / "Just now" / "14:32" — formatted for human reading.
    /// Raw ISO `ts` is dropped; we render the same row in the audit log
    /// page with the full timestamp, this is just the overview card.
    time_display: String,
    /// HTTP verb extracted from `op` ("POST /records/foo" → "POST").
    /// Empty when the op doesn't follow that shape.
    method: String,
    /// Path part of `op` minus the leading slash ("records/foo").
    path_display: String,
    status: String,
    /// Empty when status is `ok`; otherwise the canonical error code so
    /// the chip renders the failure mode rather than the generic word
    /// "error".
    error_code: String,
    /// "service" / "anon" / "user" — read from `extra.auth_kind`.
    /// Token-hint hashes are dropped (not human readable).
    auth_kind: String,
    duration_ms: u64,
}

fn humanize_audit_ts(ts: &str) -> String {
    let Ok(then) = chrono::DateTime::parse_from_rfc3339(ts) else {
        return ts.to_string();
    };
    let secs = (Utc::now() - then.with_timezone(&Utc))
        .num_seconds()
        .max(0);
    match secs {
        0..=10 => "just now".to_string(),
        11..=59 => format!("{}s ago", secs),
        60..=3599 => format!("{}m ago", secs / 60),
        3600..=86399 => format!("{}h ago", secs / 3600),
        _ => then.format("%Y-%m-%d %H:%M").to_string(),
    }
}

/// `GET /admin/tenants/{id}/_overview` — virtual sidebar entry that summarises
/// the tenant's data plane: collection counts, storage size, end-users,
/// stored RPCs, OAuth providers, recent audit, and webhook failures within
/// the last 24h. New landing page (the legacy redirect target
/// `/_api_keys` is still reachable but no longer the default).
pub async fn tenant_overview_page(
    State(state): State<TenantsState>,
    LocaleHint(locale): LocaleHint,
    crate::mgmt::theme::ThemeHint(theme): crate::mgmt::theme::ThemeHint,
    Path(tenant_id): Path<String>,
) -> Response {
    if validate_tenant_id(&tenant_id).is_err() {
        return (StatusCode::BAD_REQUEST, "invalid tenant id").into_response();
    }

    // Tenant metadata + active-token count from meta.sqlite.
    let (tenant_name, created_at, token_count) = {
        let conn = state.session.meta.lock().await;
        let row: Option<(String, String)> = conn
            .query_row(
                "SELECT name, created_at FROM tenants WHERE id = ?1 AND deleted_at IS NULL",
                rusqlite::params![tenant_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .ok();
        let (name, created_at) = match row {
            Some(t) => t,
            None => return (StatusCode::NOT_FOUND, "tenant not found").into_response(),
        };
        let token_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM tokens WHERE tenant_id = ?1 AND revoked_at IS NULL",
                rusqlite::params![tenant_id],
                |r| r.get(0),
            )
            .unwrap_or(0);
        (name, created_at, token_count)
    };

    // data.sqlite file size.
    let db_path = tenant_dir(&state.data_dir, &tenant_id).join("data.sqlite");
    let db_size = std::fs::metadata(&db_path).map(|m| m.len()).unwrap_or(0);
    let db_size_display = humanize_bytes(db_size);

    // Tenant data-plane queries. A failure to open the data db (fresh
    // tenant pre-write, or trashed) yields zeroes — the page still renders
    // with the meta info above.
    let mut collections: Vec<crate::storage::schema::Collection> = Vec::new();
    let mut total_records: i64 = 0;
    let mut user_count: i64 = 0;
    let mut rpc_count: i64 = 0;
    let mut webhook_active_count: i64 = 0;
    let mut webhook_total_count: i64 = 0;
    let mut oauth_count: i64 = 0;
    let mut webhook_failures: Vec<WebhookFailureRow> = Vec::new();

    if let Ok(conn) = open_read(&state.data_dir, &tenant_id) {
        collections = crate::storage::schema::list_collections(&conn).unwrap_or_default();
        total_records = collections.iter().map(|c| c.row_count).sum();
        user_count = conn
            .query_row("SELECT COUNT(*) FROM _system_users", [], |r| r.get(0))
            .unwrap_or(0);
        rpc_count = conn
            .query_row("SELECT COUNT(*) FROM _system_rpc", [], |r| r.get(0))
            .unwrap_or(0);
        webhook_active_count = conn
            .query_row(
                "SELECT COUNT(*) FROM _system_webhooks WHERE active = 1",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        webhook_total_count = conn
            .query_row("SELECT COUNT(*) FROM _system_webhooks", [], |r| r.get(0))
            .unwrap_or(0);
        oauth_count = conn
            .query_row("SELECT COUNT(*) FROM _system_oauth_providers", [], |r| r.get(0))
            .unwrap_or(0);

        // Recent webhook failures (last 24h). Best-effort: any column-shape
        // mismatch on older tenants is suppressed and the card stays hidden.
        let cutoff_str = (Utc::now() - chrono::Duration::hours(24))
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();
        if let Ok(mut stmt) = conn.prepare(
            "SELECT id, collection, url, events, last_failure_at, \
                COALESCE(last_failure_reason, '') \
             FROM _system_webhooks \
             WHERE last_failure_at IS NOT NULL AND last_failure_at >= ?1 \
             ORDER BY last_failure_at DESC LIMIT 5",
        ) && let Ok(rows) = stmt.query_map(rusqlite::params![cutoff_str], |r| {
            Ok(WebhookFailureRow {
                id: r.get(0)?,
                collection: r.get(1)?,
                url: r.get(2)?,
                events: r.get(3)?,
                last_failure_at: r.get(4)?,
                last_failure_reason: r.get(5)?,
            })
        }) {
            webhook_failures.extend(rows.flatten());
        }
    }

    // Recent audit entries for this tenant (last 24h, newest first, capped 10).
    let scan = crate::mgmt::audit::scan_window(
        &state.log_dir,
        crate::mgmt::audit::Window::H24,
        Utc::now(),
    );
    let mut recent_audit: Vec<RecentAuditRow> = scan
        .entries
        .into_iter()
        .filter(|e| e.tenant == tenant_id)
        .map(|e| {
            let (method, path_display) = match e.op.split_once(' ') {
                Some((m, p)) => (m.to_string(), p.trim_start_matches('/').to_string()),
                None => (String::new(), e.op.clone()),
            };
            let auth_kind = e
                .extra
                .get("auth_kind")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            RecentAuditRow {
                time_display: humanize_audit_ts(&e.ts),
                method,
                path_display,
                status: e.status,
                error_code: e.error_code.unwrap_or_default(),
                auth_kind,
                duration_ms: e.duration_ms,
            }
        })
        .collect();
    recent_audit.reverse();
    recent_audit.truncate(10);

    let collection_count = collections.len();
    let trc = crate::mgmt::theme::ThemeRenderCtx::build(theme);
    Html(
        TenantOverviewPage {
            tenant_id: tenant_id.clone(),
            tenant_name,
            created_at,
            version: env!("CARGO_PKG_VERSION"),
            collections,
            active_coll: "_overview".to_string(),
            collection_count,
            total_records,
            db_size_display,
            user_count,
            rpc_count,
            webhook_active_count,
            webhook_total_count,
            oauth_count,
            token_count,
            webhook_failures,
            recent_audit,
            t: Translator::new(locale),
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

/// GET /admin/tenants/{id}/files
/// Renders the tenant's _system_files with upload form + per-row actions.
/// Admin uploads go to the tenant's own buckets (tenant-{id}-{pub,prv}).
pub async fn tenant_files_admin_page(
    State(state): State<TenantsState>,
    LocaleHint(locale): LocaleHint,
    crate::mgmt::theme::ThemeHint(theme): crate::mgmt::theme::ThemeHint,
    Path(tenant_id): Path<String>,
    axum::extract::Query(qs): axum::extract::Query<TenantFilesListQs>,
) -> Response {
    // Resolve tenant name (and validate existence) from meta.sqlite.
    let tenant_name: Option<String> = {
        let conn = state.session.meta.lock().await;
        conn.query_row(
            "SELECT name FROM tenants WHERE id = ?1 AND deleted_at IS NULL",
            rusqlite::params![tenant_id],
            |r| r.get(0),
        )
        .ok()
    };
    let tenant_name = match tenant_name {
        Some(n) => n,
        None => {
            return (
                StatusCode::NOT_FOUND,
                format!("no such tenant: {tenant_id}"),
            )
                .into_response();
        }
    };

    let disk = crate::mgmt::public_files::build_disk_view();
    let max_upload_mb = (state.max_upload_bytes / (1024 * 1024)) as u64;
    let storage_available = state.garage.is_some();

    let per_page = qs
        .per_page
        .filter(|n| TENANT_FILES_PER_PAGE_OPTIONS.contains(n))
        .unwrap_or(TENANT_FILES_DEFAULT_PER_PAGE);
    let req_page = qs.page.unwrap_or(1).max(1);
    let per_page_options: Vec<TenantFilesPerPageOption> = TENANT_FILES_PER_PAGE_OPTIONS
        .iter()
        .map(|&v| TenantFilesPerPageOption {
            value: v,
            selected: v == per_page,
        })
        .collect();

    let pager_url = |p: u32| -> String {
        if per_page == TENANT_FILES_DEFAULT_PER_PAGE {
            format!("/drust/admin/tenants/{tenant_id}/files?page={p}")
        } else {
            format!("/drust/admin/tenants/{tenant_id}/files?page={p}&per_page={per_page}")
        }
    };

    let empty_page = |tenant_id: String, tenant_name: String| -> Response {
        // Sidebar still renders the virtual rows even when the tenant DB
        // hasn't been opened; `collections: vec![]` is fine here.
        let trc = crate::mgmt::theme::ThemeRenderCtx::build(theme);
        Html(
            TenantFilesAdminPage {
                version: env!("CARGO_PKG_VERSION"),
                tenant_id,
                tenant_name,
                files: vec![],
                total_files: 0,
                used_mb_display: "0.0 MB".into(),
                storage_available,
                max_upload_mb,
                disk: disk.clone(),
                collections: vec![],
                active_coll: "_system_files".to_string(),
                page: 1,
                total_pages: 1,
                prev_url: None,
                next_url: None,
                per_page_options: per_page_options.clone(),
                t: Translator::new(locale),
                palette_resolved: trc.palette_resolved,
                mascot_json_static: trc.mascot_json_static,
                mascot_json_light: trc.mascot_json_light,
                mascot_json_dark: trc.mascot_json_dark,
            }
            .render()
            .unwrap(),
        )
        .into_response()
    };

    // Open the tenant's data.sqlite read-only.
    let conn = match open_read(&state.data_dir, &tenant_id) {
        Ok(c) => c,
        Err(_) => return empty_page(tenant_id, tenant_name),
    };

    // Total count + total bytes for the header. Falls back to (0, 0) when
    // _system_files doesn't exist yet (Garage disabled at creation).
    let (total_files_i64, total_bytes_i64): (i64, i64) = conn
        .query_row(
            "SELECT COUNT(*), COALESCE(SUM(size_bytes), 0) FROM _system_files",
            [],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
        )
        .unwrap_or((0, 0));
    let total_files = total_files_i64.max(0) as usize;
    let used_mb_display = format!("{:.1} MB", total_bytes_i64 as f64 / 1_048_576.0);

    let total_pages: u32 = if total_files == 0 {
        1
    } else {
        ((total_files as u64).div_ceil(per_page as u64)) as u32
    };
    let page = req_page.min(total_pages);
    let offset = ((page - 1) as i64) * (per_page as i64);

    // Paginated SELECT.
    let mut stmt = match conn.prepare(
        "SELECT id, key, original_name, content_type, size_bytes, visibility, uploaded_at \
         FROM _system_files ORDER BY uploaded_at DESC LIMIT ?1 OFFSET ?2",
    ) {
        Ok(s) => s,
        Err(_) => return empty_page(tenant_id, tenant_name),
    };

    let base_url = &state.public_base_url;
    let files: Vec<AdminTenantFileRow> = match stmt.query_map(
        rusqlite::params![per_page as i64, offset],
        |r| {
            let _id: i64 = r.get(0)?;
            let key: String = r.get(1)?;
            let original_name: String = r.get(2)?;
            let content_type: Option<String> = r.get(3)?;
            let size_bytes: i64 = r.get(4)?;
            let visibility: String = r.get(5)?;
            let uploaded_at: String = r.get(6)?;
            let vis_enum = if visibility == "public" {
                crate::storage::files::Visibility::Public
            } else {
                crate::storage::files::Visibility::Private
            };
            let public_url = crate::storage::files::build_public_url(
                base_url,
                &crate::storage::files::Owner::Tenant(tenant_id.clone()),
                vis_enum,
                &key,
            );
            Ok(AdminTenantFileRow {
                key,
                original_name,
                content_type: content_type.unwrap_or_else(|| "application/octet-stream".into()),
                size_human: humanize_bytes(size_bytes as u64),
                visibility,
                uploaded_at,
                public_url,
            })
        },
    ) {
        Ok(rows) => rows.filter_map(Result::ok).collect(),
        Err(_) => vec![],
    };

    let prev_url = (page > 1).then(|| pager_url(page - 1));
    let next_url = (page < total_pages).then(|| pager_url(page + 1));

    let collections = crate::storage::schema::list_collections(&conn).unwrap_or_default();

    let trc = crate::mgmt::theme::ThemeRenderCtx::build(theme);
    Html(
        TenantFilesAdminPage {
            version: env!("CARGO_PKG_VERSION"),
            tenant_id,
            tenant_name,
            files,
            total_files,
            used_mb_display,
            storage_available,
            max_upload_mb,
            disk,
            collections,
            active_coll: "_system_files".to_string(),
            page,
            total_pages,
            prev_url,
            next_url,
            per_page_options,
            t: Translator::new(locale),
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

/// Internal: resolve tenant name (404 if missing/deleted) and pull the
/// collection list for the sidebar. Mirrors what `_api_keys` does.
async fn load_tenant_shell(
    state: &TenantsState,
    tenant_id: &str,
) -> Result<(String, Vec<crate::storage::schema::Collection>), Response> {
    let tenant_name: Option<String> = {
        let conn = state.session.meta.lock().await;
        conn.query_row(
            "SELECT name FROM tenants WHERE id = ?1 AND deleted_at IS NULL",
            rusqlite::params![tenant_id],
            |r| r.get(0),
        )
        .ok()
    };
    let tenant_name = match tenant_name {
        Some(n) => n,
        None => {
            return Err((StatusCode::NOT_FOUND, "no such tenant").into_response());
        }
    };
    let collections = open_read(&state.data_dir, tenant_id)
        .ok()
        .and_then(|c| crate::storage::schema::list_collections(&c).ok())
        .unwrap_or_default();
    Ok((tenant_name, collections))
}

/// Lightweight existence guard for admin POST handlers (DELETE / upsert):
/// returns `None` if the tenant exists in `meta.tenants` and isn't
/// soft-deleted, or a 404 response otherwise. Used before
/// `state.tenants.get_or_open(...)` so we don't materialise an empty
/// `tenants/<bogus_id>/data.sqlite` for an admin-typed path. Cheaper than
/// `load_tenant_shell` (no collection list).
async fn ensure_tenant_exists(
    state: &TenantsState,
    tenant_id: &str,
) -> Option<Response> {
    let exists: bool = {
        let conn = state.session.meta.lock().await;
        conn.query_row(
            "SELECT 1 FROM tenants WHERE id = ?1 AND deleted_at IS NULL",
            rusqlite::params![tenant_id],
            |_| Ok(()),
        )
        .is_ok()
    };
    if !exists {
        return Some((StatusCode::NOT_FOUND, "no such tenant").into_response());
    }
    None
}

/// Render the page. Internal helper so the upsert handler can surface an
/// error inline without an extra round-trip.
async fn render_oauth_providers_page(
    state: &TenantsState,
    tenant_id: String,
    error: Option<String>,
    locale: Locale,
    theme: crate::mgmt::theme::Theme,
) -> Response {
    let (tenant_name, collections) = match load_tenant_shell(state, &tenant_id).await {
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
            Ok(rows) => rows.into_iter().map(TenantOauthProviderRow::from_config).collect(),
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
    Path(tenant_id): Path<String>,
) -> Response {
    render_oauth_providers_page(&state, tenant_id, None, locale, theme).await
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
    Path(tenant_id): Path<String>,
    Form(form): Form<OauthProviderUpsertForm>,
) -> Response {
    // Guard FIRST: a missing/soft-deleted tenant must not be re-materialised
    // by the writer-mutex below via get_or_open → open_write → create_dir_all.
    // GET path runs the same check via load_tenant_shell; DELETE and the
    // upsert error-leg need it too.
    if let Some(r) = ensure_tenant_exists(&state, &tenant_id).await {
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
        return render_oauth_providers_page(&state, tenant_id, Some(e.to_string()), locale, theme).await;
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
            crate::tenant::oauth_config::upsert(c, &provider, &client_id, &client_secret, &uris_owned)
                .map_err(|e| rusqlite::Error::InvalidParameterName(e.to_string()))
        })
        .await
        .map_err(|e| e.to_string());

    match res {
        Ok(()) => Redirect::to(&format!(
            "/drust/admin/tenants/{tenant_id}/_oauth_providers"
        ))
        .into_response(),
        Err(msg) => render_oauth_providers_page(&state, tenant_id, Some(msg), locale, theme).await,
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
    if let Some(r) = ensure_tenant_exists(&state, &tenant_id).await {
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
async fn load_webhook_rows(
    state: &TenantsState,
    tenant_id: &str,
) -> Vec<TenantWebhookRow> {
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
                let events: Vec<String> =
                    serde_json::from_str(&events_raw).unwrap_or_default();
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
    format!(
        "{WEBHOOK_SECRET_ONCE_COOKIE}={encoded}; Path=/; Max-Age=120; HttpOnly; SameSite=Lax"
    )
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
) -> Response {
    let (tenant_name, collections) = match load_tenant_shell(state, &tenant_id).await {
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
    Path(tenant_id): Path<String>,
    Form(form): Form<WebhookCreateForm>,
) -> Response {
    // Guard FIRST so a missing tenant doesn't re-materialise its dir.
    if let Some(r) = ensure_tenant_exists(&state, &tenant_id).await {
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
    if let Some(r) = ensure_tenant_exists(&state, &tenant_id).await {
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
