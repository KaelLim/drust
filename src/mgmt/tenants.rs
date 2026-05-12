use crate::auth::bearer::{generate_token, hash_token};
use crate::auth::middleware::AdminSessionState;
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

#[derive(Template)]
#[template(path = "tenants_list.html")]
struct TenantsListPage {
    tenants: Vec<TenantRow>,
    version: &'static str,
    disk: crate::mgmt::public_files::DiskView,
}

struct TenantRow {
    id: String,
    /// Short display of id (e.g. first 8 chars + "…" + last 4) for UI cells.
    id_short: String,
    name: String,
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

pub async fn list_page_axum(State(state): State<TenantsState>) -> Response {
    let conn = state.session.meta.lock().await;
    let mut stmt = conn
        .prepare("SELECT id, name, created_at FROM tenants WHERE deleted_at IS NULL ORDER BY id")
        .unwrap();
    let rows: Vec<TenantRow> = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })
        .unwrap()
        .filter_map(Result::ok)
        .map(|(id, name, created_at)| {
            let db_path = tenant_dir(&state.data_dir, &id).join("data.sqlite");
            let db_bytes: u64 = std::fs::metadata(&db_path).map(|m| m.len()).unwrap_or(0);
            // Compute files usage from the tenant's _system_files table.
            // Gracefully degrades to 0 if the tenant predates the per-tenant
            // files feature or the DB doesn't exist yet.
            let files_bytes: u64 = crate::storage::tenant_db::open_read(&state.data_dir, &id)
                .ok()
                .and_then(|conn| {
                    conn.query_row(
                        "SELECT COALESCE(SUM(size_bytes), 0) FROM _system_files",
                        [],
                        |r| r.get::<_, i64>(0),
                    )
                    .ok()
                })
                .map(|b| b.max(0) as u64)
                .unwrap_or(0);
            TenantRow {
                id_short: short_id(&id),
                id,
                name,
                created_at,
                db_display: humanize_bytes(db_bytes),
                files_display: humanize_bytes(files_bytes),
                total_display: humanize_bytes(db_bytes + files_bytes),
            }
        })
        .collect();
    let disk = crate::mgmt::public_files::build_disk_view();
    Html(
        TenantsListPage {
            tenants: rows,
            version: env!("CARGO_PKG_VERSION"),
            disk,
        }
        .render()
        .unwrap(),
    )
    .into_response()
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
        Ok(_) => Redirect::to("/drust/admin/tenants").into_response(),
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

/// GET /admin/tenants/{id}/files
/// Renders the tenant's _system_files with upload form + per-row actions.
/// Admin uploads go to the tenant's own buckets (tenant-{id}-{pub,prv}).
pub async fn tenant_files_admin_page(
    State(state): State<TenantsState>,
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
        }
        .render()
        .unwrap(),
    )
    .into_response()
}
