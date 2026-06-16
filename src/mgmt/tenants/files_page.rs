//! Tenant-files admin page (group D). Relocated from `tenants.rs` by Finding #4.

use super::TenantsState;
use crate::mgmt::format::humanize_bytes;
use crate::mgmt::i18n::{LocaleHint, Translator};
use crate::storage::tenant_db::open_read;
use askama::Template;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};

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
    admin: crate::mgmt::admin_profile::AdminProfileExt,
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

/// GET /admin/tenants/{id}/files
/// Renders the tenant's _system_files with upload form + per-row actions.
/// Admin uploads go to the tenant's own buckets (tenant-{id}-{pub,prv}).
pub async fn tenant_files_admin_page(
    State(state): State<TenantsState>,
    LocaleHint(locale): LocaleHint,
    crate::mgmt::theme::ThemeHint(theme): crate::mgmt::theme::ThemeHint,
    axum::Extension(admin): axum::Extension<crate::mgmt::admin_profile::AdminProfileExt>,
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
            crate::base_path::base(&format!("/admin/tenants/{tenant_id}/files?page={p}"))
        } else {
            crate::base_path::base(&format!(
                "/admin/tenants/{tenant_id}/files?page={p}&per_page={per_page}"
            ))
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
                admin: admin.clone(),
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
    let files: Vec<AdminTenantFileRow> =
        match stmt.query_map(rusqlite::params![per_page as i64, offset], |r| {
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
        }) {
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
