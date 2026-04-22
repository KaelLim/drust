//! Admin UI for the host-level public bucket. Provides list, upload, delete,
//! and reconcile actions against Garage (via `storage::garage::GarageClient`).
//!
//! Reads are NOT served through here — anonymous GETs go
//! `Caddy → Garage s3_web` directly. This module only handles management.

use crate::auth::middleware::AdminSessionState;
use crate::storage::files::{
    Disposition, Owner, Visibility, bucket_for_upload, default_cache_control,
};
use crate::storage::garage::GarageClient;
use askama::Template;
use axum::extract::{Multipart, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
// axum_extra::extract::Form uses `serde_html_form` under the hood which
// handles repeated form fields (e.g. multiple checkboxes with the same
// name) as `Vec<T>`. The stock axum `Form` uses `serde_urlencoded`,
// which only keeps the last value and errors out for Vec-typed fields.
use axum_extra::extract::Form;
use rusqlite::Connection;
use serde::Deserialize;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::Mutex;

const DEFAULT_PER_PAGE: u32 = 25;
const PER_PAGE_OPTIONS: &[u32] = &[10, 25, 50, 100];

#[derive(Clone)]
pub struct PublicFilesState {
    pub session: AdminSessionState,
    pub meta: Arc<Mutex<Connection>>,
    pub garage: Option<Arc<GarageClient>>,
    pub base_url: String,
    pub max_upload_bytes: usize,
    /// Minimum free-disk percentage before uploads are refused (507).
    pub disk_min_free_pct: u8,
}

#[derive(Debug, Clone)]
pub struct PublicFileRow {
    pub id: i64,
    pub key: String,
    pub original_name: String,
    pub content_type: String,
    pub size_human: String,
    pub uploaded_at: String,
    pub public_url: String,
    /// "public" or "private"
    pub visibility: String,
}

/// File counts broken down by visibility.
pub struct Counts {
    pub total: i64,
    pub public: i64,
    pub private: i64,
}

/// Disk usage view for the banner.
pub struct DiskView {
    pub used_gb: String,
    pub total_gb: String,
    pub free_pct: f64,
    pub free_pct_display: String,
}

#[derive(Template)]
#[template(path = "files.html")]
struct FilesPage {
    version: &'static str,
    storage_available: bool,
    files: Vec<PublicFileRow>,
    total_files: i64,
    total_bytes_human: String,
    max_upload_mb: u64,
    page: u32,
    per_page: u32,
    total_pages: u32,
    prev_url: Option<String>,
    next_url: Option<String>,
    per_page_options: Vec<PerPageOption>,
    filter: String,
    counts: Counts,
    disk: DiskView,
}

struct PerPageOption {
    value: u32,
    selected: bool,
}

#[derive(Debug, Deserialize, Default)]
pub struct ListQs {
    #[serde(default)]
    pub page: Option<u32>,
    #[serde(default)]
    pub per_page: Option<u32>,
    #[serde(default)]
    pub vis: Option<String>,
}

#[derive(Template)]
#[template(path = "public_files_reconcile.html")]
struct ReconcilePage {
    version: &'static str,
    orphan_objects: Vec<(String, String)>, // (key, size_human)
    dangling_rows: Vec<(i64, String, String)>, // (id, key, original_name)
}

/// Build a `DiskView` for the Garage data volume. If `/var/lib/garage` is
/// unavailable, returns neutral placeholder values (free_pct = 100 so no
/// warning banner appears).
pub fn build_disk_view() -> DiskView {
    match crate::storage::disk::disk_stats(std::path::Path::new("/var/lib/garage")) {
        Ok(stats) => {
            let gb = |b: u64| format!("{:.1}", b as f64 / 1_073_741_824.0);
            DiskView {
                used_gb: gb(stats.used_bytes),
                total_gb: gb(stats.total_bytes),
                free_pct: stats.free_pct,
                free_pct_display: format!("{:.1}", stats.free_pct),
            }
        }
        Err(_) => DiskView {
            used_gb: "?".into(),
            total_gb: "?".into(),
            free_pct: 100.0,
            free_pct_display: "?".into(),
        },
    }
}

pub async fn list_page(
    State(state): State<PublicFilesState>,
    Query(qs): Query<ListQs>,
) -> Response {
    let per_page = qs
        .per_page
        .filter(|n| PER_PAGE_OPTIONS.contains(n))
        .unwrap_or(DEFAULT_PER_PAGE);
    let page_num = qs.page.unwrap_or(1).max(1);

    // Normalize the vis filter: only "public" or "private" are valid; everything else is "all".
    let filter = match qs.vis.as_deref() {
        Some("public") => "public".to_string(),
        Some("private") => "private".to_string(),
        _ => "all".to_string(),
    };

    let (files, total_files, total_bytes, counts) =
        match load_files(&state, page_num, per_page, &filter).await {
            Ok(v) => v,
            Err(e) => return internal(format!("load: {e}")),
        };
    let total_pages = if total_files == 0 {
        1
    } else {
        ((total_files as f64) / (per_page as f64)).ceil() as u32
    };

    let pager_url = |p: u32| -> String {
        let vis_part = if filter != "all" {
            format!("&vis={}", filter)
        } else {
            String::new()
        };
        if per_page == DEFAULT_PER_PAGE {
            format!("/drust/admin/files?page={p}{vis_part}")
        } else {
            format!("/drust/admin/files?page={p}&per_page={per_page}{vis_part}")
        }
    };
    let prev_url = (page_num > 1).then(|| pager_url(page_num - 1));
    let next_url = (page_num < total_pages).then(|| pager_url(page_num + 1));

    let per_page_options: Vec<PerPageOption> = PER_PAGE_OPTIONS
        .iter()
        .map(|&v| PerPageOption {
            value: v,
            selected: v == per_page,
        })
        .collect();

    // Build disk view. If /var/lib/garage is unavailable, show neutral placeholders.
    let disk = build_disk_view();

    let page = FilesPage {
        version: env!("CARGO_PKG_VERSION"),
        storage_available: state.garage.is_some(),
        files,
        total_files,
        total_bytes_human: humanize_bytes(total_bytes),
        max_upload_mb: (state.max_upload_bytes / (1024 * 1024)) as u64,
        page: page_num,
        per_page,
        total_pages,
        prev_url,
        next_url,
        per_page_options,
        filter,
        counts,
        disk,
    };
    Html(page.render().unwrap()).into_response()
}

/// Parsed, validated fields extracted from the upload multipart form.
/// Used by `upload_submit` and directly testable via `parse_upload_fields`.
#[derive(Debug)]
pub struct UploadFields {
    pub original_name: String,
    pub explicit_ct: Option<String>,
    pub body: bytes::Bytes,
    pub visibility: Visibility,
    pub disposition: Disposition,
    pub cache_control_override: Option<String>,
    pub meta_json: Option<String>,
}

/// Parse and validate the multipart fields from an admin upload form.
///
/// Returns `Ok(UploadFields)` on success or `Err(reason)` for user-visible
/// 400 errors. Kept pure (no I/O) so it can be tested without spinning up
/// an axum router or a Garage mock.
pub async fn parse_upload_fields(mut multipart: Multipart) -> Result<UploadFields, String> {
    let mut file_name: Option<String> = None;
    let mut file_ct: Option<String> = None;
    let mut file_body: Option<bytes::Bytes> = None;
    let mut visibility_str: Option<String> = None;
    let mut disposition_str: Option<String> = None;
    let mut cache_control: Option<String> = None;
    let mut meta_json: Option<String> = None;

    loop {
        let field = match multipart.next_field().await {
            Ok(Some(f)) => f,
            Ok(None) => break,
            Err(e) => {
                let msg = e.to_string();
                if msg.to_lowercase().contains("large") {
                    // surface as caller-distinguishable string; upload_submit maps this to 413
                    return Err(format!("__413__{msg}"));
                }
                return Err(format!("multipart: {e}"));
            }
        };

        let field_name = field.name().unwrap_or("").to_string();
        match field_name.as_str() {
            "file" => {
                file_name = field.file_name().map(|s| s.to_string());
                file_ct = field.content_type().map(|s| s.to_string());
                let b = match field.bytes().await {
                    Ok(b) => b,
                    Err(e) => {
                        let msg = e.to_string();
                        if msg.to_lowercase().contains("large") {
                            return Err(format!("__413__{msg}"));
                        }
                        return Err(format!("read body: {e}"));
                    }
                };
                file_body = Some(b);
            }
            "visibility" => {
                visibility_str = Some(
                    field
                        .text()
                        .await
                        .map_err(|e| format!("visibility field: {e}"))?,
                );
            }
            "disposition" => {
                disposition_str = Some(
                    field
                        .text()
                        .await
                        .map_err(|e| format!("disposition field: {e}"))?,
                );
            }
            "cache_control" => {
                let v = field
                    .text()
                    .await
                    .map_err(|e| format!("cache_control field: {e}"))?;
                if !v.is_empty() {
                    cache_control = Some(v);
                }
            }
            "meta" => {
                let v = field.text().await.map_err(|e| format!("meta field: {e}"))?;
                if !v.is_empty() {
                    // Validate: must be a JSON object, not array/scalar.
                    let parsed: serde_json::Value = serde_json::from_str(&v)
                        .map_err(|e| format!("meta is not valid JSON: {e}"))?;
                    if !parsed.is_object() {
                        return Err("meta must be a JSON object (got array or scalar)".to_string());
                    }
                    meta_json = Some(v);
                }
            }
            _ => {
                // Drain unknown fields silently.
                let _ = field.bytes().await;
            }
        }
    }

    let body = file_body.ok_or("missing file field")?;
    let original_name = file_name.unwrap_or_else(|| "unnamed".to_string());

    let visibility = match visibility_str.as_deref().unwrap_or("public") {
        "public" => Visibility::Public,
        "private" => Visibility::Private,
        other => {
            return Err(format!(
                "invalid visibility: {other:?}; must be public or private"
            ));
        }
    };

    let disposition = match disposition_str.as_deref().unwrap_or("inline") {
        "inline" => Disposition::Inline,
        "attachment" => Disposition::Attachment,
        other => {
            return Err(format!(
                "invalid disposition: {other:?}; must be inline or attachment"
            ));
        }
    };

    Ok(UploadFields {
        original_name,
        explicit_ct: file_ct,
        body,
        visibility,
        disposition,
        cache_control_override: cache_control,
        meta_json,
    })
}

pub async fn upload_submit(
    State(state): State<PublicFilesState>,
    headers: axum::http::HeaderMap,
    multipart: Multipart,
) -> Response {
    let Some(garage) = state.garage.clone() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "storage not configured").into_response();
    };

    // Step 1: disk check BEFORE reading the body.
    // Best-effort: if /var/lib/garage doesn't exist or isn't readable, skip.
    match crate::storage::disk::disk_stats(std::path::Path::new("/var/lib/garage")) {
        Ok(stats) => {
            if (stats.free_pct as u8) < state.disk_min_free_pct {
                return (
                    StatusCode::INSUFFICIENT_STORAGE,
                    format!(
                        "disk too full: {:.1}% free, minimum {}% required",
                        stats.free_pct, state.disk_min_free_pct
                    ),
                )
                    .into_response();
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "disk_stats for /var/lib/garage failed — skipping disk check");
        }
    }

    // Pre-check Content-Length so an oversized upload surfaces as 413 with a
    // clean message — otherwise DefaultBodyLimit kicks in mid-stream and the
    // multipart parser reports an opaque 400 "incomplete stream".
    if let Some(cl) = headers
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
    {
        if cl as usize > state.max_upload_bytes {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                format!(
                    "upload exceeds {} MB limit ({} bytes provided)",
                    state.max_upload_bytes / (1024 * 1024),
                    cl
                ),
            )
                .into_response();
        }
    }

    // Step 2: parse + validate multipart fields.
    let fields = match parse_upload_fields(multipart).await {
        Ok(f) => f,
        Err(e) if e.starts_with("__413__") => {
            return (StatusCode::PAYLOAD_TOO_LARGE, e[7..].to_string()).into_response();
        }
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };

    let UploadFields {
        original_name,
        explicit_ct,
        body,
        visibility,
        disposition,
        cache_control_override,
        meta_json,
    } = fields;

    let size = body.len() as i64;

    // Step 3: resolve content-type.
    let sniffed_ct = explicit_ct
        .filter(|ct| ct != "application/octet-stream")
        .or_else(|| {
            mime_guess::from_path(&original_name)
                .first_raw()
                .map(|s| s.to_string())
        });

    // Step 4: build cache_control.
    let cache_control = cache_control_override
        .as_deref()
        .map(|s| s.to_string())
        .unwrap_or_else(|| default_cache_control(visibility, disposition).to_string());

    // Step 5: resolve disposition mode string and bucket.
    let disp_mode = match disposition {
        Disposition::Inline => "inline",
        Disposition::Attachment => "attachment",
    };
    let vis_str = match visibility {
        Visibility::Public => "public",
        Visibility::Private => "private",
    };
    let bucket = bucket_for_upload(&Owner::Admin, visibility);

    // Step 6: generate key.
    let ext = std::path::Path::new(&original_name)
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("bin");
    let key = format!("{}.{}", uuid::Uuid::new_v4(), ext);

    // Step 7: SQLite-first insert. Push to Garage next. Compensate on failure.
    {
        let conn = state.meta.lock().await;
        if let Err(e) = conn.execute(
            "INSERT INTO _system_files
             (key, original_name, content_type, size_bytes, content_disposition,
              visibility, cache_control, meta_json, uploader)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                &key,
                &original_name,
                &sniffed_ct,
                size,
                disp_mode,
                vis_str,
                &cache_control,
                &meta_json,
                "admin",
            ],
        ) {
            return internal(format!("db insert: {e}"));
        }
    }

    // Step 8: PUT to Garage. On failure, compensating DELETE.
    if let Err(e) = garage
        .put_object_in(
            &bucket,
            &key,
            body,
            sniffed_ct.as_deref(),
            disp_mode,
            &original_name,
            Some(&cache_control),
            meta_json.as_deref(),
        )
        .await
    {
        tracing::error!(
            key = %key,
            bucket = %bucket,
            original_name = %original_name,
            content_type = ?sniffed_ct,
            error = format!("{e:#}"),
            "garage put_object_in failed — rolling back metadata row"
        );
        let conn = state.meta.lock().await;
        let _ = conn.execute(
            "DELETE FROM _system_files WHERE key = ?1",
            rusqlite::params![&key],
        );
        return (StatusCode::BAD_GATEWAY, format!("garage put: {e:#}")).into_response();
    }

    Redirect::to("/drust/admin/files").into_response()
}

pub async fn delete_submit(State(state): State<PublicFilesState>, Path(id): Path<i64>) -> Response {
    let Some(garage) = state.garage.clone() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "storage not configured").into_response();
    };

    let key: Option<String> = {
        let conn = state.meta.lock().await;
        conn.query_row(
            "SELECT key FROM _system_files WHERE id = ?1",
            rusqlite::params![id],
            |r| r.get::<_, String>(0),
        )
        .ok()
    };
    let Some(key) = key else {
        // Already gone — idempotent.
        return Redirect::to("/drust/admin/files").into_response();
    };

    if let Err(e) = garage.delete_object(&key).await {
        return internal(format!("garage delete: {e}"));
    }
    {
        let conn = state.meta.lock().await;
        if let Err(e) = conn.execute(
            "DELETE FROM _system_files WHERE id = ?1",
            rusqlite::params![id],
        ) {
            return internal(format!("db delete: {e}"));
        }
    }
    Redirect::to("/drust/admin/files").into_response()
}

pub async fn reconcile_page(State(state): State<PublicFilesState>) -> Response {
    let Some(garage) = state.garage.clone() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "storage not configured").into_response();
    };

    let garage_list = match garage.list_objects().await {
        Ok(v) => v,
        Err(e) => return internal(format!("garage list: {e}")),
    };
    let garage_keys: HashSet<String> = garage_list.iter().map(|o| o.key.clone()).collect();

    let db_rows: Vec<(i64, String, String)> = {
        let conn = state.meta.lock().await;
        let mut stmt =
            match conn.prepare("SELECT id, key, original_name FROM _system_files ORDER BY id") {
                Ok(s) => s,
                Err(e) => return internal(format!("db prepare: {e}")),
            };
        match stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        }) {
            Ok(it) => it.filter_map(|r| r.ok()).collect(),
            Err(e) => return internal(format!("db query: {e}")),
        }
    };
    let db_keys: HashSet<String> = db_rows.iter().map(|(_, k, _)| k.clone()).collect();

    let orphan_objects: Vec<(String, String)> = garage_list
        .iter()
        .filter(|o| !db_keys.contains(&o.key))
        .map(|o| (o.key.clone(), humanize_bytes(o.size)))
        .collect();

    let dangling_rows: Vec<(i64, String, String)> = db_rows
        .into_iter()
        .filter(|(_, k, _)| !garage_keys.contains(k))
        .collect();

    Html(
        ReconcilePage {
            version: env!("CARGO_PKG_VERSION"),
            orphan_objects,
            dangling_rows,
        }
        .render()
        .unwrap(),
    )
    .into_response()
}

#[derive(Debug, Deserialize)]
pub struct ReconcileForm {
    #[serde(default)]
    pub delete_orphan_keys: Vec<String>,
    #[serde(default)]
    pub delete_dangling_ids: Vec<i64>,
}

pub async fn reconcile_apply(
    State(state): State<PublicFilesState>,
    Form(form): Form<ReconcileForm>,
) -> Response {
    let Some(garage) = state.garage.clone() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "storage not configured").into_response();
    };

    for key in form.delete_orphan_keys {
        if let Err(e) = garage.delete_object(&key).await {
            tracing::warn!(key = %key, error = %e, "reconcile: orphan delete failed");
        }
    }
    {
        let conn = state.meta.lock().await;
        for id in form.delete_dangling_ids {
            let _ = conn.execute(
                "DELETE FROM _system_files WHERE id = ?1",
                rusqlite::params![id],
            );
        }
    }
    Redirect::to("/drust/admin/files").into_response()
}

async fn load_files(
    state: &PublicFilesState,
    page: u32,
    per_page: u32,
    filter: &str,
) -> anyhow::Result<(Vec<PublicFileRow>, i64, u64, Counts)> {
    let conn = state.meta.lock().await;

    // Counts broken down by visibility (always over the full table, not just the current filter).
    let count_total: i64 =
        conn.query_row("SELECT COUNT(*) FROM _system_files", [], |r| r.get(0))?;
    let count_public: i64 = conn.query_row(
        "SELECT COUNT(*) FROM _system_files WHERE visibility = 'public'",
        [],
        |r| r.get(0),
    )?;
    let count_private: i64 = conn.query_row(
        "SELECT COUNT(*) FROM _system_files WHERE visibility = 'private'",
        [],
        |r| r.get(0),
    )?;
    let counts = Counts {
        total: count_total,
        public: count_public,
        private: count_private,
    };

    // total_files for the current filter (used for pager).
    let total_files: i64 = match filter {
        "public" => count_public,
        "private" => count_private,
        _ => count_total,
    };

    let total_bytes: i64 = match filter {
        "public" => conn
            .query_row(
                "SELECT COALESCE(SUM(size_bytes), 0) FROM _system_files WHERE visibility = 'public'",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0),
        "private" => conn
            .query_row(
                "SELECT COALESCE(SUM(size_bytes), 0) FROM _system_files WHERE visibility = 'private'",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0),
        _ => conn
            .query_row(
                "SELECT COALESCE(SUM(size_bytes), 0) FROM _system_files",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0),
    };

    let offset = (page.saturating_sub(1) as i64) * (per_page as i64);

    // Build the query string depending on the visibility filter.
    let sql = match filter {
        "public" => {
            "SELECT id, key, original_name, COALESCE(content_type,''), size_bytes, uploaded_at, visibility
             FROM _system_files
             WHERE visibility = 'public'
             ORDER BY uploaded_at DESC, id DESC
             LIMIT ?1 OFFSET ?2"
        }
        "private" => {
            "SELECT id, key, original_name, COALESCE(content_type,''), size_bytes, uploaded_at, visibility
             FROM _system_files
             WHERE visibility = 'private'
             ORDER BY uploaded_at DESC, id DESC
             LIMIT ?1 OFFSET ?2"
        }
        _ => {
            "SELECT id, key, original_name, COALESCE(content_type,''), size_bytes, uploaded_at, visibility
             FROM _system_files
             ORDER BY uploaded_at DESC, id DESC
             LIMIT ?1 OFFSET ?2"
        }
    };

    let mut stmt = conn.prepare(sql)?;
    let rows = stmt
        .query_map(rusqlite::params![per_page as i64, offset], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, String>(6)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let base = state.base_url.trim_end_matches('/');
    let files = rows
        .into_iter()
        .map(
            |(id, key, original_name, content_type, size_bytes, uploaded_at, visibility)| {
                PublicFileRow {
                    id,
                    public_url: format!("{base}/public/{key}"),
                    key,
                    original_name,
                    content_type,
                    size_human: humanize_bytes(size_bytes.max(0) as u64),
                    uploaded_at,
                    visibility,
                }
            },
        )
        .collect();
    Ok((files, total_files, total_bytes.max(0) as u64, counts))
}

fn humanize_bytes(n: u64) -> String {
    const K: u64 = 1024;
    if n < K {
        format!("{n} B")
    } else if n < K * K {
        format!("{:.1} KB", n as f64 / K as f64)
    } else if n < K * K * K {
        format!("{:.1} MB", n as f64 / (K * K) as f64)
    } else {
        format!("{:.2} GB", n as f64 / (K * K * K) as f64)
    }
}

// (Previous `parse_size_human` summed displayed strings back into bytes —
// removed in favour of SQL SUM at query time, which is both exact and
// cheaper.)

/// GET /drust/admin/files/<key>/bytes
/// Admin-only: streams the raw bytes for any file stored in the admin buckets
/// (both public and private). Requires an active admin session.
pub async fn admin_stream_bytes(
    State(state): State<PublicFilesState>,
    Path(key): Path<String>,
) -> Result<axum::response::Response, (StatusCode, String)> {
    let garage = state.garage.clone().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "storage not configured".into(),
        )
    })?;

    let conn = state.meta.lock().await;
    let row = conn
        .query_row(
            "SELECT * FROM _system_files WHERE key = ?1",
            rusqlite::params![key],
            crate::storage::files::map_file_row,
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => (StatusCode::NOT_FOUND, "not found".into()),
            other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
        })?;
    drop(conn);

    let visibility = if row.visibility == "public" {
        crate::storage::files::Visibility::Public
    } else {
        crate::storage::files::Visibility::Private
    };
    let bucket =
        crate::storage::files::bucket_for_upload(&crate::storage::files::Owner::Admin, visibility);

    let stream = garage
        .get_object_stream_in(&bucket, &key)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("get: {e}")))?;

    let ct = row
        .content_type
        .as_deref()
        .unwrap_or("application/octet-stream");
    let disp_mode = row.content_disposition.as_deref().unwrap_or("inline");
    let ascii = crate::storage::garage::ascii_fallback_filename(&row.original_name);
    let pct = urlencoding::encode(&row.original_name);
    let cd = format!("{disp_mode}; filename=\"{ascii}\"; filename*=UTF-8''{pct}");
    let cc = row.cache_control.as_deref().unwrap_or("private, no-store");

    let mut headers = axum::http::HeaderMap::new();
    headers.insert(axum::http::header::CONTENT_TYPE, ct.parse().unwrap());
    headers.insert(axum::http::header::CONTENT_DISPOSITION, cd.parse().unwrap());
    headers.insert(axum::http::header::CACHE_CONTROL, cc.parse().unwrap());

    Ok((headers, axum::body::Body::from_stream(stream)).into_response())
}

fn internal(msg: String) -> Response {
    let mut r = msg.into_response();
    *r.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    r
}

#[derive(serde::Deserialize, Default)]
pub struct AdminSignRequest {
    pub expires_in: Option<u64>,
    pub download: Option<bool>,
}

#[derive(serde::Serialize)]
pub struct AdminSignResponse {
    pub url: String,
    pub expires_at: Option<String>,
}

/// POST /drust/admin/files/<key>/sign
pub async fn admin_sign_url(
    State(state): State<PublicFilesState>,
    Path(key): Path<String>,
    axum::Json(req): axum::Json<AdminSignRequest>,
) -> Result<axum::Json<AdminSignResponse>, (StatusCode, String)> {
    let expires_in = req.expires_in.unwrap_or(3600);
    if expires_in == 0 || expires_in > 604_800 {
        return Err((
            StatusCode::BAD_REQUEST,
            "expires_in must be 1–604800 seconds (7 days)".into(),
        ));
    }

    let conn = state.meta.lock().await;
    let row = conn
        .query_row(
            "SELECT * FROM _system_files WHERE key = ?1",
            rusqlite::params![key],
            crate::storage::files::map_file_row,
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => (StatusCode::NOT_FOUND, "not found".into()),
            other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
        })?;
    drop(conn);

    if row.visibility == "public" {
        let url = crate::storage::files::build_public_url(
            &state.base_url,
            &crate::storage::files::Owner::Admin,
            crate::storage::files::Visibility::Public,
            &row.key,
        );
        return Ok(axum::Json(AdminSignResponse {
            url,
            expires_at: None,
        }));
    }

    let garage = state.garage.clone().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "storage not configured".into(),
        )
    })?;

    let bucket = crate::storage::files::bucket_for_upload(
        &crate::storage::files::Owner::Admin,
        crate::storage::files::Visibility::Private,
    );
    let download_name = if req.download.unwrap_or(false) {
        Some(row.original_name.as_str())
    } else {
        None
    };
    let url = garage
        .signed_get_url(
            &bucket,
            &row.key,
            std::time::Duration::from_secs(expires_in),
            download_name,
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("sign: {e}")))?;

    let expires_at =
        (chrono::Utc::now() + chrono::Duration::seconds(expires_in as i64)).to_rfc3339();
    Ok(axum::Json(AdminSignResponse {
        url,
        expires_at: Some(expires_at),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn humanize_bytes_ranges() {
        assert_eq!(humanize_bytes(0), "0 B");
        assert_eq!(humanize_bytes(512), "512 B");
        assert_eq!(humanize_bytes(1536), "1.5 KB");
        assert_eq!(humanize_bytes(5 * 1024 * 1024), "5.0 MB");
    }
}
