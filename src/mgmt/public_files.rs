//! Admin UI for the host-level public bucket. Provides list, upload, delete,
//! and reconcile actions against Garage (via `storage::garage::GarageClient`).
//!
//! Reads are NOT served through here — anonymous GETs go
//! `Caddy → Garage s3_web` directly. This module only handles management.

use crate::auth::middleware::AdminSessionState;
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
}

#[derive(Template)]
#[template(path = "public_files.html")]
struct PublicFilesPage {
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
}

#[derive(Template)]
#[template(path = "public_files_reconcile.html")]
struct ReconcilePage {
    version: &'static str,
    orphan_objects: Vec<(String, String)>, // (key, size_human)
    dangling_rows: Vec<(i64, String, String)>, // (id, key, original_name)
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

    let (files, total_files, total_bytes) = match load_files(&state, page_num, per_page).await {
        Ok(v) => v,
        Err(e) => return internal(format!("load: {e}")),
    };
    let total_pages = if total_files == 0 {
        1
    } else {
        ((total_files as f64) / (per_page as f64)).ceil() as u32
    };

    let pager_url = |p: u32| -> String {
        if per_page == DEFAULT_PER_PAGE {
            format!("/drust/admin/public-files?page={p}")
        } else {
            format!("/drust/admin/public-files?page={p}&per_page={per_page}")
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

    let page = PublicFilesPage {
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
    };
    Html(page.render().unwrap()).into_response()
}

pub async fn upload_submit(
    State(state): State<PublicFilesState>,
    headers: axum::http::HeaderMap,
    mut multipart: Multipart,
) -> Response {
    let Some(garage) = state.garage.clone() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "storage not configured").into_response();
    };

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

    let field = match multipart.next_field().await {
        Ok(Some(f)) => f,
        Ok(None) => return (StatusCode::BAD_REQUEST, "missing file field").into_response(),
        Err(e) => return (StatusCode::BAD_REQUEST, format!("multipart: {e}")).into_response(),
    };
    let original_name = field
        .file_name()
        .map(|s| s.to_string())
        .unwrap_or_else(|| "unnamed".to_string());
    let explicit_ct = field.content_type().map(|s| s.to_string());
    let body = match field.bytes().await {
        Ok(b) => b,
        Err(e) => {
            // `axum::extract::Multipart::bytes` surfaces DefaultBodyLimit
            // overflow as a 413. Other errors (e.g. connection reset) land
            // here — treat as bad request.
            let msg = e.to_string();
            if msg.to_lowercase().contains("large") {
                return (StatusCode::PAYLOAD_TOO_LARGE, msg).into_response();
            }
            return (StatusCode::BAD_REQUEST, format!("read body: {e}")).into_response();
        }
    };
    let size = body.len() as i64;

    let ext = std::path::Path::new(&original_name)
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("bin");
    let key = format!("{}.{}", uuid::Uuid::new_v4(), ext);

    // Browsers send `application/octet-stream` for any type they don't
    // recognise (notably `.md`, `.toml`, `.rs`, …). Treat that as "no
    // useful guess" and fall back to mime_guess from the filename
    // extension. Only honour an explicit non-octet-stream Content-Type.
    let sniffed_ct = explicit_ct
        .filter(|ct| ct != "application/octet-stream")
        .or_else(|| {
            mime_guess::from_path(&original_name)
                .first_raw()
                .map(|s| s.to_string())
        });
    let disposition = format!(
        "inline; filename=\"{}\"",
        original_name.replace('\\', "\\\\").replace('"', "\\\"")
    );

    // SQLite-first: insert metadata, then push to Garage. If the Garage put
    // fails we compensate by deleting the row so we don't leave a ghost.
    {
        let conn = state.meta.lock().await;
        if let Err(e) = conn.execute(
            "INSERT INTO _system_files
             (key, original_name, content_type, size_bytes, content_disposition, uploader)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                &key,
                &original_name,
                &sniffed_ct,
                size,
                &disposition,
                "admin",
            ],
        ) {
            return internal(format!("db insert: {e}"));
        }
    }

    if let Err(e) = garage
        .put_object(&key, body, sniffed_ct.as_deref(), &original_name)
        .await
    {
        // Log the full error chain (context + source) so we can see the
        // underlying object_store message, not just the outer `context`.
        tracing::error!(
            key = %key,
            original_name = %original_name,
            content_type = ?sniffed_ct,
            error = format!("{e:#}"),
            "garage put failed — rolling back metadata row"
        );
        let conn = state.meta.lock().await;
        let _ = conn.execute(
            "DELETE FROM _system_files WHERE key = ?1",
            rusqlite::params![&key],
        );
        return internal(format!("garage put: {e:#}"));
    }

    Redirect::to("/drust/admin/public-files").into_response()
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
        return Redirect::to("/drust/admin/public-files").into_response();
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
    Redirect::to("/drust/admin/public-files").into_response()
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
        let mut stmt = match conn
            .prepare("SELECT id, key, original_name FROM _system_files ORDER BY id")
        {
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
    Redirect::to("/drust/admin/public-files").into_response()
}

async fn load_files(
    state: &PublicFilesState,
    page: u32,
    per_page: u32,
) -> anyhow::Result<(Vec<PublicFileRow>, i64, u64)> {
    let conn = state.meta.lock().await;

    // Totals across ALL rows (not just the current page).
    let total_files: i64 =
        conn.query_row("SELECT COUNT(*) FROM _system_files", [], |r| {
            r.get(0)
        })?;
    let total_bytes: i64 = conn
        .query_row(
            "SELECT COALESCE(SUM(size_bytes), 0) FROM _system_files",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);

    let offset = (page.saturating_sub(1) as i64) * (per_page as i64);
    let mut stmt = conn.prepare(
        "SELECT id, key, original_name, COALESCE(content_type,''), size_bytes, uploaded_at
         FROM _system_files
         ORDER BY uploaded_at DESC, id DESC
         LIMIT ?1 OFFSET ?2",
    )?;
    let rows = stmt
        .query_map(rusqlite::params![per_page as i64, offset], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, String>(5)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let base = state.base_url.trim_end_matches('/');
    let files = rows
        .into_iter()
        .map(
            |(id, key, original_name, content_type, size_bytes, uploaded_at)| PublicFileRow {
                id,
                public_url: format!("{base}/public/{key}"),
                key,
                original_name,
                content_type,
                size_human: humanize_bytes(size_bytes.max(0) as u64),
                uploaded_at,
            },
        )
        .collect();
    Ok((files, total_files, total_bytes.max(0) as u64))
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

fn internal(msg: String) -> Response {
    let mut r = msg.into_response();
    *r.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    r
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
