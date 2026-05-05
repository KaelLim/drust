//! Admin-UI handlers for `drust-backup` snapshot inspection + download.
//!
//! Read-only on top of the existing `drust-backup.timer` output. Snapshots
//! live at `<data_dir>/backups/drust-*.tar.zst` (rotated 30 days by the
//! shell script). This module never writes — restore lives outside this
//! UI for now (extract manually via `tar --zstd -xf ...`).

use askama::Template;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use chrono::{DateTime, Utc};
use std::path::PathBuf;
use std::time::SystemTime;

#[derive(Clone)]
pub struct BackupsState {
    pub data_dir: PathBuf,
}

pub struct BackupRow {
    pub filename: String,
    pub size_human: String,
    pub mtime_iso: String,
    pub age_human: String,
}

#[derive(Template)]
#[template(path = "backups.html")]
struct BackupsPage {
    version: &'static str,
    backups: Vec<BackupRow>,
    backup_dir: String,
    total_size_human: String,
}

fn humanize_bytes(n: u64) -> String {
    let nf = n as f64;
    if n < 1024 {
        format!("{n} B")
    } else if n < 1024 * 1024 {
        format!("{:.1} KB", nf / 1024.0)
    } else if n < 1024 * 1024 * 1024 {
        format!("{:.1} MB", nf / 1_048_576.0)
    } else {
        format!("{:.2} GB", nf / 1_073_741_824.0)
    }
}

fn humanize_age(secs: i64) -> String {
    if secs < 0 {
        return "future".into();
    }
    let s = secs as u64;
    if s < 60 {
        format!("{s}s ago")
    } else if s < 3600 {
        format!("{}m ago", s / 60)
    } else if s < 86_400 {
        format!("{}h ago", s / 3600)
    } else {
        format!("{}d ago", s / 86_400)
    }
}

/// Treat the leaf as a backup if it (a) is a regular file, (b) starts with
/// `drust-`, and (c) ends with `.tar.zst`. Anything else (including `..`
/// segments — which `Path::file_name()` can never return for valid input)
/// is rejected by the download handler before any FS access.
fn is_safe_backup_filename(name: &str) -> bool {
    name.starts_with("drust-")
        && name.ends_with(".tar.zst")
        && !name.contains('/')
        && !name.contains('\\')
        && name != "."
        && name != ".."
}

pub async fn list_page(State(state): State<BackupsState>) -> Response {
    let dir = state.data_dir.join("backups");
    let mut rows: Vec<BackupRow> = Vec::new();
    let mut total: u64 = 0;
    let now_sys = SystemTime::now();

    if let Ok(entries) = std::fs::read_dir(&dir) {
        let mut collected: Vec<(String, u64, SystemTime)> = entries
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                if !is_safe_backup_filename(&name) {
                    return None;
                }
                let md = e.metadata().ok()?;
                if !md.is_file() {
                    return None;
                }
                let mtime = md.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                Some((name, md.len(), mtime))
            })
            .collect();
        // Newest first by filename (timestamp embedded in name → lexical sort works).
        collected.sort_by(|a, b| b.0.cmp(&a.0));
        for (name, size, mtime) in collected {
            total += size;
            let dt: DateTime<Utc> = mtime.into();
            let age_secs = now_sys
                .duration_since(mtime)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            rows.push(BackupRow {
                filename: name,
                size_human: humanize_bytes(size),
                mtime_iso: dt.format("%Y-%m-%d %H:%M UTC").to_string(),
                age_human: humanize_age(age_secs),
            });
        }
    }

    Html(
        BackupsPage {
            version: env!("CARGO_PKG_VERSION"),
            backups: rows,
            backup_dir: dir.display().to_string(),
            total_size_human: humanize_bytes(total),
        }
        .render()
        .unwrap(),
    )
    .into_response()
}

pub async fn download_one(
    State(state): State<BackupsState>,
    Path(filename): Path<String>,
) -> Response {
    if !is_safe_backup_filename(&filename) {
        return (StatusCode::BAD_REQUEST, "invalid backup name").into_response();
    }
    let path = state.data_dir.join("backups").join(&filename);
    let file = match tokio::fs::File::open(&path).await {
        Ok(f) => f,
        Err(_) => return (StatusCode::NOT_FOUND, "backup not found").into_response(),
    };
    let size = match file.metadata().await {
        Ok(m) => m.len(),
        Err(_) => 0,
    };
    let stream = tokio_util::io::ReaderStream::new(file);
    let body = Body::from_stream(stream);
    let mut resp = body.into_response();
    let headers = resp.headers_mut();
    headers.insert(header::CONTENT_TYPE, "application/zstd".parse().unwrap());
    if size > 0 {
        headers.insert(header::CONTENT_LENGTH, size.into());
    }
    headers.insert(
        header::CONTENT_DISPOSITION,
        format!("attachment; filename=\"{filename}\"")
            .parse()
            .unwrap(),
    );
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_backup_filenames() {
        assert!(!is_safe_backup_filename(""));
        assert!(!is_safe_backup_filename("../etc/passwd"));
        assert!(!is_safe_backup_filename("drust-foo.txt"));
        assert!(!is_safe_backup_filename("evil/drust-2026.tar.zst"));
        assert!(!is_safe_backup_filename(".."));
        assert!(!is_safe_backup_filename("."));
    }

    #[test]
    fn accepts_real_backup_names() {
        assert!(is_safe_backup_filename("drust-2026-04-20-191001.tar.zst"));
        assert!(is_safe_backup_filename("drust-2026-05-05-030000.tar.zst"));
    }

    #[test]
    fn humanize_bytes_picks_correct_unit() {
        assert_eq!(humanize_bytes(0), "0 B");
        assert_eq!(humanize_bytes(512), "512 B");
        assert_eq!(humanize_bytes(2048), "2.0 KB");
        assert_eq!(humanize_bytes(2_097_152), "2.0 MB");
        assert_eq!(humanize_bytes(2_147_483_648), "2.00 GB");
    }
}
