//! Admin-UI handlers for `drust-backup` snapshot inspection + download.
//!
//! Read-only on top of the existing `drust-backup.timer` output. Snapshots
//! live at `<data_dir>/backups/drust-*.tar.zst` (rotated 30 days by the
//! shell script). This module never writes — restore lives outside this
//! UI for now (extract manually via `tar --zstd -xf ...`).

use askama::Template;
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use chrono::{DateTime, Utc};
use std::collections::BTreeMap;
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

pub struct TenantInBackup {
    pub id: String,
    pub name: String,
    pub created_at: String,
    /// `data.sqlite` size for this tenant inside the archive ("—" when
    /// the file is absent from the snapshot, e.g. tenant created after
    /// the backup ran).
    pub db_size_human: String,
    pub db_present: bool,
}

#[derive(Template)]
#[template(path = "backup_inspect.html")]
struct BackupInspectPage {
    version: &'static str,
    filename: String,
    snapshot_ts: String,
    snapshot_size_human: String,
    tenants: Vec<TenantInBackup>,
    /// Set after a successful restore (PRG-style flash).
    flash: Option<RestoreFlash>,
    error: Option<String>,
}

pub struct RestoreFlash {
    pub tenant_id: String,
    pub destination: String,
}

#[derive(Debug, serde::Deserialize)]
pub struct RestoreForm {
    pub tenant_id: String,
}

#[derive(Debug, Default, serde::Deserialize)]
pub struct InspectQs {
    /// Set after a successful PRG redirect from POST /restore.
    #[serde(default)]
    pub restored: Option<String>,
    /// Destination path produced by the same redirect.
    #[serde(default)]
    pub dest: Option<String>,
}

use crate::mgmt::format::humanize_bytes;

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

/// Extract just `meta.sqlite` from the snapshot to a freshly-allocated temp
/// file, plus a per-tenant lookup of the data.sqlite size present in the
/// same archive. Tar+zstd are synchronous, so this runs on a blocking
/// thread.
fn extract_meta_and_sizes(
    backup_path: &std::path::Path,
) -> anyhow::Result<(tempfile::NamedTempFile, BTreeMap<String, u64>)> {
    use std::fs::File;
    use std::io::Write;
    let file = File::open(backup_path)?;
    let dec = zstd::Decoder::new(file)?;
    let mut ar = tar::Archive::new(dec);

    let mut meta_tmp = tempfile::NamedTempFile::new()?;
    let mut meta_written = false;
    let mut tenant_db_sizes: BTreeMap<String, u64> = BTreeMap::new();

    for entry_res in ar.entries()? {
        let mut entry = entry_res?;
        let header = entry.header().clone();
        if header.entry_type() != tar::EntryType::Regular {
            continue;
        }
        let path = entry.path()?.to_path_buf();
        let path_str = path.to_string_lossy();
        let normalized = path_str.trim_start_matches("./");

        if normalized == "meta.sqlite" {
            std::io::copy(&mut entry, meta_tmp.as_file_mut())?;
            meta_tmp.as_file_mut().flush()?;
            meta_written = true;
        } else if let Some(tid) = parse_tenant_db_path(normalized) {
            tenant_db_sizes.insert(tid, header.size().unwrap_or(0));
        }
    }

    if !meta_written {
        anyhow::bail!("meta.sqlite not present in archive");
    }
    Ok((meta_tmp, tenant_db_sizes))
}

/// Parse `tenants/<id>/data.sqlite` (with optional `./` prefix) → `Some(id)`.
/// Anything else returns `None`.
fn parse_tenant_db_path(p: &str) -> Option<String> {
    let stripped = p.trim_start_matches("./");
    let rest = stripped.strip_prefix("tenants/")?;
    let mut parts = rest.splitn(2, '/');
    let tid = parts.next()?;
    let tail = parts.next()?;
    if tail == "data.sqlite" && !tid.is_empty() {
        Some(tid.to_string())
    } else {
        None
    }
}

/// `GET /admin/backups/{filename}/inspect` — open the archive on a blocking
/// thread, extract `meta.sqlite` + per-tenant data.sqlite sizes, render a
/// list. The temp meta.sqlite is dropped before the response is rendered.
pub async fn inspect(
    State(state): State<BackupsState>,
    Path(filename): Path<String>,
    Query(qs): Query<InspectQs>,
) -> Response {
    if !is_safe_backup_filename(&filename) {
        return (StatusCode::BAD_REQUEST, "invalid backup name").into_response();
    }
    let backup_path = state.data_dir.join("backups").join(&filename);
    let metadata = match std::fs::metadata(&backup_path) {
        Ok(m) => m,
        Err(_) => return (StatusCode::NOT_FOUND, "backup not found").into_response(),
    };

    let snapshot_size_human = humanize_bytes(metadata.len());
    let snapshot_mtime: DateTime<Utc> = metadata
        .modified()
        .map(DateTime::<Utc>::from)
        .unwrap_or_else(|_| Utc::now());

    let backup_path_clone = backup_path.clone();
    let extract_result = tokio::task::spawn_blocking(move || {
        extract_meta_and_sizes(&backup_path_clone)
    })
    .await;

    let (meta_tmp, sizes) = match extract_result {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            return render_inspect_error(filename, snapshot_mtime, snapshot_size_human, e.to_string());
        }
        Err(e) => {
            return render_inspect_error(filename, snapshot_mtime, snapshot_size_human, format!("join error: {e}"));
        }
    };

    let conn_res = rusqlite::Connection::open_with_flags(
        meta_tmp.path(),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    );
    let conn = match conn_res {
        Ok(c) => c,
        Err(e) => {
            return render_inspect_error(filename, snapshot_mtime, snapshot_size_human, format!("open meta.sqlite: {e}"));
        }
    };

    let tenants: Vec<TenantInBackup> = match conn
        .prepare("SELECT id, name, created_at FROM tenants WHERE deleted_at IS NULL ORDER BY name")
    {
        Ok(mut stmt) => stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })
            .map(|rows| {
                rows.filter_map(Result::ok)
                    .map(|(id, name, created_at)| {
                        let db_present = sizes.contains_key(&id);
                        let db_size_human = sizes
                            .get(&id)
                            .map(|s| humanize_bytes(*s))
                            .unwrap_or_else(|| "—".to_string());
                        TenantInBackup {
                            id,
                            name,
                            created_at,
                            db_size_human,
                            db_present,
                        }
                    })
                    .collect()
            })
            .unwrap_or_default(),
        Err(e) => {
            return render_inspect_error(filename, snapshot_mtime, snapshot_size_human, format!("query: {e}"));
        }
    };

    let flash = match (qs.restored, qs.dest) {
        (Some(tenant_id), Some(destination)) => Some(RestoreFlash {
            tenant_id,
            destination,
        }),
        _ => None,
    };

    Html(
        BackupInspectPage {
            version: env!("CARGO_PKG_VERSION"),
            filename,
            snapshot_ts: snapshot_mtime.format("%Y-%m-%d %H:%M UTC").to_string(),
            snapshot_size_human,
            tenants,
            flash,
            error: None,
        }
        .render()
        .unwrap(),
    )
    .into_response()
}

fn render_inspect_error(
    filename: String,
    mtime: DateTime<Utc>,
    snapshot_size_human: String,
    msg: String,
) -> Response {
    Html(
        BackupInspectPage {
            version: env!("CARGO_PKG_VERSION"),
            filename,
            snapshot_ts: mtime.format("%Y-%m-%d %H:%M UTC").to_string(),
            snapshot_size_human,
            tenants: Vec::new(),
            flash: None,
            error: Some(msg),
        }
        .render()
        .unwrap(),
    )
    .into_response()
}

/// Reject anything that doesn't look like a uuid-v4 string. Restore takes
/// a raw tenant_id from the form; the server constructs filesystem paths
/// from it, so this guard is the only thing between the user and a path
/// traversal.
fn is_uuid_like(s: &str) -> bool {
    // Hyphenated UUID v4 form (8-4-4-4-12 hex chars). Lenient on the
    // version/variant nibbles since older tenants may have non-strict UUIDs.
    if s.len() != 36 {
        return false;
    }
    let bytes = s.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        match i {
            8 | 13 | 18 | 23 => {
                if *b != b'-' {
                    return false;
                }
            }
            _ => {
                if !b.is_ascii_hexdigit() {
                    return false;
                }
            }
        }
    }
    true
}

/// `POST /admin/backups/{filename}/restore` — extract the named tenant's
/// `data.sqlite` (and `meta.json` if present) from the archive into
/// `<data_dir>/_trash/<tid>-restored-<ts>/`. Does NOT overwrite the live
/// tenant directory; the admin must `mv` it back manually after
/// inspection. This protects against accidental overwrites of work that
/// post-dates the snapshot.
pub async fn restore_tenant(
    State(state): State<BackupsState>,
    Path(filename): Path<String>,
    axum::Form(form): axum::Form<RestoreForm>,
) -> Response {
    if !is_safe_backup_filename(&filename) {
        return (StatusCode::BAD_REQUEST, "invalid backup name").into_response();
    }
    if !is_uuid_like(&form.tenant_id) {
        return (StatusCode::BAD_REQUEST, "invalid tenant_id").into_response();
    }
    let backup_path = state.data_dir.join("backups").join(&filename);
    if !backup_path.is_file() {
        return (StatusCode::NOT_FOUND, "backup not found").into_response();
    }

    let ts = chrono::Utc::now().format("%Y%m%d-%H%M%S").to_string();
    let dest_dir = state
        .data_dir
        .join("_trash")
        .join(format!("{tid}-restored-{ts}", tid = form.tenant_id));
    let target_db = dest_dir.join("data.sqlite");

    let backup_path_clone = backup_path.clone();
    let dest_dir_clone = dest_dir.clone();
    let target_db_clone = target_db.clone();
    let tid_clone = form.tenant_id.clone();

    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        use std::fs::File;
        use std::io::Write;
        std::fs::create_dir_all(&dest_dir_clone)?;
        let file = File::open(&backup_path_clone)?;
        let dec = zstd::Decoder::new(file)?;
        let mut ar = tar::Archive::new(dec);
        let want_db = format!("tenants/{tid_clone}/data.sqlite");
        let want_meta = format!("tenants/{tid_clone}/meta.json");
        let mut wrote_db = false;
        for entry_res in ar.entries()? {
            let mut entry = entry_res?;
            let path_buf = entry.path()?.to_path_buf();
            let path_str = path_buf.to_string_lossy();
            let normalized = path_str.trim_start_matches("./").to_string();
            if normalized == want_db {
                let mut out = File::create(&target_db_clone)?;
                std::io::copy(&mut entry, &mut out)?;
                out.flush()?;
                wrote_db = true;
            } else if normalized == want_meta {
                let mut out = File::create(dest_dir_clone.join("meta.json"))?;
                std::io::copy(&mut entry, &mut out)?;
                out.flush()?;
            }
        }
        if !wrote_db {
            anyhow::bail!(
                "tenant '{tid_clone}' not present in archive (only meta.sqlite or another tenant)"
            );
        }
        Ok(())
    })
    .await;

    match result {
        Ok(Ok(())) => {
            // PRG: redirect back to inspect page with success flash via query string.
            Redirect::to(&format!(
                "/drust/admin/backups/{filename}/inspect?restored={tid}&dest={dest}",
                tid = form.tenant_id,
                dest = urlencoding::encode(&dest_dir.display().to_string()),
            ))
            .into_response()
        }
        Ok(Err(e)) => {
            // Best-effort cleanup of the partially-created dest dir.
            let _ = std::fs::remove_dir_all(&dest_dir);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("restore failed: {e}"),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("join error: {e}"),
        )
            .into_response(),
    }
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
    fn parse_tenant_db_path_handles_prefix_variants() {
        assert_eq!(
            parse_tenant_db_path("tenants/abc/data.sqlite"),
            Some("abc".to_string())
        );
        assert_eq!(
            parse_tenant_db_path("./tenants/abc/data.sqlite"),
            Some("abc".to_string())
        );
        assert_eq!(parse_tenant_db_path("tenants/abc/meta.json"), None);
        assert_eq!(parse_tenant_db_path("meta.sqlite"), None);
        assert_eq!(parse_tenant_db_path("tenants//data.sqlite"), None);
    }

    #[test]
    fn uuid_like_accepts_valid_and_rejects_traversal() {
        assert!(is_uuid_like("d26a0119-5633-41d0-8ea8-388f12105f26"));
        assert!(is_uuid_like("00000000-0000-0000-0000-000000000000"));
        assert!(!is_uuid_like(""));
        assert!(!is_uuid_like("../etc"));
        assert!(!is_uuid_like("d26a0119-5633-41d0-8ea8-388f12105f2")); // 35 chars
        assert!(!is_uuid_like("d26a0119-5633-41d0-8ea8-388f12105f266")); // 37 chars
        assert!(!is_uuid_like("d26a0119_5633-41d0-8ea8-388f12105f26")); // _ instead of -
        assert!(!is_uuid_like("d26a0119-5633-41d0-8ea8-388f12105f2g")); // non-hex
    }

    /// Build a minimal in-memory tar.zst with a meta.sqlite-shaped file
    /// and one tenant directory; assert extract_meta_and_sizes finds both.
    #[test]
    fn extract_meta_and_sizes_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let archive_path = dir.path().join("test.tar.zst");

        // Build a tiny tar in memory, then zstd-compress to disk.
        let mut tar_buf: Vec<u8> = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_buf);
            // Fake meta.sqlite: SQLite file header so the open later doesn't
            // panic at runtime if we ever try to use it (we don't here).
            let sqlite_header = b"SQLite format 3\0".to_vec();
            let mut header = tar::Header::new_gnu();
            header.set_path("meta.sqlite").unwrap();
            header.set_size(sqlite_header.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append(&header, sqlite_header.as_slice()).unwrap();

            // tenants/<id>/data.sqlite of known size
            let tdb = vec![0u8; 137];
            let mut th = tar::Header::new_gnu();
            th.set_path("tenants/abc-tenant/data.sqlite").unwrap();
            th.set_size(tdb.len() as u64);
            th.set_mode(0o644);
            th.set_cksum();
            builder.append(&th, tdb.as_slice()).unwrap();

            builder.finish().unwrap();
        }

        // Compress.
        let compressed = zstd::encode_all(tar_buf.as_slice(), 0).unwrap();
        std::fs::write(&archive_path, compressed).unwrap();

        let (meta_tmp, sizes) = extract_meta_and_sizes(&archive_path).unwrap();
        assert_eq!(sizes.get("abc-tenant"), Some(&137));

        // meta.sqlite contents: read first 16 bytes.
        let mut buf = [0u8; 16];
        let mut f = std::fs::File::open(meta_tmp.path()).unwrap();
        std::io::Read::read_exact(&mut f, &mut buf).unwrap();
        assert_eq!(&buf, b"SQLite format 3\0");
    }
}
