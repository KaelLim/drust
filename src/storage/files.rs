//! Shared file-storage helpers used by both admin and tenant upload flows.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub enum Owner {
    Admin,
    Tenant(String),
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Visibility {
    Public,
    Private,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Disposition {
    Inline,
    Attachment,
}

/// Bucket for the given visibility. Only two buckets exist host-wide:
/// `public` (website=on, anonymous read via Caddy) and `private` (drust-
/// proxied). Tenant vs admin ownership is encoded in the key prefix,
/// not the bucket.
pub fn bucket_for(visibility: Visibility) -> &'static str {
    match visibility {
        Visibility::Public => "public",
        Visibility::Private => "private",
    }
}

/// Build the object key for a new upload. Admin uploads land at the
/// bucket root (`<file-id>`); tenant uploads are prefixed with the
/// tenant id so one bucket can host every tenant safely.
pub fn compose_key(owner: &Owner, file_id: &str) -> String {
    match owner {
        Owner::Admin => file_id.to_string(),
        Owner::Tenant(id) => format!("{id}/{file_id}"),
    }
}

/// Backward-compat shim: some call sites ask for just the bucket based
/// on (owner, vis); admin and tenant now share buckets so we ignore
/// `owner` and route by visibility alone.
pub fn bucket_for_upload(_owner: &Owner, visibility: Visibility) -> String {
    bucket_for(visibility).to_string()
}

pub fn build_public_url(
    base_url: &str,
    owner: &Owner,
    visibility: Visibility,
    key: &str,
) -> String {
    let base = base_url.trim_end_matches('/');
    // DB stores the bare object id (`<uuid>.<ext>`). Tenant objects live
    // under `<tenant>/<uuid>` inside the shared bucket, so public URLs
    // interleave the tenant id. Private URLs go through drust's own
    // bytes/signed endpoints and keep the bare key for the /{key} route.
    match (owner, visibility) {
        (Owner::Admin, Visibility::Public) => format!("{base}/public/{key}"),
        (Owner::Tenant(id), Visibility::Public) => format!("{base}/public/{id}/{key}"),
        (Owner::Admin, Visibility::Private) => format!("{base}/drust/admin/files/{key}/bytes"),
        (Owner::Tenant(id), Visibility::Private) => {
            format!("{base}/drust/t/{id}/files/{key}/bytes")
        }
    }
}

pub fn default_cache_control(visibility: Visibility, _disposition: Disposition) -> &'static str {
    match visibility {
        Visibility::Public => "public, max-age=86400",
        Visibility::Private => "private, no-store",
    }
}

/// Binding to a row of _system_files. Shared between admin (meta.sqlite)
/// and tenant (data.sqlite) — same shape in both.
#[derive(Debug, Clone, Serialize)]
pub struct FileRow {
    pub id: i64,
    pub key: String,
    pub original_name: String,
    pub content_type: Option<String>,
    pub size_bytes: i64,
    pub content_disposition: Option<String>, // mode: "inline" | "attachment"
    pub visibility: String,                  // "public" | "private"
    pub cache_control: Option<String>,
    pub meta_json: Option<String>,
    pub uploaded_at: String,
    pub uploader: String,
}

pub fn map_file_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<FileRow> {
    Ok(FileRow {
        id: row.get("id")?,
        key: row.get("key")?,
        original_name: row.get("original_name")?,
        content_type: row.get("content_type")?,
        size_bytes: row.get("size_bytes")?,
        content_disposition: row.get("content_disposition")?,
        visibility: row.get("visibility")?,
        cache_control: row.get("cache_control")?,
        meta_json: row.get("meta_json")?,
        uploaded_at: row.get("uploaded_at")?,
        uploader: row.get("uploader")?,
    })
}
