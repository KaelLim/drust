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

pub fn bucket_for_upload(owner: &Owner, visibility: Visibility) -> String {
    match (owner, visibility) {
        (Owner::Admin, Visibility::Public) => "public".to_string(),
        (Owner::Admin, Visibility::Private) => "admin-private".to_string(),
        (Owner::Tenant(id), Visibility::Public) => format!("tenant-{id}-pub"),
        (Owner::Tenant(id), Visibility::Private) => format!("tenant-{id}-prv"),
    }
}

pub fn build_public_url(
    base_url: &str,
    owner: &Owner,
    visibility: Visibility,
    key: &str,
) -> String {
    let base = base_url.trim_end_matches('/');
    match (owner, visibility) {
        (Owner::Admin, Visibility::Public) => format!("{base}/public/{key}"),
        (Owner::Admin, Visibility::Private) => format!("{base}/drust/admin/files/{key}/bytes"),
        (Owner::Tenant(id), Visibility::Public) => format!("{base}/t-public/{id}/{key}"),
        (Owner::Tenant(id), Visibility::Private) => {
            format!("{base}/drust/t/{id}/files/{key}/bytes")
        }
    }
}

pub fn default_cache_control(visibility: Visibility, _disposition: Disposition) -> &'static str {
    match visibility {
        Visibility::Public => "public, max-age=3600",
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
