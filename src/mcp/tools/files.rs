//! Y-scope MCP file tools — list / delete / get_file_url.
//!
//! Backed by the per-tenant `_system_files` table and the tenant's two
//! Garage buckets (`tenant-<id>-pub` / `tenant-<id>-prv`). Returns
//! `{"error_code": "STORAGE_UNAVAILABLE"}` when drust was started without
//! a Garage client.
use crate::mcp::server::DrustMcp;
use crate::storage::files::{Owner, Visibility, bucket_for, build_public_url, compose_key};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListFilesArgs {
    /// Optional filter: "public" or "private". Anything else is ignored.
    #[serde(default)]
    pub visibility: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: u32,
    #[serde(default)]
    pub offset: u32,
}
fn default_limit() -> u32 {
    50
}

#[derive(Debug, Serialize)]
struct ListFilesResult {
    files: Vec<FileBrief>,
    total_count: i64,
}

#[derive(Debug, Serialize)]
struct FileBrief {
    id: String,
    original_name: String,
    size_bytes: i64,
    content_type: Option<String>,
    visibility: String,
    content_disposition: Option<String>,
    uploaded_at: String,
}

fn storage_unavailable() -> serde_json::Value {
    serde_json::json!({ "error_code": "STORAGE_UNAVAILABLE" })
}

pub async fn list_files(s: &DrustMcp, args: ListFilesArgs) -> anyhow::Result<serde_json::Value> {
    let limit = args.limit.clamp(1, 500) as i64;
    let offset = args.offset as i64;
    let vis_filter = match args.visibility.as_deref() {
        Some("public") => Some("public".to_string()),
        Some("private") => Some("private".to_string()),
        _ => None,
    };

    let pool = s.inner().pool.clone();
    let (total, rows) = pool
        .with_reader(move |conn| -> rusqlite::Result<(i64, Vec<FileBrief>)> {
            let total: i64 = if let Some(v) = vis_filter.as_deref() {
                conn.query_row(
                    "SELECT COUNT(*) FROM _system_files WHERE visibility=?1",
                    rusqlite::params![v],
                    |r| r.get(0),
                )?
            } else {
                conn.query_row("SELECT COUNT(*) FROM _system_files", [], |r| r.get(0))?
            };
            let rows: Vec<FileBrief> = if let Some(v) = vis_filter.as_deref() {
                let mut stmt = conn.prepare(
                    "SELECT key, original_name, size_bytes, content_type, visibility, \
                     content_disposition, uploaded_at \
                     FROM _system_files WHERE visibility=?1 \
                     ORDER BY uploaded_at DESC LIMIT ?2 OFFSET ?3",
                )?;
                stmt.query_map(rusqlite::params![v, limit, offset], |r| {
                    Ok(FileBrief {
                        id: r.get(0)?,
                        original_name: r.get(1)?,
                        size_bytes: r.get(2)?,
                        content_type: r.get(3)?,
                        visibility: r.get(4)?,
                        content_disposition: r.get(5)?,
                        uploaded_at: r.get(6)?,
                    })
                })?
                .filter_map(Result::ok)
                .collect()
            } else {
                let mut stmt = conn.prepare(
                    "SELECT key, original_name, size_bytes, content_type, visibility, \
                     content_disposition, uploaded_at \
                     FROM _system_files \
                     ORDER BY uploaded_at DESC LIMIT ?1 OFFSET ?2",
                )?;
                stmt.query_map(rusqlite::params![limit, offset], |r| {
                    Ok(FileBrief {
                        id: r.get(0)?,
                        original_name: r.get(1)?,
                        size_bytes: r.get(2)?,
                        content_type: r.get(3)?,
                        visibility: r.get(4)?,
                        content_disposition: r.get(5)?,
                        uploaded_at: r.get(6)?,
                    })
                })?
                .filter_map(Result::ok)
                .collect()
            };
            Ok((total, rows))
        })
        .await?;

    Ok(serde_json::to_value(ListFilesResult {
        files: rows,
        total_count: total,
    })?)
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DeleteFileArgs {
    /// The file's id (the UUID key returned by upload / list_files).
    pub id: String,
}

pub async fn delete_file(s: &DrustMcp, args: DeleteFileArgs) -> anyhow::Result<serde_json::Value> {
    let Some(garage) = s.garage().cloned() else {
        return Ok(storage_unavailable());
    };
    let tenant_id = s.tenant_id().to_string();
    let key = args.id;

    let pool = s.inner().pool.clone();

    let key_lookup = key.clone();
    let vis_opt: Option<String> = pool
        .with_reader(move |conn| -> rusqlite::Result<Option<String>> {
            match conn.query_row(
                "SELECT visibility FROM _system_files WHERE key=?1",
                rusqlite::params![key_lookup],
                |r| r.get::<_, String>(0),
            ) {
                Ok(v) => Ok(Some(v)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(e),
            }
        })
        .await?;

    let Some(vis_str) = vis_opt else {
        return Ok(serde_json::json!({ "error_code": "NOT_FOUND" }));
    };
    let vis = if vis_str == "public" {
        Visibility::Public
    } else {
        Visibility::Private
    };
    let bucket = bucket_for(vis);
    let object_key = compose_key(&Owner::Tenant(tenant_id), &key);
    garage.delete_object_in(bucket, &object_key).await?;

    let key_del = key.clone();
    pool.with_writer(move |conn| -> rusqlite::Result<()> {
        conn.execute(
            "DELETE FROM _system_files WHERE key=?1",
            rusqlite::params![key_del],
        )?;
        Ok(())
    })
    .await?;

    Ok(serde_json::json!({ "ok": true }))
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetFileUrlArgs {
    /// The file's id (the UUID key).
    pub id: String,
    /// Seconds until the pre-signed URL expires. Private only, 1..=604800.
    /// Default 3600. Ignored for public files.
    #[serde(default)]
    pub expires_in: Option<u64>,
    /// Private files only: if true, inject
    /// `response-content-disposition=attachment; filename=<original>` so
    /// browsers download instead of inlining.
    #[serde(default)]
    pub download: Option<bool>,
}

pub async fn get_file_url(s: &DrustMcp, args: GetFileUrlArgs) -> anyhow::Result<serde_json::Value> {
    let Some(garage) = s.garage().cloned() else {
        return Ok(storage_unavailable());
    };
    let tenant_id = s.tenant_id().to_string();
    let key = args.id.clone();

    let pool = s.inner().pool.clone();
    let key_lookup = key.clone();
    let row_opt: Option<(String, String)> = pool
        .with_reader(move |conn| -> rusqlite::Result<Option<(String, String)>> {
            match conn.query_row(
                "SELECT visibility, original_name FROM _system_files WHERE key=?1",
                rusqlite::params![key_lookup],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
            ) {
                Ok(v) => Ok(Some(v)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(e),
            }
        })
        .await?;

    let Some((visibility, original_name)) = row_opt else {
        return Ok(serde_json::json!({ "error_code": "NOT_FOUND" }));
    };

    if visibility == "public" {
        let url = build_public_url(
            s.public_base_url(),
            &Owner::Tenant(tenant_id),
            Visibility::Public,
            &key,
        );
        return Ok(serde_json::json!({
            "url": url,
            "expires_at": serde_json::Value::Null,
        }));
    }

    let expires_in = args.expires_in.unwrap_or(3600);
    if !(1..=604_800).contains(&expires_in) {
        anyhow::bail!("expires_in must be 1..=604800 seconds");
    }
    // Sanity: storage must be live to even signal a URL (the download itself
    // will hit Garage via drust's /s/t/... proxy).
    let _ = garage;
    let _ = original_name;
    let download = args.download.unwrap_or(false);
    let expires_ts = chrono::Utc::now().timestamp() + expires_in as i64;
    let sign_owner = crate::storage::signed_url::Owner::Tenant(tenant_id);
    let token = crate::storage::signed_url::mint(
        s.url_sign_secret(),
        &sign_owner,
        &key,
        expires_ts,
        download,
    );
    let url = crate::storage::signed_url::build_url(
        s.public_base_url(),
        &sign_owner,
        &key,
        expires_ts,
        download,
        &token,
    );
    let expires_at =
        (chrono::Utc::now() + chrono::Duration::seconds(expires_in as i64)).to_rfc3339();
    Ok(serde_json::json!({
        "url": url,
        "expires_at": expires_at,
    }))
}
