//! In-place file visibility toggle (public <-> private).
//!
//! Moves the Garage object between the host-wide `public`/`private` buckets and
//! updates the per-tenant `_system_files` row. Ordering is **copy -> UPDATE row
//! -> delete-old** so the live row always references an existing object; a crash
//! leaves only a space-only orphan (reclaimed by the reconcile page) and a retry
//! is idempotent. This is the only UPDATE path on `_system_files`.

use crate::storage::files::{
    Disposition, Owner, Visibility, bucket_for, compose_key, default_cache_control,
};
use crate::storage::garage::GarageClient;
use crate::storage::pool::SharedTenantPool;

#[derive(Debug, PartialEq, Eq)]
pub enum VisibilityOutcome {
    Changed { from: String, to: String },
    NoOp,
    NotFound,
}

struct FileMeta {
    visibility: String,
    content_type: Option<String>,
    original_name: String,
    content_disposition: Option<String>,
    meta_json: Option<String>,
}

/// Toggle one tenant file between `public` and `private`. Service-only gating is
/// the caller's responsibility (MCP dispatch / `require_service` / admin session).
pub async fn change_visibility(
    garage: &GarageClient,
    pool: &SharedTenantPool,
    tenant_id: &str,
    key: &str,
    target: Visibility,
) -> anyhow::Result<VisibilityOutcome> {
    // 1. Read current metadata for the re-PUT + decision.
    let key_read = key.to_string();
    let meta: Option<FileMeta> = pool
        .with_reader(move |c| -> rusqlite::Result<Option<FileMeta>> {
            match c.query_row(
                "SELECT visibility, content_type, original_name, content_disposition, meta_json \
                 FROM _system_files WHERE key=?1",
                rusqlite::params![key_read],
                |r| {
                    Ok(FileMeta {
                        visibility: r.get(0)?,
                        content_type: r.get(1)?,
                        original_name: r.get(2)?,
                        content_disposition: r.get(3)?,
                        meta_json: r.get(4)?,
                    })
                },
            ) {
                Ok(m) => Ok(Some(m)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(e),
            }
        })
        .await?;

    let Some(meta) = meta else {
        return Ok(VisibilityOutcome::NotFound);
    };

    let target_str = match target {
        Visibility::Public => "public",
        Visibility::Private => "private",
    };
    if meta.visibility == target_str {
        return Ok(VisibilityOutcome::NoOp);
    }

    let from_vis = if meta.visibility == "public" {
        Visibility::Public
    } else {
        Visibility::Private
    };
    let old_bucket = bucket_for(from_vis);
    let new_bucket = bucket_for(target);
    // Object key is always tenant-prefixed — a crafted `key` cannot escape the
    // `<tenant>/` namespace.
    let object_key = compose_key(&Owner::Tenant(tenant_id.to_string()), key);

    let disposition = match meta.content_disposition.as_deref() {
        Some("attachment") => Disposition::Attachment,
        _ => Disposition::Inline,
    };
    let disposition_mode = match disposition {
        Disposition::Attachment => "attachment",
        Disposition::Inline => "inline",
    };
    // Reset cache_control to the target visibility's default so a now-private
    // file never carries a public cache header (and vice versa).
    let new_cc = default_cache_control(target, disposition);

    // 2. Copy: read bytes from the old bucket, put to the new bucket.
    let bytes = garage.get_object_bytes_in(old_bucket, &object_key).await?;
    garage
        .put_object_in(
            new_bucket,
            &object_key,
            bytes,
            meta.content_type.as_deref(),
            disposition_mode,
            &meta.original_name,
            Some(new_cc),
            meta.meta_json.as_deref(),
        )
        .await?;

    // 3. UPDATE the row (visibility + cache_control) — the single linearization
    //    point. Before this commits, reads see the old bucket; after, the new.
    let key_upd = key.to_string();
    let cc_upd = new_cc.to_string();
    let tgt_upd = target_str.to_string();
    pool.with_writer(move |c| {
        c.execute(
            "UPDATE _system_files SET visibility=?1, cache_control=?2 WHERE key=?3",
            rusqlite::params![tgt_upd, cc_upd, key_upd],
        )
        .map(|_| ())
    })
    .await?;

    // 4. Delete the old-bucket object. Non-fatal: the move already succeeded;
    //    a leftover is a space-only orphan the reconcile page reclaims.
    if let Err(e) = garage.delete_object_in(old_bucket, &object_key).await {
        tracing::warn!(
            key = %key,
            old_bucket = %old_bucket,
            error = format!("{e:#}"),
            "visibility change: old-bucket delete failed; left as reconcile orphan"
        );
    }

    Ok(VisibilityOutcome::Changed {
        from: meta.visibility,
        to: target_str.to_string(),
    })
}
