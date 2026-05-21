//! MCP `set_realtime` tool — toggle SSE broadcast on one collection.
//! Service-only at the MCP-dispatch layer; this helper performs the
//! validation chain and writer transaction.

use crate::mcp::server::DrustMcp;
use crate::storage::schema::{collection_exists, is_protected_collection, write_realtime_enabled};
use serde_json::json;

pub async fn set_realtime(
    s: &DrustMcp,
    collection: &str,
    enabled: bool,
) -> anyhow::Result<serde_json::Value> {
    super::schema::identifier(collection)?;
    if is_protected_collection(collection) {
        anyhow::bail!(
            "refusing to set realtime on system collection {collection:?} \
             (protected by _system_ prefix)"
        );
    }
    let pool = s.inner().pool.clone();
    let coll = collection.to_string();
    // v1.20 TOCTOU fix: fold existence check inside the writer closure so a
    // concurrent drop_collection cannot leave an orphan _system_collection_meta row.
    pool.with_writer(move |c| {
        if !collection_exists(c, &coll)? {
            return Err(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(1),
                Some(format!("COLLECTION_NOT_FOUND: {coll}")),
            ));
        }
        write_realtime_enabled(c, &coll, enabled)
    })
    .await
    .map_err(|e| {
        let msg = e.to_string();
        if msg.contains("COLLECTION_NOT_FOUND") {
            anyhow::anyhow!("unknown collection: {}", msg.splitn(2, ": ").nth(1).unwrap_or(&msg))
        } else {
            anyhow::anyhow!("{e}")
        }
    })?;
    pool.schema_cache.invalidate(collection);
    if !enabled {
        // Mirror the REST handler: cache invalidate BEFORE eviction so any
        // subscriber racing in between reads the fresh schema.
        let tenant = s.inner().tenant_id.clone();
        s.inner().bus.evict_collection(&tenant, collection);
    }
    Ok(json!({
        "ok": true,
        "collection": collection,
        "realtime_enabled": enabled,
    }))
}
