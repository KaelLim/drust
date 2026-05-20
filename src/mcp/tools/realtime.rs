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
    let name_check = collection.to_string();
    let exists = pool
        .with_reader(move |c| collection_exists(c, &name_check))
        .await?;
    if !exists {
        anyhow::bail!("unknown collection: {collection}");
    }
    let coll = collection.to_string();
    pool.with_writer(move |c| write_realtime_enabled(c, &coll, enabled))
        .await?;
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
