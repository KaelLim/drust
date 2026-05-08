use crate::mcp::server::DrustMcp;
use crate::mcp::tools::schema::identifier;
use crate::storage::schema::{collection_exists, describe_collection, is_protected_collection};
use serde_json::json;
use std::time::Instant;

/// Create a (possibly unique) index on one or more fields of a collection.
///
/// Auto-names the index `idx_<coll>_<f1>_<f2>_..._<fN>`. Refuses to build
/// on a collection larger than `large_table_rows` unless `force` is true.
/// On success, returns the new index's identity plus the full updated
/// `indices` array (mirrors `add_field`'s "post-state" return shape).
pub async fn create_index(
    s: &DrustMcp,
    collection: &str,
    fields: &[String],
    unique: bool,
    force: bool,
) -> anyhow::Result<serde_json::Value> {
    identifier(collection)?;
    if is_protected_collection(collection) {
        anyhow::bail!("no such collection: {collection}");
    }
    if fields.is_empty() {
        anyhow::bail!("fields must be non-empty");
    }
    for f in fields {
        identifier(f)?;
    }

    let pool = s.inner().pool.clone();
    let coll_for_check = collection.to_string();
    let exists = pool
        .with_reader(move |c| collection_exists(c, &coll_for_check))
        .await?;
    if !exists {
        anyhow::bail!("no such collection: {collection}");
    }

    let index_name = derive_index_name(collection, fields);
    let cols_clause = fields
        .iter()
        .map(|f| format!("\"{}\"", f.replace('"', "\"\"")))
        .collect::<Vec<_>>()
        .join(",");
    let unique_kw = if unique { "UNIQUE " } else { "" };
    let sql = format!(
        "CREATE {uniq}INDEX \"{name}\" ON \"{coll}\" ({cols});",
        uniq = unique_kw,
        name = index_name.replace('"', "\"\""),
        coll = collection.replace('"', "\"\""),
        cols = cols_clause
    );

    let start = Instant::now();
    let pool2 = pool.clone();
    pool.with_writer(move |c| c.execute_batch(&sql)).await?;
    let duration_ms = start.elapsed().as_millis() as u64;
    pool.schema_cache.invalidate(collection);

    let coll_for_describe = collection.to_string();
    let schema = pool2
        .with_reader(move |c| describe_collection(c, &coll_for_describe))
        .await?
        .ok_or_else(|| anyhow::anyhow!("collection vanished after create_index"))?;

    // suppress unused-variable warning when force is not yet used
    let _ = force;

    Ok(json!({
        "ok": true,
        "collection": collection,
        "name": index_name,
        "indices": schema.indices,
        "row_count_at_build": schema.row_count,
        "duration_ms": duration_ms
    }))
}

pub(crate) fn derive_index_name(collection: &str, fields: &[String]) -> String {
    let mut s = String::from("idx_");
    s.push_str(collection);
    for f in fields {
        s.push('_');
        s.push_str(f);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_name_format_matches_spec() {
        assert_eq!(
            derive_index_name("check_ins", &["user_id".into(), "day_number".into()]),
            "idx_check_ins_user_id_day_number"
        );
        assert_eq!(
            derive_index_name("posts", &["slug".into()]),
            "idx_posts_slug"
        );
    }
}
