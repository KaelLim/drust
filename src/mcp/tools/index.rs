use crate::mcp::server::DrustMcp;
use crate::mcp::tools::schema::identifier;
use crate::storage::schema::{collection_exists, describe_collection, is_protected_collection};
use serde_json::json;
use std::time::Instant;

/// Create a (possibly unique) index on one or more fields of a collection.
///
/// Thin wrapper that calls [`create_index_with_threshold`] with the default
/// 1 000 000-row threshold.
pub async fn create_index(
    s: &DrustMcp,
    collection: &str,
    fields: &[String],
    unique: bool,
    force: bool,
) -> anyhow::Result<serde_json::Value> {
    create_index_with_threshold(s, collection, fields, unique, force, 1_000_000).await
}

/// Create a (possibly unique) index on one or more fields of a collection.
///
/// Auto-names the index `idx_<coll>_<f1>_<f2>_..._<fN>`. Refuses to build
/// on a collection larger than `large_table_rows` unless `force` is true.
/// On success, returns the new index's identity plus the full updated
/// `indices` array (mirrors `add_field`'s "post-state" return shape).
pub async fn create_index_with_threshold(
    s: &DrustMcp,
    collection: &str,
    fields: &[String],
    unique: bool,
    force: bool,
    large_table_rows: u64,
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

    // Reject duplicate field names inside the same index spec.
    let mut seen = std::collections::BTreeSet::new();
    for f in fields {
        if !seen.insert(f.as_str()) {
            anyhow::bail!("duplicate field in index spec: {f}");
        }
    }

    let pool = s.inner().pool.clone();
    let coll_for_check = collection.to_string();
    let exists = pool
        .with_reader(move |c| collection_exists(c, &coll_for_check))
        .await?;
    if !exists {
        anyhow::bail!("no such collection: {collection}");
    }

    // Validate that every requested field exists on the collection.
    let coll_for_fields = collection.to_string();
    let fields_owned: Vec<String> = fields.to_vec();
    let pool_for_field_check = pool.clone();
    let missing: Option<String> = pool_for_field_check
        .with_reader(move |c| {
            for f in &fields_owned {
                let count: i64 = c.query_row(
                    "SELECT COUNT(*) FROM pragma_table_info(?1) WHERE name = ?2",
                    rusqlite::params![&coll_for_fields, f],
                    |r| r.get(0),
                )?;
                if count == 0 {
                    return Ok::<Option<String>, rusqlite::Error>(Some(f.clone()));
                }
            }
            Ok(None)
        })
        .await?;
    if let Some(f) = missing {
        anyhow::bail!("field \"{f}\" not found on collection \"{collection}\"");
    }

    // Row-count guard: refuse to build on a large table unless force=true.
    let coll_for_count = collection.to_string();
    let row_count: u64 = pool
        .with_reader(move |c| {
            c.query_row(
                &format!("SELECT COUNT(*) FROM \"{}\"", coll_for_count.replace('"', "\"\"")),
                [],
                |r| r.get::<_, i64>(0),
            )
        })
        .await? as u64;
    if row_count > large_table_rows && !force {
        anyhow::bail!(
            "LARGE_TABLE: {collection} has {row_count} rows (threshold {large_table_rows}); pass force=true to proceed"
        );
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

    Ok(json!({
        "ok": true,
        "collection": collection,
        "name": index_name,
        "indices": schema.indices,
        "row_count_at_build": row_count,
        "duration_ms": duration_ms,
        "force_used": force
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
