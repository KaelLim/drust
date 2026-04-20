use crate::mcp::server::DrustMcp;
use crate::query::authorizer::attach_readonly_authorizer;
use crate::query::executor::execute_read_query;
use crate::query::filter::build_count_sql;
use crate::storage::schema::{describe_collection as describe_inner, list_collections as list_inner};
use serde_json::json;

pub async fn list_collections(s: &DrustMcp) -> anyhow::Result<serde_json::Value> {
    let pool = s.inner().pool.clone();
    let list = pool.with_reader(|c| list_inner(c)).await?;
    Ok(json!({ "collections": list }))
}

pub async fn describe_collection(s: &DrustMcp, name: &str) -> anyhow::Result<serde_json::Value> {
    let pool = s.inner().pool.clone();
    let name_owned = name.to_string();
    let out = pool
        .with_reader(move |c| describe_inner(c, &name_owned))
        .await?;
    match out {
        Some(schema) => Ok(serde_json::to_value(schema)?),
        None => Ok(json!({ "error_code": "UNKNOWN_COLLECTION" })),
    }
}

pub async fn sample_rows(
    s: &DrustMcp,
    name: &str,
    n: usize,
) -> anyhow::Result<serde_json::Value> {
    let pool = s.inner().pool.clone();
    let sql = format!(
        "SELECT * FROM \"{}\" ORDER BY id LIMIT {}",
        name.replace('"', "\"\""),
        n.min(500)
    );
    let out = pool
        .with_reader(move |c| {
            attach_readonly_authorizer(c);
            execute_read_query(c, &sql, 500, 16_384)
                .map_err(|_| rusqlite::Error::InvalidQuery)
        })
        .await?;
    Ok(serde_json::to_value(out)?)
}

pub async fn count_rows(
    s: &DrustMcp,
    name: &str,
    where_clause: Option<&str>,
) -> anyhow::Result<serde_json::Value> {
    let pool = s.inner().pool.clone();
    let sql = build_count_sql(name, where_clause);
    let n: i64 = pool
        .with_reader(move |c| {
            attach_readonly_authorizer(c);
            c.query_row(&sql, [], |r| r.get(0))
        })
        .await?;
    Ok(json!({ "count": n }))
}
