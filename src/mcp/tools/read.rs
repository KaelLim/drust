use crate::mcp::server::DrustMcp;
use crate::query::authorizer::attach_readonly_authorizer;
use crate::query::executor::execute_read_query;
use serde_json::json;

pub async fn query(s: &DrustMcp, sql: &str) -> anyhow::Result<serde_json::Value> {
    let pool = s.inner().pool.clone();
    let sql_owned = sql.to_string();
    let qr = pool
        .with_reader(move |c| {
            attach_readonly_authorizer(c);
            execute_read_query(c, &sql_owned, 10_000, 16_384)
                .map_err(|_| rusqlite::Error::InvalidQuery)
        })
        .await?;
    Ok(serde_json::to_value(qr)?)
}

pub async fn explain(s: &DrustMcp, sql: &str, _analyze: bool) -> anyhow::Result<serde_json::Value> {
    let pool = s.inner().pool.clone();
    let sql_owned = sql.to_string();
    let plan: String = pool
        .with_reader(move |c| -> rusqlite::Result<String> {
            attach_readonly_authorizer(c);
            let explain_sql = format!("EXPLAIN QUERY PLAN {sql_owned}");
            let mut stmt = c.prepare(&explain_sql)?;
            let lines: Vec<String> = stmt
                .query_map([], |r| {
                    let detail: String = r.get(3)?;
                    Ok(detail)
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(lines.join("\n"))
        })
        .await?;
    Ok(json!({ "plan": plan }))
}
