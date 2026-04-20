use crate::mcp::server::DrustMcp;
use crate::storage::schema::describe_collection;
use crate::tenant::events::Event;
use rusqlite::types::Value;
use serde_json::json;

fn json_to_sql_value(v: &serde_json::Value) -> Value {
    match v {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Integer(if *b { 1 } else { 0 }),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Integer(i)
            } else if let Some(f) = n.as_f64() {
                Value::Real(f)
            } else {
                Value::Null
            }
        }
        serde_json::Value::String(s) => Value::Text(s.clone()),
        other => Value::Text(other.to_string()),
    }
}

fn read_record(
    c: &rusqlite::Connection,
    coll: &str,
    id: i64,
) -> rusqlite::Result<serde_json::Value> {
    let sql = format!(
        "SELECT * FROM \"{}\" WHERE id = ?1",
        coll.replace('"', "\"\"")
    );
    let mut stmt = c.prepare(&sql)?;
    let col_names: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
    stmt.query_row(rusqlite::params![id], |r| {
        let mut obj = serde_json::Map::new();
        for (i, n) in col_names.iter().enumerate() {
            let v = r.get_ref(i)?;
            let jv = match v {
                rusqlite::types::ValueRef::Null => serde_json::Value::Null,
                rusqlite::types::ValueRef::Integer(i) => serde_json::json!(i),
                rusqlite::types::ValueRef::Real(f) => serde_json::json!(f),
                rusqlite::types::ValueRef::Text(t) => {
                    serde_json::Value::String(String::from_utf8_lossy(t).into_owned())
                }
                rusqlite::types::ValueRef::Blob(b) => json!({ "__blob_bytes": b.len() }),
            };
            obj.insert(n.clone(), jv);
        }
        Ok(serde_json::Value::Object(obj))
    })
}

pub async fn insert_record(
    s: &DrustMcp,
    collection: &str,
    data: serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    let coll = collection.to_string();
    let data_map = data
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("data must be object"))?
        .clone();
    let pool = s.inner().pool.clone();
    let tenant = s.inner().tenant_id.clone();
    let bus = s.inner().bus.clone();
    let (id, record) = pool
        .with_writer(move |c| -> rusqlite::Result<(i64, serde_json::Value)> {
            let schema = describe_collection(c, &coll)?.ok_or(rusqlite::Error::InvalidQuery)?;
            let allowed: std::collections::HashSet<&str> =
                schema.fields.iter().map(|f| f.name.as_str()).collect();
            for k in data_map.keys() {
                if !allowed.contains(k.as_str()) {
                    return Err(rusqlite::Error::InvalidQuery);
                }
            }
            let cols: Vec<&str> = data_map.keys().map(|k| k.as_str()).collect();
            let placeholders: Vec<String> = (1..=cols.len()).map(|i| format!("?{i}")).collect();
            let sql = if cols.is_empty() {
                format!(
                    "INSERT INTO \"{}\" DEFAULT VALUES",
                    coll.replace('"', "\"\"")
                )
            } else {
                format!(
                    "INSERT INTO \"{}\" ({}) VALUES ({})",
                    coll.replace('"', "\"\""),
                    cols.iter()
                        .map(|c| format!("\"{}\"", c.replace('"', "\"\"")))
                        .collect::<Vec<_>>()
                        .join(","),
                    placeholders.join(","),
                )
            };
            let params: Vec<Value> = data_map.values().map(json_to_sql_value).collect();
            let refs: Vec<&dyn rusqlite::ToSql> =
                params.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
            c.execute(&sql, &refs[..])?;
            let id = c.last_insert_rowid();
            let rec = read_record(c, &coll, id)?;
            Ok((id, rec))
        })
        .await?;
    bus.publish(
        &tenant,
        collection,
        Event::Created {
            record: record.clone(),
        },
    );
    Ok(json!({ "id": id, "record": record }))
}

pub async fn update_record(
    s: &DrustMcp,
    collection: &str,
    id: i64,
    data: serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    let coll = collection.to_string();
    let data_map = data
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("data must be object"))?
        .clone();
    if data_map.is_empty() {
        anyhow::bail!("data must have at least one field");
    }
    let pool = s.inner().pool.clone();
    let tenant = s.inner().tenant_id.clone();
    let bus = s.inner().bus.clone();
    let record = pool
        .with_writer(move |c| -> rusqlite::Result<serde_json::Value> {
            let schema = describe_collection(c, &coll)?.ok_or(rusqlite::Error::InvalidQuery)?;
            let allowed: std::collections::HashSet<&str> =
                schema.fields.iter().map(|f| f.name.as_str()).collect();
            for k in data_map.keys() {
                if !allowed.contains(k.as_str()) {
                    return Err(rusqlite::Error::InvalidQuery);
                }
            }
            let set_exprs: Vec<String> = data_map
                .keys()
                .enumerate()
                .map(|(i, k)| format!("\"{}\" = ?{}", k.replace('"', "\"\""), i + 1))
                .collect();
            let sql = format!(
                "UPDATE \"{}\" SET {}, updated_at = datetime('now') WHERE id = ?{}",
                coll.replace('"', "\"\""),
                set_exprs.join(","),
                data_map.len() + 1
            );
            let mut params: Vec<Value> = data_map.values().map(json_to_sql_value).collect();
            params.push(Value::Integer(id));
            let refs: Vec<&dyn rusqlite::ToSql> =
                params.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
            let n = c.execute(&sql, &refs[..])?;
            if n == 0 {
                return Err(rusqlite::Error::QueryReturnedNoRows);
            }
            read_record(c, &coll, id)
        })
        .await?;
    bus.publish(
        &tenant,
        collection,
        Event::Updated {
            record: record.clone(),
        },
    );
    Ok(json!({ "record": record }))
}

pub async fn delete_record(
    s: &DrustMcp,
    collection: &str,
    id: i64,
) -> anyhow::Result<serde_json::Value> {
    let coll = collection.to_string();
    let pool = s.inner().pool.clone();
    let tenant = s.inner().tenant_id.clone();
    let bus = s.inner().bus.clone();
    let n = pool
        .with_writer(move |c| {
            let sql = format!(
                "DELETE FROM \"{}\" WHERE id = ?1",
                coll.replace('"', "\"\"")
            );
            c.execute(&sql, rusqlite::params![id])
        })
        .await?;
    if n == 0 {
        return Ok(json!({ "ok": false, "error_code": "UNKNOWN_COLLECTION" }));
    }
    bus.publish(&tenant, collection, Event::Deleted { id });
    Ok(json!({ "ok": true }))
}
