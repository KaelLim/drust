use crate::mcp::server::DrustMcp;
use crate::storage::schema::{describe_collection, is_protected_collection, VectorField};
use crate::tenant::events::Event;
use rusqlite::types::Value;
use serde_json::json;
use std::collections::HashSet;

/// Build a `rusqlite::Error` whose Display renders the given human-readable
/// message. Using `rusqlite::Error::InvalidQuery` (the obvious-looking variant)
/// is wrong — its Display is hard-coded to `"Query is not read-only"`, which
/// bubbles up as a confusing error from the writer path.
fn invalid_input(msg: String) -> rusqlite::Error {
    rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(1), Some(msg))
}

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
    vector_names: &HashSet<String>,
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
            // Vector columns are hidden by default — same shape as the REST
            // records.rs path. Keep them out of the response entirely;
            // retrieval is via search_collection.
            if vector_names.contains(n) {
                continue;
            }
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

/// Encode every vector field present in `data_map` to a packed-f32
/// BLOB, returning the bytes keyed by field name. Errors map to typed
/// strings so callers can render them as the expected error codes
/// (`VECTOR_DIM_MISMATCH` / `VECTOR_NON_FINITE` / `VECTOR_TYPE_ERROR`).
fn pre_encode_vectors(
    vector_fields: &[VectorField],
    data_map: &serde_json::Map<String, serde_json::Value>,
) -> Result<std::collections::HashMap<String, Vec<u8>>, anyhow::Error> {
    let mut out = std::collections::HashMap::new();
    for vf in vector_fields {
        if let Some(v) = data_map.get(&vf.name) {
            match crate::query::vector_codec::pack(&vf.name, vf.dim, v) {
                Ok(bytes) => {
                    out.insert(vf.name.clone(), bytes);
                }
                Err(crate::query::vector_codec::VectorCodecError::DimMismatch { .. }) => {
                    anyhow::bail!("VECTOR_DIM_MISMATCH: vector field {:?} has wrong dim", vf.name);
                }
                Err(crate::query::vector_codec::VectorCodecError::NonFinite { .. }) => {
                    anyhow::bail!("VECTOR_NON_FINITE: vector field {:?} contains NaN or Inf", vf.name);
                }
                Err(e) => {
                    anyhow::bail!("VECTOR_TYPE_ERROR: {e}");
                }
            }
        }
    }
    Ok(out)
}

pub async fn insert_record(
    s: &DrustMcp,
    collection: &str,
    data: serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    if is_protected_collection(collection) {
        anyhow::bail!("PROTECTED_COLLECTION: _system_* tables are read-only via MCP records tools. Use the dedicated admin tools.");
    }
    let coll = collection.to_string();
    let data_map = data
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("data must be object"))?
        .clone();
    let pool = s.inner().pool.clone();
    let tenant = s.inner().tenant_id.clone();
    let bus = s.inner().bus.clone();

    // Read schema OUTSIDE the writer closure so vector_codec errors
    // can surface as typed anyhow!() before we take the writer lock —
    // matches records.rs (REST) shape.
    let coll_for_schema = coll.clone();
    let schema = pool
        .with_reader(move |c| describe_collection(c, &coll_for_schema))
        .await?
        .ok_or_else(|| anyhow::anyhow!("unknown collection: '{}'", coll))?;

    let vector_bytes = pre_encode_vectors(&schema.vector_fields, &data_map)?;
    let vector_names: HashSet<String> = schema
        .vector_fields
        .iter()
        .map(|v| v.name.clone())
        .collect();

    let webhooks = s.inner().webhooks.clone();
    let (id, record) = pool
        .with_writer_tx(move |tx| -> rusqlite::Result<(i64, serde_json::Value)> {
            let schema = describe_collection(tx, &coll)?.ok_or_else(|| {
                invalid_input(format!("unknown collection: '{}'", coll))
            })?;
            let allowed: std::collections::HashSet<&str> =
                schema.fields.iter().map(|f| f.name.as_str()).collect();
            for k in data_map.keys() {
                if !allowed.contains(k.as_str()) {
                    let mut names: Vec<&str> = allowed.iter().copied().collect();
                    names.sort();
                    return Err(invalid_input(format!(
                        "unknown field '{}' for collection '{}' (allowed: {})",
                        k,
                        coll,
                        names.join(", ")
                    )));
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
            // Vector fields bind as BLOB from the pre-encoded bytes; the
            // rest go through json_to_sql_value.
            let params: Vec<Value> = data_map
                .iter()
                .map(|(k, v)| match vector_bytes.get(k) {
                    Some(bytes) => Value::Blob(bytes.clone()),
                    None => json_to_sql_value(v),
                })
                .collect();
            let refs: Vec<&dyn rusqlite::ToSql> =
                params.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
            tx.execute(&sql, &refs[..])?;
            let id = tx.last_insert_rowid();
            let rec = read_record(tx, &coll, id, &vector_names)?;
            Ok((id, rec))
        })
        .await?;
    let ev = Event::Created { record: record.clone() };
    bus.publish(&tenant, collection, ev.clone());
    webhooks.dispatch(&tenant, collection, ev);
    Ok(json!({ "id": id, "record": record }))
}

pub async fn update_record(
    s: &DrustMcp,
    collection: &str,
    id: i64,
    data: serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    if is_protected_collection(collection) {
        anyhow::bail!("PROTECTED_COLLECTION: _system_* tables are read-only via MCP records tools. Use the dedicated admin tools.");
    }
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
    let webhooks = s.inner().webhooks.clone();

    let coll_for_schema = coll.clone();
    let schema = pool
        .with_reader(move |c| describe_collection(c, &coll_for_schema))
        .await?
        .ok_or_else(|| anyhow::anyhow!("unknown collection: '{}'", coll))?;
    let vector_bytes = pre_encode_vectors(&schema.vector_fields, &data_map)?;
    let vector_names: HashSet<String> = schema
        .vector_fields
        .iter()
        .map(|v| v.name.clone())
        .collect();

    let record = pool
        .with_writer_tx(move |tx| -> rusqlite::Result<serde_json::Value> {
            let schema = describe_collection(tx, &coll)?.ok_or_else(|| {
                invalid_input(format!("unknown collection: '{}'", coll))
            })?;
            let allowed: std::collections::HashSet<&str> =
                schema.fields.iter().map(|f| f.name.as_str()).collect();
            for k in data_map.keys() {
                if !allowed.contains(k.as_str()) {
                    let mut names: Vec<&str> = allowed.iter().copied().collect();
                    names.sort();
                    return Err(invalid_input(format!(
                        "unknown field '{}' for collection '{}' (allowed: {})",
                        k,
                        coll,
                        names.join(", ")
                    )));
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
            let mut params: Vec<Value> = data_map
                .iter()
                .map(|(k, v)| match vector_bytes.get(k) {
                    Some(bytes) => Value::Blob(bytes.clone()),
                    None => json_to_sql_value(v),
                })
                .collect();
            params.push(Value::Integer(id));
            let refs: Vec<&dyn rusqlite::ToSql> =
                params.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
            let n = tx.execute(&sql, &refs[..])?;
            if n == 0 {
                return Err(rusqlite::Error::QueryReturnedNoRows);
            }
            read_record(tx, &coll, id, &vector_names)
        })
        .await?;
    let ev = Event::Updated { record: record.clone() };
    bus.publish(&tenant, collection, ev.clone());
    webhooks.dispatch(&tenant, collection, ev);
    Ok(json!({ "record": record }))
}

/// v1.26 — Validation half of `delete_record`, used by dry_run mode.
/// Runs the existence + protection checks but returns Ok before the
/// DELETE would execute. Errors mirror the real path 1:1 so dry_run
/// surfaces the same problems a real call would.
pub async fn delete_record_validate(
    s: &DrustMcp,
    collection: &str,
    id: i64,
) -> anyhow::Result<()> {
    if is_protected_collection(collection) {
        anyhow::bail!("PROTECTED_COLLECTION: cannot delete from {collection}");
    }
    let coll_owned = collection.to_string();
    let exists: i64 = s
        .inner()
        .pool
        .with_reader(move |c| {
            let count_sql = format!(
                "SELECT COUNT(*) FROM \"{}\" WHERE id = ?1",
                coll_owned.replace('"', "\"\"")
            );
            c.query_row(&count_sql, rusqlite::params![id], |r| r.get(0))
        })
        .await
        .map_err(|e| anyhow::anyhow!("COLLECTION_NOT_FOUND: {e}"))?;
    if exists == 0 {
        anyhow::bail!("RECORD_NOT_FOUND: id {id} not in {collection}");
    }
    Ok(())
}

pub async fn delete_record(
    s: &DrustMcp,
    collection: &str,
    id: i64,
) -> anyhow::Result<serde_json::Value> {
    if is_protected_collection(collection) {
        anyhow::bail!("PROTECTED_COLLECTION: _system_* tables are read-only via MCP records tools. Use the dedicated admin tools.");
    }
    let coll = collection.to_string();
    let pool = s.inner().pool.clone();
    let tenant = s.inner().tenant_id.clone();
    let bus = s.inner().bus.clone();
    let webhooks = s.inner().webhooks.clone();
    let n = pool
        .with_writer_tx(move |tx| {
            let sql = format!(
                "DELETE FROM \"{}\" WHERE id = ?1",
                coll.replace('"', "\"\"")
            );
            tx.execute(&sql, rusqlite::params![id])
        })
        .await?;
    if n == 0 {
        return Ok(json!({ "ok": false, "error_code": "RECORD_NOT_FOUND", "message": format!("record with id {} not found in collection {:?}", id, collection) }));
    }
    let ev = Event::Deleted { id };
    bus.publish(&tenant, collection, ev.clone());
    webhooks.dispatch(&tenant, collection, ev);
    Ok(json!({ "ok": true }))
}
