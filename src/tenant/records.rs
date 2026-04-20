use crate::query::authorizer::{attach_readonly_authorizer, detach_authorizer};
use crate::query::executor::execute_read_query;
use crate::query::filter::{ListParams, SortDir, build_count_sql, build_list_sql, parse_sort};
use crate::storage::schema::{collection_exists, describe_collection};
use crate::tenant::events::{Event, EventBus};
use crate::tenant::router::{TenantRef, require_service};
use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use rusqlite::types::Value;
use serde::Deserialize;
use serde_json::json;

#[derive(Debug, Deserialize, Default)]
pub struct ListQs {
    #[serde(default)]
    pub filter: Option<String>,
    #[serde(default)]
    pub sort: Option<String>,
    #[serde(default)]
    pub page: Option<u32>,
    #[serde(default)]
    pub per_page: Option<u32>,
}

fn json_error(status: StatusCode, code: &str, msg: &str) -> Response {
    let mut r = Json(json!({ "error_code": code, "message": msg })).into_response();
    *r.status_mut() = status;
    r
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

fn record_as_json(
    stmt: &mut rusqlite::Statement,
    column_names: &[String],
    id: i64,
) -> rusqlite::Result<serde_json::Value> {
    let row = stmt.query_row(rusqlite::params![id], |r| {
        let mut obj = serde_json::Map::new();
        for (i, n) in column_names.iter().enumerate() {
            let v = r.get_ref(i)?;
            let jv = match v {
                rusqlite::types::ValueRef::Null => serde_json::Value::Null,
                rusqlite::types::ValueRef::Integer(i) => serde_json::json!(i),
                rusqlite::types::ValueRef::Real(f) => serde_json::json!(f),
                rusqlite::types::ValueRef::Text(t) => {
                    serde_json::Value::String(String::from_utf8_lossy(t).into_owned())
                }
                rusqlite::types::ValueRef::Blob(b) => {
                    serde_json::json!({ "__blob_bytes": b.len() })
                }
            };
            obj.insert(n.clone(), jv);
        }
        Ok(serde_json::Value::Object(obj))
    })?;
    Ok(row)
}

pub async fn list_handler(
    Extension(t): Extension<TenantRef>,
    Path((_tenant, coll)): Path<(String, String)>,
    Query(qs): Query<ListQs>,
) -> Response {
    let pool = t.pool.clone();
    let coll_clone = coll.clone();
    let exists = pool
        .with_reader(move |c| collection_exists(c, &coll_clone))
        .await
        .unwrap_or(false);
    if !exists {
        return json_error(
            StatusCode::NOT_FOUND,
            "UNKNOWN_COLLECTION",
            "no such collection",
        );
    }
    let (sort_field, sort_dir) = match qs.sort.as_deref() {
        Some(s) => parse_sort(s),
        None => ("created_at".into(), SortDir::Desc),
    };
    let params = ListParams {
        filter: qs.filter.clone(),
        sort_field,
        sort_dir,
        page: qs.page.unwrap_or(1),
        per_page: qs.per_page.unwrap_or(20),
    };
    let list_sql = build_list_sql(&coll, &params);
    let count_sql = build_count_sql(&coll, qs.filter.as_deref());
    let records_res = {
        let sql = list_sql.clone();
        pool.with_reader(move |c| {
            execute_read_query(c, &sql, 500, 32_768).map_err(|_e| rusqlite::Error::InvalidQuery)
        })
        .await
    };
    let records = match records_res {
        Ok(qr) => qr,
        Err(_) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "QUERY_FORBIDDEN",
                "filter rejected",
            );
        }
    };
    let total = {
        let sql = count_sql.clone();
        pool.with_reader(move |c| {
            attach_readonly_authorizer(c);
            let r = c.query_row(&sql, [], |r| r.get::<_, i64>(0));
            detach_authorizer(c);
            r
        })
        .await
        .unwrap_or(0)
    };
    let records_out: Vec<serde_json::Value> = records
        .rows
        .iter()
        .map(|row| {
            let mut m = serde_json::Map::new();
            for (i, name) in records.column_names.iter().enumerate() {
                m.insert(name.clone(), row[i].clone());
            }
            serde_json::Value::Object(m)
        })
        .collect();
    let per_page = params.per_page.clamp(1, 500) as u64;
    let total_pages = (total as u64).div_ceil(per_page.max(1));
    Json(json!({
        "records": records_out,
        "page": params.page,
        "perPage": per_page,
        "total": total,
        "totalPages": total_pages,
    }))
    .into_response()
}

pub async fn get_handler(
    Extension(t): Extension<TenantRef>,
    Path((_tenant, coll, id)): Path<(String, String, i64)>,
) -> Response {
    let pool = t.pool.clone();
    let coll_clone = coll.clone();
    let out = pool
        .with_reader(move |c| {
            if !collection_exists(c, &coll_clone)? {
                return Ok(None);
            }
            let mut stmt = c.prepare(&format!(
                "SELECT * FROM \"{}\" WHERE id = ?1",
                coll_clone.replace('"', "\"\"")
            ))?;
            let cols: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
            let rec = record_as_json(&mut stmt, &cols, id);
            match rec {
                Ok(v) => Ok(Some(v)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(e),
            }
        })
        .await;
    match out {
        Ok(Some(v)) => Json(json!({ "record": v })).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "not found").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub struct DataBody {
    pub data: serde_json::Value,
}

pub async fn create_handler(
    Extension(t): Extension<TenantRef>,
    Path((_tenant, coll)): Path<(String, String)>,
    Json(body): Json<DataBody>,
    bus: EventBus,
) -> Response {
    if let Err(resp) = require_service(&t) {
        return resp;
    }
    let data = match body.data.as_object() {
        Some(o) => o.clone(),
        None => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "TYPE_MISMATCH",
                "data must be object",
            );
        }
    };
    let pool = t.pool.clone();
    let coll_clone = coll.clone();
    let tenant_id = t.tenant_id.clone();
    let res = pool
        .with_writer(move |c| -> rusqlite::Result<(i64, serde_json::Value)> {
            // Validate against schema
            let schema = match describe_collection(c, &coll_clone)? {
                Some(s) => s,
                None => return Err(rusqlite::Error::InvalidQuery),
            };
            let allowed: std::collections::HashSet<&str> =
                schema.fields.iter().map(|f| f.name.as_str()).collect();
            for k in data.keys() {
                if !allowed.contains(k.as_str()) {
                    return Err(rusqlite::Error::InvalidQuery);
                }
            }
            let cols: Vec<&str> = data.keys().map(|k| k.as_str()).collect();
            let placeholders: Vec<String> = (1..=cols.len()).map(|i| format!("?{i}")).collect();
            let sql = if cols.is_empty() {
                format!(
                    "INSERT INTO \"{}\" DEFAULT VALUES",
                    coll_clone.replace('"', "\"\"")
                )
            } else {
                format!(
                    "INSERT INTO \"{}\" ({}) VALUES ({})",
                    coll_clone.replace('"', "\"\""),
                    cols.iter()
                        .map(|c| format!("\"{}\"", c.replace('"', "\"\"")))
                        .collect::<Vec<_>>()
                        .join(","),
                    placeholders.join(","),
                )
            };
            let params: Vec<Value> = data.values().map(json_to_sql_value).collect();
            let refs: Vec<&dyn rusqlite::ToSql> =
                params.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
            c.execute(&sql, &refs[..])?;
            let id = c.last_insert_rowid();
            let mut stmt = c.prepare(&format!(
                "SELECT * FROM \"{}\" WHERE id = ?1",
                coll_clone.replace('"', "\"\"")
            ))?;
            let cols_out: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
            let rec = record_as_json(&mut stmt, &cols_out, id)?;
            Ok((id, rec))
        })
        .await;
    match res {
        Ok((id, rec)) => {
            bus.publish(
                &tenant_id,
                &coll,
                Event::Created {
                    record: rec.clone(),
                },
            );
            let mut r = Json(json!({ "id": id, "record": rec })).into_response();
            *r.status_mut() = StatusCode::CREATED;
            r
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("InvalidQuery") {
                json_error(
                    StatusCode::BAD_REQUEST,
                    "UNKNOWN_FIELD",
                    "unknown field or missing collection",
                )
            } else {
                (StatusCode::BAD_REQUEST, msg).into_response()
            }
        }
    }
}

pub async fn update_handler(
    Extension(t): Extension<TenantRef>,
    Path((_tenant, coll, id)): Path<(String, String, i64)>,
    Json(body): Json<DataBody>,
    bus: EventBus,
) -> Response {
    if let Err(resp) = require_service(&t) {
        return resp;
    }
    let data = match body.data.as_object() {
        Some(o) => o.clone(),
        None => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "TYPE_MISMATCH",
                "data must be object",
            );
        }
    };
    if data.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            "TYPE_MISMATCH",
            "data must have at least one field",
        );
    }
    let pool = t.pool.clone();
    let coll_clone = coll.clone();
    let tenant_id = t.tenant_id.clone();
    let res = pool
        .with_writer(move |c| -> rusqlite::Result<serde_json::Value> {
            let schema = match describe_collection(c, &coll_clone)? {
                Some(s) => s,
                None => return Err(rusqlite::Error::InvalidQuery),
            };
            let allowed: std::collections::HashSet<&str> =
                schema.fields.iter().map(|f| f.name.as_str()).collect();
            for k in data.keys() {
                if !allowed.contains(k.as_str()) {
                    return Err(rusqlite::Error::InvalidQuery);
                }
            }
            let set_exprs: Vec<String> = data
                .keys()
                .enumerate()
                .map(|(i, k)| format!("\"{}\" = ?{}", k.replace('"', "\"\""), i + 1))
                .collect();
            let sql = format!(
                "UPDATE \"{}\" SET {}, updated_at = datetime('now') WHERE id = ?{}",
                coll_clone.replace('"', "\"\""),
                set_exprs.join(","),
                data.len() + 1
            );
            let mut params: Vec<Value> = data.values().map(json_to_sql_value).collect();
            params.push(Value::Integer(id));
            let refs: Vec<&dyn rusqlite::ToSql> =
                params.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
            let n = c.execute(&sql, &refs[..])?;
            if n == 0 {
                return Err(rusqlite::Error::QueryReturnedNoRows);
            }
            let mut stmt = c.prepare(&format!(
                "SELECT * FROM \"{}\" WHERE id = ?1",
                coll_clone.replace('"', "\"\"")
            ))?;
            let cols_out: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
            let rec = record_as_json(&mut stmt, &cols_out, id)?;
            Ok(rec)
        })
        .await;
    match res {
        Ok(rec) => {
            bus.publish(
                &tenant_id,
                &coll,
                Event::Updated {
                    record: rec.clone(),
                },
            );
            Json(json!({ "record": rec })).into_response()
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            (StatusCode::NOT_FOUND, "no such record").into_response()
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("InvalidQuery") {
                json_error(StatusCode::BAD_REQUEST, "UNKNOWN_FIELD", "unknown field")
            } else {
                (StatusCode::BAD_REQUEST, msg).into_response()
            }
        }
    }
}

pub async fn delete_handler(
    Extension(t): Extension<TenantRef>,
    Path((_tenant, coll, id)): Path<(String, String, i64)>,
    bus: EventBus,
) -> Response {
    if let Err(resp) = require_service(&t) {
        return resp;
    }
    let pool = t.pool.clone();
    let coll_clone = coll.clone();
    let tenant_id = t.tenant_id.clone();
    let res = pool
        .with_writer(move |c| {
            let sql = format!(
                "DELETE FROM \"{}\" WHERE id = ?1",
                coll_clone.replace('"', "\"\"")
            );
            c.execute(&sql, rusqlite::params![id])
        })
        .await;
    match res {
        Ok(0) => (StatusCode::NOT_FOUND, "no such record").into_response(),
        Ok(_) => {
            bus.publish(&tenant_id, &coll, Event::Deleted { id });
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}
