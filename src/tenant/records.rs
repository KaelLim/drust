use crate::auth::middleware::AuthCtx;
use crate::query::authorizer::{attach_readonly_authorizer, detach_authorizer};
use crate::query::executor::execute_read_query;
use crate::query::filter::{ListParams, SortDir, build_count_sql, build_list_sql, parse_sort};
use crate::storage::schema::{
    CollectionSchema, DmlVerb, collection_exists, describe_collection, has_dml_cap,
    is_protected_collection,
};
use crate::tenant::events::{Event, EventBus};
use crate::tenant::router::TenantRef;
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

/// Resolve the cached schema for `coll`, then gate the caller's role
/// against `verb`. Returns the schema on success so the handler can
/// reuse it for field-name validation. Returns a 403 (anon lacks cap)
/// or 404 (collection not found) `Response` on failure.
async fn require_dml_cap(
    tenant: &TenantRef,
    coll: &str,
    verb: DmlVerb,
) -> Result<CollectionSchema, Response> {
    // _system_* tables are internal storage and never exposed via the
    // records API regardless of role. Service tokens that need to touch
    // them have dedicated admin/MCP entry points.
    if is_protected_collection(coll) {
        return Err(json_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            &format!("no such collection: {coll}"),
        ));
    }
    let pool = tenant.pool.clone();
    let cache = pool.schema_cache.clone();
    let coll_owned = coll.to_string();
    let load_res = pool
        .with_reader(move |c| cache.ensure_loaded(c, &coll_owned))
        .await;
    let schema = match load_res {
        Ok(Some(s)) => s,
        Ok(None) => {
            return Err(json_error(
                StatusCode::NOT_FOUND,
                "NOT_FOUND",
                &format!("no such collection: {coll}"),
            ));
        }
        Err(e) => {
            return Err(json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DB_ERROR",
                &e.to_string(),
            ));
        }
    };
    // Anon on owner-scoped collection with read_scope=own has no user_id to
    // match against, so it can't see any rows — fail loudly rather than
    // silently returning an empty list.
    if matches!(tenant.role, crate::tenant::router::TokenRole::Anon)
        && schema.owner_field.is_some()
        && schema.read_scope.as_deref() == Some("own")
    {
        return Err(json_error(
            StatusCode::FORBIDDEN,
            "ANON_FORBIDDEN_OWNER_SCOPED_READ",
            "anon cannot read owner-scoped collection with read_scope=own",
        ));
    }
    if !has_dml_cap(tenant.role, verb, &schema) {
        return Err(json_error(
            StatusCode::FORBIDDEN,
            "ANON_DENIED",
            &format!(
                "anon role lacks '{}' on collection '{}'",
                verb.as_str(),
                coll
            ),
        ));
    }
    Ok(schema)
}

/// Same as `require_dml_cap` for write verbs (Insert/Update/Delete), but
/// additionally checks owner-scoped anon policy *before* anon_caps, so
/// anon callers on owner-scoped collections get `ANON_FORBIDDEN_OWNER_SCOPED`
/// rather than the generic `ANON_DENIED`.
async fn require_write_cap(
    tenant: &TenantRef,
    ctx: &AuthCtx,
    coll: &str,
    verb: DmlVerb,
) -> Result<CollectionSchema, Response> {
    if is_protected_collection(coll) {
        return Err(json_error(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            &format!("no such collection: {coll}"),
        ));
    }
    let pool = tenant.pool.clone();
    let cache = pool.schema_cache.clone();
    let coll_owned = coll.to_string();
    let load_res = pool
        .with_reader(move |c| cache.ensure_loaded(c, &coll_owned))
        .await;
    let schema = match load_res {
        Ok(Some(s)) => s,
        Ok(None) => {
            return Err(json_error(
                StatusCode::NOT_FOUND,
                "NOT_FOUND",
                &format!("no such collection: {coll}"),
            ));
        }
        Err(e) => {
            return Err(json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DB_ERROR",
                &e.to_string(),
            ));
        }
    };
    // Anon on an owner-scoped collection gets a specific error that distinguishes
    // "collection is owner-gated" from "this collection doesn't allow anon writes".
    if matches!(ctx, AuthCtx::Anon) && schema.owner_field.is_some() {
        return Err(json_error(
            StatusCode::FORBIDDEN,
            "ANON_FORBIDDEN_OWNER_SCOPED",
            "anon tokens may not write to owner-scoped collections",
        ));
    }
    // Standard anon_caps gate (also allows User/Service through unconditionally).
    if !has_dml_cap(tenant.role, verb, &schema) {
        return Err(json_error(
            StatusCode::FORBIDDEN,
            "ANON_DENIED",
            &format!(
                "anon role lacks '{}' on collection '{}'",
                verb.as_str(),
                coll
            ),
        ));
    }
    Ok(schema)
}

/// Compute an owner row-level filter `(field_name, user_id)` when:
/// - the collection has an `owner_field` with `read_scope = "own"`, AND
/// - the caller is a `User` token (Service and Anon bypass the filter).
fn compute_owner_filter(ctx: &AuthCtx, schema: &CollectionSchema) -> Option<(String, String)> {
    match (ctx, schema.owner_field.as_deref(), schema.read_scope.as_deref()) {
        (AuthCtx::User { user_id, .. }, Some(field), Some("own")) => {
            Some((field.to_string(), user_id.clone()))
        }
        _ => None,
    }
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
    Extension(ctx): Extension<AuthCtx>,
    Path((_tenant, coll)): Path<(String, String)>,
    Query(qs): Query<ListQs>,
) -> Response {
    let schema = match require_dml_cap(&t, &coll, DmlVerb::Select).await {
        Ok(s) => s,
        Err(r) => return r,
    };
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
    // Compute owner_filter: only for User tokens on collections with
    // read_scope = "own".  Service and Anon bypass the row-level filter.
    let owner_filter = compute_owner_filter(&ctx, &schema);
    let (sort_field, sort_dir) = match qs.sort.as_deref() {
        Some(s) => parse_sort(s),
        None => ("created_at".into(), SortDir::Desc),
    };
    // Keep a copy of the (field, user_id) tuple for the count query — we
    // need `&str` slices that outlive the params struct.
    let owner_filter_for_count = owner_filter.clone();
    let params = ListParams {
        filter: qs.filter.clone(),
        sort_field,
        sort_dir,
        page: qs.page.unwrap_or(1),
        per_page: qs.per_page.unwrap_or(20),
        owner_filter,
    };
    let list_sql = build_list_sql(&coll, &params);
    let count_sql = build_count_sql(
        &coll,
        qs.filter.as_deref(),
        owner_filter_for_count
            .as_ref()
            .map(|(f, v)| (f.as_str(), v.as_str())),
    );
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
    Extension(ctx): Extension<AuthCtx>,
    Path((_tenant, coll, id)): Path<(String, String, i64)>,
) -> Response {
    let schema = match require_dml_cap(&t, &coll, DmlVerb::Select).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let owner_filter = compute_owner_filter(&ctx, &schema);
    let pool = t.pool.clone();
    let coll_clone = coll.clone();
    let out = pool
        .with_reader(move |c| {
            if !collection_exists(c, &coll_clone)? {
                return Ok(None);
            }
            // Build the query; append owner filter as a literal when needed.
            let mut sql = format!(
                "SELECT * FROM \"{}\" WHERE id = ?1",
                coll_clone.replace('"', "\"\"")
            );
            if let Some((field, user_id)) = &owner_filter {
                sql.push_str(&format!(
                    " AND \"{}\" = '{}'",
                    field.replace('"', "\"\""),
                    user_id.replace('\'', "''")
                ));
            }
            let mut stmt = c.prepare(&sql)?;
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
    Extension(ctx): Extension<AuthCtx>,
    Path((_tenant, coll)): Path<(String, String)>,
    Json(body): Json<DataBody>,
    bus: EventBus,
) -> Response {
    let schema = match require_write_cap(&t, &ctx, &coll, DmlVerb::Insert).await {
        Ok(s) => s,
        Err(r) => return r,
    };

    // Owner-field policy checks for Service/User (anon already blocked by require_write_cap):
    if let Some(ref owner_field) = schema.owner_field {
        match &ctx {
            AuthCtx::Anon => {
                // already blocked above; unreachable but keep for exhaustiveness
                return json_error(
                    StatusCode::FORBIDDEN,
                    "ANON_FORBIDDEN_OWNER_SCOPED",
                    "anon tokens may not write to owner-scoped collections",
                );
            }
            AuthCtx::Service => {
                // Service must explicitly supply the owner field so the row
                // is attributed to a real user; missing it is a caller error.
                let data_obj = body.data.as_object();
                let supplied = data_obj
                    .and_then(|o| o.get(owner_field))
                    .and_then(|v| v.as_str())
                    .map(|s| !s.is_empty())
                    .unwrap_or(false);
                if !supplied {
                    return json_error(
                        StatusCode::CONFLICT,
                        "OWNER_FIELD_REQUIRED",
                        &format!("service token must supply '{owner_field}' on owner-scoped collection"),
                    );
                }
            }
            AuthCtx::User { user_id, .. } => {
                // User token: the owner field is always overwritten to the
                // caller's user_id — clients cannot forge another user's id.
                // (Handled inside the writer closure below.)
                let _ = user_id; // used in closure capture
            }
        }
    }

    let mut data = match body.data.as_object() {
        Some(o) => o.clone(),
        None => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "TYPE_MISMATCH",
                "data must be object",
            );
        }
    };

    // For user tokens with an owner_field, overwrite whatever the client sent.
    if let (Some(owner_field), AuthCtx::User { user_id, .. }) = (&schema.owner_field, &ctx) {
        data.insert(
            owner_field.clone(),
            serde_json::Value::String(user_id.clone()),
        );
    }

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
    Extension(ctx): Extension<AuthCtx>,
    Path((_tenant, coll, id)): Path<(String, String, i64)>,
    Json(body): Json<DataBody>,
    bus: EventBus,
) -> Response {
    let schema = match require_write_cap(&t, &ctx, &coll, DmlVerb::Update).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let owner_filter = compute_owner_filter(&ctx, &schema);
    let mut data = match body.data.as_object() {
        Some(o) => o.clone(),
        None => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "TYPE_MISMATCH",
                "data must be object",
            );
        }
    };
    // Strip any client-supplied owner_field on the User-owner-scoped path so
    // a user cannot transfer ownership of their own row to another user via
    // PATCH {"data": {"user_id": "u-other"}}.
    if let (AuthCtx::User { .. }, Some(field)) = (&ctx, schema.owner_field.as_deref()) {
        data.shift_remove(field);
    }
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
            let id_param_idx = data.len() + 1;
            // Append owner filter as a literal — user_id is UUID shaped,
            // safe to inline after escaping.
            let owner_clause = if let Some((field, user_id)) = &owner_filter {
                format!(
                    " AND \"{}\" = '{}'",
                    field.replace('"', "\"\""),
                    user_id.replace('\'', "''")
                )
            } else {
                String::new()
            };
            let sql = format!(
                "UPDATE \"{}\" SET {}, updated_at = datetime('now') WHERE id = ?{}{}",
                coll_clone.replace('"', "\"\""),
                set_exprs.join(","),
                id_param_idx,
                owner_clause,
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
    Extension(ctx): Extension<AuthCtx>,
    Path((_tenant, coll, id)): Path<(String, String, i64)>,
    bus: EventBus,
) -> Response {
    let schema = match require_write_cap(&t, &ctx, &coll, DmlVerb::Delete).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let owner_filter = compute_owner_filter(&ctx, &schema);
    let pool = t.pool.clone();
    let coll_clone = coll.clone();
    let tenant_id = t.tenant_id.clone();
    let res = pool
        .with_writer(move |c| {
            let owner_clause = if let Some((field, user_id)) = &owner_filter {
                format!(
                    " AND \"{}\" = '{}'",
                    field.replace('"', "\"\""),
                    user_id.replace('\'', "''")
                )
            } else {
                String::new()
            };
            let sql = format!(
                "DELETE FROM \"{}\" WHERE id = ?1{}",
                coll_clone.replace('"', "\"\""),
                owner_clause,
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
