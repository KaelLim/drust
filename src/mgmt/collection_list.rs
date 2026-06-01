//! Admin-only POST /admin/tenants/<id>/collections/<coll>/_list endpoint
//! that backs the v1.28 chip filter on the collection editor.
//!
//! Browser sends `{filters, sort, page, per_page}` with filter ops drawn
//! from the toolbar dropdown (`eq`, `contains`, `between`, `is_null`, …).
//! Handler bridges these to FilterAst (`src/query/vector_filter.rs`),
//! compiles to SQL with `?` binds, runs against the read-only connection,
//! and returns `{columns, rows, total, page, per_page, total_pages}`.

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct ListRequest {
    #[serde(default)]
    pub filters: Vec<FilterTriple>,
    #[serde(default)]
    pub sort: Option<SortSpec>,
    #[serde(default = "default_page")]
    pub page: u32,
    #[serde(default = "default_per_page")]
    pub per_page: u32,
}

fn default_page() -> u32 { 1 }
fn default_per_page() -> u32 { 50 }

#[derive(Debug, Deserialize)]
pub struct FilterTriple {
    pub field: String,
    pub op: String,
    /// Always present in JSON; for `is_null` / `is_not_null` / `is_true`
    /// / `is_false` the value is ignored by the bridge.
    #[serde(default)]
    pub value: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct SortSpec {
    pub field: String,
    pub dir: SortDir,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SortDir {
    Asc,
    Desc,
}

#[derive(Debug, Serialize)]
pub struct ListResponse {
    pub columns: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column_labels: Option<Vec<String>>,
    pub rows: Vec<Vec<serde_json::Value>>,
    pub total: i64,
    pub page: u32,
    pub per_page: u32,
    pub total_pages: u32,
}

/// Render a BLOB cell as a human-readable preview. Vector columns (the
/// schema's declared `vector_fields`) get their declared `dim` plus the
/// first three f32 values decoded from the packed little-endian layout
/// produced by `crate::query::vector_codec::pack`. Non-vector BLOBs
/// just get a byte-count hint. The full vector value remains available
/// through the existing `/records/<id>` REST endpoint when a row needs
/// to be inspected; the list view is intentionally a teaser.
fn format_blob_cell(
    col_name: &str,
    bytes: &[u8],
    vector_dim_by_col: &std::collections::HashMap<String, u32>,
) -> String {
    let Some(&declared_dim) = vector_dim_by_col.get(col_name) else {
        return format!("[blob bytes={}]", bytes.len());
    };
    // Each f32 is 4 bytes packed little-endian. A column whose declared
    // dim disagrees with the on-disk byte length is almost certainly a
    // foreign BLOB that snuck in through `query` / `insert_record` —
    // fall back to the neutral hint so the list view doesn't lie.
    if bytes.len() % 4 != 0 || bytes.len() as u32 / 4 != declared_dim {
        return format!("[blob bytes={}]", bytes.len());
    }
    let take = (declared_dim as usize).min(3);
    let mut head: Vec<String> = Vec::with_capacity(take);
    for chunk in bytes.chunks_exact(4).take(take) {
        let f = f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        // Two decimals is enough to convey magnitude + sign without
        // dominating the cell. The full-precision value lives behind
        // the row-detail modal that v1.32.9 introduces.
        head.push(format!("{f:.2}"));
    }
    let suffix = if (declared_dim as usize) > take { ", …" } else { "" };
    format!("[vec dim={} · {}{}]", declared_dim, head.join(", "), suffix)
}

/// Keys consumed by `system_column_labels` via `format!("{prefix}.{raw}")`.
/// Listed explicitly so `build.rs`'s orphan scanner sees the references —
/// it walks `src/**/*.rs` for literal strings matching known en.toml keys
/// but does not simulate format!/concat-time key construction. Keep this
/// in sync with the actual `_system_users` schema and the
/// `[system_users.col]` block in `locales/en.toml`.
#[allow(dead_code)]
const SYSTEM_USERS_COL_KEYS: &[&str] = &[
    "system_users.col.id",
    "system_users.col.email",
    "system_users.col.password_hash",
    "system_users.col.verified",
    "system_users.col.profile",
    "system_users.col.created_at",
    "system_users.col.updated_at",
];

/// Returns localized display labels for a system collection's columns,
/// one per entry in `columns`. Unknown column names fall back to the
/// raw SQL name so adding a column doesn't break rendering. Returns
/// `None` for non-system collections — user-defined tables show the
/// raw column names that the schema author chose.
fn system_column_labels(
    coll_name: &str,
    columns: &[String],
    locale: crate::mgmt::i18n::Locale,
) -> Option<Vec<String>> {
    let prefix = match coll_name {
        "_system_users" => "system_users.col",
        _ => return None,
    };
    let t = crate::mgmt::i18n::Translator::new(locale);
    Some(columns.iter().map(|raw| {
        let key = format!("{prefix}.{raw}");
        let translated = t.s(&key);
        if translated.starts_with("!!") && translated.ends_with("!!") {
            raw.clone()
        } else {
            translated.into_owned()
        }
    }).collect())
}

/// Translate a flat list of `{field, op, value}` triples to a single
/// FilterAst tree. The result is `FilterAst::And { and: <nodes> }` so an
/// empty input compiles to `1=1` (matches all rows).
///
/// Bridge ops (op → FilterAst):
/// - `contains`      → `{field: {like: "%value%"}}`
/// - `starts_with`   → `{field: {like: "value%"}}`
/// - `ends_with`     → `{field: {like: "%value"}}`
/// - `between`       → `{and: [{field: {gte: lo}}, {field: {lte: hi}}]}`
///                      (value must be a 2-element array)
/// - `is_true`       → `{field: {eq: 1}}`
/// - `is_false`      → `{field: {eq: 0}}`
/// Pass-through ops: eq, ne, gt, gte, lt, lte, in, nin, like, is_null, is_not_null.
pub fn filter_triples_to_ast(
    triples: &[FilterTriple],
) -> Result<crate::query::vector_filter::FilterAst, String> {
    let mut nodes = Vec::with_capacity(triples.len());
    for t in triples {
        nodes.push(triple_to_node(t)?);
    }
    Ok(crate::query::vector_filter::FilterAst::And { and: nodes })
}

fn triple_to_node(
    t: &FilterTriple,
) -> Result<crate::query::vector_filter::FilterAst, String> {
    use crate::query::vector_filter::FilterAst;
    use serde_json::{Map, Value as J};

    fn leaf(field: &str, body: J) -> FilterAst {
        let mut m = Map::new();
        m.insert(field.to_string(), body);
        FilterAst::Leaf(m)
    }
    fn op_obj(op: &str, v: J) -> J {
        let mut m = Map::new();
        m.insert(op.to_string(), v);
        J::Object(m)
    }

    match t.op.as_str() {
        "eq" | "ne" | "gt" | "gte" | "lt" | "lte"
        | "in" | "nin" | "like" | "is_null" | "is_not_null" => {
            Ok(leaf(&t.field, op_obj(&t.op, t.value.clone())))
        }
        "contains" => {
            let s = t.value.as_str().ok_or("contains requires string")?;
            Ok(leaf(&t.field, op_obj("like", J::String(format!("%{s}%")))))
        }
        "starts_with" => {
            let s = t.value.as_str().ok_or("starts_with requires string")?;
            Ok(leaf(&t.field, op_obj("like", J::String(format!("{s}%")))))
        }
        "ends_with" => {
            let s = t.value.as_str().ok_or("ends_with requires string")?;
            Ok(leaf(&t.field, op_obj("like", J::String(format!("%{s}")))))
        }
        "between" => {
            let arr = t.value.as_array().ok_or("between requires 2-element array")?;
            if arr.len() != 2 {
                return Err("between requires exactly 2 elements".into());
            }
            Ok(FilterAst::And {
                and: vec![
                    leaf(&t.field, op_obj("gte", arr[0].clone())),
                    leaf(&t.field, op_obj("lte", arr[1].clone())),
                ],
            })
        }
        "is_true"  => Ok(leaf(&t.field, op_obj("eq", J::Number(1.into())))),
        "is_false" => Ok(leaf(&t.field, op_obj("eq", J::Number(0.into())))),
        other => Err(format!("unknown op {other:?}")),
    }
}

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use crate::mgmt::tenants::TenantsState;

/// POST /admin/tenants/<id>/collections/<coll>/_list
pub async fn admin_list_handler(
    State(state): State<TenantsState>,
    Path((tenant_id, coll_name)): Path<(String, String)>,
    locale: Option<axum::Extension<crate::mgmt::i18n::Locale>>,
    Json(req): Json<ListRequest>,
) -> Response {
    let started = std::time::Instant::now();
    let locale = locale.map(|axum::Extension(l)| l).unwrap_or(crate::mgmt::i18n::Locale::En);
    let result = admin_list_inner(&state, &tenant_id, &coll_name, req, locale).await;
    let duration_ms = started.elapsed().as_millis().min(u64::MAX as u128) as u64;
    match result {
        Ok(body) => {
            let entry = crate::safety::audit::AuditEntry::success(
                &tenant_id, "-", "admin.collection.list", duration_ms,
            );
            crate::safety::audit_db::try_send(&entry);
            Json(body).into_response()
        }
        Err((status, code, msg)) => {
            let entry = crate::safety::audit::AuditEntry::failure(
                &tenant_id, "-", "admin.collection.list", duration_ms,
                &format!("HTTP_{}", status.as_u16()),
                &msg,
            );
            crate::safety::audit_db::try_send(&entry);
            error_response(status, code, &msg)
        }
    }
}

async fn admin_list_inner(
    state: &TenantsState,
    tenant_id: &str,
    coll_name: &str,
    req: ListRequest,
    locale: crate::mgmt::i18n::Locale,
) -> Result<ListResponse, (StatusCode, &'static str, String)> {
    // Tenant existence check — mirrors browse.rs.
    let meta = state.session.meta.lock().await;
    let active = meta.query_row(
        "SELECT COUNT(*) FROM tenants WHERE id = ?1 AND deleted_at IS NULL",
        rusqlite::params![tenant_id],
        |r| r.get::<_, i64>(0),
    ).map(|n| n > 0).unwrap_or(false);
    drop(meta);
    if !active {
        return Err((StatusCode::NOT_FOUND, "TENANT_NOT_FOUND", "no such tenant".to_string()));
    }

    // Load schema (need it for FilterAst::compile + column_names).
    let pool = match state.tenants.get_or_open(tenant_id) {
        Ok(p) => p,
        Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", e.to_string())),
    };
    let coll_for_describe = coll_name.to_string();
    let schema = match pool.with_reader(move |c| {
        crate::storage::schema::describe_collection(c, &coll_for_describe)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))
    }).await {
        Ok(Some(s)) => s,
        Ok(None) => return Err((StatusCode::NOT_FOUND, "COLLECTION_NOT_FOUND", "no such collection".to_string())),
        Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", e.to_string())),
    };

    // Translate triples → FilterAst → SQL fragment + binds.
    let ast = match filter_triples_to_ast(&req.filters) {
        Ok(a) => a,
        Err(msg) => return Err((StatusCode::BAD_REQUEST, "INVALID_FILTER", msg)),
    };
    let (where_sql, binds) = match crate::query::vector_filter::compile(&schema, &ast) {
        Ok(p) => p,
        Err(e) => return Err((StatusCode::BAD_REQUEST, "INVALID_FILTER", e.to_string())),
    };

    // Sort field must exist in schema (unless caller omitted sort).
    let (sort_field, sort_dir_sql) = match &req.sort {
        Some(s) => {
            if !schema.fields.iter().any(|f| f.name == s.field) {
                return Err((StatusCode::BAD_REQUEST, "UNKNOWN_SORT_FIELD",
                    format!("sort field {:?} not in schema", s.field)));
            }
            let dir = match s.dir { SortDir::Asc => "ASC", SortDir::Desc => "DESC" };
            (s.field.clone(), dir)
        }
        None => ("id".to_string(), "DESC"),
    };

    let page = req.page.max(1);
    let per_page = req.per_page.clamp(1, 500);
    let offset = (page as u64 - 1) * per_page as u64;
    let table = format!("\"{}\"", coll_name.replace('"', "\"\""));
    let sort_col = format!("\"{}\"", sort_field.replace('"', "\"\""));

    let list_sql = format!(
        "SELECT * FROM {table} WHERE {where_sql} ORDER BY {sort_col} {sort_dir_sql} LIMIT {per_page} OFFSET {offset}"
    );
    let count_sql = format!("SELECT COUNT(*) FROM {table} WHERE {where_sql}");

    // Execute under read lock. Admin path bypasses the read-only authorizer
    // for _system_* tables (connection is still SQLITE_OPEN_READONLY).
    let is_protected = crate::storage::schema::is_protected_collection(coll_name);
    let binds_for_list = binds.clone();
    let list_sql_for_closure = list_sql.clone();
    // v1.32.9 — pass the schema's declared vector fields into the read
    // closure so a BLOB cell coming back from a vector column renders as
    // `[vec dim=N · 0.12, -0.45, 0.78, …]` instead of the opaque
    // `[blob]` sentinel. Non-vector BLOBs still get an honest
    // `[blob bytes=N]` placeholder so the row count is visible.
    let vector_dim_by_col: std::collections::HashMap<String, u32> = schema
        .vector_fields
        .iter()
        .map(|v| (v.name.clone(), v.dim))
        .collect();
    let rows_result = pool.with_reader(move |c| -> rusqlite::Result<(Vec<String>, Vec<Vec<serde_json::Value>>)> {
        if !is_protected {
            crate::query::authorizer::attach_readonly_authorizer(c);
        }
        let mut stmt = c.prepare(&list_sql_for_closure)?;
        let col_names: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
        let mut rows_iter = stmt.query(rusqlite::params_from_iter(binds_for_list.iter()))?;
        let mut out: Vec<Vec<serde_json::Value>> = Vec::new();
        while let Some(r) = rows_iter.next()? {
            let mut row_vals = Vec::with_capacity(col_names.len());
            for i in 0..col_names.len() {
                let v: rusqlite::types::Value = r.get(i)?;
                row_vals.push(match v {
                    rusqlite::types::Value::Null => serde_json::Value::Null,
                    rusqlite::types::Value::Integer(n) => serde_json::Value::Number(n.into()),
                    rusqlite::types::Value::Real(f) => serde_json::Number::from_f64(f)
                        .map(serde_json::Value::Number).unwrap_or(serde_json::Value::Null),
                    rusqlite::types::Value::Text(s) => serde_json::Value::String(s),
                    rusqlite::types::Value::Blob(bytes) => {
                        let col_name = &col_names[i];
                        let display = format_blob_cell(col_name, &bytes, &vector_dim_by_col);
                        serde_json::Value::String(display)
                    }
                });
            }
            out.push(row_vals);
        }
        if !is_protected {
            crate::query::authorizer::detach_authorizer(c);
        }
        Ok((col_names, out))
    }).await;

    let (column_names, rows) = match rows_result {
        Ok(pair) => pair,
        Err(e) => return Err((StatusCode::BAD_REQUEST, "SQL_ERROR", e.to_string())),
    };

    // Mask sensitive columns (e.g. _system_users.password_hash). The masker
    // operates on stringified rows, so round-trip through Vec<Vec<String>>.
    let rows_stringified: Vec<Vec<String>> = rows.iter().map(|row| {
        row.iter().map(|v| match v {
            serde_json::Value::Null => "NULL".to_string(),
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        }).collect()
    }).collect();
    let (column_names, rows_masked_stringified) =
        crate::mgmt::browse::mask_sensitive_columns(coll_name, column_names, rows_stringified);
    let rows: Vec<Vec<serde_json::Value>> = rows_masked_stringified.into_iter().map(|r| {
        r.into_iter().map(serde_json::Value::String).collect()
    }).collect();

    // Count.
    let binds_for_count = binds;
    let count_sql_for_closure = count_sql;
    let total_result = pool.with_reader(move |c| -> rusqlite::Result<i64> {
        if !is_protected {
            crate::query::authorizer::attach_readonly_authorizer(c);
        }
        let n = c.query_row(
            &count_sql_for_closure,
            rusqlite::params_from_iter(binds_for_count.iter()),
            |r| r.get::<_, i64>(0),
        )?;
        if !is_protected {
            crate::query::authorizer::detach_authorizer(c);
        }
        Ok(n)
    }).await;
    let total: i64 = match total_result {
        Ok(n) => n,
        Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", e.to_string())),
    };

    let total_pages = if total == 0 { 1 } else { (total as u64).div_ceil(per_page as u64) as u32 };

    let column_labels = system_column_labels(coll_name, &column_names, locale);

    Ok(ListResponse {
        columns: column_names,
        column_labels,
        rows,
        total,
        page,
        per_page,
        total_pages,
    })
}

fn error_response(status: StatusCode, code: &'static str, msg: &str) -> Response {
    let body = serde_json::json!({"error_code": code, "message": msg});
    let mut r = Json(body).into_response();
    *r.status_mut() = status;
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::vector_filter::{compile, FilterAst};
    use crate::storage::schema::{CollectionSchema, Field};
    use std::collections::BTreeSet;

    fn schema(fields: &[(&str, &str)]) -> CollectionSchema {
        CollectionSchema {
            name: "t".into(),
            fields: fields.iter().map(|(n, ty)| Field {
                name: n.to_string(),
                sql_type: ty.to_string(),
                nullable: true,
                pk: false,
                default_value: None,
                foreign_key: None,
                description: None,
            }).collect(),
            indices: vec![],
            row_count: 0,
            anon_caps: BTreeSet::new(),
            owner_field: None,
            read_scope: None,
            vector_fields: vec![],
            realtime_enabled: true,
            description: None,
        }
    }

    fn triple(field: &str, op: &str, value: serde_json::Value) -> FilterTriple {
        FilterTriple { field: field.into(), op: op.into(), value }
    }

    #[test]
    fn empty_triples_match_all() {
        let ast = filter_triples_to_ast(&[]).unwrap();
        let (sql, _) = compile(&schema(&[("a","TEXT")]), &ast).unwrap();
        assert_eq!(sql, "1=1");
    }

    #[test]
    fn eq_passes_through() {
        let t = vec![triple("name", "eq", serde_json::json!("Kael"))];
        let ast = filter_triples_to_ast(&t).unwrap();
        let (sql, binds) = compile(&schema(&[("name","TEXT")]), &ast).unwrap();
        assert_eq!(sql, r#"("name" = ?)"#);
        assert_eq!(binds.len(), 1);
    }

    #[test]
    fn contains_rewrites_to_like_with_percent_wraps() {
        let t = vec![triple("name", "contains", serde_json::json!("ael"))];
        let ast = filter_triples_to_ast(&t).unwrap();
        let (sql, binds) = compile(&schema(&[("name","TEXT")]), &ast).unwrap();
        assert_eq!(sql, r#"("name" LIKE ?)"#);
        assert_eq!(binds.len(), 1);
        match &binds[0] {
            rusqlite::types::Value::Text(s) => assert_eq!(s, "%ael%"),
            other => panic!("expected text, got {other:?}"),
        }
    }

    #[test]
    fn starts_with_appends_percent() {
        let t = vec![triple("name", "starts_with", serde_json::json!("Ka"))];
        let ast = filter_triples_to_ast(&t).unwrap();
        let (_, binds) = compile(&schema(&[("name","TEXT")]), &ast).unwrap();
        match &binds[0] {
            rusqlite::types::Value::Text(s) => assert_eq!(s, "Ka%"),
            other => panic!("expected text, got {other:?}"),
        }
    }

    #[test]
    fn between_expands_to_gte_and_lte() {
        let t = vec![triple("age", "between", serde_json::json!([10, 20]))];
        let ast = filter_triples_to_ast(&t).unwrap();
        let (sql, binds) = compile(&schema(&[("age","INTEGER")]), &ast).unwrap();
        assert_eq!(sql, r#"(("age" >= ? AND "age" <= ?))"#);
        assert_eq!(binds.len(), 2);
    }

    #[test]
    fn is_true_becomes_eq_1() {
        let t = vec![triple("active", "is_true", serde_json::json!(true))];
        let ast = filter_triples_to_ast(&t).unwrap();
        let (sql, binds) = compile(&schema(&[("active","INTEGER")]), &ast).unwrap();
        assert_eq!(sql, r#"("active" = ?)"#);
        assert!(matches!(binds[0], rusqlite::types::Value::Integer(1)));
    }

    #[test]
    fn is_null_passes_through() {
        let t = vec![triple("note", "is_null", serde_json::json!(true))];
        let ast = filter_triples_to_ast(&t).unwrap();
        let (sql, binds) = compile(&schema(&[("note","TEXT")]), &ast).unwrap();
        assert_eq!(sql, r#"("note" IS NULL)"#);
        assert!(binds.is_empty());
    }

    #[test]
    fn unknown_op_errors() {
        let t = vec![triple("a", "matches_regex", serde_json::json!("x"))];
        let err = filter_triples_to_ast(&t).unwrap_err();
        assert!(err.contains("unknown op"));
    }

    #[test]
    fn multiple_triples_andd_together() {
        let t = vec![
            triple("a", "eq", serde_json::json!(1)),
            triple("b", "gt", serde_json::json!(2)),
        ];
        let ast = filter_triples_to_ast(&t).unwrap();
        match ast {
            FilterAst::And { and } => assert_eq!(and.len(), 2),
            _ => panic!("expected And"),
        }
    }
}
