use crate::mgmt::tenants::TenantsState;
use crate::query::authorizer::{attach_readonly_authorizer, detach_authorizer};
use crate::query::executor::execute_read_query;
use crate::query::filter::{ListParams, SortDir, build_count_sql, build_list_sql, parse_sort};
use crate::storage::schema::{
    Collection, CollectionSchema, Field, IndexInfo, describe_collection, list_collections,
};
use crate::storage::tenant_db::{open_read, open_write};
use askama::Template;
use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use serde::Deserialize;

#[derive(Template)]
#[template(path = "collections.html")]
struct CollectionsPage {
    tenant_id: String,
    version: &'static str,
}

#[derive(Template)]
#[template(path = "collection_rows.html")]
struct RowsPage {
    tenant_id: String,
    tenant_name: String,
    coll_name: String,
    active_coll: String,
    collections: Vec<Collection>,
    fields: Vec<Field>,
    column_names: Vec<String>,
    rows: Vec<Vec<String>>,
    total_rows: i64,
    page: u32,
    total_pages: u32,
    prev_url: Option<String>,
    next_url: Option<String>,
    filter_val: String,
    sort_options: Vec<SortOption>,
    per_page_options: Vec<PerPageOption>,
    error: Option<String>,
    /// Either `"data"` (default) or `"schema"`. Toggled by `?tab=…`.
    active_tab: String,
    /// Pre-built href for the Data tab — preserves filter/sort/per_page/page
    /// so switching tabs doesn't lose the user's query state.
    tab_data_url: String,
    /// Pre-built href for the Schema tab — strips data-only params (filter,
    /// sort, per_page, page) since they're meaningless in schema view.
    tab_schema_url: String,
    /// Pairs of `(verb, currently_enabled)` for the four DML verbs in
    /// canonical order. Drives the checkbox row in the Schema tab editor.
    anon_cap_choices: Vec<(&'static str, bool)>,
    /// Index list for the Schema tab's Indexes section.
    indices: Vec<IndexInfo>,
    version: &'static str,
}

struct SortOption {
    value: String,
    label: String,
    selected: bool,
}

struct PerPageOption {
    value: u32,
    selected: bool,
}

#[derive(Debug, Deserialize, Default)]
pub struct BrowseQs {
    #[serde(default)]
    pub filter: Option<String>,
    #[serde(default)]
    pub sort: Option<String>,
    #[serde(default)]
    pub page: Option<u32>,
    #[serde(default)]
    pub per_page: Option<u32>,
    /// `data` (default) or `schema`. Anything else falls back to `data`.
    #[serde(default)]
    pub tab: Option<String>,
}

fn tenant_active(conn: &rusqlite::Connection, tenant_id: &str) -> bool {
    conn.query_row(
        "SELECT COUNT(*) FROM tenants WHERE id = ?1 AND deleted_at IS NULL",
        rusqlite::params![tenant_id],
        |r| r.get::<_, i64>(0),
    )
    .map(|n| n > 0)
    .unwrap_or(false)
}

fn tenant_name_lookup(conn: &rusqlite::Connection, tenant_id: &str) -> Option<String> {
    conn.query_row(
        "SELECT name FROM tenants WHERE id = ?1 AND deleted_at IS NULL",
        rusqlite::params![tenant_id],
        |r| r.get::<_, String>(0),
    )
    .ok()
}

pub async fn collections_page(
    State(state): State<TenantsState>,
    Path(tenant_id): Path<String>,
) -> Response {
    let meta = state.session.meta.lock().await;
    if !tenant_active(&meta, &tenant_id) {
        return (StatusCode::NOT_FOUND, "no such tenant").into_response();
    }
    drop(meta);

    let conn = match open_read(&state.data_dir, &tenant_id) {
        Ok(c) => c,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let collections = match list_collections(&conn) {
        Ok(v) => v,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    if let Some(first) = collections.first() {
        let to = format!(
            "/drust/admin/tenants/{}/collections/{}",
            tenant_id, first.name
        );
        return Redirect::to(&to).into_response();
    }

    Html(
        CollectionsPage {
            tenant_id,
            version: env!("CARGO_PKG_VERSION"),
        }
        .render()
        .unwrap(),
    )
    .into_response()
}

fn build_page_url(
    tenant: &str,
    coll: &str,
    page: u32,
    per_page: u32,
    filter: &str,
    sort: &str,
) -> String {
    let mut parts: Vec<String> = vec![format!("page={page}"), format!("per_page={per_page}")];
    if !filter.is_empty() {
        parts.push(format!("filter={}", urlencoding::encode(filter)));
    }
    if !sort.is_empty() {
        parts.push(format!("sort={}", urlencoding::encode(sort)));
    }
    format!(
        "/drust/admin/tenants/{tenant}/collections/{coll}?{}",
        parts.join("&")
    )
}

pub async fn collection_rows_page(
    State(state): State<TenantsState>,
    Path((tenant_id, coll_name)): Path<(String, String)>,
    Query(qs): Query<BrowseQs>,
) -> Response {
    let meta = state.session.meta.lock().await;
    let tenant_name = match tenant_name_lookup(&meta, &tenant_id) {
        Some(n) => n,
        None => return (StatusCode::NOT_FOUND, "no such tenant").into_response(),
    };
    drop(meta);

    let conn = match open_read(&state.data_dir, &tenant_id) {
        Ok(c) => c,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    let schema: CollectionSchema = match describe_collection(&conn, &coll_name) {
        Ok(Some(s)) => s,
        Ok(None) => return (StatusCode::NOT_FOUND, "collection not found").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    let collections = match list_collections(&conn) {
        Ok(v) => v,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    let filter_val = qs.filter.clone().unwrap_or_default();
    let sort_val = qs.sort.clone().unwrap_or_default();
    let per_page = qs.per_page.unwrap_or(20).clamp(1, 500);
    let page = qs.page.unwrap_or(1).max(1);
    let active_tab = match qs.tab.as_deref() {
        Some("schema") => "schema".to_string(),
        _ => "data".to_string(),
    };

    let (sort_field, sort_dir) = if sort_val.is_empty() {
        ("id".to_string(), SortDir::Desc)
    } else {
        parse_sort(&sort_val)
    };
    let params = ListParams {
        filter: if filter_val.is_empty() {
            None
        } else {
            Some(filter_val.clone())
        },
        sort_field,
        sort_dir,
        page,
        per_page,
    };

    let list_sql = build_list_sql(&coll_name, &params);
    let count_sql = build_count_sql(
        &coll_name,
        if filter_val.is_empty() {
            None
        } else {
            Some(filter_val.as_str())
        },
    );

    let mut error: Option<String> = None;

    let rows_result = execute_read_query(&conn, &list_sql, per_page as usize, 32_768);
    let (column_names, rows): (Vec<String>, Vec<Vec<String>>) = match rows_result {
        Ok(qr) => {
            let cols = qr.column_names.clone();
            let stringified: Vec<Vec<String>> = qr
                .rows
                .into_iter()
                .map(|row| {
                    row.into_iter()
                        .map(|v| match v {
                            serde_json::Value::Null => "NULL".to_string(),
                            serde_json::Value::String(s) => s,
                            other => other.to_string(),
                        })
                        .collect()
                })
                .collect();
            (cols, stringified)
        }
        Err(e) => {
            error = Some(format!(
                "filter/sort 解析失敗：{}（常見原因：欄位名打錯、引號沒配、SQL 片段被 authorizer 擋）",
                e
            ));
            (
                schema.fields.iter().map(|f| f.name.clone()).collect(),
                vec![],
            )
        }
    };

    // Count uses raw query_row with scoped authorizer
    let total: i64 = {
        attach_readonly_authorizer(&conn);
        let r = conn
            .query_row(&count_sql, [], |r| r.get::<_, i64>(0))
            .unwrap_or(schema.row_count);
        detach_authorizer(&conn);
        r
    };

    let total_pages = if total == 0 {
        1
    } else {
        (total as u64).div_ceil(per_page as u64) as u32
    };
    let prev_url = if page > 1 {
        Some(build_page_url(
            &tenant_id,
            &coll_name,
            page - 1,
            per_page,
            &filter_val,
            &sort_val,
        ))
    } else {
        None
    };
    let next_url = if page < total_pages {
        Some(build_page_url(
            &tenant_id,
            &coll_name,
            page + 1,
            per_page,
            &filter_val,
            &sort_val,
        ))
    } else {
        None
    };

    let mut sort_options: Vec<SortOption> = Vec::with_capacity(schema.fields.len() * 2);
    for f in &schema.fields {
        let desc_value = format!("-{}", f.name);
        sort_options.push(SortOption {
            value: f.name.clone(),
            label: format!("{} ↑", f.name),
            selected: sort_val == f.name,
        });
        sort_options.push(SortOption {
            value: desc_value.clone(),
            label: format!("{} ↓", f.name),
            selected: sort_val == desc_value,
        });
    }
    let per_page_options: Vec<PerPageOption> = [20u32, 50, 100, 200, 500]
        .into_iter()
        .map(|v| PerPageOption {
            value: v,
            selected: v == per_page,
        })
        .collect();

    // Build the two tab anchors. The Data link preserves any current
    // filter/sort/page so toggling tabs doesn't lose query state. The
    // Schema link strips data-only params — they're meaningless in
    // schema view and would just clutter the URL.
    let tab_data_url =
        build_page_url(&tenant_id, &coll_name, page, per_page, &filter_val, &sort_val);
    let tab_schema_url = format!(
        "/drust/admin/tenants/{}/collections/{}?tab=schema",
        tenant_id, coll_name
    );

    // Materialise the four DML verbs with their current on/off state so
    // the template can iterate without knowing about `BTreeSet<DmlVerb>`.
    let current_caps = schema.anon_caps.clone();
    let anon_cap_choices: Vec<(&'static str, bool)> = ["select", "insert", "update", "delete"]
        .iter()
        .map(|v| {
            let verb = match *v {
                "select" => crate::storage::schema::DmlVerb::Select,
                "insert" => crate::storage::schema::DmlVerb::Insert,
                "update" => crate::storage::schema::DmlVerb::Update,
                "delete" => crate::storage::schema::DmlVerb::Delete,
                _ => unreachable!(),
            };
            (*v, current_caps.contains(&verb))
        })
        .collect();

    Html(
        RowsPage {
            tenant_id,
            tenant_name,
            active_coll: coll_name.clone(),
            coll_name,
            collections,
            fields: schema.fields,
            indices: schema.indices,
            column_names,
            rows,
            total_rows: total,
            page,
            total_pages,
            prev_url,
            next_url,
            filter_val,
            sort_options,
            per_page_options,
            error,
            active_tab,
            tab_data_url,
            tab_schema_url,
            anon_cap_choices,
            version: env!("CARGO_PKG_VERSION"),
        }
        .render()
        .unwrap(),
    )
    .into_response()
}

/// Form payload for the anon_caps editor on the Schema tab. Empty
/// `caps` means "lock the collection" (anon role gets nothing).
#[derive(serde::Deserialize)]
pub struct AnonCapsForm {
    #[serde(default)]
    pub caps: Vec<String>,
}

/// POST `/admin/tenants/{tenant}/collections/{coll}/anon-caps`.
///
/// Writes the new capability set to `_system_collection_meta` and
/// invalidates the in-process schema cache for the collection so the
/// next REST/MCP request re-reads from SQLite. Unknown verb strings in
/// the form are silently dropped — the UI only ever submits the four
/// canonical names.
pub async fn update_anon_caps(
    State(state): State<TenantsState>,
    Path((tenant_id, coll_name)): Path<(String, String)>,
    // Use axum_extra::Form (serde_html_form) — the stdlib serde_urlencoded
    // backing axum::Form cannot deserialize repeated keys (`caps=select&caps=insert`)
    // into Vec<String>, so the HTML checkbox form would 422 on every submit.
    axum_extra::extract::Form(form): axum_extra::extract::Form<AnonCapsForm>,
) -> Response {
    use crate::storage::schema::{DmlVerb, write_anon_caps};
    let meta = state.session.meta.lock().await;
    if !tenant_active(&meta, &tenant_id) {
        return (StatusCode::NOT_FOUND, "no such tenant").into_response();
    }
    drop(meta);

    let mut caps = std::collections::BTreeSet::new();
    for v in form.caps {
        match v.as_str() {
            "select" => {
                caps.insert(DmlVerb::Select);
            }
            "insert" => {
                caps.insert(DmlVerb::Insert);
            }
            "update" => {
                caps.insert(DmlVerb::Update);
            }
            "delete" => {
                caps.insert(DmlVerb::Delete);
            }
            _ => {}
        }
    }
    let writer = match open_write(&state.data_dir, &tenant_id) {
        Ok(w) => w,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    if let Err(e) = write_anon_caps(&writer, &coll_name, &caps) {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }
    drop(writer);

    // Invalidate the per-tenant schema cache for this collection so the
    // next REST/MCP request through the tenant router sees the new gate
    // immediately, not after the next DDL or process restart.
    if let Ok(pool) = state.tenants.get_or_open(&tenant_id) {
        pool.schema_cache.invalidate(&coll_name);
    }

    Redirect::to(&format!(
        "/drust/admin/tenants/{tenant_id}/collections/{coll_name}?tab=schema"
    ))
    .into_response()
}

// ── Admin index DDL endpoints ─────────────────────────────────────────────────
// These are JSON-returning endpoints called via fetch() from the admin UI
// (Tasks 19/20). They use the same admin-session middleware as all other
// tenants_router routes — no explicit session extractor needed.

#[derive(serde::Deserialize)]
pub struct AdminCreateIndexBody {
    pub fields: Vec<String>,
    #[serde(default)]
    pub unique: Option<bool>,
    #[serde(default)]
    pub force: Option<bool>,
}

/// POST `/admin/tenants/{id}/collections/{coll}/_indexes`
///
/// Create an index on a collection. Returns JSON. Admin-session-protected
/// (via the wrapping `admin_session_layer` on `tenants_router`).
pub async fn create_index_admin(
    State(state): State<TenantsState>,
    Path((tenant_id, coll_name)): Path<(String, String)>,
    Json(body): Json<AdminCreateIndexBody>,
) -> Response {
    let meta = state.session.meta.lock().await;
    if !tenant_active(&meta, &tenant_id) {
        return (StatusCode::NOT_FOUND, "no such tenant").into_response();
    }
    drop(meta);

    let pool = match state.tenants.get_or_open(&tenant_id) {
        Ok(p) => p,
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
        }
    };
    match crate::mcp::tools::index::create_index(
        &pool,
        &coll_name,
        &body.fields,
        body.unique.unwrap_or(false),
        body.force.unwrap_or(false),
    )
    .await
    {
        Ok(v) => (StatusCode::CREATED, axum::Json(v)).into_response(),
        Err(e) => {
            use axum::Json;
            let msg = e.to_string();
            let (status, code) = map_index_admin_error(&msg);
            let body = serde_json::json!({ "error_code": code, "message": msg });
            let mut r = Json(body).into_response();
            *r.status_mut() = status;
            r
        }
    }
}

/// DELETE `/admin/tenants/{id}/collections/{coll}/_indexes/{name}`
///
/// Drop an index by name. Returns JSON.
pub async fn drop_index_admin(
    State(state): State<TenantsState>,
    Path((tenant_id, coll_name, index_name)): Path<(String, String, String)>,
) -> Response {
    let meta = state.session.meta.lock().await;
    if !tenant_active(&meta, &tenant_id) {
        return (StatusCode::NOT_FOUND, "no such tenant").into_response();
    }
    drop(meta);

    let pool = match state.tenants.get_or_open(&tenant_id) {
        Ok(p) => p,
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
        }
    };
    match crate::mcp::tools::index::drop_index(&pool, &coll_name, Some(&index_name), None).await {
        Ok(v) => axum::Json(v).into_response(),
        Err(e) => {
            use axum::Json;
            let msg = e.to_string();
            let (status, code) = map_index_admin_error(&msg);
            let body = serde_json::json!({ "error_code": code, "message": msg });
            let mut r = Json(body).into_response();
            *r.status_mut() = status;
            r
        }
    }
}

/// POST `/admin/tenants/{id}/collections/{coll}/_explain`
///
/// Run `EXPLAIN QUERY PLAN` on a SQL string. Returns JSON `{"plan":[...]}`.
pub async fn explain_admin(
    State(state): State<TenantsState>,
    Path((tenant_id, _coll_name)): Path<(String, String)>,
    Json(body): Json<crate::tenant::query_endpoint::ExplainBody>,
) -> Response {
    let meta = state.session.meta.lock().await;
    if !tenant_active(&meta, &tenant_id) {
        return (StatusCode::NOT_FOUND, "no such tenant").into_response();
    }
    drop(meta);

    let pool = match state.tenants.get_or_open(&tenant_id) {
        Ok(p) => p,
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
        }
    };
    match crate::mcp::tools::index::explain_select(&pool, &body.sql).await {
        Ok(v) => (StatusCode::OK, axum::Json(v)).into_response(),
        Err(e) => {
            use axum::Json;
            let msg = e.to_string();
            let (status, code) = if msg.contains("not authorized")
                || msg.contains("authorizer")
                || msg.contains("prohibited")
            {
                (StatusCode::BAD_REQUEST, "SQL_NOT_ALLOWED")
            } else if msg.contains("syntax") || msg.contains("near") {
                (StatusCode::BAD_REQUEST, "SQL_PARSE_ERROR")
            } else {
                (StatusCode::BAD_REQUEST, "SQL_ERROR")
            };
            let body = serde_json::json!({ "error_code": code, "message": msg });
            let mut r = Json(body).into_response();
            *r.status_mut() = status;
            r
        }
    }
}

fn map_index_admin_error(msg: &str) -> (StatusCode, &'static str) {
    if msg.contains("no such collection") || msg.contains("no such index") {
        (StatusCode::NOT_FOUND, "NOT_FOUND")
    } else if msg.contains("not found on collection") {
        (StatusCode::NOT_FOUND, "FIELD_NOT_FOUND")
    } else if msg.contains("LARGE_TABLE") {
        (StatusCode::CONFLICT, "LARGE_TABLE")
    } else if msg.contains("already exists") {
        (StatusCode::CONFLICT, "INDEX_EXISTS")
    } else if msg.contains("UNIQUE") || msg.contains("unique") {
        (StatusCode::CONFLICT, "UNIQUE_VIOLATION")
    } else if msg.contains("INVALID_PARAMS")
        || msg.contains("must be non-empty")
        || msg.contains("non-empty")
        || msg.contains("duplicate")
    {
        (StatusCode::BAD_REQUEST, "INVALID_PARAMS")
    } else if msg.contains("invalid identifier") {
        (StatusCode::BAD_REQUEST, "INVALID_IDENTIFIER")
    } else {
        (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL")
    }
}
