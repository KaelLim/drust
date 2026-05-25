use crate::mgmt::i18n::{LocaleHint, Translator};
use crate::mgmt::tenants::TenantsState;
use crate::query::authorizer::{attach_readonly_authorizer, detach_authorizer};
use crate::query::executor::{execute_read_query, execute_read_query_admin};
use crate::query::filter::{ListParams, SortDir, build_count_sql, build_list_sql, parse_sort};
use crate::storage::schema::{
    Collection, CollectionSchema, Field, IndexInfo, describe_collection, list_collections,
};
use crate::storage::tenant_db::open_read;
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
    tenant_name: String,
    version: &'static str,
    t: Translator,
    palette_resolved: crate::mgmt::theme::ResolvedPalette,
    mascot_json_static: String,
    mascot_json_light: String,
    mascot_json_dark: String,
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
    /// Per-field rows enriched with `is_indexed`; consumed only by the
    /// schema tab to render PK / FK / IDX badge-mini chips. Built from
    /// `fields` × `indices` in the handler so the template can stay
    /// presentation-only.
    fields_with_badges: Vec<FieldRow>,
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
    /// `"rows"` (default) | `"schema"` | `"indexes"` | `"anon"` | `"realtime"` | `"explain"`.
    /// The legacy `"data"` value is mapped to `"rows"` for back-compat with
    /// bookmarks from before v1.14.
    active_tab: String,
    /// Pre-built tab anchors. Only the rows URL preserves filter/sort/page
    /// (the other tabs ignore those params); each non-rows URL is
    /// the canonical collection URL plus `?tab=<name>`.
    tab_rows_url: String,
    tab_schema_url: String,
    tab_indexes_url: String,
    tab_anon_url: String,
    tab_realtime_url: String,
    tab_explain_url: String,
    /// Pairs of `(verb, currently_enabled)` for the four DML verbs in
    /// canonical order. Drives the checkbox row in the Anon tab editor.
    anon_cap_choices: Vec<(&'static str, bool)>,
    /// v1.16 — whether SSE broadcast is enabled for this collection. Drives
    /// the Realtime tab's single toggle.
    realtime_enabled: bool,
    /// Index list for the Indexes tab.
    indices: Vec<IndexInfo>,
    /// v1.19 — collection-level description for the description tile.
    collection_description: Option<String>,
    /// v1.19.1 — error code surfaced when the description form bounced off
    /// the server-side validator. `None` on the plain GET render.
    desc_error: Option<String>,
    version: &'static str,
    t: Translator,
    palette_resolved: crate::mgmt::theme::ResolvedPalette,
    mascot_json_static: String,
    mascot_json_light: String,
    mascot_json_dark: String,
}

/// Field row enriched with badge flags, consumed by the schema tab.
/// `is_indexed` is set when the field name appears in any explicit
/// index on this collection (PK columns surface via `pk` instead, so
/// `is_indexed` is only useful when the field is *also* covered by a
/// non-PK explicit index — the template hides IDX when `pk` is true).
struct FieldRow {
    name: String,
    sql_type: String,
    nullable: bool,
    pk: bool,
    foreign_key: Option<String>,
    default_value: Option<String>,
    is_indexed: bool,
    /// v1.19 — per-field description, threaded from `Field::description`.
    description: Option<String>,
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
    /// v1.19.1 — surfaced after a server-side description validator failure
    /// (e.g. NUL byte slipped past the JS hint). Rendered as an inline
    /// error banner on the schema/indexes tab.
    #[serde(default)]
    pub desc_error: Option<String>,
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
    LocaleHint(locale): LocaleHint,
    crate::mgmt::theme::ThemeHint(theme): crate::mgmt::theme::ThemeHint,
    Path(tenant_id): Path<String>,
) -> Response {
    let meta = state.session.meta.lock().await;
    if !tenant_active(&meta, &tenant_id) {
        return (StatusCode::NOT_FOUND, "no such tenant").into_response();
    }
    let tenant_name = tenant_name_lookup(&meta, &tenant_id).unwrap_or_else(|| tenant_id.clone());
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

    let trc = crate::mgmt::theme::ThemeRenderCtx::build(theme);
    Html(
        CollectionsPage {
            tenant_id,
            tenant_name,
            version: env!("CARGO_PKG_VERSION"),
            t: Translator::new(locale),
            palette_resolved: trc.palette_resolved,
            mascot_json_static: trc.mascot_json_static,
            mascot_json_light: trc.mascot_json_light,
            mascot_json_dark: trc.mascot_json_dark,
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

/// Replace cell values in columns that should never appear in HTML
/// (e.g. password hashes). Returns the column names unchanged and the
/// masked rows. When there are no sensitive columns for the given
/// collection name this is a zero-cost passthrough.
pub(crate) fn mask_sensitive_columns(
    coll: &str,
    column_names: Vec<String>,
    rows: Vec<Vec<String>>,
) -> (Vec<String>, Vec<Vec<String>>) {
    let mask_cols: &[&str] = match coll {
        "_system_users" => &["password_hash"],
        _ => &[],
    };
    if mask_cols.is_empty() {
        return (column_names, rows);
    }
    let masked_idxs: Vec<usize> = column_names
        .iter()
        .enumerate()
        .filter(|(_, n)| mask_cols.contains(&n.as_str()))
        .map(|(i, _)| i)
        .collect();
    if masked_idxs.is_empty() {
        return (column_names, rows);
    }
    let masked_rows = rows
        .into_iter()
        .map(|row| {
            row.into_iter()
                .enumerate()
                .map(|(i, v)| {
                    if masked_idxs.contains(&i) {
                        "\u{25cf}\u{25cf}\u{25cf}\u{25cf}".to_string()
                    } else {
                        v
                    }
                })
                .collect()
        })
        .collect();
    (column_names, masked_rows)
}

pub async fn collection_rows_page(
    State(state): State<TenantsState>,
    LocaleHint(locale): LocaleHint,
    crate::mgmt::theme::ThemeHint(theme): crate::mgmt::theme::ThemeHint,
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
        Some("indexes") => "indexes".to_string(),
        Some("anon") => "anon".to_string(),
        Some("realtime") => "realtime".to_string(),
        Some("explain") => "explain".to_string(),
        // `"data"` is the pre-v1.14 alias for `"rows"`. Anything else
        // (None, unknown) defaults to rows.
        _ => "rows".to_string(),
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
        owner_filter: None, // admin browse has no row-level owner filter
    };

    let list_sql = build_list_sql(&coll_name, &params);
    let count_sql = build_count_sql(
        &coll_name,
        if filter_val.is_empty() {
            None
        } else {
            Some(filter_val.as_str())
        },
        None,
    );

    let mut error: Option<String> = None;

    // Admin UI is allowed to browse _system_* tables (e.g. _system_users). The
    // read-only authorizer would block them, so bypass it for protected names —
    // the connection is still SQLITE_OPEN_READONLY, so writes are impossible.
    let rows_result = if crate::storage::schema::is_protected_collection(&coll_name) {
        execute_read_query_admin(&conn, &list_sql, per_page as usize, 32_768)
    } else {
        execute_read_query(&conn, &list_sql, per_page as usize, 32_768)
    };
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

    // Mask sensitive columns so secrets never appear in the HTML response.
    // Currently only _system_users.password_hash — the argon2 PHC string
    // is security-irrelevant to display but could leak into logs/screenshots.
    let (column_names, rows) = mask_sensitive_columns(&coll_name, column_names, rows);

    // Count uses raw query_row. Skip the authorizer for protected system
    // tables (admin-only route; connection is still SQLITE_OPEN_READONLY).
    let total: i64 = {
        if !crate::storage::schema::is_protected_collection(&coll_name) {
            attach_readonly_authorizer(&conn);
        }
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

    // Build the five tab anchors. Only the rows link preserves
    // filter/sort/page state — the schema, indexes, anon, and explain
    // tabs ignore those params, so their URLs are kept clean.
    let tab_rows_url =
        build_page_url(&tenant_id, &coll_name, page, per_page, &filter_val, &sort_val);
    let coll_base = format!(
        "/drust/admin/tenants/{}/collections/{}",
        tenant_id, coll_name
    );
    let tab_schema_url = format!("{coll_base}?tab=schema");
    let tab_indexes_url = format!("{coll_base}?tab=indexes");
    let tab_anon_url = format!("{coll_base}?tab=anon");
    let tab_realtime_url = format!("{coll_base}?tab=realtime");
    let tab_explain_url = format!("{coll_base}?tab=explain");
    // v1.16 — pull the current SSE broadcast flag off the same schema row
    // we already loaded above. `describe_collection` falls back to true
    // when no `_system_collection_meta` row exists yet.
    let realtime_enabled = schema.realtime_enabled;

    // Cross-reference indices to mark fields that participate in any
    // explicit index. Used by the schema tab to render an IDX badge.
    let indexed_fields: std::collections::HashSet<String> = schema
        .indices
        .iter()
        .flat_map(|idx| idx.fields.iter().cloned())
        .collect();
    let fields_with_badges: Vec<FieldRow> = schema
        .fields
        .iter()
        .map(|f| FieldRow {
            name: f.name.clone(),
            sql_type: f.sql_type.clone(),
            nullable: f.nullable,
            pk: f.pk,
            foreign_key: f.foreign_key.clone(),
            default_value: f.default_value.clone(),
            is_indexed: indexed_fields.contains(&f.name),
            description: f.description.clone(),
        })
        .collect();

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

    let trc = crate::mgmt::theme::ThemeRenderCtx::build(theme);
    Html(
        RowsPage {
            tenant_id,
            tenant_name,
            active_coll: coll_name.clone(),
            coll_name,
            collections,
            fields: schema.fields,
            fields_with_badges,
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
            tab_rows_url,
            tab_schema_url,
            tab_indexes_url,
            tab_anon_url,
            tab_realtime_url,
            tab_explain_url,
            anon_cap_choices,
            realtime_enabled,
            collection_description: schema.description,
            desc_error: qs.desc_error.clone(),
            version: env!("CARGO_PKG_VERSION"),
            t: Translator::new(locale),
            palette_resolved: trc.palette_resolved,
            mascot_json_static: trc.mascot_json_static,
            mascot_json_light: trc.mascot_json_light,
            mascot_json_dark: trc.mascot_json_dark,
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
    let pool = match state.tenants.get_or_open(&tenant_id) {
        Ok(p) => p,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let coll_for_writer = coll_name.clone();
    let caps_for_writer = caps.clone();
    if let Err(e) = pool
        .with_writer(move |c| write_anon_caps(c, &coll_for_writer, &caps_for_writer))
        .await
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }

    // Invalidate the per-tenant schema cache for this collection so the
    // next REST/MCP request through the tenant router sees the new gate
    // immediately, not after the next DDL or process restart.
    pool.schema_cache.invalidate(&coll_name);

    Redirect::to(&format!(
        "/drust/admin/tenants/{tenant_id}/collections/{coll_name}?tab=schema"
    ))
    .into_response()
}

/// Form payload for the Realtime tab toggle.
///
/// Browser checkbox semantics: a checked box submits `enabled=1`; an
/// unchecked box omits the field entirely. We map "field present" → on,
/// "field absent" → off.
#[derive(serde::Deserialize)]
pub struct RealtimeForm {
    #[serde(default)]
    pub enabled: Option<String>,
}

/// POST `/admin/tenants/{tenant}/collections/{coll}/realtime`.
///
/// Form submit from the Realtime tab. Flips the flag, invalidates the
/// schema cache, and evicts the broadcast channel on disable so any
/// in-flight SSE connection terminates immediately.
pub async fn update_realtime(
    State(state): State<TenantsState>,
    Path((tenant_id, coll_name)): Path<(String, String)>,
    axum_extra::extract::Form(form): axum_extra::extract::Form<RealtimeForm>,
) -> Response {
    let meta = state.session.meta.lock().await;
    if !tenant_active(&meta, &tenant_id) {
        return (StatusCode::NOT_FOUND, "no such tenant").into_response();
    }
    drop(meta);

    let enabled = form.enabled.is_some();
    let pool = match state.tenants.get_or_open(&tenant_id) {
        Ok(p) => p,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let coll_for_writer = coll_name.clone();
    if let Err(e) = pool
        .with_writer(move |c| {
            crate::storage::schema::write_realtime_enabled(c, &coll_for_writer, enabled)
        })
        .await
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }

    // Cache invalidate BEFORE bus evict — mirrors the REST handler's
    // ordering so any subscriber racing in between reads fresh schema.
    pool.schema_cache.invalidate(&coll_name);
    if !enabled {
        state.bus.evict_collection(&tenant_id, &coll_name);
    }
    Redirect::to(&format!(
        "/drust/admin/tenants/{tenant_id}/collections/{coll_name}?tab=realtime"
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
    match crate::mcp::tools::index::create_index_with_threshold(
        &pool,
        &coll_name,
        &body.fields,
        body.unique.unwrap_or(false),
        body.force.unwrap_or(false),
        state.index_large_table_rows,
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

// ── Description admin POST endpoints (v1.19) ─────────────────────────────────
// Three form-POST routes that proxy to the write_*_description helpers.
// Auth shape is identical to update_anon_caps (same session middleware wraps
// all /admin/tenants/* routes — no explicit extractor needed).

/// Shared form body for the three description endpoints.
#[derive(serde::Deserialize)]
pub struct DescriptionForm {
    #[serde(default)]
    pub description: String,
}

/// POST `/admin/tenants/{id}/collections/{coll}/description`
pub async fn admin_update_collection_description(
    State(state): State<TenantsState>,
    Path((tenant_id, coll_name)): Path<(String, String)>,
    axum::extract::Form(form): axum::extract::Form<DescriptionForm>,
) -> Response {
    use crate::storage::schema::{
        check_description, collection_exists, is_protected_collection,
        write_collection_description,
    };
    let meta = state.session.meta.lock().await;
    if !tenant_active(&meta, &tenant_id) {
        return (StatusCode::NOT_FOUND, "no such tenant").into_response();
    }
    drop(meta);

    if is_protected_collection(&coll_name) {
        return (StatusCode::FORBIDDEN, "cannot set description on a _system_* collection").into_response();
    }

    let validated = match check_description(&form.description) {
        Ok(v) => v,
        Err((code, _)) => {
            return Redirect::to(&format!(
                "/drust/admin/tenants/{tenant_id}/collections/{coll_name}?tab=schema&desc_error={code}"
            ))
            .into_response();
        }
    };
    let value: Option<String> = if validated.is_empty() { None } else { Some(validated) };

    let pool = match state.tenants.get_or_open(&tenant_id) {
        Ok(p) => p,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    // Existence check before any write.
    let coll_for_check = coll_name.clone();
    let exists = match pool
        .with_reader(move |c| collection_exists(c, &coll_for_check))
        .await
    {
        Ok(b) => b,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    if !exists {
        return (StatusCode::NOT_FOUND, "no such collection").into_response();
    }

    let coll_for_writer = coll_name.clone();
    let value_for_writer = value.clone();
    if let Err(e) = pool
        .with_writer(move |c| {
            write_collection_description(c, &coll_for_writer, value_for_writer.as_deref())
        })
        .await
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }

    pool.schema_cache.invalidate(&coll_name);

    Redirect::to(&format!(
        "/drust/admin/tenants/{tenant_id}/collections/{coll_name}?tab=schema"
    ))
    .into_response()
}

/// POST `/admin/tenants/{id}/collections/{coll}/fields/{field}/description`
pub async fn admin_update_field_description(
    State(state): State<TenantsState>,
    Path((tenant_id, coll_name, field_name)): Path<(String, String, String)>,
    axum::extract::Form(form): axum::extract::Form<DescriptionForm>,
) -> Response {
    use crate::storage::schema::{
        check_description, describe_collection, is_protected_collection,
        write_field_description,
    };
    let meta = state.session.meta.lock().await;
    if !tenant_active(&meta, &tenant_id) {
        return (StatusCode::NOT_FOUND, "no such tenant").into_response();
    }
    drop(meta);

    if is_protected_collection(&coll_name) {
        return (StatusCode::FORBIDDEN, "cannot set description on a _system_* collection").into_response();
    }

    let validated = match check_description(&form.description) {
        Ok(v) => v,
        Err((code, _)) => {
            return Redirect::to(&format!(
                "/drust/admin/tenants/{tenant_id}/collections/{coll_name}?tab=schema&desc_error={code}"
            ))
            .into_response();
        }
    };
    let value: Option<String> = if validated.is_empty() { None } else { Some(validated) };

    let pool = match state.tenants.get_or_open(&tenant_id) {
        Ok(p) => p,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    // Existence: collection + field both must exist.
    let coll_for_check = coll_name.clone();
    let cs = match pool
        .with_reader(move |c| describe_collection(c, &coll_for_check))
        .await
    {
        Ok(Some(c)) => c,
        Ok(None) => return (StatusCode::NOT_FOUND, "no such collection").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    if !cs.fields.iter().any(|f| f.name == field_name) {
        return (StatusCode::NOT_FOUND, "no such field").into_response();
    }

    let coll_for_writer = coll_name.clone();
    let field_for_writer = field_name.clone();
    let value_for_writer = value.clone();
    if let Err(e) = pool
        .with_writer(move |c| {
            write_field_description(c, &coll_for_writer, &field_for_writer, value_for_writer.as_deref())
        })
        .await
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }

    pool.schema_cache.invalidate(&coll_name);

    Redirect::to(&format!(
        "/drust/admin/tenants/{tenant_id}/collections/{coll_name}?tab=schema"
    ))
    .into_response()
}

/// POST `/admin/tenants/{id}/collections/{coll}/indexes/{index_name}/description`
pub async fn admin_update_index_description(
    State(state): State<TenantsState>,
    Path((tenant_id, coll_name, index_name)): Path<(String, String, String)>,
    axum::extract::Form(form): axum::extract::Form<DescriptionForm>,
) -> Response {
    use crate::storage::schema::{
        check_description, describe_collection, is_protected_collection,
        write_index_description,
    };
    let meta = state.session.meta.lock().await;
    if !tenant_active(&meta, &tenant_id) {
        return (StatusCode::NOT_FOUND, "no such tenant").into_response();
    }
    drop(meta);

    if is_protected_collection(&coll_name) {
        return (StatusCode::FORBIDDEN, "cannot set description on a _system_* collection").into_response();
    }

    let validated = match check_description(&form.description) {
        Ok(v) => v,
        Err((code, _)) => {
            return Redirect::to(&format!(
                "/drust/admin/tenants/{tenant_id}/collections/{coll_name}?tab=indexes&desc_error={code}"
            ))
            .into_response();
        }
    };
    let value: Option<String> = if validated.is_empty() { None } else { Some(validated) };

    let pool = match state.tenants.get_or_open(&tenant_id) {
        Ok(p) => p,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    // Existence: collection + index both must exist.
    let coll_for_check = coll_name.clone();
    let cs = match pool
        .with_reader(move |c| describe_collection(c, &coll_for_check))
        .await
    {
        Ok(Some(c)) => c,
        Ok(None) => return (StatusCode::NOT_FOUND, "no such collection").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    if !cs.indices.iter().any(|i| i.name == index_name) {
        return (StatusCode::NOT_FOUND, "no such index").into_response();
    }

    let coll_for_writer = coll_name.clone();
    let idx_for_writer = index_name.clone();
    let value_for_writer = value.clone();
    if let Err(e) = pool
        .with_writer(move |c| {
            write_index_description(c, &coll_for_writer, &idx_for_writer, value_for_writer.as_deref())
        })
        .await
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }

    pool.schema_cache.invalidate(&coll_name);

    Redirect::to(&format!(
        "/drust/admin/tenants/{tenant_id}/collections/{coll_name}?tab=indexes"
    ))
    .into_response()
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
