use crate::mgmt::tenants::TenantsState;
use crate::storage::schema::{Collection, CollectionSchema, Field, describe_collection, list_collections};
use crate::storage::tenant_db::open_read;
use askama::Template;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};

#[derive(Template)]
#[template(path = "collections.html")]
struct CollectionsPage {
    tenant_id: String,
    collections: Vec<Collection>,
}

#[derive(Template)]
#[template(path = "collection_rows.html")]
struct RowsPage {
    tenant_id: String,
    coll_name: String,
    fields: Vec<Field>,
    column_names: Vec<String>,
    rows: Vec<Vec<String>>,
    total_rows: i64,
    shown_rows: usize,
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
    Html(CollectionsPage { tenant_id, collections }.render().unwrap()).into_response()
}

fn value_to_display(v: rusqlite::types::ValueRef<'_>) -> String {
    match v {
        rusqlite::types::ValueRef::Null => "NULL".into(),
        rusqlite::types::ValueRef::Integer(i) => i.to_string(),
        rusqlite::types::ValueRef::Real(f) => format!("{f}"),
        rusqlite::types::ValueRef::Text(t) => String::from_utf8_lossy(t).into_owned(),
        rusqlite::types::ValueRef::Blob(b) => format!("<blob {} bytes>", b.len()),
    }
}

pub async fn collection_rows_page(
    State(state): State<TenantsState>,
    Path((tenant_id, coll_name)): Path<(String, String)>,
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

    let schema: CollectionSchema = match describe_collection(&conn, &coll_name) {
        Ok(Some(s)) => s,
        Ok(None) => return (StatusCode::NOT_FOUND, "collection not found").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    let quoted = format!("\"{}\"", coll_name.replace('"', "\"\""));
    let sql = format!("SELECT * FROM {quoted} ORDER BY id DESC LIMIT 100");
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let column_names: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
    let col_count = column_names.len();

    let rows: Vec<Vec<String>> = match stmt.query_map([], |r| {
        let mut out = Vec::with_capacity(col_count);
        for i in 0..col_count {
            out.push(value_to_display(r.get_ref(i)?));
        }
        Ok(out)
    }) {
        Ok(iter) => iter.filter_map(Result::ok).collect(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    Html(
        RowsPage {
            tenant_id,
            coll_name,
            fields: schema.fields,
            column_names,
            rows: rows.clone(),
            total_rows: schema.row_count,
            shown_rows: rows.len(),
        }
        .render()
        .unwrap(),
    )
    .into_response()
}
