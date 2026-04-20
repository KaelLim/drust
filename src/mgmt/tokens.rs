use crate::auth::bearer::{generate_token, hash_token};
use crate::mgmt::tenants::TenantsState;
use askama::Template;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::{Form, Json};
use serde::{Deserialize, Serialize};

#[derive(Template)]
#[template(path = "tenant_detail.html")]
struct DetailPage {
    tenant_id: String,
    tenant_name: String,
    created_at: String,
    tokens: Vec<TokenRow>,
    new_token: Option<String>,
}

struct TokenRow {
    id: i64,
    label: String,
    created_at: String,
    revoked_at: String,
}

#[derive(Debug, Deserialize, Default)]
pub struct IssueBody {
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct IssueResp {
    pub id: i64,
    pub token: String,
    pub label: Option<String>,
    pub created_at: String,
}

pub async fn issue_token_json(
    State(state): State<TenantsState>,
    Path(tenant_id): Path<String>,
    Json(body): Json<IssueBody>,
) -> Response {
    let conn = state.session.meta.lock().await;
    let exists: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM tenants WHERE id = ?1 AND deleted_at IS NULL",
            rusqlite::params![tenant_id],
            |r| r.get(0),
        )
        .unwrap_or(0);
    if exists == 0 {
        return (StatusCode::NOT_FOUND, "no such tenant").into_response();
    }
    let plaintext = generate_token();
    let hash = hash_token(&plaintext);
    conn.execute(
        "INSERT INTO tokens (tenant_id, token_hash, label) VALUES (?1, ?2, ?3)",
        rusqlite::params![tenant_id, hash, body.label],
    )
    .unwrap();
    let id = conn.last_insert_rowid();
    let created: String = conn
        .query_row(
            "SELECT created_at FROM tokens WHERE id = ?1",
            rusqlite::params![id],
            |r| r.get(0),
        )
        .unwrap_or_default();
    (
        StatusCode::CREATED,
        Json(IssueResp { id, token: plaintext, label: body.label, created_at: created }),
    )
        .into_response()
}

pub async fn revoke_token(
    State(state): State<TenantsState>,
    Path((tenant_id, token_id)): Path<(String, i64)>,
) -> Response {
    let conn = state.session.meta.lock().await;
    let n = conn
        .execute(
            "UPDATE tokens SET revoked_at = datetime('now') WHERE id = ?1 AND tenant_id = ?2 AND revoked_at IS NULL",
            rusqlite::params![token_id, tenant_id],
        )
        .unwrap_or(0);
    if n == 0 {
        (StatusCode::NOT_FOUND, "no active token with that id").into_response()
    } else {
        StatusCode::NO_CONTENT.into_response()
    }
}

pub async fn issue_token_form(
    State(state): State<TenantsState>,
    Path(tenant_id): Path<String>,
    Form(form): Form<IssueBody>,
) -> Response {
    let resp = issue_token_json(
        State(state.clone()),
        Path(tenant_id.clone()),
        Json(IssueBody { label: form.label }),
    )
    .await;
    // Extract the JSON token for display, then redirect to detail page with it in the query string.
    let status = resp.status();
    if !status.is_success() {
        return resp;
    }
    let body = axum::body::to_bytes(resp.into_body(), 65_536).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let tok = v["token"].as_str().unwrap_or("");
    let url = format!("/admin/tenants/{}?new_token={}", tenant_id, urlencoding::encode(tok));
    Redirect::to(&url).into_response()
}

pub async fn revoke_token_form(
    State(state): State<TenantsState>,
    Path((tenant_id, token_id)): Path<(String, i64)>,
) -> Response {
    let _ = revoke_token(State(state), Path((tenant_id.clone(), token_id))).await;
    Redirect::to(&format!("/admin/tenants/{tenant_id}")).into_response()
}

#[derive(Debug, Deserialize)]
pub struct DetailQs {
    #[serde(default)]
    pub new_token: Option<String>,
}

pub async fn detail_page(
    State(state): State<TenantsState>,
    Path(tenant_id): Path<String>,
    Query(qs): Query<DetailQs>,
) -> Response {
    let conn = state.session.meta.lock().await;
    let meta: Option<(String, String)> = conn
        .query_row(
            "SELECT name, created_at FROM tenants WHERE id = ?1 AND deleted_at IS NULL",
            rusqlite::params![tenant_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .ok();
    let (name, created) = match meta {
        Some(m) => m,
        None => return (StatusCode::NOT_FOUND, "tenant not found").into_response(),
    };
    let mut stmt = conn
        .prepare(
            "SELECT id, COALESCE(label, '-'), created_at, COALESCE(revoked_at, '-')
             FROM tokens WHERE tenant_id = ?1 ORDER BY id DESC",
        )
        .unwrap();
    let tokens: Vec<TokenRow> = stmt
        .query_map(rusqlite::params![tenant_id], |r| {
            Ok(TokenRow {
                id: r.get(0)?,
                label: r.get(1)?,
                created_at: r.get(2)?,
                revoked_at: r.get(3)?,
            })
        })
        .unwrap()
        .filter_map(Result::ok)
        .collect();
    Html(
        DetailPage {
            tenant_id: tenant_id.clone(),
            tenant_name: name,
            created_at: created,
            tokens,
            new_token: qs.new_token,
        }
        .render()
        .unwrap(),
    )
    .into_response()
}
