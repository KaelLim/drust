use crate::auth::bearer::{generate_token, hash_token};
use crate::mgmt::tenants::TenantsState;
use askama::Template;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::{Form, Json};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Template)]
#[template(path = "tenant_detail.html")]
struct DetailPage {
    tenant_id: String,
    tenant_name: String,
    created_at: String,
    anon: Option<TokenSlotInfo>,
    service: Option<TokenSlotInfo>,
    new_token: Option<String>,
    new_token_role: Option<String>,
    version: &'static str,
}

pub struct TokenSlotInfo {
    pub id: i64,
    pub created_at: String,
    /// Count of OTHER currently-active tokens with the same role (>0 means
    /// this tenant was created before the 2-slot model; a reroll will clean
    /// them up).
    pub legacy_siblings: i64,
}

#[derive(Debug, Serialize)]
pub struct RerollResp {
    pub role: String,
    pub token: String,
    pub id: i64,
    pub created_at: String,
    pub revoked_legacy_count: usize,
}

fn validate_role(s: &str) -> Option<&'static str> {
    match s {
        "anon" => Some("anon"),
        "service" => Some("service"),
        _ => None,
    }
}

pub async fn reroll_token_json(
    State(state): State<TenantsState>,
    Path((tenant_id, role)): Path<(String, String)>,
) -> Response {
    let role_str = match validate_role(&role) {
        Some(r) => r,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error_code": "TYPE_MISMATCH",
                    "message": "role must be 'anon' or 'service'"
                })),
            )
                .into_response();
        }
    };
    let mut conn = state.session.meta.lock().await;
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

    let tx = match conn.transaction() {
        Ok(t) => t,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let revoked = tx
        .execute(
            "UPDATE tokens SET revoked_at = datetime('now') \
             WHERE tenant_id = ?1 AND role = ?2 AND revoked_at IS NULL",
            rusqlite::params![tenant_id, role_str],
        )
        .unwrap_or(0);
    let plaintext = generate_token();
    tx.execute(
        "INSERT INTO tokens (tenant_id, token_hash, label, role) VALUES (?1, ?2, 'rotated', ?3)",
        rusqlite::params![tenant_id, hash_token(&plaintext), role_str],
    )
    .unwrap();
    let id = tx.last_insert_rowid();
    tx.commit().unwrap();

    let created: String = conn
        .query_row(
            "SELECT created_at FROM tokens WHERE id = ?1",
            rusqlite::params![id],
            |r| r.get(0),
        )
        .unwrap_or_default();
    (
        StatusCode::CREATED,
        Json(RerollResp {
            role: role_str.to_string(),
            token: plaintext,
            id,
            created_at: created,
            revoked_legacy_count: revoked,
        }),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
pub struct RerollForm {}

pub async fn reroll_token_form(
    State(state): State<TenantsState>,
    Path((tenant_id, role)): Path<(String, String)>,
    Form(_): Form<RerollForm>,
) -> Response {
    let resp = reroll_token_json(
        State(state.clone()),
        Path((tenant_id.clone(), role.clone())),
    )
    .await;
    if !resp.status().is_success() {
        return resp;
    }
    let body = axum::body::to_bytes(resp.into_body(), 65_536)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let tok = v["token"].as_str().unwrap_or("");
    let url = format!(
        "/drust/admin/tenants/{}?new_token={}&new_token_role={}",
        tenant_id,
        urlencoding::encode(tok),
        role,
    );
    Redirect::to(&url).into_response()
}

#[derive(Debug, Deserialize)]
pub struct DetailQs {
    #[serde(default)]
    pub new_token: Option<String>,
    #[serde(default)]
    pub new_token_role: Option<String>,
}

fn read_slot(conn: &rusqlite::Connection, tenant_id: &str, role: &str) -> Option<TokenSlotInfo> {
    let row: Option<(i64, String)> = conn
        .query_row(
            "SELECT id, created_at FROM tokens \
             WHERE tenant_id = ?1 AND role = ?2 AND revoked_at IS NULL \
             ORDER BY created_at DESC LIMIT 1",
            rusqlite::params![tenant_id, role],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .ok();
    let (id, created_at) = row?;
    let total: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM tokens \
             WHERE tenant_id = ?1 AND role = ?2 AND revoked_at IS NULL",
            rusqlite::params![tenant_id, role],
            |r| r.get(0),
        )
        .unwrap_or(1);
    Some(TokenSlotInfo {
        id,
        created_at,
        legacy_siblings: (total - 1).max(0),
    })
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
    let anon = read_slot(&conn, &tenant_id, "anon");
    let service = read_slot(&conn, &tenant_id, "service");
    Html(
        DetailPage {
            tenant_id: tenant_id.clone(),
            tenant_name: name,
            created_at: created,
            anon,
            service,
            new_token: qs.new_token,
            new_token_role: qs.new_token_role,
            version: env!("CARGO_PKG_VERSION"),
        }
        .render()
        .unwrap(),
    )
    .into_response()
}
