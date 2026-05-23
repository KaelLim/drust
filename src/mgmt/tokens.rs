use crate::auth::bearer::{generate_token, hash_token};
use crate::mgmt::i18n::{LocaleHint, Translator};
use crate::mgmt::tenants::TenantsState;
use crate::storage::schema::{Collection, list_collections};
use crate::storage::tenant_db::open_read;
use askama::Template;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::{Form, Json};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Template)]
#[template(path = "tenant_api_keys.html")]
struct ApiKeysPage {
    tenant_id: String,
    tenant_name: String,
    created_at: String,
    anon: Option<TokenSlotInfo>,
    service: Option<TokenSlotInfo>,
    /// Driver list for `_collection_sidebar.html`. Empty Vec is fine — the
    /// sidebar still renders the virtual `_api_keys` and `_system_files` rows.
    collections: Vec<Collection>,
    active_coll: String,
    /// Current state of `tenants.allow_self_register`. Drives the checkbox.
    allow_self_register: bool,
    version: &'static str,
    t: Translator,
    palette_resolved: crate::mgmt::theme::ResolvedPalette,
    mascot_json_static: String,
    mascot_json_light: String,
    mascot_json_dark: String,
}

pub struct TokenSlotInfo {
    pub id: i64,
    pub created_at: String,
    /// Plaintext key. `None` for tokens created before v1.1c (only the hash
    /// was stored back then); reroll to recover.
    pub plaintext: Option<String>,
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
        "INSERT INTO tokens (tenant_id, token_hash, plaintext, label, role) \
         VALUES (?1, ?2, ?3, 'rotated', ?4)",
        rusqlite::params![tenant_id, hash_token(&plaintext), plaintext, role_str],
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
    let resp = reroll_token_json(State(state), Path((tenant_id.clone(), role))).await;
    if !resp.status().is_success() {
        return resp;
    }
    Redirect::to(&format!(
        "/drust/admin/tenants/{}/_api_keys",
        tenant_id
    ))
    .into_response()
}

fn read_slot(conn: &rusqlite::Connection, tenant_id: &str, role: &str) -> Option<TokenSlotInfo> {
    let row: Option<(i64, String, Option<String>)> = conn
        .query_row(
            "SELECT id, created_at, plaintext FROM tokens \
             WHERE tenant_id = ?1 AND role = ?2 AND revoked_at IS NULL \
             ORDER BY created_at DESC LIMIT 1",
            rusqlite::params![tenant_id, role],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .ok();
    let (id, created_at, plaintext) = row?;
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
        plaintext,
        legacy_siblings: (total - 1).max(0),
    })
}

/// `GET /admin/tenants/{id}` — redirect to the tenant Overview (v1.14+).
/// Before v1.14 this redirected to `_api_keys`, which is still reachable
/// via the sidebar.
pub async fn detail_redirect(Path(tenant_id): Path<String>) -> Response {
    Redirect::to(&format!(
        "/drust/admin/tenants/{}/_overview",
        tenant_id
    ))
    .into_response()
}

/// `GET /admin/tenants/{id}/_api_keys` — virtual collection that renders the
/// API key cards + MCP setup card inside the same 2-pane shell as a real
/// collection page. The sidebar's `_api_keys` row links here.
pub async fn api_keys_page(
    State(state): State<TenantsState>,
    LocaleHint(locale): LocaleHint,
    crate::mgmt::theme::ThemeHint(theme): crate::mgmt::theme::ThemeHint,
    Path(tenant_id): Path<String>,
) -> Response {
    let conn = state.session.meta.lock().await;
    let meta: Option<(String, String, i64)> = conn
        .query_row(
            "SELECT name, created_at, COALESCE(allow_self_register, 0) FROM tenants WHERE id = ?1 AND deleted_at IS NULL",
            rusqlite::params![tenant_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .ok();
    let (name, created, self_register_flag) = match meta {
        Some(m) => m,
        None => return (StatusCode::NOT_FOUND, "tenant not found").into_response(),
    };
    let anon = read_slot(&conn, &tenant_id, "anon");
    let service = read_slot(&conn, &tenant_id, "service");
    drop(conn);

    // Load collections for the sidebar. A failure here (DB missing, fresh
    // tenant pre-write) is non-fatal — the sidebar still shows the virtual
    // rows (`_api_keys`, `_system_files`).
    let collections = open_read(&state.data_dir, &tenant_id)
        .ok()
        .and_then(|c| list_collections(&c).ok())
        .unwrap_or_default();

    let trc = crate::mgmt::theme::ThemeRenderCtx::build(theme);
    Html(
        ApiKeysPage {
            tenant_id: tenant_id.clone(),
            tenant_name: name,
            created_at: created,
            anon,
            service,
            collections,
            active_coll: "_api_keys".to_string(),
            allow_self_register: self_register_flag != 0,
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
