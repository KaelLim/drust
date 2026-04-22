use crate::auth::bearer::{generate_token, hash_token};
use crate::auth::middleware::AdminSessionState;
use crate::storage::garage::GarageClient;
use crate::storage::tenant_db::{open_write, tenant_dir, validate_tenant_id};
use askama::Template;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::{Form, Json};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Clone)]
pub struct TenantsState {
    pub session: AdminSessionState,
    pub data_dir: PathBuf,
    pub garage: Option<Arc<GarageClient>>,
    pub garage_client_key_id: String,
}

#[derive(Template)]
#[template(path = "tenants_list.html")]
struct TenantsListPage {
    tenants: Vec<TenantRow>,
    version: &'static str,
}

struct TenantRow {
    id: String,
    name: String,
    created_at: String,
    db_size_kb: u64,
}

#[derive(Debug, Deserialize)]
pub struct CreateTenantJson {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub quota_db_mb: Option<i64>,
    #[serde(default)]
    pub quota_rows: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct CreateTenantForm {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct CreatedResp {
    pub tenant: TenantInfo,
    /// Both initial keys, shown once only.
    pub initial_tokens: InitialTokens,
    /// Back-compat field: equals `initial_tokens.service`.
    pub initial_token: String,
}

#[derive(Debug, Serialize)]
pub struct InitialTokens {
    pub anon: String,
    pub service: String,
}

#[derive(Debug, Serialize)]
pub struct TenantInfo {
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub quota_db_mb: i64,
    pub quota_rows: i64,
}

/// Create both tenant buckets and grant drust-client access.
/// Idempotent-ish: if a bucket with that name already exists, treat as reuse.
/// On any mid-sequence failure, attempts to compensate by deleting buckets
/// this call created (not pre-existing ones).
pub async fn provision_storage_for_tenant(
    garage: &GarageClient,
    drust_client_key_id: &str,
    tenant_id: &str,
) -> anyhow::Result<(String, String)> {
    let pub_name = format!("tenant-{tenant_id}-pub");
    let prv_name = format!("tenant-{tenant_id}-prv");

    // Track whether we created each bucket (for targeted rollback).
    let pub_lookup = garage.lookup_bucket(&pub_name).await?;
    let pub_existed = pub_lookup.is_some();
    let pub_id = match pub_lookup {
        Some(info) => info.id,
        None => garage.create_bucket(&pub_name).await?,
    };

    let result: anyhow::Result<String> = async {
        garage.set_website(&pub_id, true).await?;
        garage
            .bucket_allow(&pub_id, drust_client_key_id, true, true, true)
            .await?;

        let prv_lookup = garage.lookup_bucket(&prv_name).await?;
        let prv_id = match prv_lookup {
            Some(info) => info.id,
            None => garage.create_bucket(&prv_name).await?,
        };
        garage
            .bucket_allow(&prv_id, drust_client_key_id, true, true, true)
            .await?;
        Ok(prv_id)
    }
    .await;

    match result {
        Ok(prv_id) => Ok((pub_id, prv_id)),
        Err(e) => {
            // Roll back only what THIS call created.
            if !pub_existed {
                let _ = garage.delete_bucket(&pub_id).await;
            }
            // Also clean up prv if we got as far as creating it. `delete_bucket`
            // is idempotent (404 ok), so the lookup-then-delete heuristic is
            // safe even under pathological concurrent creation.
            if let Ok(Some(info)) = garage.lookup_bucket(&prv_name).await {
                let _ = garage.delete_bucket(&info.id).await;
            }
            Err(e.context(format!("provisioning tenant-{tenant_id} buckets")))
        }
    }
}

pub fn valid_slug(s: &str) -> bool {
    let bytes = s.as_bytes();
    if !(3..=40).contains(&bytes.len()) {
        return false;
    }
    let first = bytes[0];
    let last = bytes[bytes.len() - 1];
    let is_lead = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    if !is_lead(first) || !is_lead(last) {
        return false;
    }
    bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

pub async fn list_page_axum(State(state): State<TenantsState>) -> Response {
    let conn = state.session.meta.lock().await;
    let mut stmt = conn
        .prepare("SELECT id, name, created_at FROM tenants WHERE deleted_at IS NULL ORDER BY id")
        .unwrap();
    let rows: Vec<TenantRow> = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })
        .unwrap()
        .filter_map(Result::ok)
        .map(|(id, name, created_at)| {
            let db_path = tenant_dir(&state.data_dir, &id).join("data.sqlite");
            let db_size_kb = std::fs::metadata(&db_path)
                .map(|m| m.len() / 1024)
                .unwrap_or(0);
            TenantRow {
                id,
                name,
                created_at,
                db_size_kb,
            }
        })
        .collect();
    Html(
        TenantsListPage {
            tenants: rows,
            version: env!("CARGO_PKG_VERSION"),
        }
        .render()
        .unwrap(),
    )
    .into_response()
}

fn make_tenant_inner(
    conn: &mut rusqlite::Connection,
    data_dir: &std::path::Path,
    id: &str,
    name: &str,
    quota_mb: i64,
    quota_rows: i64,
) -> anyhow::Result<CreatedResp> {
    if let Err(e) = validate_tenant_id(id) {
        anyhow::bail!("invalid tenant id: {e}");
    }
    conn.execute(
        "INSERT INTO tenants (id, name, quota_db_mb, quota_rows) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![id, name, quota_mb, quota_rows],
    )?;
    // Create directory + data.sqlite file
    let _ = open_write(data_dir, id)?;
    std::fs::write(
        tenant_dir(data_dir, id).join("meta.json"),
        serde_json::to_vec_pretty(&json!({
            "name": name,
            "created_at": Utc::now().to_rfc3339(),
            "quota_db_mb": quota_mb,
            "quota_rows": quota_rows,
        }))?,
    )?;
    // Issue both an anon and a service key on creation. Shown once.
    let service_token = generate_token();
    let anon_token = generate_token();
    conn.execute(
        "INSERT INTO tokens (tenant_id, token_hash, plaintext, label, role) \
         VALUES (?1, ?2, ?3, 'initial-service', 'service')",
        rusqlite::params![id, hash_token(&service_token), service_token],
    )?;
    conn.execute(
        "INSERT INTO tokens (tenant_id, token_hash, plaintext, label, role) \
         VALUES (?1, ?2, ?3, 'initial-anon', 'anon')",
        rusqlite::params![id, hash_token(&anon_token), anon_token],
    )?;
    Ok(CreatedResp {
        tenant: TenantInfo {
            id: id.to_string(),
            name: name.to_string(),
            created_at: Utc::now().to_rfc3339(),
            quota_db_mb: quota_mb,
            quota_rows,
        },
        initial_tokens: InitialTokens {
            anon: anon_token,
            service: service_token.clone(),
        },
        initial_token: service_token,
    })
}

/// Roll back everything `make_tenant_inner` did for `id`: delete token rows,
/// the tenant row, and the on-disk directory. Used when Garage provisioning
/// fails after local state has already been written.
fn rollback_local_tenant(conn: &mut rusqlite::Connection, data_dir: &std::path::Path, id: &str) {
    if let Err(e) = conn.execute(
        "DELETE FROM tokens WHERE tenant_id = ?1",
        rusqlite::params![id],
    ) {
        tracing::warn!(tenant_id = %id, error = %e, "rollback: failed to delete token rows");
    }
    if let Err(e) = conn.execute("DELETE FROM tenants WHERE id = ?1", rusqlite::params![id]) {
        tracing::warn!(tenant_id = %id, error = %e, "rollback: failed to delete tenant row");
    }
    let dir = tenant_dir(data_dir, id);
    if let Err(e) = std::fs::remove_dir_all(&dir) {
        tracing::warn!(tenant_id = %id, path = %dir.display(), error = %e, "rollback: failed to remove tenant dir");
    }
}

pub async fn create_tenant_json(
    State(state): State<TenantsState>,
    Json(form): Json<CreateTenantJson>,
) -> Response {
    let mb = form.quota_db_mb.unwrap_or(500);
    let rows = form.quota_rows.unwrap_or(1_000_000);

    let mut conn = state.session.meta.lock().await;
    let resp = match make_tenant_inner(&mut conn, &state.data_dir, &form.id, &form.name, mb, rows) {
        Ok(resp) => resp,
        Err(e) => {
            let msg = e.to_string();
            return if msg.contains("invalid tenant id") || msg.contains("UNIQUE") {
                (StatusCode::BAD_REQUEST, msg).into_response()
            } else {
                (StatusCode::INTERNAL_SERVER_ERROR, msg).into_response()
            };
        }
    };
    drop(conn);

    if let Some(ref garage) = state.garage {
        if garage.ping().await.is_err() {
            let mut conn = state.session.meta.lock().await;
            rollback_local_tenant(&mut conn, &state.data_dir, &form.id);
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "Garage unreachable — tenant not created",
            )
                .into_response();
        }
        if let Err(e) =
            provision_storage_for_tenant(garage.as_ref(), &state.garage_client_key_id, &form.id)
                .await
        {
            let mut conn = state.session.meta.lock().await;
            rollback_local_tenant(&mut conn, &state.data_dir, &form.id);
            tracing::error!(tenant_id = %form.id, error = %e, "storage provisioning failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("storage provisioning failed: {e}"),
            )
                .into_response();
        }
    }

    (StatusCode::CREATED, Json(resp)).into_response()
}

pub async fn create_tenant_form(
    State(state): State<TenantsState>,
    Form(form): Form<CreateTenantForm>,
) -> Response {
    let mut conn = state.session.meta.lock().await;
    let created = make_tenant_inner(
        &mut conn,
        &state.data_dir,
        &form.id,
        &form.name,
        500,
        1_000_000,
    );
    drop(conn);

    match created {
        Ok(_) => {
            if let Some(ref garage) = state.garage {
                if garage.ping().await.is_err() {
                    let mut conn = state.session.meta.lock().await;
                    rollback_local_tenant(&mut conn, &state.data_dir, &form.id);
                    return (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Garage unreachable — tenant not created",
                    )
                        .into_response();
                }
                if let Err(e) = provision_storage_for_tenant(
                    garage.as_ref(),
                    &state.garage_client_key_id,
                    &form.id,
                )
                .await
                {
                    let mut conn = state.session.meta.lock().await;
                    rollback_local_tenant(&mut conn, &state.data_dir, &form.id);
                    tracing::error!(tenant_id = %form.id, error = %e, "storage provisioning failed");
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("storage provisioning failed: {e}"),
                    )
                        .into_response();
                }
            }
            Redirect::to("/drust/admin/tenants").into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

pub async fn soft_delete_tenant(
    State(state): State<TenantsState>,
    Path(id): Path<String>,
) -> Response {
    let conn = state.session.meta.lock().await;
    let affected = conn
        .execute(
            "UPDATE tenants SET deleted_at = datetime('now') WHERE id = ?1 AND deleted_at IS NULL",
            rusqlite::params![id],
        )
        .unwrap_or(0);
    if affected == 0 {
        return (StatusCode::NOT_FOUND, "no such tenant").into_response();
    }
    let ts = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let src = tenant_dir(&state.data_dir, &id);
    let dst = state.data_dir.join("_trash").join(format!("{id}-{ts}"));
    if let Some(parent) = dst.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if src.exists() {
        let _ = std::fs::rename(&src, &dst);
    }
    StatusCode::NO_CONTENT.into_response()
}

pub async fn soft_delete_tenant_form(
    State(state): State<TenantsState>,
    Path(id): Path<String>,
) -> Response {
    let _ = soft_delete_tenant(State(state), Path(id)).await;
    Redirect::to("/drust/admin/tenants").into_response()
}
