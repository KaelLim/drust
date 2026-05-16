use crate::auth::admin::{dummy_hash, verify_password};
use crate::auth::middleware::{build_session_cookie, clear_session_cookie};
use crate::auth::session::{create_session, revoke_session};
use askama::Template;
use axum::Router;
use axum::extract::{Form, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use rusqlite::Connection;
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct MgmtState {
    pub meta: Arc<Mutex<Connection>>,
    pub session_ttl_days: u64,
    pub garage: Option<Arc<crate::storage::garage::GarageClient>>,
    pub public_base_url: String,
    pub max_upload_bytes: usize,
    /// Garage S3 access-key-id for the drust-client key, used when granting
    /// per-tenant bucket access. Empty when garage is `None`.
    pub garage_client_key_id: String,
    /// Minimum free-disk percentage before uploads are refused (507).
    /// Sourced from `DRUST_DISK_MIN_FREE_PCT`; default 20.
    pub disk_min_free_pct: u8,
    /// Directory containing `audit-YYYY-MM-DD.jsonl` files. Sourced from
    /// `$DRUST_LOG_DIR` at boot; consumed by the admin audit UI.
    pub log_dir: std::path::PathBuf,
    /// 32-byte HMAC secret for drust-minted signed URLs. Generated at boot;
    /// signed URLs do not survive a restart.
    pub url_sign_secret: Arc<[u8; 32]>,
    /// Per-tenant pool registry. Admin handlers need this to invalidate
    /// the schema cache after writes (e.g. anon_caps mutation) so the
    /// next REST/MCP request through the tenant router sees the change
    /// without waiting for natural cache turnover.
    pub tenants: Arc<crate::storage::pool::TenantRegistry>,
    /// Per-tenant MCP service registry. soft_delete_tenant evicts the
    /// cached `DrustMcpService` for a tenant so its in-flight session
    /// state and `Arc<TenantPool>` clones release.
    pub mcp: Arc<crate::mcp::http_registry::McpHttpRegistry>,
    /// Per-(tenant, collection) SSE broadcast channels. soft_delete_tenant
    /// drops every channel keyed on the tenant so subscribers receive
    /// `Closed` instead of dangling forever.
    pub bus: crate::tenant::events::EventBus,
    /// Row count threshold above which index creation is considered "large
    /// table" and returns `LARGE_TABLE` unless `force=true`. Sourced from
    /// `DRUST_INDEX_LARGE_TABLE_ROWS` (default 1 000 000).
    pub index_large_table_rows: u64,
    /// External base URL used to build OAuth redirect URIs (e.g.
    /// `https://tool.tzuchi-org.tw`). Sourced from `DRUST_PUBLIC_URL`.
    /// Empty when unset, which disables OAuth login.
    pub public_url: String,
    /// Registered OAuth providers (Google / GitHub) keyed by short name.
    /// Cloned per request, so wrapped in `Arc`. When `enabled_names()` is
    /// empty, the admin login page hides the OAuth button.
    pub oauth_registry: std::sync::Arc<crate::oauth::ProviderRegistry>,
    /// Lower-case email allowlist for admin OAuth login. Sourced from
    /// `DRUST_ADMIN_OAUTH_ALLOWED_EMAILS` (comma-separated). Empty when
    /// unset, which disables OAuth login.
    pub oauth_allowlist: std::sync::Arc<std::collections::HashSet<String>>,
}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginPage {
    error: Option<String>,
    version: &'static str,
    oauth_providers: Vec<&'static str>,
    oauth_error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

#[derive(Debug, Default, Deserialize)]
struct LoginPageQuery {
    #[serde(default)]
    oauth_error: Option<String>,
}

async fn login_page(
    State(state): State<MgmtState>,
    Query(q): Query<LoginPageQuery>,
) -> Html<String> {
    Html(
        LoginPage {
            error: None,
            version: env!("CARGO_PKG_VERSION"),
            oauth_providers: state.oauth_registry.enabled_names(),
            oauth_error: q.oauth_error,
        }
        .render()
        .unwrap(),
    )
}

async fn login_submit(State(state): State<MgmtState>, Form(form): Form<LoginForm>) -> Response {
    let op = "POST /login";
    let mut conn = state.meta.lock().await;
    let row: Option<(i64, String)> = conn
        .query_row(
            "SELECT id, password_hash FROM admins WHERE username = ?1",
            rusqlite::params![form.username],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .ok();
    let (admin_id, phc) = match row {
        Some((id, hash)) => (id, hash),
        None => {
            // S1: spend one argon2 verify so timing matches the wrong-password
            // path — prevents admin username existence leaking via wall-clock.
            let _ = verify_password(dummy_hash(), &form.password);
            let mut entry =
                crate::safety::audit::AuditEntry::failure("-", "-", op, 0, "HTTP_401", "");
            entry.auth_method = Some("password".to_string());
            entry = entry.with_extra(serde_json::json!({ "auth_kind": "admin" }));
            crate::safety::audit::write_entry(&state.log_dir, &entry).await;
            return unauthorized("Invalid credentials", &state);
        }
    };
    match verify_password(&phc, &form.password) {
        Ok(true) => {}
        _ => {
            let mut entry =
                crate::safety::audit::AuditEntry::failure("-", "-", op, 0, "HTTP_401", "");
            entry.auth_method = Some("password".to_string());
            entry = entry.with_extra(serde_json::json!({ "auth_kind": "admin" }));
            crate::safety::audit::write_entry(&state.log_dir, &entry).await;
            return unauthorized("Invalid credentials", &state);
        }
    }
    let ttl_secs = (state.session_ttl_days * 86_400) as i64;
    let token = match create_session(&mut conn, admin_id, ttl_secs) {
        Ok(t) => t,
        Err(e) => return internal(e.to_string()),
    };
    drop(conn);
    let mut entry = crate::safety::audit::AuditEntry::success("-", "-", op, 0)
        .with_extra(serde_json::json!({ "admin_id": admin_id, "auth_kind": "admin" }));
    entry.auth_method = Some("password".to_string());
    crate::safety::audit::write_entry(&state.log_dir, &entry).await;
    let cookie = build_session_cookie(&token, state.session_ttl_days * 86_400);
    let mut resp = Redirect::to("/drust/admin/tenants").into_response();
    resp.headers_mut()
        .insert(header::SET_COOKIE, cookie.parse().unwrap());
    resp
}

async fn logout_submit(State(state): State<MgmtState>, headers: axum::http::HeaderMap) -> Response {
    if let Some(c) = headers.get(header::COOKIE).and_then(|v| v.to_str().ok())
        && let Some(tok) = c.split(';').find_map(|p| {
            let t = p.trim();
            t.strip_prefix("drust_session=").map(|s| s.to_string())
        })
    {
        let mut conn = state.meta.lock().await;
        let _ = revoke_session(&mut conn, &tok);
    }
    let mut resp = Redirect::to("/drust/login").into_response();
    resp.headers_mut()
        .insert(header::SET_COOKIE, clear_session_cookie().parse().unwrap());
    resp
}

async fn root_redirect() -> Redirect {
    Redirect::to("/drust/admin/tenants")
}

fn unauthorized(msg: &str, state: &MgmtState) -> Response {
    let body = LoginPage {
        error: Some(msg.to_string()),
        version: env!("CARGO_PKG_VERSION"),
        oauth_providers: state.oauth_registry.enabled_names(),
        oauth_error: None,
    }
    .render()
    .unwrap();
    let mut r = Html(body).into_response();
    *r.status_mut() = StatusCode::UNAUTHORIZED;
    r
}

fn internal(msg: String) -> Response {
    let mut r = msg.into_response();
    *r.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    r
}

async fn legacy_files_redirect() -> Response {
    let mut resp = "".into_response();
    *resp.status_mut() = StatusCode::MOVED_PERMANENTLY;
    resp.headers_mut()
        .insert(header::LOCATION, "/admin/files".parse().unwrap());
    resp
}

async fn legacy_reconcile_redirect() -> Response {
    let mut resp = "".into_response();
    *resp.status_mut() = StatusCode::MOVED_PERMANENTLY;
    resp.headers_mut()
        .insert(header::LOCATION, "/admin/files/reconcile".parse().unwrap());
    resp
}

pub fn build_mgmt_router(state: MgmtState) -> Router {
    Router::new()
        .route("/", get(root_redirect))
        .route("/login", get(login_page).post(login_submit))
        .route("/logout", post(logout_submit))
        .with_state(state)
}

impl MgmtState {
    pub fn with_data_dir(self, data_dir: std::path::PathBuf) -> Router {
        use crate::auth::middleware::{AdminSessionState, admin_session_layer};
        use crate::mgmt::public_files::{
            PublicFilesState, admin_sign_url, admin_stream_bytes, delete_submit,
            list_page as public_files_list_page, reconcile_apply, reconcile_page, upload_submit,
        };
        use crate::mgmt::tenant_files::{
            TenantFilesState, delete_one as tfiles_delete, sign_url as tfiles_sign,
            stream_bytes as tfiles_stream, upload as tfiles_upload,
        };
        use crate::mgmt::tenants::{
            TenantsState, create_tenant_form, create_tenant_json, list_page_axum,
            soft_delete_tenant, soft_delete_tenant_form, tenant_files_admin_page,
            tenant_oauth_provider_delete, tenant_oauth_provider_upsert,
            tenant_oauth_providers_page, tenant_webhook_create_form,
            tenant_webhook_delete_form, tenant_webhooks_page, toggle_self_register,
        };
        use axum::extract::DefaultBodyLimit;

        let session = AdminSessionState {
            meta: self.meta.clone(),
        };
        let tenants_state = TenantsState {
            session: session.clone(),
            data_dir: data_dir.clone(),
            garage: self.garage.clone(),
            garage_client_key_id: self.garage_client_key_id.clone(),
            max_upload_bytes: self.max_upload_bytes,
            disk_min_free_pct: self.disk_min_free_pct,
            public_base_url: self.public_base_url.clone(),
            tenants: self.tenants.clone(),
            mcp: self.mcp.clone(),
            bus: self.bus.clone(),
            log_dir: self.log_dir.clone(),
            index_large_table_rows: self.index_large_table_rows,
        };
        let public_files_state = PublicFilesState {
            session: session.clone(),
            meta: self.meta.clone(),
            garage: self.garage.clone(),
            base_url: self.public_base_url.clone(),
            max_upload_bytes: self.max_upload_bytes,
            disk_min_free_pct: self.disk_min_free_pct,
            garage_client_key_id: self.garage_client_key_id.clone(),
            url_sign_secret: self.url_sign_secret.clone(),
        };
        let tenant_files_state = TenantFilesState {
            garage: self.garage.clone(),
            data_root: data_dir.clone(),
            disk_min_free_pct: self.disk_min_free_pct,
            max_upload_bytes: self.max_upload_bytes,
            public_base_url: self.public_base_url.clone(),
            url_sign_secret: self.url_sign_secret.clone(),
        };
        let signed_bytes_state = crate::mgmt::signed_bytes::SignedBytesState {
            meta: self.meta.clone(),
            data_root: data_dir.clone(),
            garage: self.garage.clone(),
            url_sign_secret: self.url_sign_secret.clone(),
        };
        let backups_state = crate::mgmt::backups::BackupsState {
            data_dir: data_dir.clone(),
        };

        // TODO: rate-limit admin oauth callback
        let public = Router::new()
            .route("/", get(root_redirect))
            .route("/login", get(login_page).post(login_submit))
            .route("/logout", post(logout_submit))
            .route(
                "/admin/oauth/{provider}/start",
                get(crate::mgmt::oauth_login::oauth_start),
            )
            .route(
                "/admin/oauth/{provider}/callback",
                get(crate::mgmt::oauth_login::oauth_callback),
            )
            .with_state(self.clone());

        // Legacy redirects (back-compat v1.4.0) — 301 to the new paths. These don't require
        // authentication since they're just static redirects.
        let legacy_redirects = Router::new()
            .route("/admin/public-files", get(legacy_files_redirect))
            .route(
                "/admin/public-files/reconcile",
                get(legacy_reconcile_redirect),
            );

        // Unauth public signed-bytes endpoints — token validates in the handler.
        let signed_router = Router::new()
            .route(
                "/s/admin/{key}",
                get(crate::mgmt::signed_bytes::admin_signed_bytes),
            )
            .route(
                "/s/t/{tenant}/{key}",
                get(crate::mgmt::signed_bytes::tenant_signed_bytes),
            )
            .with_state(signed_bytes_state);

        // Tenant admin sub-router (existing behaviour).
        let tenants_router = Router::new()
            .route("/admin/tenants", get(list_page_axum))
            .route("/admin/tenants/new", post(create_tenant_form))
            .route("/admin/api/tenants", post(create_tenant_json))
            .route(
                "/admin/api/tenants/{id}",
                axum::routing::delete(soft_delete_tenant),
            )
            .route("/admin/tenants/{id}/delete", post(soft_delete_tenant_form))
            .route("/admin/tenants/{id}", get(super::tokens::detail_redirect))
            .route(
                "/admin/tenants/{id}/_api_keys",
                get(super::tokens::api_keys_page),
            )
            .route(
                "/admin/tenants/{id}/_rpc",
                get(super::rpc_admin::rpc_index),
            )
            .route(
                "/admin/tenants/{id}/_rpc/new",
                get(super::rpc_admin::rpc_new_form).post(super::rpc_admin::rpc_save),
            )
            .route(
                "/admin/tenants/{id}/_rpc/{name}/edit",
                get(super::rpc_admin::rpc_edit_form),
            )
            .route(
                "/admin/tenants/{id}/_rpc/{name}/save",
                post(super::rpc_admin::rpc_save),
            )
            .route(
                "/admin/tenants/{id}/_rpc/{name}/delete",
                post(super::rpc_admin::rpc_delete),
            )
            .route(
                "/admin/tenants/{id}/_rpc/{name}/test",
                get(super::rpc_admin::rpc_test_form),
            )
            .route(
                "/admin/tenants/{id}/_rpc/{name}/test/run",
                post(super::rpc_admin::rpc_test_run),
            )
            .route(
                "/admin/api/tenants/{id}/tokens/{role}/reroll",
                post(super::tokens::reroll_token_json),
            )
            .route(
                "/admin/tenants/{id}/tokens/{role}/reroll",
                post(super::tokens::reroll_token_form),
            )
            .route("/admin/tenants/{id}/files", get(tenant_files_admin_page))
            .route(
                "/admin/_docs/changelog",
                get(super::docs::changelog_page),
            )
            .route(
                "/admin/tenants/{id}/collections",
                get(super::browse::collections_page),
            )
            .route(
                "/admin/tenants/{id}/collections/{coll}",
                get(super::browse::collection_rows_page),
            )
            .route(
                "/admin/tenants/{id}/collections/{coll}/anon-caps",
                post(super::browse::update_anon_caps),
            )
            .route(
                "/admin/tenants/{id}/collections/{coll}/_indexes",
                post(super::browse::create_index_admin),
            )
            .route(
                "/admin/tenants/{id}/collections/{coll}/_indexes/{name}",
                axum::routing::delete(super::browse::drop_index_admin),
            )
            .route(
                "/admin/tenants/{id}/collections/{coll}/_explain",
                post(super::browse::explain_admin),
            )
            .route(
                "/admin/audit",
                get(super::audit::audit_host_page),
            )
            .route(
                "/admin/tenants/{id}/_logs",
                get(super::audit::audit_tenant_page),
            )
            .route(
                "/admin/tenants/{id}/allow-self-register",
                post(toggle_self_register),
            )
            // v1.12 per-tenant OAuth admin UI — virtual sidebar entry
            // `🔐 _oauth_providers`. GET renders the page; POST upserts a
            // provider (form-encoded); `<provider>/delete` removes one.
            .route(
                "/admin/tenants/{id}/_oauth_providers",
                get(tenant_oauth_providers_page).post(tenant_oauth_provider_upsert),
            )
            .route(
                "/admin/tenants/{id}/_oauth_providers/{provider}/delete",
                post(tenant_oauth_provider_delete),
            )
            // v1.13 outbound webhooks admin UI — virtual sidebar entry
            // `🔔 _webhooks`. GET renders the page; POST inserts a new
            // subscription + 303s with a short-lived secret-once cookie;
            // `<wid>/delete` removes one. The same `_system_webhooks` table
            // is also reachable via the service-only REST endpoints
            // (src/tenant/webhook_routes.rs) and the MCP tools — this is
            // the UI surface.
            .route(
                "/admin/tenants/{id}/_webhooks",
                get(tenant_webhooks_page).post(tenant_webhook_create_form),
            )
            .route(
                "/admin/tenants/{id}/_webhooks/{wid}/delete",
                post(tenant_webhook_delete_form),
            )
            .with_state(tenants_state);

        // Backups sub-router — list + download snapshots produced by
        // drust-backup.timer. Read-only; restore is intentionally manual
        // (extract via `tar --zstd -xf`) until we add a guarded UI flow.
        let backups_router = Router::new()
            .route("/admin/backups", get(super::backups::list_page))
            .route(
                "/admin/backups/{filename}/download",
                get(super::backups::download_one),
            )
            .route(
                "/admin/backups/{filename}/inspect",
                get(super::backups::inspect),
            )
            .route(
                "/admin/backups/{filename}/restore",
                post(super::backups::restore_tenant),
            )
            .with_state(backups_state);

        // Public-files sub-router (new in v1.4.0). Upload route carries its
        // own DefaultBodyLimit so multipart payloads larger than the cap
        // return 413 without consuming memory.
        let public_files_router = Router::new()
            // Renamed routes (new in Y):
            .route("/admin/files", get(public_files_list_page))
            .route(
                "/admin/files/upload",
                post(upload_submit).layer(DefaultBodyLimit::max(self.max_upload_bytes)),
            )
            .route("/admin/files/{id}/delete", post(delete_submit))
            .route(
                "/admin/files/reconcile",
                get(reconcile_page).post(reconcile_apply),
            )
            .route("/admin/files/{key}/bytes", get(admin_stream_bytes))
            .route("/admin/files/{key}/sign", post(admin_sign_url))
            .with_state(public_files_state);

        // Admin-scoped tenant files sub-router — uploads land in the tenant's
        // own buckets (tenant-{id}-pub / tenant-{id}-prv) and its data.sqlite
        // _system_files. Reuses the tenant-side handlers unchanged; admin
        // auth is applied via `protected` below.
        let admin_tenant_files_router = Router::new()
            .route(
                "/admin/tenants/{id}/files/upload",
                post(tfiles_upload).layer(DefaultBodyLimit::max(self.max_upload_bytes)),
            )
            .route(
                "/admin/tenants/{id}/files/{key}",
                axum::routing::delete(tfiles_delete),
            )
            .route("/admin/tenants/{id}/files/{key}/sign", post(tfiles_sign))
            .route("/admin/tenants/{id}/files/{key}/bytes", get(tfiles_stream))
            .with_state(tenant_files_state);

        let protected = tenants_router
            .merge(public_files_router)
            .merge(admin_tenant_files_router)
            .merge(backups_router)
            .layer(axum::middleware::from_fn_with_state(
                session,
                admin_session_layer,
            ));

        public
            .merge(legacy_redirects)
            .merge(signed_router)
            .merge(protected)
    }
}
