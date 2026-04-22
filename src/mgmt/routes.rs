use crate::auth::admin::verify_password;
use crate::auth::middleware::{build_session_cookie, clear_session_cookie};
use crate::auth::session::{create_session, revoke_session};
use askama::Template;
use axum::Router;
use axum::extract::{Form, State};
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
}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginPage {
    error: Option<String>,
    version: &'static str,
}

#[derive(Debug, Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

async fn login_page() -> Html<String> {
    Html(
        LoginPage {
            error: None,
            version: env!("CARGO_PKG_VERSION"),
        }
        .render()
        .unwrap(),
    )
}

async fn login_submit(State(state): State<MgmtState>, Form(form): Form<LoginForm>) -> Response {
    let mut conn = state.meta.lock().await;
    let row: Option<(i64, String)> = conn
        .query_row(
            "SELECT id, password_hash FROM admins WHERE username = ?1",
            rusqlite::params![form.username],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .ok();
    let admin_id = match row {
        Some((id, hash)) => match verify_password(&hash, &form.password) {
            Ok(true) => id,
            _ => return unauthorized("Invalid credentials"),
        },
        None => return unauthorized("Invalid credentials"),
    };
    let ttl_secs = (state.session_ttl_days * 86_400) as i64;
    let token = match create_session(&mut conn, admin_id, ttl_secs) {
        Ok(t) => t,
        Err(e) => return internal(e.to_string()),
    };
    drop(conn);
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

fn unauthorized(msg: &str) -> Response {
    let body = LoginPage {
        error: Some(msg.to_string()),
        version: env!("CARGO_PKG_VERSION"),
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
        use crate::mgmt::tenants::{
            TenantsState, create_tenant_form, create_tenant_json, list_page_axum,
            soft_delete_tenant, soft_delete_tenant_form,
        };
        use axum::extract::DefaultBodyLimit;

        let session = AdminSessionState {
            meta: self.meta.clone(),
        };
        let tenants_state = TenantsState {
            session: session.clone(),
            data_dir,
            garage: self.garage.clone(),
            garage_client_key_id: self.garage_client_key_id.clone(),
        };
        let public_files_state = PublicFilesState {
            session: session.clone(),
            meta: self.meta.clone(),
            garage: self.garage.clone(),
            base_url: self.public_base_url.clone(),
            max_upload_bytes: self.max_upload_bytes,
            disk_min_free_pct: self.disk_min_free_pct,
        };

        let public = Router::new()
            .route("/", get(root_redirect))
            .route("/login", get(login_page).post(login_submit))
            .route("/logout", post(logout_submit))
            .with_state(self.clone());

        // Legacy redirects (back-compat v1.4.0) — 301 to the new paths. These don't require
        // authentication since they're just static redirects.
        let legacy_redirects = Router::new()
            .route("/admin/public-files", get(legacy_files_redirect))
            .route(
                "/admin/public-files/reconcile",
                get(legacy_reconcile_redirect),
            );

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
            .route("/admin/tenants/{id}", get(super::tokens::detail_page))
            .route(
                "/admin/api/tenants/{id}/tokens/{role}/reroll",
                post(super::tokens::reroll_token_json),
            )
            .route(
                "/admin/tenants/{id}/tokens/{role}/reroll",
                post(super::tokens::reroll_token_form),
            )
            .route(
                "/admin/tenants/{id}/collections",
                get(super::browse::collections_page),
            )
            .route(
                "/admin/tenants/{id}/collections/{coll}",
                get(super::browse::collection_rows_page),
            )
            .with_state(tenants_state);

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

        let protected =
            tenants_router
                .merge(public_files_router)
                .layer(axum::middleware::from_fn_with_state(
                    session,
                    admin_session_layer,
                ));

        public.merge(legacy_redirects).merge(protected)
    }
}
