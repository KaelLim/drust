use crate::auth::admin::verify_password;
use crate::auth::middleware::{build_session_cookie, clear_session_cookie};
use crate::auth::session::{create_session, revoke_session};
use askama::Template;
use axum::extract::{Form, State};
use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;
use rusqlite::Connection;
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct MgmtState {
    pub meta: Arc<Mutex<Connection>>,
    pub session_ttl_days: u64,
}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginPage {
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

async fn login_page() -> Html<String> {
    Html(LoginPage { error: None }.render().unwrap())
}

async fn login_submit(
    State(state): State<MgmtState>,
    Form(form): Form<LoginForm>,
) -> Response {
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
    let mut resp = Redirect::to("/admin/tenants").into_response();
    resp.headers_mut().insert(header::SET_COOKIE, cookie.parse().unwrap());
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
    let mut resp = Redirect::to("/login").into_response();
    resp.headers_mut().insert(header::SET_COOKIE, clear_session_cookie().parse().unwrap());
    resp
}

async fn root_redirect() -> Redirect {
    Redirect::to("/admin/tenants")
}

fn unauthorized(msg: &str) -> Response {
    let body = LoginPage { error: Some(msg.to_string()) }.render().unwrap();
    let mut r = Html(body).into_response();
    *r.status_mut() = StatusCode::UNAUTHORIZED;
    r
}

fn internal(msg: String) -> Response {
    let mut r = msg.into_response();
    *r.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    r
}

pub fn build_mgmt_router(state: MgmtState) -> Router {
    Router::new()
        .route("/", get(root_redirect))
        .route("/login", get(login_page).post(login_submit))
        .route("/logout", post(logout_submit))
        .with_state(state)
}
