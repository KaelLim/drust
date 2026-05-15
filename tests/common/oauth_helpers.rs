//! Shared OAuth test scaffolding factored from `tests/admin_oauth.rs`
//! (v1.11) so the v1.12 per-tenant OAuth integration tests can reuse the
//! fake-provider HTTP servers, cookie helpers, and audit-row pollers.
//!
//! Admin-specific helpers (the MgmtState builder + `spin_up_admin_*`) stay
//! in `tests/admin_oauth.rs`; only the actor-agnostic bits live here.

use axum::body::Body;
use axum::extract::Form;
use axum::http::{Response, StatusCode, header};
use axum::response::Json;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

// ---------- Fake provider server ----------

#[derive(Clone)]
pub struct FakeScript {
    pub email: String,
    pub email_verified: bool,
    pub provider_user_id: String,
    /// Avatar URL the fake provider returns. Google emits this in the
    /// id_token `picture` claim; GitHub emits it as `avatar_url` on
    /// `GET /user`.
    pub picture: String,
}

impl Default for FakeScript {
    fn default() -> Self {
        Self {
            email: "kael@example.com".to_string(),
            email_verified: true,
            provider_user_id: "sub-default".to_string(),
            picture: "https://example.test/avatar.png".to_string(),
        }
    }
}

pub struct FakeProvider {
    pub base_url: String,
    pub last_code: Mutex<Option<String>>,
    pub script: Mutex<FakeScript>,
}

/// Spawn a fake Google OIDC provider on 127.0.0.1:0. Returns an Arc whose
/// `base_url` is the live `http://127.0.0.1:<port>` and whose `/token`
/// endpoint returns a synthesized id_token built from the current script.
pub async fn spawn_fake_google() -> Arc<FakeProvider> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{addr}");
    let state = Arc::new(FakeProvider {
        base_url: base_url.clone(),
        last_code: Mutex::new(None),
        script: Mutex::new(FakeScript::default()),
    });

    let st = state.clone();
    let app = axum::Router::new().route(
        "/token",
        axum::routing::post(move |Form(form): Form<HashMap<String, String>>| {
            let st = st.clone();
            async move {
                if let Some(code) = form.get("code") {
                    *st.last_code.lock().await = Some(code.clone());
                }
                let script = st.script.lock().await.clone();
                let claims = serde_json::json!({
                    "sub": script.provider_user_id,
                    "email": script.email,
                    "email_verified": script.email_verified,
                    "name": "Kael",
                    "picture": script.picture,
                });
                let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
                let id_token = format!("header.{payload}.sig");
                Json(serde_json::json!({ "id_token": id_token }))
            }
        }),
    );
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    state
}

/// Variant of `spawn_fake_google` whose `/token` endpoint returns 400 so
/// `GoogleAdapter::exchange` (which calls `.error_for_status()?`) fails —
/// exercising the `oauth_provider_error` branch in `oauth_callback`.
pub async fn spawn_fake_google_returning_400() -> Arc<FakeProvider> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{addr}");
    let state = Arc::new(FakeProvider {
        base_url: base_url.clone(),
        last_code: Mutex::new(None),
        script: Mutex::new(FakeScript::default()),
    });

    let st = state.clone();
    let app = axum::Router::new().route(
        "/token",
        axum::routing::post(move |Form(form): Form<HashMap<String, String>>| {
            let st = st.clone();
            async move {
                if let Some(code) = form.get("code") {
                    *st.last_code.lock().await = Some(code.clone());
                }
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": "invalid_grant" })),
                )
            }
        }),
    );
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    state
}

/// Spawn a fake GitHub OAuth provider on 127.0.0.1:0. Exposes the three
/// endpoints `GitHubAdapter::exchange` calls.
pub async fn spawn_fake_github() -> Arc<FakeProvider> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{addr}");
    let state = Arc::new(FakeProvider {
        base_url: base_url.clone(),
        last_code: Mutex::new(None),
        script: Mutex::new(FakeScript::default()),
    });

    let st1 = state.clone();
    let st2 = state.clone();
    let st3 = state.clone();
    let app = axum::Router::new()
        .route(
            "/login/oauth/access_token",
            axum::routing::post(move |Form(form): Form<HashMap<String, String>>| {
                let st = st1.clone();
                async move {
                    if let Some(code) = form.get("code") {
                        *st.last_code.lock().await = Some(code.clone());
                    }
                    Json(serde_json::json!({
                        "access_token": "fake-token",
                        "token_type": "bearer",
                        "scope": "read:user user:email",
                    }))
                }
            }),
        )
        .route(
            "/user/emails",
            axum::routing::get(move || {
                let st = st2.clone();
                async move {
                    let script = st.script.lock().await.clone();
                    Json(serde_json::json!([{
                        "email": script.email,
                        "primary": true,
                        "verified": script.email_verified,
                    }]))
                }
            }),
        )
        .route(
            "/user",
            axum::routing::get(move || {
                let st = st3.clone();
                async move {
                    let script = st.script.lock().await.clone();
                    let id: u64 = script.provider_user_id.parse().unwrap_or(0);
                    Json(serde_json::json!({
                        "id": id,
                        "name": "Kael",
                        "avatar_url": script.picture,
                    }))
                }
            }),
        );
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    state
}

// ---------- Response helpers ----------

/// Pull a cookie VALUE (the bit before the first `;`) by name from all
/// `Set-Cookie` headers on a response. Returns `None` if absent.
pub fn extract_set_cookie(resp: &Response<Body>, name: &str) -> Option<String> {
    for v in resp.headers().get_all(header::SET_COOKIE).iter() {
        let raw = v.to_str().ok()?;
        let first = raw.split(';').next().unwrap_or("");
        if let Some((k, val)) = first.split_once('=') {
            if k.trim() == name {
                return Some(val.trim().to_string());
            }
        }
    }
    None
}

pub fn assert_redirect_contains(resp: &Response<Body>, fragment: &str) {
    let status = resp.status();
    assert!(
        status == StatusCode::FOUND || status == StatusCode::SEE_OTHER,
        "expected redirect, got {status}"
    );
    let loc = resp
        .headers()
        .get(header::LOCATION)
        .unwrap_or_else(|| panic!("no Location header on {status} response"))
        .to_str()
        .unwrap();
    assert!(loc.contains(fragment), "expected {fragment:?} in {loc:?}");
}

// ---------- Audit row helpers ----------

pub async fn poll_for_audit_row(
    log_dir: &std::path::Path,
    auth_method: &str,
    max_ms: u64,
) -> serde_json::Value {
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(max_ms);
    loop {
        if let Some(row) = try_find_audit_row(log_dir, auth_method) {
            return row;
        }
        if std::time::Instant::now() >= deadline {
            panic!("audit row with auth_method={auth_method} not written within {max_ms}ms");
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

pub fn try_find_audit_row(
    log_dir: &std::path::Path,
    auth_method: &str,
) -> Option<serde_json::Value> {
    let latest = std::fs::read_dir(log_dir)
        .ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("audit-") && n.ends_with(".jsonl"))
        })
        .max_by_key(|p| std::fs::metadata(p).and_then(|m| m.modified()).ok())?;
    let body = std::fs::read_to_string(&latest).ok()?;
    body.lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .find(|v| v["auth_method"] == auth_method)
}
