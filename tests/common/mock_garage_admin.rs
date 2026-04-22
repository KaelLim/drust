//! Minimal replay-and-record HTTP server that mimics the Garage admin API
//! surface drust uses. Tests spawn one with `start()`, inspect captured
//! requests via `requests()`, and pre-seed responses via `seed_bucket`.

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, Method, StatusCode},
    response::IntoResponse,
    routing::{any, delete, get, post},
};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use tokio::net::TcpListener;

#[derive(Clone, Debug)]
pub struct RecordedRequest {
    pub method: String,
    pub path: String,
    pub query: String,
    pub auth: Option<String>,
    pub body: String,
}

#[derive(Clone, Default)]
struct InnerState {
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    buckets_by_name: Arc<Mutex<HashMap<String, String>>>, // name → id
    next_id: Arc<Mutex<u64>>,
    fail_next: Arc<Mutex<Option<StatusCode>>>,
}

pub struct MockAdminServer {
    addr: SocketAddr,
    state: InnerState,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

impl MockAdminServer {
    pub async fn start() -> Self {
        let state = InnerState::default();
        let app = Router::new()
            .route("/v1/status", get(handle_status))
            .route("/v1/bucket", post(handle_create_bucket))
            .route("/v1/bucket", delete(handle_delete_bucket))
            .route("/v1/bucket", get(handle_lookup_bucket))
            .route("/v1/bucket/allow", post(handle_allow))
            .route("/v1/bucket/deny", post(handle_deny))
            .route("/v1/bucket/{id}/website", post(handle_website))
            .fallback(any(handle_fallback))
            .with_state(state.clone());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = rx.await;
                })
                .await
                .unwrap();
        });
        Self {
            addr,
            state,
            _shutdown: tx,
        }
    }

    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.state.requests.lock().unwrap().clone()
    }

    pub fn clear_requests(&self) {
        self.state.requests.lock().unwrap().clear();
    }

    pub fn seed_bucket(&self, name: &str, id: &str) {
        self.state
            .buckets_by_name
            .lock()
            .unwrap()
            .insert(name.to_string(), id.to_string());
    }

    /// Make the NEXT admin call return the given status (then reset).
    pub fn fail_next_with(&self, status: StatusCode) {
        *self.state.fail_next.lock().unwrap() = Some(status);
    }
}

async fn record_and_maybe_fail(
    state: &InnerState,
    method: Method,
    path: &str,
    query: String,
    headers: HeaderMap,
    body: String,
) -> Option<StatusCode> {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    state.requests.lock().unwrap().push(RecordedRequest {
        method: method.to_string(),
        path: path.to_string(),
        query,
        auth,
        body,
    });
    state.fail_next.lock().unwrap().take()
}

async fn handle_status(State(state): State<InnerState>, headers: HeaderMap) -> impl IntoResponse {
    if let Some(s) = record_and_maybe_fail(
        &state,
        Method::GET,
        "/v1/status",
        String::new(),
        headers,
        String::new(),
    )
    .await
    {
        return (s, Json(json!({"error": "forced"}))).into_response();
    }
    Json(json!({"node":"mock","status":"Healthy"})).into_response()
}

async fn handle_create_bucket(
    State(state): State<InnerState>,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    if let Some(s) = record_and_maybe_fail(
        &state,
        Method::POST,
        "/v1/bucket",
        String::new(),
        headers,
        body.clone(),
    )
    .await
    {
        return (s, Json(json!({"error":"forced"}))).into_response();
    }
    let v: Value = serde_json::from_str(&body).unwrap_or(json!({}));
    let name = v
        .get("globalAlias")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let mut next = state.next_id.lock().unwrap();
    *next += 1;
    let id = format!("bkt-{}", *next);
    state
        .buckets_by_name
        .lock()
        .unwrap()
        .insert(name.clone(), id.clone());
    (
        StatusCode::OK,
        Json(json!({"id": id, "globalAliases": [name]})),
    )
        .into_response()
}

async fn handle_delete_bucket(
    State(state): State<InnerState>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let qs = serde_urlencoded::to_string(&q).unwrap_or_default();
    if let Some(s) = record_and_maybe_fail(
        &state,
        Method::DELETE,
        "/v1/bucket",
        qs,
        headers,
        String::new(),
    )
    .await
    {
        return (s, Json(json!({"error":"forced"}))).into_response();
    }
    if let Some(id) = q.get("id") {
        let mut map = state.buckets_by_name.lock().unwrap();
        map.retain(|_, v| v != id);
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn handle_lookup_bucket(
    State(state): State<InnerState>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let qs = serde_urlencoded::to_string(&q).unwrap_or_default();
    if let Some(s) = record_and_maybe_fail(
        &state,
        Method::GET,
        "/v1/bucket",
        qs,
        headers,
        String::new(),
    )
    .await
    {
        return (s, Json(json!({"error":"forced"}))).into_response();
    }
    if let Some(name) = q.get("globalAlias") {
        if let Some(id) = state.buckets_by_name.lock().unwrap().get(name) {
            return (
                StatusCode::OK,
                Json(json!({"id": id, "globalAliases": [name]})),
            )
                .into_response();
        }
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error":"bucket not found"})),
        )
            .into_response();
    }
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error":"missing globalAlias"})),
    )
        .into_response()
}

async fn handle_allow(
    State(state): State<InnerState>,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    if let Some(s) = record_and_maybe_fail(
        &state,
        Method::POST,
        "/v1/bucket/allow",
        String::new(),
        headers,
        body,
    )
    .await
    {
        return (s, Json(json!({"error":"forced"}))).into_response();
    }
    (StatusCode::OK, Json(json!({"ok": true}))).into_response()
}

async fn handle_deny(
    State(state): State<InnerState>,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    if let Some(s) = record_and_maybe_fail(
        &state,
        Method::POST,
        "/v1/bucket/deny",
        String::new(),
        headers,
        body,
    )
    .await
    {
        return (s, Json(json!({"error":"forced"}))).into_response();
    }
    (StatusCode::OK, Json(json!({"ok": true}))).into_response()
}

async fn handle_website(
    Path(id): Path<String>,
    State(state): State<InnerState>,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    let path = format!("/v1/bucket/{id}/website");
    if let Some(s) =
        record_and_maybe_fail(&state, Method::POST, &path, String::new(), headers, body).await
    {
        return (s, Json(json!({"error":"forced"}))).into_response();
    }
    (StatusCode::OK, Json(json!({"ok": true}))).into_response()
}

async fn handle_fallback(
    State(state): State<InnerState>,
    method: Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    state.requests.lock().unwrap().push(RecordedRequest {
        method: method.to_string(),
        path: uri.path().to_string(),
        query: uri.query().unwrap_or("").to_string(),
        auth: headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
        body,
    });
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({"error":"mock-unhandled"})),
    )
        .into_response()
}
