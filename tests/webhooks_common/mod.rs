//! Local fake HTTP server for webhook tests. One per test (call
//! `FakeHook::start()`); records every request, supports scripted
//! per-call responses for retry behaviour tests.

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::post;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub struct Received {
    pub method: String,
    pub headers: HashMap<String, String>,
    pub body_text: String,
}

#[derive(Default)]
struct State_ {
    received: Vec<Received>,
    /// Sequence of status codes to return; pops one per request.
    /// When empty, returns 200.
    response_seq: std::collections::VecDeque<u16>,
}

pub struct FakeHook {
    base_url: String,
    state: Arc<Mutex<State_>>,
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for FakeHook {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

impl FakeHook {
    pub async fn start() -> Self {
        Self::start_scripted(vec![]).await
    }

    /// Start with a fixed response code sequence; consumed in order, then
    /// further requests get 200.
    pub async fn start_scripted(seq: Vec<u16>) -> Self {
        let state = Arc::new(Mutex::new(State_ {
            received: Vec::new(),
            response_seq: seq.into(),
        }));
        let router = Router::new()
            .route("/hook", post(handle))
            .with_state(state.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        Self {
            base_url: format!("http://{}/hook", addr),
            state,
            handle,
        }
    }

    pub fn url(&self) -> &str {
        &self.base_url
    }

    pub async fn requests(&self) -> Vec<Received> {
        self.state.lock().await.received.clone()
    }
}

async fn handle(State(s): State<Arc<Mutex<State_>>>, req: Request) -> impl IntoResponse {
    let (parts, body) = req.into_parts();
    let body_bytes = axum::body::to_bytes(body, 1_048_576)
        .await
        .unwrap_or_default();
    let body_text = String::from_utf8_lossy(&body_bytes).to_string();
    let mut headers = HashMap::new();
    for (k, v) in parts.headers.iter() {
        if let Ok(vs) = v.to_str() {
            headers.insert(k.as_str().to_string(), vs.to_string());
        }
    }
    let r = Received {
        method: parts.method.to_string(),
        headers,
        body_text,
    };
    let mut g = s.lock().await;
    g.received.push(r);
    let code = g.response_seq.pop_front().unwrap_or(200);
    (
        StatusCode::from_u16(code).unwrap_or(StatusCode::OK),
        Body::empty(),
    )
}
