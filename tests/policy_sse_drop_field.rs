//! E6′ — dropping a field that the select policy names must not open the anon
//! SSE stream.
//!
//! The realtime face filters anon events in memory. Before the fix it used
//! `eval_policy`, which reads a key absent from the event row as NULL, so after
//! `drop_field x` a policy such as `{"x":{"$is_null":true}}` admitted every row
//! while `/list` for the same caller refused the read (`POLICY_COMPILE_ERROR`).
//! Now SSE evaluates through `eval_policy_materialized`: a policy naming a field
//! the materialized `RETURNING *` row does not carry is denied whole.
//!
//! Ordering trap (see `policy_sse.rs`): `grab_pool` is a SEPARATE registry with
//! its own schema cache, so the seed and the policy are written before the app
//! first touches `posts`, and the drop goes THROUGH the app's MCP so the app's
//! cache is invalidated the way a real caller sees it.

#[path = "helpers.rs"]
mod helpers;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::storage::schema::DmlVerb;
use eventsource_stream::Eventsource;
use futures::StreamExt;
use helpers::{grab_pool, spin_up_dual_role_self_register};
use serde_json::{Value, json};
use std::time::Duration;
use tower::ServiceExt;

/// How long "no event" is waited for.
const QUIET: Duration = Duration::from_millis(500);

/// `posts(status, x, y)` with anon select cap + realtime enabled + a select
/// policy `using`, all written before the app's first read of `posts`.
async fn seed(dir: &tempfile::TempDir, tenant: &str, using: Value) {
    let pool = grab_pool(tenant, dir).await;
    let policy: drust::query::policy::Policy =
        serde_json::from_value(json!({ "using": using })).unwrap();
    pool.with_writer(move |c| {
        c.execute_batch(
            "CREATE TABLE posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                status TEXT NOT NULL,
                x TEXT,
                y TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
             );
             INSERT INTO _system_collection_meta
                  (collection_name, anon_caps_json)
                  VALUES ('posts', '[\"select\"]')
                  ON CONFLICT(collection_name) DO UPDATE SET
                    anon_caps_json = '[\"select\"]';",
        )?;
        drust::storage::schema::write_realtime_enabled(c, "posts", true)?;
        drust::storage::schema::write_policy(c, "posts", DmlVerb::Select, Some(&policy))
    })
    .await
    .unwrap();
    pool.schema_cache.invalidate("posts");
}

type SseStream = std::pin::Pin<
    Box<
        dyn futures::Stream<
                Item = Result<
                    eventsource_stream::Event,
                    eventsource_stream::EventStreamError<std::io::Error>,
                >,
            > + Send,
    >,
>;

/// Open `GET /t/<id>/records/posts/subscribe`; asserts 200.
async fn open_sse(app: &axum::Router, tid: &str, tok: &str) -> SseStream {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/t/{tid}/records/posts/subscribe"))
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::ACCEPT, "text/event-stream")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "subscribe must answer 200");
    let body = resp.into_body();
    let bytes_stream = tokio_stream::wrappers::ReceiverStream::new({
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        let mut body_stream = body.into_data_stream();
        tokio::spawn(async move {
            while let Some(chunk) = body_stream.next().await {
                if let Ok(b) = chunk {
                    let _ = tx.send(Ok::<_, std::io::Error>(b)).await;
                }
            }
        });
        rx
    });
    Box::pin(bytes_stream.eventsource())
}

/// The next event's JSON `data`, within 2 s.
async fn next_event(events: &mut SseStream) -> Value {
    let ev = tokio::time::timeout(Duration::from_secs(2), events.next())
        .await
        .expect("timeout waiting for an event")
        .expect("stream closed")
        .expect("sse parse error");
    serde_json::from_str(&ev.data).unwrap()
}

/// No event within `QUIET`, AND the stream is still open (`Ok(None)` would
/// mean the subscriber was disconnected — this fix must not evict).
async fn assert_silent_but_open(events: &mut SseStream, why: &str) {
    match tokio::time::timeout(QUIET, events.next()).await {
        Err(_) => {}
        Ok(None) => panic!("{why}: the stream was closed — a drop must not evict"),
        Ok(Some(ev)) => panic!("{why}: an event leaked: {ev:?}"),
    }
}

/// `POST /t/<id>/records/posts` as the service token → the new row's id.
async fn insert_post(app: &axum::Router, tid: &str, tok: &str, data: Value) -> i64 {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{tid}/records/posts"))
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({ "data": data }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED, "insert {data} failed");
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    v["record"]["id"]
        .as_i64()
        .expect("insert response carries id")
}

/// `PATCH /t/<id>/records/posts/<id>` as the service token → status.
async fn patch_post(app: &axum::Router, tid: &str, tok: &str, id: i64, data: Value) -> StatusCode {
    app.clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/t/{tid}/records/posts/{id}"))
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({ "data": data }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

/// `POST /t/<id>/collections/posts/list` → (status, body).
async fn list_posts(app: &axum::Router, tid: &str, tok: &str) -> (StatusCode, Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{tid}/collections/posts/list"))
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

// ── MCP plumbing (drop_field is service-only MCP) ──────────────────────

fn mcp_req_with_session(tid: &str, token: &str, sid: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!("/t/{tid}/mcp"))
        .header(header::HOST, "127.0.0.1")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header("mcp-session-id", sid)
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn parse_mcp_response(resp: axum::response::Response) -> Vec<Value> {
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&bytes);
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.strip_prefix("data:").unwrap_or(line).trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<Value>(line) {
            out.push(v);
        }
    }
    out
}

async fn mcp_init(app: &axum::Router, tid: &str, token: &str) -> String {
    let init = Request::builder()
        .method("POST")
        .uri(format!("/t/{tid}/mcp"))
        .header(header::HOST, "127.0.0.1")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .body(Body::from(
            json!({
                "jsonrpc":"2.0","id":1,"method":"initialize",
                "params":{"protocolVersion":"2024-11-05","capabilities":{},
                          "clientInfo":{"name":"test","version":"0"}}
            })
            .to_string(),
        ))
        .unwrap();
    let r = app.clone().oneshot(init).await.unwrap();
    assert_eq!(r.status(), StatusCode::OK, "initialize failed");
    let sid = r
        .headers()
        .get("mcp-session-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let _ = parse_mcp_response(r).await;
    let ack = mcp_req_with_session(
        tid,
        token,
        &sid,
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    );
    let _ = app.clone().oneshot(ack).await.unwrap();
    sid
}

async fn mcp_call_tool(
    app: &axum::Router,
    tid: &str,
    token: &str,
    sid: &str,
    name: &str,
    args: Value,
) -> String {
    let call = mcp_req_with_session(
        tid,
        token,
        sid,
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call",
               "params":{"name":name,"arguments":args}}),
    );
    let resp = app.clone().oneshot(call).await.unwrap();
    assert!(
        resp.status().is_success(),
        "tools/call {name} status {}",
        resp.status()
    );
    let msgs = parse_mcp_response(resp).await;
    msgs.iter()
        .find_map(|m| {
            m["result"]["content"]
                .as_array()
                .and_then(|a| a.first())
                .and_then(|c| c["text"].as_str())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| serde_json::to_string(&msgs).unwrap())
}

/// `drop_field posts.<field>` through the app's MCP → the parsed tool result.
async fn mcp_drop_field(app: &axum::Router, tid: &str, svc: &str, field: &str) -> Value {
    let sid = mcp_init(app, tid, svc).await;
    let out = mcp_call_tool(
        app,
        tid,
        svc,
        &sid,
        "drop_field",
        json!({"collection": "posts", "field": field}),
    )
    .await;
    serde_json::from_str(&out).unwrap_or_else(|_| panic!("drop_field did not succeed: {out}"))
}

// ── Tests ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn inflight_anon_sse_goes_silent_after_a_policy_field_is_dropped() {
    let (app, tid, svc, anon, dir) = spin_up_dual_role_self_register("e6-inflight").await;
    seed(&dir, &tid, json!({"x": {"$is_null": true}})).await;
    let mut events = open_sse(&app, &tid, &anon).await;

    // Before the drop the policy works: `hidden` (x set) is filtered.
    let hidden = insert_post(&app, &tid, &svc, json!({"status": "hidden", "x": "h"})).await;
    insert_post(&app, &tid, &svc, json!({"status": "visible"})).await;
    let first = next_event(&mut events).await;
    assert_eq!(
        first["record"]["status"], "visible",
        "pre-drop: the policy must hide `hidden`"
    );

    let drop = mcp_drop_field(&app, &tid, &svc, "x").await;
    assert_eq!(drop["dropped_field"], "x");

    // After the drop every event row lacks `x`: none may pass.
    insert_post(&app, &tid, &svc, json!({"status": "after"})).await;
    assert_eq!(
        patch_post(&app, &tid, &svc, hidden, json!({"status": "after2"})).await,
        StatusCode::OK,
        "the write must really happen, else silence proves nothing"
    );
    assert_silent_but_open(&mut events, "in-flight anon after drop").await;

    // The drop still succeeded, and said why the stream went quiet — exactly
    // once: only the select policy's `using` clause names `x`.
    assert_eq!(drop["warnings"].as_array().map(Vec::len), Some(1), "{drop}");
    let w = &drop["warnings"][0];
    assert_eq!(w["code"], "FIELD_REFERENCED_BY_POLICY", "{drop}");
    assert_eq!(w["op"], "select", "{drop}");
    assert_eq!(w["clause"], "using", "{drop}");
    assert_eq!(w["field"], "x", "{drop}");
}

#[tokio::test]
async fn anon_sse_reconnect_after_the_drop_is_200_and_silent() {
    let (app, tid, svc, anon, dir) = spin_up_dual_role_self_register("e6-reconnect").await;
    seed(&dir, &tid, json!({"x": {"$is_null": true}})).await;
    mcp_drop_field(&app, &tid, &svc, "x").await;

    // Connect-time does not compile the policy: still 200 (no new 4xx/5xx).
    let mut events = open_sse(&app, &tid, &anon).await;
    insert_post(&app, &tid, &svc, json!({"status": "after"})).await;
    assert_silent_but_open(&mut events, "anon reconnected after drop").await;
}

#[tokio::test]
async fn service_sse_still_receives_every_event_after_the_drop() {
    let (app, tid, svc, _anon, dir) = spin_up_dual_role_self_register("e6-service").await;
    seed(&dir, &tid, json!({"x": {"$is_null": true}})).await;
    mcp_drop_field(&app, &tid, &svc, "x").await;

    let mut events = open_sse(&app, &tid, &svc).await;
    insert_post(&app, &tid, &svc, json!({"status": "after"})).await;
    let ev = next_event(&mut events).await;
    assert_eq!(ev["record"]["status"], "after");
    assert!(
        ev["record"].get("x").is_none(),
        "the dropped column is gone from the row: {ev}"
    );
}

#[tokio::test]
async fn dropping_an_unreferenced_field_changes_nothing() {
    let (app, tid, svc, anon, dir) = spin_up_dual_role_self_register("e6-unref").await;
    seed(&dir, &tid, json!({"status": "published"})).await;
    let mut events = open_sse(&app, &tid, &anon).await;

    let drop = mcp_drop_field(&app, &tid, &svc, "y").await;
    assert_eq!(drop["dropped_field"], "y");
    assert!(drop.get("warnings").is_none(), "nothing to report: {drop}");

    insert_post(&app, &tid, &svc, json!({"status": "draft"})).await;
    insert_post(&app, &tid, &svc, json!({"status": "published"})).await;
    let first = next_event(&mut events).await;
    assert_eq!(first["record"]["status"], "published");
    assert_silent_but_open(&mut events, "draft must stay filtered").await;
}

#[tokio::test]
async fn sql_face_still_fails_closed_after_the_drop() {
    let (app, tid, svc, anon, dir) = spin_up_dual_role_self_register("e6-sql").await;
    seed(&dir, &tid, json!({"x": {"$is_null": true}})).await;
    insert_post(&app, &tid, &svc, json!({"status": "a"})).await;
    insert_post(&app, &tid, &svc, json!({"status": "b", "x": "set"})).await;
    mcp_drop_field(&app, &tid, &svc, "x").await;

    let (status, body) = list_posts(&app, &tid, &anon).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    assert_eq!(body["error_code"], "POLICY_COMPILE_ERROR", "{body}");

    let (status, body) = list_posts(&app, &tid, &svc).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["records"].as_array().map(Vec::len),
        Some(2),
        "service reads every row: {body}"
    );
}
