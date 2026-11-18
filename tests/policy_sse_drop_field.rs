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
//! first touches `posts`, and the drop goes THROUGH the app's account-level
//! MCP so the app's cache is invalidated the way a real caller sees it.

#[path = "helpers.rs"]
mod helpers;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::storage::schema::DmlVerb;
use eventsource_stream::Eventsource;
use futures::StreamExt;
use helpers::grab_pool;
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

/// The account harness with self-registration on (the fixture these tests
/// were written against had it on).
async fn harness(t: &'static str) -> helpers::AccountMcpHarness {
    let h = helpers::spin_up_account_mcp(t).await;
    helpers::account_allow_self_register(&h).await;
    h
}

/// `drop_field posts.<field>` through the app's account-level MCP → the
/// parsed tool result.
async fn mcp_drop_field(h: &helpers::AccountMcpHarness, field: &str) -> Value {
    let out = helpers::mcp_tool_text(
        &h.app,
        &h.access,
        &h.tid,
        "drop_field",
        json!({"collection": "posts", "field": field}),
    )
    .await;
    serde_json::from_str(&out).unwrap_or_else(|_| panic!("drop_field did not succeed: {out}"))
}

// ── Tests ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn inflight_anon_sse_goes_silent_after_a_policy_field_is_dropped() {
    let h = harness("e6-inflight").await;
    seed(&h.dir, &h.tid, json!({"x": {"$is_null": true}})).await;
    let mut events = open_sse(&h.app, &h.tid, &h.anon).await;

    // Before the drop the policy works: `hidden` (x set) is filtered.
    let hidden = insert_post(
        &h.app,
        &h.tid,
        &h.svc,
        json!({"status": "hidden", "x": "h"}),
    )
    .await;
    insert_post(&h.app, &h.tid, &h.svc, json!({"status": "visible"})).await;
    let first = next_event(&mut events).await;
    assert_eq!(
        first["record"]["status"], "visible",
        "pre-drop: the policy must hide `hidden`"
    );

    let drop = mcp_drop_field(&h, "x").await;
    assert_eq!(drop["dropped_field"], "x");

    // After the drop every event row lacks `x`: none may pass.
    insert_post(&h.app, &h.tid, &h.svc, json!({"status": "after"})).await;
    assert_eq!(
        patch_post(&h.app, &h.tid, &h.svc, hidden, json!({"status": "after2"})).await,
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
    let h = harness("e6-reconnect").await;
    seed(&h.dir, &h.tid, json!({"x": {"$is_null": true}})).await;
    mcp_drop_field(&h, "x").await;

    // Connect-time does not compile the policy: still 200 (no new 4xx/5xx).
    let mut events = open_sse(&h.app, &h.tid, &h.anon).await;
    insert_post(&h.app, &h.tid, &h.svc, json!({"status": "after"})).await;
    assert_silent_but_open(&mut events, "anon reconnected after drop").await;
}

#[tokio::test]
async fn service_sse_still_receives_every_event_after_the_drop() {
    let h = harness("e6-service").await;
    seed(&h.dir, &h.tid, json!({"x": {"$is_null": true}})).await;
    mcp_drop_field(&h, "x").await;

    let mut events = open_sse(&h.app, &h.tid, &h.svc).await;
    insert_post(&h.app, &h.tid, &h.svc, json!({"status": "after"})).await;
    let ev = next_event(&mut events).await;
    assert_eq!(ev["record"]["status"], "after");
    assert!(
        ev["record"].get("x").is_none(),
        "the dropped column is gone from the row: {ev}"
    );
}

#[tokio::test]
async fn dropping_an_unreferenced_field_changes_nothing() {
    let h = harness("e6-unref").await;
    seed(&h.dir, &h.tid, json!({"status": "published"})).await;
    let mut events = open_sse(&h.app, &h.tid, &h.anon).await;

    let drop = mcp_drop_field(&h, "y").await;
    assert_eq!(drop["dropped_field"], "y");
    assert!(drop.get("warnings").is_none(), "nothing to report: {drop}");

    insert_post(&h.app, &h.tid, &h.svc, json!({"status": "draft"})).await;
    insert_post(&h.app, &h.tid, &h.svc, json!({"status": "published"})).await;
    let first = next_event(&mut events).await;
    assert_eq!(first["record"]["status"], "published");
    assert_silent_but_open(&mut events, "draft must stay filtered").await;
}

#[tokio::test]
async fn sql_face_still_fails_closed_after_the_drop() {
    let h = harness("e6-sql").await;
    seed(&h.dir, &h.tid, json!({"x": {"$is_null": true}})).await;
    insert_post(&h.app, &h.tid, &h.svc, json!({"status": "a"})).await;
    insert_post(&h.app, &h.tid, &h.svc, json!({"status": "b", "x": "set"})).await;
    mcp_drop_field(&h, "x").await;

    let (status, body) = list_posts(&h.app, &h.tid, &h.anon).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    assert_eq!(body["error_code"], "POLICY_COMPILE_ERROR", "{body}");

    let (status, body) = list_posts(&h.app, &h.tid, &h.svc).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["records"].as_array().map(Vec::len),
        Some(2),
        "service reads every row: {body}"
    );
}
