//! E4 (S-44) — a real `drop_collection` over `/t/<id>/mcp` closes the dropped
//! collection's live SSE streams.
//!
//! The subscribe handler gates once at connect and `publish` never re-checks
//! that gate, so before the fix an anon stream opened on `posts` stayed attached
//! to the same-name broadcast channel across a drop + recreate, and received
//! every row the RECREATED table wrote — even though the recreated table starts
//! realtime OFF and a fresh connect is refused. These tests drive the real
//! router (SSE route + MCP route on one shared EventBus).

#[path = "helpers.rs"]
mod helpers;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use eventsource_stream::Eventsource;
use futures::StreamExt;
use helpers::{grab_pool, spin_up_dual_role_self_register};
use serde_json::{Value, json};
use std::pin::Pin;
use std::time::Duration;
use tower::ServiceExt;

type SseEvents = Pin<Box<dyn futures::Stream<Item = eventsource_stream::Event> + Send>>;

// ── MCP plumbing (private per file, as in tests/mcp_merged_tools.rs) ────────

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
        json!({
            "jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":name,"arguments":args}
        }),
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

// ── SSE + record plumbing (as in tests/policy_sse.rs) ───────────────────────

/// `<coll>(status TEXT)` with anon select cap + realtime enabled.
async fn seed_realtime(dir: &tempfile::TempDir, tenant: &str, coll: &'static str) {
    let pool = grab_pool(tenant, dir).await;
    pool.with_writer(move |c| {
        c.execute_batch(&format!(
            "CREATE TABLE {coll} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
             );
             INSERT INTO _system_collection_meta
                  (collection_name, anon_caps_json)
                  VALUES ('{coll}', '[\"select\"]')
                  ON CONFLICT(collection_name) DO UPDATE SET
                    anon_caps_json = '[\"select\"]';"
        ))?;
        drust::storage::schema::write_realtime_enabled(c, coll, true)?;
        Ok::<_, rusqlite::Error>(())
    })
    .await
    .unwrap();
}

/// `POST /t/<id>/records/<coll>` as the service token.
async fn insert_row(app: &axum::Router, tid: &str, tok: &str, coll: &str, status: &str) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{tid}/records/{coll}"))
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({"data": {"status": status}}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "insert {status} into {coll} failed"
    );
}

async fn subscribe(
    app: &axum::Router,
    tid: &str,
    tok: &str,
    coll: &str,
) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .uri(format!("/t/{tid}/records/{coll}/subscribe"))
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::ACCEPT, "text/event-stream")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

/// Turn a 200 SSE response into a stream of parsed events. The stream ENDS
/// (yields `None`) when the server closes the response body.
fn events_of(resp: axum::response::Response) -> SseEvents {
    let (tx, rx) = tokio::sync::mpsc::channel(8);
    let mut body_stream = resp.into_body().into_data_stream();
    tokio::spawn(async move {
        while let Some(chunk) = body_stream.next().await {
            if let Ok(b) = chunk
                && tx.send(Ok::<_, std::io::Error>(b)).await.is_err()
            {
                break;
            }
        }
    });
    Box::pin(
        tokio_stream::wrappers::ReceiverStream::new(rx)
            .eventsource()
            .filter_map(|r| async move { r.ok() }),
    )
}

async fn open_stream(app: &axum::Router, tid: &str, tok: &str, coll: &str) -> SseEvents {
    let resp = subscribe(app, tid, tok, coll).await;
    assert_eq!(resp.status(), StatusCode::OK, "subscribe {coll} refused");
    events_of(resp)
}

fn record_status(ev: &eventsource_stream::Event) -> String {
    let v: Value = serde_json::from_str(&ev.data).unwrap();
    v["record"]["status"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

#[tokio::test]
async fn drop_then_recreate_closes_old_anon_stream_and_new_rows_do_not_leak() {
    let (app, tid, svc, anon, dir) = spin_up_dual_role_self_register("e4-drop-sse").await;
    seed_realtime(&dir, &tid, "posts").await;
    let mut events = open_stream(&app, &tid, &anon, "posts").await;

    let sid = mcp_init(&app, &tid, &svc).await;
    let dropped = mcp_call_tool(
        &app,
        &tid,
        &svc,
        &sid,
        "drop_collection",
        json!({"collection": "posts"}),
    )
    .await;
    assert!(
        dropped.contains("dropped_collection"),
        "drop failed: {dropped}"
    );
    // Recreate the same name through the production tool → realtime OFF.
    let created = mcp_call_tool(
        &app,
        &tid,
        &svc,
        &sid,
        "create_collection",
        json!({"name": "posts", "fields": [{"name": "status", "sql_type": "text"}]}),
    )
    .await;
    assert!(created.contains("posts"), "recreate failed: {created}");

    insert_row(&app, &tid, &svc, "posts", "secret").await;

    let next = tokio::time::timeout(Duration::from_secs(2), events.next()).await;
    match next {
        Ok(None) => {}
        Ok(Some(ev)) => panic!(
            "the pre-drop anon stream received an event from the recreated table: {} {}",
            ev.event, ev.data
        ),
        Err(_) => panic!("the pre-drop anon stream is still open after the drop"),
    }

    // A fresh connect gets the recreated table's own verdict.
    let again = subscribe(&app, &tid, &anon, "posts").await;
    assert_eq!(again.status(), StatusCode::FORBIDDEN);
    let bytes = axum::body::to_bytes(again.into_body(), 1 << 16)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["error_code"], "REALTIME_DISABLED");
}

#[tokio::test]
async fn drop_collection_dry_run_keeps_the_anon_stream() {
    let (app, tid, svc, anon, dir) = spin_up_dual_role_self_register("e4-dry-sse").await;
    seed_realtime(&dir, &tid, "posts").await;
    let mut events = open_stream(&app, &tid, &anon, "posts").await;

    let sid = mcp_init(&app, &tid, &svc).await;
    let preview = mcp_call_tool(
        &app,
        &tid,
        &svc,
        &sid,
        "drop_collection",
        json!({"collection": "posts", "dry_run": true}),
    )
    .await;
    assert!(preview.contains("would_drop"), "dry run failed: {preview}");

    insert_row(&app, &tid, &svc, "posts", "still-live").await;
    let next = tokio::time::timeout(Duration::from_secs(2), events.next()).await;
    let ev = match next {
        Ok(Some(ev)) => ev,
        other => panic!("dry_run must keep the stream open and delivering, got {other:?}"),
    };
    assert_eq!(ev.event, "created");
    assert_eq!(record_status(&ev), "still-live");

    let pool = grab_pool(&tid, &dir).await;
    let n: i64 = pool
        .with_reader(|c| {
            c.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='posts'",
                [],
                |r| r.get(0),
            )
        })
        .await
        .unwrap();
    assert_eq!(n, 1, "dry_run must not drop the table");
}

#[tokio::test]
async fn service_stream_on_other_collection_survives_a_drop() {
    let (app, tid, svc, _anon, dir) = spin_up_dual_role_self_register("e4-other-sse").await;
    seed_realtime(&dir, &tid, "posts").await;
    seed_realtime(&dir, &tid, "notes").await;
    let mut notes = open_stream(&app, &tid, &svc, "notes").await;

    let sid = mcp_init(&app, &tid, &svc).await;
    let dropped = mcp_call_tool(
        &app,
        &tid,
        &svc,
        &sid,
        "drop_collection",
        json!({"collection": "posts"}),
    )
    .await;
    assert!(
        dropped.contains("dropped_collection"),
        "drop failed: {dropped}"
    );

    insert_row(&app, &tid, &svc, "notes", "kept").await;
    let next = tokio::time::timeout(Duration::from_secs(2), notes.next()).await;
    let ev = match next {
        Ok(Some(ev)) => ev,
        other => panic!("a sibling collection's stream must survive the drop, got {other:?}"),
    };
    assert_eq!(ev.event, "created");
    assert_eq!(record_status(&ev), "kept");
}
