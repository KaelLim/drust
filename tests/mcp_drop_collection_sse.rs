//! E4 (S-44) — a real `drop_collection` over the account-level `/mcp` closes the dropped
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
use serde_json::{Value, json};
use std::pin::Pin;
use std::time::Duration;
use tower::ServiceExt;

type SseEvents = Pin<Box<dyn futures::Stream<Item = eventsource_stream::Event> + Send>>;

// ── MCP plumbing ────────────────────────────────────────────────────────────

/// The account harness with self-registration on (the fixture these tests
/// were written against had it on).
async fn harness(t: &'static str) -> helpers::AccountMcpHarness {
    let h = helpers::spin_up_account_mcp(t).await;
    helpers::account_allow_self_register(&h).await;
    h
}

/// The first content text of a `tools/call` on the account endpoint.
async fn tool(h: &helpers::AccountMcpHarness, name: &str, args: Value) -> String {
    helpers::mcp_tool_text(&h.app, &h.access, &h.tid, name, args).await
}

// ── SSE + record plumbing (as in tests/policy_sse.rs) ───────────────────────

/// `<coll>(status TEXT)` with anon select cap + realtime enabled.
async fn seed_realtime(h: &helpers::AccountMcpHarness, coll: &'static str) {
    let pool = h.tenants.get_or_create(&h.tid).unwrap();
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
    let h = harness("e4-drop-sse").await;
    seed_realtime(&h, "posts").await;
    let mut events = open_stream(&h.app, &h.tid, &h.anon, "posts").await;

    let dropped = tool(&h, "drop_collection", json!({"collection": "posts"})).await;
    assert!(
        dropped.contains("dropped_collection"),
        "drop failed: {dropped}"
    );
    // Recreate the same name through the production tool → realtime OFF.
    let created = tool(
        &h,
        "create_collection",
        json!({"name": "posts", "fields": [{"name": "status", "sql_type": "text"}]}),
    )
    .await;
    assert!(created.contains("posts"), "recreate failed: {created}");

    insert_row(&h.app, &h.tid, &h.svc, "posts", "secret").await;

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
    let again = subscribe(&h.app, &h.tid, &h.anon, "posts").await;
    assert_eq!(again.status(), StatusCode::FORBIDDEN);
    let bytes = axum::body::to_bytes(again.into_body(), 1 << 16)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["error_code"], "REALTIME_DISABLED");
}

#[tokio::test]
async fn drop_collection_dry_run_keeps_the_anon_stream() {
    let h = harness("e4-dry-sse").await;
    seed_realtime(&h, "posts").await;
    let mut events = open_stream(&h.app, &h.tid, &h.anon, "posts").await;

    let preview = tool(
        &h,
        "drop_collection",
        json!({"collection": "posts", "dry_run": true}),
    )
    .await;
    assert!(preview.contains("would_drop"), "dry run failed: {preview}");

    insert_row(&h.app, &h.tid, &h.svc, "posts", "still-live").await;
    let next = tokio::time::timeout(Duration::from_secs(2), events.next()).await;
    let ev = match next {
        Ok(Some(ev)) => ev,
        other => panic!("dry_run must keep the stream open and delivering, got {other:?}"),
    };
    assert_eq!(ev.event, "created");
    assert_eq!(record_status(&ev), "still-live");

    let pool = h.tenants.get_or_create(&h.tid).unwrap();
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
    let h = harness("e4-other-sse").await;
    seed_realtime(&h, "posts").await;
    seed_realtime(&h, "notes").await;
    let mut notes = open_stream(&h.app, &h.tid, &h.svc, "notes").await;

    let dropped = tool(&h, "drop_collection", json!({"collection": "posts"})).await;
    assert!(
        dropped.contains("dropped_collection"),
        "drop failed: {dropped}"
    );

    insert_row(&h.app, &h.tid, &h.svc, "notes", "kept").await;
    let next = tokio::time::timeout(Duration::from_secs(2), notes.next()).await;
    let ev = match next {
        Ok(Some(ev)) => ev,
        other => panic!("a sibling collection's stream must survive the drop, got {other:?}"),
    };
    assert_eq!(ev.event, "created");
    assert_eq!(record_status(&ev), "kept");
}
