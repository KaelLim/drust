//! RLS Phase 7 (SSE) — per-event select-policy USING filter for anon
//! subscribers.
//!
//! A `select` policy `{"using":{"status":"published"}}` on a realtime
//! collection must filter the SSE event stream for an anon subscriber:
//! the `draft` insert must be dropped, the `published` insert delivered.
//! Service subscribers bypass the filter (covered indirectly by the
//! existing SSE suite); users are denied at the gate. Deleted events
//! (id-only) always pass — documented v1 limitation.
//!
//! Until Task 17 (the REST `set_policy`) lands, the policy is written
//! directly via `storage::schema::write_policy` + `schema_cache.invalidate`
//! per the plan's Test Harness appendix.

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

/// `posts(status TEXT)` with anon select cap + realtime enabled.
async fn seed_realtime_posts(dir: &tempfile::TempDir, tenant: &str) {
    let pool = grab_pool(tenant, dir).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                status TEXT NOT NULL,
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
        Ok::<_, rusqlite::Error>(())
    })
    .await
    .unwrap();
}

/// Write a select-policy USING directly (pre-Task-17) + invalidate cache.
async fn set_select_using(dir: &tempfile::TempDir, tenant: &str, coll: &str, policy_json: Value) {
    let pool = grab_pool(tenant, dir).await;
    let policy: drust::query::policy::Policy = serde_json::from_value(policy_json).unwrap();
    let coll_owned = coll.to_string();
    pool.with_writer(move |c| {
        drust::storage::schema::write_policy(c, &coll_owned, DmlVerb::Select, Some(&policy))
    })
    .await
    .unwrap();
    pool.schema_cache.invalidate(coll);
}

/// `POST /t/<id>/records/posts` as the service token.
async fn insert_post(app: &axum::Router, tid: &str, tok: &str, status: &str) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{tid}/records/posts"))
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({"data": {"status": status}}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED, "insert {status} failed");
}

#[tokio::test]
async fn anon_sse_only_gets_policy_matching_events() {
    let (app, tid, svc, anon, dir) = spin_up_dual_role_self_register("policy-sse").await;
    seed_realtime_posts(&dir, &tid).await;
    set_select_using(&dir, &tid, "posts", json!({"using": {"status": "published"}})).await;

    // Open the anon SSE stream.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/t/{tid}/records/posts/subscribe"))
                .header(header::AUTHORIZATION, format!("Bearer {anon}"))
                .header(header::ACCEPT, "text/event-stream")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Stream the body as SSE events.
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
    let mut events = bytes_stream.eventsource();

    // Insert a draft (must be filtered out) then a published (must arrive).
    let app2 = app.clone();
    let tid2 = tid.clone();
    let svc2 = svc.clone();
    let inserter = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        insert_post(&app2, &tid2, &svc2, "draft").await;
        insert_post(&app2, &tid2, &svc2, "published").await;
    });

    // The FIRST event that reaches the anon subscriber must be `published`
    // — the `draft` event was dropped by the per-event USING filter.
    let ev = tokio::time::timeout(Duration::from_secs(2), events.next())
        .await
        .expect("timeout waiting for first event")
        .expect("stream closed")
        .expect("sse parse error");
    inserter.await.unwrap();
    let data: Value = serde_json::from_str(&ev.data).unwrap();
    assert_eq!(
        data["record"]["status"], "published",
        "first delivered event must be the published row; draft must have been filtered out"
    );

    // No further event arrives (the draft was filtered, not merely reordered).
    let next = tokio::time::timeout(Duration::from_millis(300), events.next()).await;
    assert!(
        next.is_err(),
        "no second event should arrive — draft event must have been filtered out, got {next:?}"
    );
}
