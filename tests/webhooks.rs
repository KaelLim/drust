mod webhooks_common;
mod helpers;
use webhooks_common::FakeHook;
use drust::tenant::webhook_dispatcher::{
    compute_signature, deliver_for_test, DeliverySchedule, WebhookRow,
};
use helpers::spin_up_tenant_with_role;
use axum::body::Body;
use axum::http::{Request, header};
use tower::ServiceExt;

fn fake_row(url: &str) -> WebhookRow {
    WebhookRow {
        id: 1,
        collection: "videos".into(),
        events: r#"["created"]"#.into(),
        url: url.into(),
        secret: "topsecret".into(),
        active: 1,
    }
}

#[tokio::test]
async fn fake_hook_records_post_with_body() {
    let hook = FakeHook::start().await;
    let body = serde_json::json!({"hi":"there"}).to_string();
    let resp = reqwest::Client::new()
        .post(hook.url())
        .header("Content-Type", "application/json")
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);

    let received = hook.requests().await;
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].body_text, body);
    assert_eq!(
        received[0].headers.get("content-type").map(|s| s.as_str()),
        Some("application/json"),
    );
}

#[tokio::test]
async fn deliver_happy_path_signature_matches() {
    let hook = FakeHook::start().await;
    let payload = serde_json::json!({"event":"created","record":{"id":1}});
    let body_bytes = serde_json::to_vec(&payload).unwrap();
    let expected_sig = compute_signature("topsecret", &body_bytes);
    let outcome = deliver_for_test(
        &reqwest::Client::new(),
        &fake_row(hook.url()),
        body_bytes.clone(),
        DeliverySchedule::fast_for_tests(),
    )
    .await;
    assert!(outcome.is_ok(), "happy path must succeed");
    let received = hook.requests().await;
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].headers.get("x-drust-signature").unwrap(), &expected_sig);
}

#[tokio::test]
async fn deliver_retries_on_5xx_then_succeeds() {
    let hook = FakeHook::start_scripted(vec![500, 503]).await; // then 200
    let outcome = deliver_for_test(
        &reqwest::Client::new(),
        &fake_row(hook.url()),
        b"{}".to_vec(),
        DeliverySchedule::fast_for_tests(),
    )
    .await;
    assert!(outcome.is_ok(), "must succeed on 3rd attempt");
    assert_eq!(hook.requests().await.len(), 3);
}

#[tokio::test]
async fn deliver_stops_on_4xx() {
    let hook = FakeHook::start_scripted(vec![401]).await;
    let outcome = deliver_for_test(
        &reqwest::Client::new(),
        &fake_row(hook.url()),
        b"{}".to_vec(),
        DeliverySchedule::fast_for_tests(),
    )
    .await;
    assert!(outcome.is_err(), "4xx must be terminal");
    assert_eq!(hook.requests().await.len(), 1, "no retry on 4xx");
}

#[tokio::test]
async fn deliver_all_four_attempts_fail_returns_err() {
    let hook = FakeHook::start_scripted(vec![500, 500, 500, 500]).await;
    let outcome = deliver_for_test(
        &reqwest::Client::new(),
        &fake_row(hook.url()),
        b"{}".to_vec(),
        DeliverySchedule::fast_for_tests(),
    )
    .await;
    assert!(outcome.is_err(), "4 consecutive 5xx must fail");
    assert_eq!(hook.requests().await.len(), 4);
}

// ── End-to-end dispatch tests ─────────────────────────────────────────────

/// Insert a webhook subscription directly into the tenant's data.sqlite,
/// then POST a record via the REST API and verify the FakeHook receives
/// exactly one delivery with the correct event+record shape.
#[tokio::test]
async fn creating_record_fires_subscribed_webhook() {
    let tid = "t-disp";
    let hook = FakeHook::start().await;
    let (app, svc, dir) = spin_up_tenant_with_role(tid, "service").await;

    // Create the `notes` collection via direct SQL (no REST POST /collections).
    let pool = helpers::grab_pool(tid, &dir).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );",
        )
    })
    .await
    .unwrap();

    // Insert webhook subscription via direct SQL.
    pool.with_writer(|c| {
        c.execute(
            "INSERT INTO _system_webhooks(collection,events,url,secret,active,created_at)
             VALUES('notes','[\"created\"]',?1,'topsecret',1,'2026-01-01T00:00:00Z')",
            rusqlite::params![hook.url()],
        )?;
        Ok(())
    })
    .await
    .unwrap();

    // POST a record — this fires the dispatcher.
    let body = serde_json::json!({"data": {"title":"hello"}});
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{tid}/records/notes"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {svc}"))
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 201);

    // Wait for spawned delivery (up to 2 s in 50 ms steps).
    for _ in 0..40 {
        if !hook.requests().await.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    let reqs = hook.requests().await;
    assert_eq!(reqs.len(), 1, "exactly one webhook delivery");
    let v: serde_json::Value = serde_json::from_str(&reqs[0].body_text).unwrap();
    assert_eq!(v["collection"], "notes");
    assert_eq!(v["event"], "created");
    assert_eq!(v["record"]["title"], "hello");
    assert_eq!(v["tenant"], tid);
}

/// Verify that a 4xx response from the subscriber URL causes
/// `last_failure_reason` to be written to `_system_webhooks` via the
/// production `deliver()` path (not `deliver_for_test`).
#[tokio::test]
async fn deliver_records_failure_on_4xx_via_production_path() {
    let tid = "t-fail4xx";
    let hook = FakeHook::start_scripted(vec![401]).await;
    let (app, svc, dir) = spin_up_tenant_with_role(tid, "service").await;

    // Create collection + insert subscription via direct SQL.
    let pool = helpers::grab_pool(tid, &dir).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                note TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );",
        )
    })
    .await
    .unwrap();

    // Insert webhook subscription pointing at the scripted 401 server.
    pool.with_writer(|c| {
        c.execute(
            "INSERT INTO _system_webhooks(collection,events,url,secret,active,created_at)
             VALUES('notes','[\"created\"]',?1,'topsecret',1,'2026-01-01T00:00:00Z')",
            rusqlite::params![hook.url()],
        )?;
        Ok(())
    })
    .await
    .unwrap();

    // POST a record to trigger dispatch.
    let body = serde_json::json!({"data": {"note":"oops"}});
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{tid}/records/notes"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {svc}"))
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 201);

    // Wait for the spawned delivery + DB write (up to 2 s).
    let mut reason: Option<String> = None;
    for _ in 0..40 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let r = pool
            .with_reader(|c| {
                c.query_row(
                    "SELECT last_failure_reason FROM _system_webhooks WHERE id = 1",
                    [],
                    |row| row.get::<_, Option<String>>(0),
                )
            })
            .await
            .ok()
            .flatten();
        if r.is_some() {
            reason = r;
            break;
        }
    }

    let reason = reason.expect("last_failure_reason must be set after 4xx delivery");
    assert!(
        reason.contains("4xx"),
        "reason should mention '4xx', got: {reason}"
    );
}
