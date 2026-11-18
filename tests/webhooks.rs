mod helpers;
use crate::webhooks_common;
use axum::body::Body;
use axum::http::{Request, header};
use drust::tenant::webhook_dispatcher::{
    DeliverySchedule, WebhookRow, compute_signature, deliver_for_test,
};
use helpers::spin_up_tenant_with_role;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use std::sync::Arc;
use tower::ServiceExt;
use webhooks_common::FakeHook;

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

/// Permissive mock resolver — lets every host resolve via stdlib DNS with
/// no public-IP filtering. v1.21 swapped `deliver_for_test`'s first arg
/// from `&reqwest::Client` to `Arc<dyn Resolve>`; for `127.0.0.1`-backed
/// FakeHook tests the dispatcher's `is_loopback_dev` bypass means this
/// resolver is never actually called, but it is still required for type
/// compatibility.
#[derive(Clone)]
struct AllowAllResolver;
impl Resolve for AllowAllResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            use std::net::ToSocketAddrs;
            let addrs: Vec<_> = (host.as_str(), 0u16)
                .to_socket_addrs()
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?
                .collect();
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

fn mock_resolver() -> Arc<dyn Resolve + Send + Sync> {
    Arc::new(AllowAllResolver)
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
        mock_resolver(),
        None,
        &fake_row(hook.url()),
        body_bytes.clone(),
        "test-delivery-id".to_string(),
        "1970-01-01T00:00:00Z".to_string(),
        DeliverySchedule::fast_for_tests(),
    )
    .await;
    assert!(outcome.is_ok(), "happy path must succeed");
    let received = hook.requests().await;
    assert_eq!(received.len(), 1);
    assert_eq!(
        received[0]
            .headers
            .get("x-drust-signature")
            .map(|s| s.as_str()),
        Some(expected_sig.as_str()),
        "header must echo the computed HMAC signature",
    );
    assert_eq!(
        received[0]
            .headers
            .get("x-drust-delivery-id")
            .map(|s| s.as_str()),
        Some("test-delivery-id"),
        "header must echo the caller-supplied delivery_id",
    );
    assert_eq!(
        received[0]
            .headers
            .get("x-drust-timestamp")
            .map(|s| s.as_str()),
        Some("1970-01-01T00:00:00Z"),
        "header must echo the caller-supplied timestamp",
    );
}

#[tokio::test]
async fn deliver_retries_on_5xx_then_succeeds() {
    let hook = FakeHook::start_scripted(vec![500, 503]).await; // then 200
    let outcome = deliver_for_test(
        mock_resolver(),
        None,
        &fake_row(hook.url()),
        b"{}".to_vec(),
        "test-delivery-id".to_string(),
        "1970-01-01T00:00:00Z".to_string(),
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
        mock_resolver(),
        None,
        &fake_row(hook.url()),
        b"{}".to_vec(),
        "test-delivery-id".to_string(),
        "1970-01-01T00:00:00Z".to_string(),
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
        mock_resolver(),
        None,
        &fake_row(hook.url()),
        b"{}".to_vec(),
        "test-delivery-id".to_string(),
        "1970-01-01T00:00:00Z".to_string(),
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

// ── REST CRUD tests for /admin/webhooks/* (Task 6) ─────────────────────────

async fn create_webhook(
    app: &axum::Router,
    tid: &str,
    svc: &str,
    body: serde_json::Value,
) -> (u16, serde_json::Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{tid}/admin/webhooks"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {svc}"))
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, v)
}

/// v1.49 — seed the tenant's egress allowlist so a REST `create_webhook`
/// registration to `origin` clears the third (egress) gate. Registration is
/// deny-all by default post-v1.49; a service caller must allowlist the origin
/// first (the real new workflow). Exercised via the service-only REST PUT.
async fn allowlist_webhook_origin(app: &axum::Router, tid: &str, svc: &str, origin: &str) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/t/{tid}/egress-allowlist"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {svc}"))
                .body(Body::from(
                    serde_json::json!({"entries":[{"system":"webhook","uri":origin}]}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        200,
        "egress allowlist PUT must succeed"
    );
}

#[tokio::test]
async fn rest_create_returns_secret_once_and_lists_with_redacted_secret() {
    let tid = "t-rest1";
    let (app, svc, _dir) = spin_up_tenant_with_role(tid, "service").await;
    allowlist_webhook_origin(&app, tid, &svc, "https://example.com").await;
    let body = serde_json::json!({
        "collection": "notes",
        "events": ["created"],
        "url": "https://example.com/x",
    });
    let (status, v) = create_webhook(&app, tid, &svc, body).await;
    assert_eq!(status, 201, "expected 201 Created, got {status}: {v}");
    let secret = v["secret"].as_str().expect("secret must be present");
    assert!(
        secret.len() >= 64,
        "secret should be at least 64 chars, got {} chars",
        secret.len()
    );
    let id = v["id"].as_i64().expect("id present");
    assert!(id > 0, "id should be positive");

    // GET list — secret should be redacted
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/t/{tid}/admin/webhooks"))
                .header(header::AUTHORIZATION, format!("Bearer {svc}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let items = v["webhooks"].as_array().expect("webhooks array");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["secret"].as_str(), Some("●●●●"));
}

#[tokio::test]
async fn rest_create_rejects_http_url() {
    let tid = "t-rest2";
    let (app, svc, _dir) = spin_up_tenant_with_role(tid, "service").await;
    let body = serde_json::json!({
        "collection": "notes",
        "events": ["created"],
        "url": "http://attacker.example",
    });
    let (status, v) = create_webhook(&app, tid, &svc, body).await;
    assert_eq!(status, 422, "expected 422, got {status}: {v}");
    assert_eq!(v["error_code"].as_str(), Some("INVALID_URL"));
}

/// task #932 HIGH #2, parallel-site pin — the per-tenant registration cap must
/// bite on the REST face too, not just the MCP one. The first cut of this fix
/// guarded only `mcp/tools/webhook.rs`, leaving this REST handler (its own
/// duplicated INSERT) uncapped; the shared `check_registration_cap` closes
/// that. Uses the default cap (32) so it manipulates no process-global env var
/// that a sibling test could race. Pre-fix the 33rd create returned 201.
#[tokio::test]
async fn rest_create_is_capped_per_tenant() {
    let tid = "t-rest-cap";
    let (app, svc, _dir) = spin_up_tenant_with_role(tid, "service").await;
    allowlist_webhook_origin(&app, tid, &svc, "https://example.com").await;
    // Default DRUST_WEBHOOK_MAX_PER_TENANT is 32; fill exactly to the cap.
    for i in 0..32 {
        let (status, v) = create_webhook(
            &app,
            tid,
            &svc,
            serde_json::json!({
                "collection": "notes",
                "events": ["created"],
                "url": format!("https://example.com/hook{i}"),
            }),
        )
        .await;
        assert_eq!(
            status, 201,
            "webhook {i} must be accepted under the cap: {v}"
        );
    }
    // The 33rd must be refused — 409 WEBHOOK_LIMIT_EXCEEDED.
    let (status, v) = create_webhook(
        &app,
        tid,
        &svc,
        serde_json::json!({
            "collection": "notes",
            "events": ["created"],
            "url": "https://example.com/hook-over",
        }),
    )
    .await;
    assert_eq!(
        status, 409,
        "the 33rd create must be refused, got {status}: {v}"
    );
    assert_eq!(v["error_code"].as_str(), Some("WEBHOOK_LIMIT_EXCEEDED"));
}

#[tokio::test]
async fn rest_create_allows_http_localhost_for_dev() {
    let tid = "t-rest3";
    let (app, svc, _dir) = spin_up_tenant_with_role(tid, "service").await;
    let body = serde_json::json!({
        "collection": "notes",
        "events": ["created"],
        "url": "http://127.0.0.1:1234/h",
    });
    let (status, v) = create_webhook(&app, tid, &svc, body).await;
    assert_eq!(status, 201, "expected 201, got {status}: {v}");
}

#[tokio::test]
async fn rest_patch_can_toggle_active_and_update_events_but_not_secret() {
    let tid = "t-rest4";
    let (app, svc, _dir) = spin_up_tenant_with_role(tid, "service").await;
    allowlist_webhook_origin(&app, tid, &svc, "https://example.com").await;
    let (status, v) = create_webhook(
        &app,
        tid,
        &svc,
        serde_json::json!({
            "collection": "notes",
            "events": ["created"],
            "url": "https://example.com/y",
        }),
    )
    .await;
    assert_eq!(status, 201);
    let id = v["id"].as_i64().unwrap();

    // Valid PATCH: toggle active off + update events
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/t/{tid}/admin/webhooks/{id}"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {svc}"))
                .body(Body::from(
                    serde_json::json!({"active": false, "events": ["updated"]}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["active"].as_bool(), Some(false));
    let events = v["events"].as_array().expect("events array");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].as_str(), Some("updated"));

    // Invalid PATCH: secret rejected
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/t/{tid}/admin/webhooks/{id}"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {svc}"))
                .body(Body::from(
                    serde_json::json!({"secret": "hacked"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 422);
    let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["error_code"].as_str(), Some("INVALID_PATCH"));
}

#[tokio::test]
async fn rest_anon_token_rejected_with_403_service_only() {
    let tid = "t-rest5";
    let (app, anon, _dir) = spin_up_tenant_with_role(tid, "anon").await;
    let body = serde_json::json!({
        "collection": "notes",
        "events": ["created"],
        "url": "https://example.com/z",
    });
    let (status, v) = create_webhook(&app, tid, &anon, body).await;
    assert_eq!(status, 403, "expected 403, got {status}: {v}");
    assert_eq!(v["error_code"].as_str(), Some("SERVICE_ONLY"));
}

// ── MCP tool tests for webhook CRUD (Task 7), over the account-level `/mcp` ──
//
// The account endpoint builds every call with the meta handle, so the
// webhook tools' egress registration gate (invariant 6) runs here exactly as
// on REST: each test allowlists the origins it registers first.

/// Allowlist `origins` for system `webhook` through the MCP
/// `set_egress_allowlist` tool (it replaces the whole list).
async fn mcp_allowlist_webhook_origins(h: &helpers::AccountMcpHarness, origins: &[&str]) {
    let entries: Vec<serde_json::Value> = origins
        .iter()
        .map(|o| serde_json::json!({"system": "webhook", "uri": o}))
        .collect();
    let txt = helpers::mcp_tool_text(
        &h.app,
        &h.access,
        &h.tid,
        "set_egress_allowlist",
        serde_json::json!({ "entries": entries }),
    )
    .await;
    for o in origins {
        assert!(txt.contains(o), "egress allowlist must hold {o}: {txt}");
    }
}

#[tokio::test]
async fn mcp_create_webhook_returns_secret_then_list_redacts() {
    let h = helpers::spin_up_account_mcp("t-mcpwh1").await;
    mcp_allowlist_webhook_origins(&h, &["https://example.com"]).await;

    // create_webhook → raw 64-hex secret
    let txt = helpers::mcp_tool_text(
        &h.app,
        &h.access,
        &h.tid,
        "create_webhook",
        serde_json::json!({
            "collection": "notes",
            "events": ["created"],
            "url": "https://example.com/x",
        }),
    )
    .await;
    let v: serde_json::Value =
        serde_json::from_str(&txt).unwrap_or_else(|_| panic!("expected JSON object, got: {txt}"));
    let secret = v["secret"]
        .as_str()
        .unwrap_or_else(|| panic!("secret must be a string, got: {txt}"));
    assert_eq!(
        secret.len(),
        64,
        "secret should be 64 hex chars, got {} chars",
        secret.len()
    );
    assert!(
        secret.chars().all(|c| c.is_ascii_hexdigit()),
        "secret should be all hex digits, got: {secret}"
    );
    let id = v["id"].as_i64().expect("id present");
    assert!(id > 0);
    assert_eq!(v["collection"], "notes");
    assert_eq!(v["active"], true);

    // list_webhooks → redacted secret
    let txt = helpers::mcp_tool_text(
        &h.app,
        &h.access,
        &h.tid,
        "list_webhooks",
        serde_json::json!({}),
    )
    .await;
    let v: serde_json::Value =
        serde_json::from_str(&txt).unwrap_or_else(|_| panic!("expected JSON, got: {txt}"));
    let items = v["webhooks"].as_array().expect("webhooks array");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["secret"].as_str(), Some("●●●●"));
    assert_eq!(items[0]["url"].as_str(), Some("https://example.com/x"));
}

#[tokio::test]
async fn mcp_update_webhook_changes_url_and_rejects_invalid() {
    let h = helpers::spin_up_account_mcp("t-mcpwh2").await;
    mcp_allowlist_webhook_origins(&h, &["https://example.com", "http://attacker.example"]).await;

    let txt = helpers::mcp_tool_text(
        &h.app,
        &h.access,
        &h.tid,
        "create_webhook",
        serde_json::json!({
            "collection": "notes",
            "events": ["created"],
            "url": "https://example.com/a",
        }),
    )
    .await;
    let v: serde_json::Value = serde_json::from_str(&txt).unwrap();
    let id = v["id"].as_i64().unwrap();

    // Good update — change url + toggle active off
    let txt = helpers::mcp_tool_text(
        &h.app,
        &h.access,
        &h.tid,
        "update_webhook",
        serde_json::json!({"id": id, "url": "https://example.com/b", "active": false}),
    )
    .await;
    let v: serde_json::Value = serde_json::from_str(&txt).unwrap();
    assert_eq!(v["updated"], true);
    assert_eq!(v["id"], id);

    // Verify via list
    let txt = helpers::mcp_tool_text(
        &h.app,
        &h.access,
        &h.tid,
        "list_webhooks",
        serde_json::json!({}),
    )
    .await;
    let v: serde_json::Value = serde_json::from_str(&txt).unwrap();
    let items = v["webhooks"].as_array().unwrap();
    assert_eq!(items[0]["url"].as_str(), Some("https://example.com/b"));
    assert_eq!(items[0]["active"].as_bool(), Some(false));

    // Bad update — http://attacker URL should error
    let txt = helpers::mcp_tool_text(
        &h.app,
        &h.access,
        &h.tid,
        "update_webhook",
        serde_json::json!({"id": id, "url": "http://attacker.example"}),
    )
    .await;
    assert!(
        txt.contains("INVALID_URL"),
        "expected INVALID_URL error, got: {txt}"
    );

    // Bad update — invalid event name
    let txt = helpers::mcp_tool_text(
        &h.app,
        &h.access,
        &h.tid,
        "update_webhook",
        serde_json::json!({"id": id, "events": ["bogus"]}),
    )
    .await;
    assert!(
        txt.contains("INVALID_EVENTS"),
        "expected INVALID_EVENTS error, got: {txt}"
    );
}

#[tokio::test]
async fn mcp_delete_webhook_succeeds_and_errors_on_missing_id() {
    let h = helpers::spin_up_account_mcp("t-mcpwh3").await;
    mcp_allowlist_webhook_origins(&h, &["https://example.com"]).await;

    let txt = helpers::mcp_tool_text(
        &h.app,
        &h.access,
        &h.tid,
        "create_webhook",
        serde_json::json!({
            "collection": "notes",
            "events": ["created"],
            "url": "https://example.com/del",
        }),
    )
    .await;
    let v: serde_json::Value = serde_json::from_str(&txt).unwrap();
    let id = v["id"].as_i64().unwrap();

    // Delete the existing webhook.
    let txt = helpers::mcp_tool_text(
        &h.app,
        &h.access,
        &h.tid,
        "delete_webhook",
        serde_json::json!({"id": id}),
    )
    .await;
    let v: serde_json::Value = serde_json::from_str(&txt).unwrap();
    assert_eq!(v["deleted"], true);
    assert_eq!(v["id"], id);

    // Delete again → NOT_FOUND error.
    let txt = helpers::mcp_tool_text(
        &h.app,
        &h.access,
        &h.tid,
        "delete_webhook",
        serde_json::json!({"id": id}),
    )
    .await;
    assert!(
        txt.contains("NOT_FOUND"),
        "expected NOT_FOUND error for missing id, got: {txt}"
    );

    // Update on missing id also errors.
    let txt = helpers::mcp_tool_text(
        &h.app,
        &h.access,
        &h.tid,
        "update_webhook",
        serde_json::json!({"id": 9999, "active": true}),
    )
    .await;
    assert!(
        txt.contains("NOT_FOUND"),
        "expected NOT_FOUND for update on missing id, got: {txt}"
    );
}

// ── Hardening tests (Task 9) ───────────────────────────────────────────────

/// Cross-tenant isolation: a record CRUD event in tenant B must not fire
/// webhooks registered in tenant A. Each `spin_up_tenant_with_role` call
/// creates its own ephemeral data_root + WebhookDispatcher, so tenant A's
/// dispatcher cannot see tenant B's `_system_webhooks` table. This test is
/// a regression sanity check that nothing in the data_root plumbing ever
/// leaks across pools.
#[tokio::test]
async fn webhook_does_not_fire_for_other_tenants() {
    let hook = FakeHook::start().await;

    // Tenant A: register a webhook on `notes` pointing at the FakeHook.
    let tid_a = "t-isoA";
    let (app_a, svc_a, _dir_a) = spin_up_tenant_with_role(tid_a, "service").await;
    let (status_a, _) = create_webhook(
        &app_a,
        tid_a,
        &svc_a,
        serde_json::json!({
            "collection": "notes",
            "events": ["created"],
            "url": hook.url(),
        }),
    )
    .await;
    assert_eq!(status_a, 201, "tenant A webhook must register");

    // Tenant B: separate ephemeral dir → separate DB + dispatcher.
    let tid_b = "t-isoB";
    let (app_b, svc_b, dir_b) = spin_up_tenant_with_role(tid_b, "service").await;

    // Create the `notes` collection on tenant B via direct SQL.
    let pool_b = helpers::grab_pool(tid_b, &dir_b).await;
    pool_b
        .with_writer(|c| {
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

    // POST a record on tenant B — must not reach tenant A's hook.
    let resp = app_b
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{tid_b}/records/notes"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {svc_b}"))
                .body(Body::from(
                    serde_json::json!({"data": {"title": "x"}}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        201,
        "tenant B record insert must succeed"
    );

    // Poll up to ~500 ms for any stray delivery; assert none happened.
    for _ in 0..10 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        if !hook.requests().await.is_empty() {
            break;
        }
    }
    assert_eq!(
        hook.requests().await.len(),
        0,
        "tenant B's events must NEVER reach tenant A's subscriber",
    );
}

/// GET /admin/webhooks/{id} must redact the secret (separate code path from
/// the list handler, which is covered by
/// `rest_create_returns_secret_once_and_lists_with_redacted_secret`).
#[tokio::test]
async fn rest_get_one_redacts_secret() {
    let tid = "t-redact";
    let (app, svc, _dir) = spin_up_tenant_with_role(tid, "service").await;
    allowlist_webhook_origin(&app, tid, &svc, "https://example.com").await;
    let (status, v) = create_webhook(
        &app,
        tid,
        &svc,
        serde_json::json!({
            "collection": "notes",
            "events": ["created"],
            "url": "https://example.com/h",
        }),
    )
    .await;
    assert_eq!(status, 201, "webhook must create");
    let id = v["id"].as_i64().expect("id present");

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/t/{tid}/admin/webhooks/{id}"))
                .header(header::AUTHORIZATION, format!("Bearer {svc}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["secret"].as_str(), Some("●●●●"));
    assert_eq!(v["id"].as_i64(), Some(id));
}
