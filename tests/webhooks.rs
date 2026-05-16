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
    let v: serde_json::Value =
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, v)
}

#[tokio::test]
async fn rest_create_returns_secret_once_and_lists_with_redacted_secret() {
    let tid = "t-rest1";
    let (app, svc, _dir) = spin_up_tenant_with_role(tid, "service").await;
    let body = serde_json::json!({
        "collection": "notes",
        "events": ["created"],
        "url": "https://hooks.example.com/x",
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
    let (status, v) = create_webhook(
        &app,
        tid,
        &svc,
        serde_json::json!({
            "collection": "notes",
            "events": ["created"],
            "url": "https://hooks.example.com/y",
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
        "url": "https://hooks.example.com/z",
    });
    let (status, v) = create_webhook(&app, tid, &anon, body).await;
    assert_eq!(status, 403, "expected 403, got {status}: {v}");
    assert_eq!(v["error_code"].as_str(), Some("SERVICE_ONLY"));
}

// ── MCP tool tests for webhook CRUD (Task 7) ───────────────────────────────
//
// TODO: extract the mcp_* helpers below into a shared module — they are
// duplicated from `tests/admin_users.rs` (lines 318-435).

/// Build one MCP HTTP request (session-id must be set externally via header).
fn mcp_req_with_session(
    tid: &str,
    token: &str,
    session_id: &str,
    body: serde_json::Value,
) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!("/t/{tid}/mcp"))
        .header(header::HOST, "127.0.0.1")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header("mcp-session-id", session_id)
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// Parse rmcp Streamable-HTTP response: JSON or SSE → flat Vec<Value>.
async fn parse_mcp_response(resp: axum::response::Response) -> Vec<serde_json::Value> {
    let ct = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    if ct.starts_with("text/event-stream") {
        let mut out = Vec::new();
        for frame in text.split("\n\n") {
            for line in frame.lines() {
                if let Some(data) = line.strip_prefix("data:") {
                    let trimmed = data.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    if let Ok(v) = serde_json::from_str(trimmed) {
                        out.push(v);
                    }
                }
            }
        }
        out
    } else if text.is_empty() {
        vec![]
    } else {
        vec![serde_json::from_str(&text).unwrap_or(serde_json::Value::Null)]
    }
}

/// Full MCP initialize handshake → returns session_id string.
async fn mcp_init(app: &axum::Router, tid: &str, token: &str) -> String {
    let init = Request::builder()
        .method("POST")
        .uri(format!("/t/{tid}/mcp"))
        .header(header::HOST, "127.0.0.1")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .body(Body::from(
            serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "0"}
                }
            })
            .to_string(),
        ))
        .unwrap();
    let init_resp = app.clone().oneshot(init).await.unwrap();
    assert_eq!(
        init_resp.status(),
        axum::http::StatusCode::OK,
        "MCP initialize failed"
    );
    let session_id = init_resp
        .headers()
        .get("mcp-session-id")
        .expect("initialize must set mcp-session-id")
        .to_str()
        .unwrap()
        .to_string();
    let _ = parse_mcp_response(init_resp).await;

    let ack = mcp_req_with_session(
        tid,
        token,
        &session_id,
        serde_json::json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    );
    let _ = app.clone().oneshot(ack).await.unwrap();
    session_id
}

/// Call one MCP tool and return the raw text of content[0].text.
async fn mcp_call_tool(
    app: &axum::Router,
    tid: &str,
    token: &str,
    session_id: &str,
    name: &str,
    args: serde_json::Value,
) -> String {
    let call = mcp_req_with_session(
        tid,
        token,
        session_id,
        serde_json::json!({
            "jsonrpc":"2.0","id":2,"method":"tools/call",
            "params":{"name":name,"arguments":args}
        }),
    );
    let resp = app.clone().oneshot(call).await.unwrap();
    assert!(
        resp.status().is_success(),
        "tools/call {name} HTTP status: {}",
        resp.status()
    );
    let msgs = parse_mcp_response(resp).await;
    msgs.iter()
        .find_map(|m| {
            m["result"]["content"]
                .as_array()
                .and_then(|arr| arr.first())
                .and_then(|c| c["text"].as_str())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| serde_json::to_string(&msgs).unwrap())
}

#[tokio::test]
async fn mcp_create_webhook_returns_secret_then_list_redacts() {
    let tid = "t-mcpwh1";
    let (app, svc, _dir) = spin_up_tenant_with_role(tid, "service").await;
    let sid = mcp_init(&app, tid, &svc).await;

    // create_webhook → raw 64-hex secret
    let txt = mcp_call_tool(
        &app,
        tid,
        &svc,
        &sid,
        "create_webhook",
        serde_json::json!({
            "collection": "notes",
            "events": ["created"],
            "url": "https://hooks.example.com/x",
        }),
    )
    .await;
    let v: serde_json::Value =
        serde_json::from_str(&txt).expect(&format!("expected JSON object, got: {txt}"));
    let secret = v["secret"]
        .as_str()
        .expect(&format!("secret must be a string, got: {txt}"));
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
    let txt = mcp_call_tool(&app, tid, &svc, &sid, "list_webhooks", serde_json::json!({})).await;
    let v: serde_json::Value =
        serde_json::from_str(&txt).expect(&format!("expected JSON, got: {txt}"));
    let items = v["webhooks"].as_array().expect("webhooks array");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["secret"].as_str(), Some("●●●●"));
    assert_eq!(items[0]["url"].as_str(), Some("https://hooks.example.com/x"));
}

#[tokio::test]
async fn mcp_update_webhook_changes_url_and_rejects_invalid() {
    let tid = "t-mcpwh2";
    let (app, svc, _dir) = spin_up_tenant_with_role(tid, "service").await;
    let sid = mcp_init(&app, tid, &svc).await;

    let txt = mcp_call_tool(
        &app,
        tid,
        &svc,
        &sid,
        "create_webhook",
        serde_json::json!({
            "collection": "notes",
            "events": ["created"],
            "url": "https://hooks.example.com/a",
        }),
    )
    .await;
    let v: serde_json::Value = serde_json::from_str(&txt).unwrap();
    let id = v["id"].as_i64().unwrap();

    // Good update — change url + toggle active off
    let txt = mcp_call_tool(
        &app,
        tid,
        &svc,
        &sid,
        "update_webhook",
        serde_json::json!({"id": id, "url": "https://hooks.example.com/b", "active": false}),
    )
    .await;
    let v: serde_json::Value = serde_json::from_str(&txt).unwrap();
    assert_eq!(v["updated"], true);
    assert_eq!(v["id"], id);

    // Verify via list
    let txt = mcp_call_tool(&app, tid, &svc, &sid, "list_webhooks", serde_json::json!({})).await;
    let v: serde_json::Value = serde_json::from_str(&txt).unwrap();
    let items = v["webhooks"].as_array().unwrap();
    assert_eq!(items[0]["url"].as_str(), Some("https://hooks.example.com/b"));
    assert_eq!(items[0]["active"].as_bool(), Some(false));

    // Bad update — http://attacker URL should error
    let txt = mcp_call_tool(
        &app,
        tid,
        &svc,
        &sid,
        "update_webhook",
        serde_json::json!({"id": id, "url": "http://attacker.example"}),
    )
    .await;
    assert!(
        txt.contains("INVALID_URL"),
        "expected INVALID_URL error, got: {txt}"
    );

    // Bad update — invalid event name
    let txt = mcp_call_tool(
        &app,
        tid,
        &svc,
        &sid,
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
    let tid = "t-mcpwh3";
    let (app, svc, _dir) = spin_up_tenant_with_role(tid, "service").await;
    let sid = mcp_init(&app, tid, &svc).await;

    let txt = mcp_call_tool(
        &app,
        tid,
        &svc,
        &sid,
        "create_webhook",
        serde_json::json!({
            "collection": "notes",
            "events": ["created"],
            "url": "https://hooks.example.com/del",
        }),
    )
    .await;
    let v: serde_json::Value = serde_json::from_str(&txt).unwrap();
    let id = v["id"].as_i64().unwrap();

    // Delete the existing webhook.
    let txt = mcp_call_tool(
        &app,
        tid,
        &svc,
        &sid,
        "delete_webhook",
        serde_json::json!({"id": id}),
    )
    .await;
    let v: serde_json::Value = serde_json::from_str(&txt).unwrap();
    assert_eq!(v["deleted"], true);
    assert_eq!(v["id"], id);

    // Delete again → NOT_FOUND error.
    let txt = mcp_call_tool(
        &app,
        tid,
        &svc,
        &sid,
        "delete_webhook",
        serde_json::json!({"id": id}),
    )
    .await;
    assert!(
        txt.contains("NOT_FOUND"),
        "expected NOT_FOUND error for missing id, got: {txt}"
    );

    // Update on missing id also errors.
    let txt = mcp_call_tool(
        &app,
        tid,
        &svc,
        &sid,
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
    assert_eq!(resp.status().as_u16(), 201, "tenant B record insert must succeed");

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
    let (status, v) = create_webhook(
        &app,
        tid,
        &svc,
        serde_json::json!({
            "collection": "notes",
            "events": ["created"],
            "url": "https://x.invalid/h",
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
