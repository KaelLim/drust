mod helpers;
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

fn mcp_req_with_session(tid: &str, token: &str, sid: &str, body: serde_json::Value) -> Request<Body> {
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

async fn parse_mcp_response(resp: axum::response::Response) -> Vec<serde_json::Value> {
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let text = String::from_utf8_lossy(&bytes);
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.strip_prefix("data:").unwrap_or(line).trim();
        if line.is_empty() { continue; }
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) { out.push(v); }
    }
    out
}

async fn mcp_init(app: &axum::Router, tid: &str, token: &str) -> String {
    let init = Request::builder()
        .method("POST").uri(format!("/t/{tid}/mcp"))
        .header(header::HOST, "127.0.0.1")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .body(Body::from(serde_json::json!({
            "jsonrpc":"2.0","id":1,"method":"initialize",
            "params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0"}}
        }).to_string())).unwrap();
    let r = app.clone().oneshot(init).await.unwrap();
    assert_eq!(r.status(), StatusCode::OK, "initialize failed");
    let sid = r.headers().get("mcp-session-id").unwrap().to_str().unwrap().to_string();
    let _ = parse_mcp_response(r).await;
    let ack = mcp_req_with_session(tid, token, &sid, serde_json::json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
    let _ = app.clone().oneshot(ack).await.unwrap();
    sid
}

async fn mcp_call_tool(app: &axum::Router, tid: &str, token: &str, sid: &str, name: &str, args: serde_json::Value) -> String {
    let call = mcp_req_with_session(tid, token, sid, serde_json::json!({
        "jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":name,"arguments":args}
    }));
    let resp = app.clone().oneshot(call).await.unwrap();
    assert!(resp.status().is_success(), "tools/call {name} status {}", resp.status());
    let msgs = parse_mcp_response(resp).await;
    msgs.iter().find_map(|m| m["result"]["content"].as_array().and_then(|a| a.first()).and_then(|c| c["text"].as_str()).map(|s| s.to_string()))
        .unwrap_or_else(|| serde_json::to_string(&msgs).unwrap())
}

#[tokio::test]
async fn set_description_dispatches_by_target() {
    let (app, tid, svc, _anon, dir) = helpers::spin_up_dual_role_self_register("t-setdesc").await;
    let pool = helpers::grab_pool(&tid, &dir).await;
    pool.with_writer(|c| c.execute_batch(
        "CREATE TABLE posts (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, created_at TEXT DEFAULT (datetime('now')), updated_at TEXT DEFAULT (datetime('now')));\n         CREATE INDEX idx_posts_title ON posts(title);")).await.unwrap();
    let sid = mcp_init(&app, &tid, &svc).await;

    let c = mcp_call_tool(&app, &tid, &svc, &sid, "set_description", serde_json::json!({"target":"collection","collection":"posts","description":"Blog posts"})).await;
    assert!(c.contains("Blog posts"), "collection desc: {c}");
    let f = mcp_call_tool(&app, &tid, &svc, &sid, "set_description", serde_json::json!({"target":"field","collection":"posts","field":"title","description":"Post title"})).await;
    assert!(f.contains("Post title"), "field desc: {f}");
    let i = mcp_call_tool(&app, &tid, &svc, &sid, "set_description", serde_json::json!({"target":"index","collection":"posts","index_name":"idx_posts_title","description":"title lookup"})).await;
    assert!(i.contains("title lookup"), "index desc: {i}");
    let nf = mcp_call_tool(&app, &tid, &svc, &sid, "set_description", serde_json::json!({"target":"field","collection":"posts","field":"ghost","description":"x"})).await;
    assert!(nf.contains("FIELD_NOT_FOUND"), "missing-field still errors: {nf}");
}

// §Isolation #2 — the merged set_description path must still refuse _system_* tables.
// (The is_protected_collection check lives inside each schema::set_* impl; this locks
// it for the merged dispatch entry.)
#[tokio::test]
async fn set_description_on_system_table_is_protected() {
    let (app, tid, svc, _anon, _dir) = helpers::spin_up_dual_role_self_register("t-setdesc-prot").await;
    let sid = mcp_init(&app, &tid, &svc).await;
    let r = mcp_call_tool(&app, &tid, &svc, &sid, "set_description",
        serde_json::json!({"target":"collection","collection":"_system_files","description":"nope"})).await;
    assert!(r.contains("PROTECTED_COLLECTION"), "_system_* must stay protected on set_description: {r}");
}
