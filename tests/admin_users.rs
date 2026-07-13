/// Integration tests for Task 23: /admin/users CRUD + cascade delete + revoke-sessions.
/// Task 24/25: MCP user-management, owner-field, and set_self_register tools.
mod helpers;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use serde_json::json;
use tower::ServiceExt;

fn req(
    method: &str,
    tid: &str,
    path: &str,
    body: Option<serde_json::Value>,
    token: &str,
) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(format!("/t/{tid}{path}"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"));
    if body.is_some() {
        b = b.header(header::CONTENT_TYPE, "application/json");
    }
    b.body(
        body.map(|v| Body::from(v.to_string()))
            .unwrap_or(Body::empty()),
    )
    .unwrap()
}

async fn read_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 65_536)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn create_list_get_user_via_service_token() {
    let (app, tid, svc, _anon, _dir) = helpers::spin_up_dual_role_self_register("t-au1").await;

    // Create user
    let r = app
        .clone()
        .oneshot(req(
            "POST",
            &tid,
            "/admin/users",
            Some(json!({"email": "a@b.com", "password": "longpassword"})),
            &svc,
        ))
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::CREATED,
        "create user should return 201"
    );
    let v = read_json(r).await;
    let uid = v["user_id"]
        .as_str()
        .expect("user_id in response")
        .to_string();
    assert_eq!(v["email"].as_str().unwrap(), "a@b.com");

    // List users
    let r = app
        .clone()
        .oneshot(req("GET", &tid, "/admin/users", None, &svc))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let v = read_json(r).await;
    assert_eq!(v["total"].as_i64().unwrap(), 1);
    assert_eq!(v["users"].as_array().unwrap().len(), 1);

    // Get one user
    let r = app
        .oneshot(req("GET", &tid, &format!("/admin/users/{uid}"), None, &svc))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let v = read_json(r).await;
    assert_eq!(v["email"].as_str().unwrap(), "a@b.com");
    // password_hash must NOT be exposed
    assert!(
        v.get("password_hash").is_none(),
        "password_hash must not be in response"
    );
}

#[tokio::test]
async fn update_user_changes_email_and_verified() {
    let (app, tid, svc, _anon, _dir) = helpers::spin_up_dual_role_self_register("t-au-upd").await;

    // Create
    let r = app
        .clone()
        .oneshot(req(
            "POST",
            &tid,
            "/admin/users",
            Some(json!({"email": "orig@b.com", "password": "longpassword"})),
            &svc,
        ))
        .await
        .unwrap();
    let v = read_json(r).await;
    let uid = v["user_id"].as_str().unwrap().to_string();

    // Update email + verified
    let r = app
        .clone()
        .oneshot(req(
            "PATCH",
            &tid,
            &format!("/admin/users/{uid}"),
            Some(json!({"email": "new@b.com", "verified": true})),
            &svc,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK, "PATCH should return 200");
    let v = read_json(r).await;
    assert_eq!(v["email"].as_str().unwrap(), "new@b.com");
    assert!(v["verified"].as_bool().unwrap(), "verified should be true");
}

#[tokio::test]
async fn delete_user_cascades_records() {
    let (app, tid, svc, _anon, dir) = helpers::spin_up_dual_role_self_register("t-au2").await;

    // Create posts collection with owner_field via pool
    let pool = helpers::grab_pool(&tid, &dir).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE posts (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 user_id TEXT REFERENCES _system_users(id),
                 title TEXT,
                 created_at TEXT DEFAULT (datetime('now')),
                 updated_at TEXT DEFAULT (datetime('now'))
             );",
        )
    })
    .await
    .unwrap();

    // Set owner-field via REST
    let r = app
        .clone()
        .oneshot(req(
            "POST",
            &tid,
            "/collections/posts/owner-field",
            Some(json!({"field": "user_id", "read_scope": "own"})),
            &svc,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK, "set owner-field failed");

    // Create user via admin endpoint
    let r = app
        .clone()
        .oneshot(req(
            "POST",
            &tid,
            "/admin/users",
            Some(json!({"email": "a@b.com", "password": "longpassword"})),
            &svc,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    let v = read_json(r).await;
    let uid = v["user_id"].as_str().unwrap().to_string();

    // Service inserts 3 posts owned by uid
    for i in 0..3 {
        let r = app
            .clone()
            .oneshot(req(
                "POST",
                &tid,
                "/records/posts",
                Some(json!({"data": {"user_id": &uid, "title": format!("t-{i}")}})),
                &svc,
            ))
            .await
            .unwrap();
        assert!(
            r.status().is_success(),
            "insert post {i} failed: {}",
            r.status()
        );
    }

    // Delete user
    let r = app
        .oneshot(req(
            "DELETE",
            &tid,
            &format!("/admin/users/{uid}"),
            None,
            &svc,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let v = read_json(r).await;
    assert_eq!(
        v["deleted_records"]["posts"].as_i64().unwrap(),
        3,
        "cascade delete should report 3 deleted posts"
    );
}

#[tokio::test]
async fn admin_users_rejects_non_service() {
    let (app, tid, _svc, anon, _dir) = helpers::spin_up_dual_role_self_register("t-au3").await;

    let r = app
        .oneshot(req("GET", &tid, "/admin/users", None, &anon))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let bytes = axum::body::to_bytes(r.into_body(), 65_536).await.unwrap();
    assert!(
        String::from_utf8_lossy(&bytes).contains("SERVICE_ONLY"),
        "wrong error code, body: {}",
        String::from_utf8_lossy(&bytes)
    );
}

#[tokio::test]
async fn revoke_sessions_kicks_all_user_tokens() {
    let (app, tid, svc, _anon, _dir) = helpers::spin_up_dual_role_self_register("t-au4").await;

    // Register + login via app
    let token = helpers::register_and_login_via_app(&app, &tid, "a@b.com", "longpassword").await;

    // Get the user ID via /me
    let r = app
        .clone()
        .oneshot(req("GET", &tid, "/me", None, &token))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let v = read_json(r).await;
    let uid = v["id"].as_str().unwrap().to_string();

    // Revoke all sessions for this user
    let r = app
        .clone()
        .oneshot(req(
            "POST",
            &tid,
            &format!("/admin/users/{uid}/revoke-sessions"),
            None,
            &svc,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let v = read_json(r).await;
    assert!(
        v["revoked"].as_i64().unwrap() >= 1,
        "at least 1 session should be revoked"
    );

    // /me now 401
    let r = app
        .oneshot(req("GET", &tid, "/me", None, &token))
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::UNAUTHORIZED,
        "/me should now be 401"
    );
}

#[tokio::test]
async fn create_user_duplicate_email_returns_409() {
    let (app, tid, svc, _anon, _dir) = helpers::spin_up_dual_role_self_register("t-au5").await;

    let create_req = || {
        req(
            "POST",
            &tid,
            "/admin/users",
            Some(json!({"email": "dup@b.com", "password": "longpassword"})),
            &svc,
        )
    };
    let r = app.clone().oneshot(create_req()).await.unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    let r = app.oneshot(create_req()).await.unwrap();
    assert_eq!(
        r.status(),
        StatusCode::CONFLICT,
        "duplicate email should be 409"
    );
    let bytes = axum::body::to_bytes(r.into_body(), 65_536).await.unwrap();
    assert!(
        String::from_utf8_lossy(&bytes).contains("EMAIL_EXISTS"),
        "wrong error code: {}",
        String::from_utf8_lossy(&bytes)
    );
}

#[tokio::test]
async fn get_nonexistent_user_returns_404() {
    let (app, tid, svc, _anon, _dir) = helpers::spin_up_dual_role_self_register("t-au6").await;

    let r = app
        .oneshot(req(
            "GET",
            &tid,
            "/admin/users/u-00000000-0000-0000-0000-000000000000",
            None,
            &svc,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
}

// =============================================================================
// Task 24 MCP tool tests
// =============================================================================

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
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
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

/// Full MCP initialize handshake → returns (app clone with session, session_id).
/// Performs: initialize + notifications/initialized, returns session_id string.
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
    assert_eq!(init_resp.status(), StatusCode::OK, "MCP initialize failed");
    let session_id = init_resp
        .headers()
        .get("mcp-session-id")
        .expect("initialize must set mcp-session-id")
        .to_str()
        .unwrap()
        .to_string();
    let _ = parse_mcp_response(init_resp).await;

    // notifications/initialized
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
    // Extract content[0].text from result or return full msg as string
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
async fn mcp_create_user_tool() {
    let (app, tid, svc, _anon, _dir) = helpers::spin_up_dual_role_self_register("t-mcpu1").await;
    let sid = mcp_init(&app, &tid, &svc).await;
    let txt = mcp_call_tool(
        &app,
        &tid,
        &svc,
        &sid,
        "create_user",
        serde_json::json!({"email":"a@b.com","password":"longpassword"}),
    )
    .await;
    assert!(txt.contains("user_id"), "body: {txt}");
    assert!(txt.contains("a@b.com"), "body: {txt}");
}

#[tokio::test]
async fn mcp_list_get_update_delete_user() {
    let (app, tid, svc, _anon, _dir) = helpers::spin_up_dual_role_self_register("t-mcpu2").await;
    let sid = mcp_init(&app, &tid, &svc).await;

    // Create
    let txt = mcp_call_tool(
        &app,
        &tid,
        &svc,
        &sid,
        "create_user",
        serde_json::json!({"email":"a@b.com","password":"longpassword"}),
    )
    .await;
    assert!(txt.contains("u-"), "create_user body: {txt}");
    // Parse user_id: find "u-<uuid4>" prefix in the response text.
    let uid_start = txt.find("u-").expect("u- prefix not found");
    let uid: String = txt[uid_start..]
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '-')
        .collect();

    // List
    let txt = mcp_call_tool(&app, &tid, &svc, &sid, "list_users", serde_json::json!({})).await;
    assert!(txt.contains("a@b.com"), "list_users body: {txt}");

    // Get
    let txt = mcp_call_tool(
        &app,
        &tid,
        &svc,
        &sid,
        "get_user",
        serde_json::json!({"user_id": &uid}),
    )
    .await;
    assert!(txt.contains("a@b.com"), "get_user body: {txt}");

    // Update — change email
    let txt = mcp_call_tool(
        &app,
        &tid,
        &svc,
        &sid,
        "update_user",
        serde_json::json!({"user_id": &uid, "email": "z@b.com"}),
    )
    .await;
    assert!(txt.contains("z@b.com"), "update_user body: {txt}");

    // Revoke sessions (safe on a user with no sessions)
    let txt = mcp_call_tool(
        &app,
        &tid,
        &svc,
        &sid,
        "revoke_user_sessions",
        serde_json::json!({"user_id": &uid}),
    )
    .await;
    assert!(txt.contains("revoked"), "revoke_user_sessions body: {txt}");

    // Delete
    let txt = mcp_call_tool(
        &app,
        &tid,
        &svc,
        &sid,
        "delete_user",
        serde_json::json!({"user_id": &uid}),
    )
    .await;
    assert!(txt.contains("deleted_records"), "delete_user body: {txt}");
}

// =============================================================================
// Task 25 MCP tool tests
// =============================================================================

#[tokio::test]
async fn mcp_set_owner_field_tool() {
    let (app, tid, svc, _anon, dir) = helpers::spin_up_dual_role_self_register("t-mcpof").await;
    let pool = helpers::grab_pool(&tid, &dir).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT REFERENCES _system_users(id),
                title TEXT,
                created_at TEXT DEFAULT (datetime('now')),
                updated_at TEXT DEFAULT (datetime('now'))
            );",
        )
    })
    .await
    .unwrap();

    let sid = mcp_init(&app, &tid, &svc).await;
    let txt = mcp_call_tool(
        &app,
        &tid,
        &svc,
        &sid,
        "set_owner_field",
        serde_json::json!({"collection":"posts","field":"user_id","read_scope":"own"}),
    )
    .await;
    assert!(txt.contains("owner_field"), "body: {txt}");
    assert!(txt.contains("user_id"), "body: {txt}");
}

#[tokio::test]
async fn mcp_set_self_register_tool() {
    // Build a tenant app with meta wired into McpRegistry so set_self_register
    // can write to meta.sqlite. The standard test helper (test_mcp_http) does
    // NOT wire meta — we build the stack manually here.
    use drust::auth::bearer::{generate_token, hash_token};
    use drust::mcp::http_registry::McpHttpRegistry;
    use drust::mcp::server::McpRegistry;
    use drust::storage::meta::open_meta;
    use drust::storage::pool::TenantRegistry;
    use drust::tenant::router::TenantAuthState;
    use drust::tenant::{TenantStack, build_tenant_router, events::EventBus};
    use std::sync::Arc;
    use tokio::sync::Mutex;

    let tid = "t-mcpsr";
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let conn = open_meta(&data.join("meta.sqlite")).unwrap();
    conn.execute(
        "INSERT INTO tenants (id, name) VALUES (?1, 'x')",
        rusqlite::params![tid],
    )
    .unwrap();
    let svc_tok = generate_token();
    conn.execute(
        "INSERT INTO tokens (tenant_id, token_hash, role) VALUES (?1, ?2, 'service')",
        rusqlite::params![tid, hash_token(&svc_tok)],
    )
    .unwrap();
    let _ = drust::storage::tenant_db::open_write(&data, tid).unwrap();
    drust::db::migrations::run_migrations(&conn, &data).unwrap();

    let tenants = Arc::new(TenantRegistry::new(data.clone(), 2));
    let bus = EventBus::new();
    let webhooks = drust::tenant::WebhookDispatcher::new(tenants.clone(), None);
    let meta_arc = Arc::new(Mutex::new(conn));
    let mcp_reg = Arc::new(McpRegistry::with_bus_and_storage(
        tenants.clone(),
        bus.clone(),
        webhooks.clone(),
        None,
        String::new(),
        Arc::new([0u8; 32]),
        Some(meta_arc.clone()),
        52_428_800,
        1_000_000,
        Arc::new(Mutex::new(
            drust::safety::audit_db::open_audit_db_memory().unwrap(),
        )),
        drust::tenant::rooms::RoomBus::new(),
        drust::tenant::rooms::RoomsConfig::test_defaults().bucket(),
        drust::tenant::rooms::RoomsConfig::test_defaults(),
        Arc::new(drust::tenant::auth_cache::AuthCache::new(
            std::time::Duration::from_secs(10),
            200_000,
        )),
        drust::functions::dispatcher::FunctionDispatcher::new(
            tenants.clone(),
            tokio::sync::mpsc::channel(8).0,
            drust::functions::FnConfig::test_default(),
        ),
    ));
    let state = TenantAuthState::test_default(meta_arc.clone(), tenants.clone());
    let (functions, functions_exec, fn_cfg) = drust::functions::test_stack_parts(tenants.clone());
    let stack = TenantStack {
        auth: state,
        bus: bus.clone(),
        bus_rooms: drust::tenant::rooms::RoomBus::new(),
        bucket: drust::tenant::rooms::RoomsConfig::test_defaults().bucket(),
        rooms_cfg: drust::tenant::rooms::RoomsConfig::test_defaults(),
        mcp: Arc::new(McpHttpRegistry::new(mcp_reg)),
        files: None,
        webhooks,
        functions,
        functions_exec,
        fn_cfg,
        cron: std::sync::Arc::new(drust::cron::CronState::test_default()),
        cors_origins: Vec::new(),
    };
    let app = build_tenant_router(stack);

    // Confirm register is off by default.
    let r = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{tid}/auth/register"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({"email":"a@b.com","password":"longpassword"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::FORBIDDEN,
        "register should be off initially"
    );

    // Enable self-register via MCP tool.
    let sid = mcp_init(&app, tid, &svc_tok).await;
    let txt = mcp_call_tool(
        &app,
        tid,
        &svc_tok,
        &sid,
        "set_self_register",
        serde_json::json!({"enabled": true}),
    )
    .await;
    assert!(txt.contains("allow_self_register"), "body: {txt}");

    // Now /auth/register should succeed.
    let r = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{tid}/auth/register"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({"email":"a@b.com","password":"longpassword"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        r.status().is_success(),
        "register should now work: {}",
        r.status()
    );
    drop(dir);
}

#[tokio::test]
async fn mcp_create_user_with_profile_returns_object_not_string() {
    // Regression: profile written as JSON object should round-trip as JSON
    // object, not as a JSON-encoded string.
    let (app, tid, svc, _anon, _dir) =
        helpers::spin_up_dual_role_self_register("t-mcpu-profile").await;
    let sid = mcp_init(&app, &tid, &svc).await;
    let txt = mcp_call_tool(
        &app,
        &tid,
        &svc,
        &sid,
        "create_user",
        json!({
            "email": "p@x.com",
            "password": "longpassword",
            "profile": {"kind": "mcp-test", "note": "validation run"},
        }),
    )
    .await;
    let create_resp: serde_json::Value = serde_json::from_str(&txt).unwrap();
    let uid = create_resp["user_id"].as_str().unwrap().to_string();

    // get_user — the profile field should be an OBJECT, not a string.
    let txt = mcp_call_tool(&app, &tid, &svc, &sid, "get_user", json!({"user_id": uid})).await;
    let got: serde_json::Value = serde_json::from_str(&txt).unwrap();
    let profile = &got["profile"];
    assert!(
        profile.is_object(),
        "profile must round-trip as JSON object, got: {profile:?} (full response: {got})"
    );
    assert_eq!(profile["kind"].as_str().unwrap(), "mcp-test");
    assert_eq!(profile["note"].as_str().unwrap(), "validation run");
}

#[tokio::test]
async fn mcp_create_user_with_stringified_profile_still_round_trips_as_object() {
    // Regression: some clients (older MCP integrations, hand-rolled JSON-RPC)
    // pre-stringify a JSON object before sending. profile arrives as
    // Value::String("{...}") instead of Value::Object. We should detect this
    // and store the inner JSON so reads still surface a structured object.
    let (app, tid, svc, _anon, _dir) =
        helpers::spin_up_dual_role_self_register("t-mcpu-strprofile").await;
    let sid = mcp_init(&app, &tid, &svc).await;
    let txt = mcp_call_tool(
        &app,
        &tid,
        &svc,
        &sid,
        "create_user",
        json!({
            "email": "s@x.com",
            "password": "longpassword",
            // Client sends profile as a JSON-encoded STRING, not an object.
            "profile": r#"{"kind":"stringified","note":"client double-encoded"}"#,
        }),
    )
    .await;
    let create_resp: serde_json::Value = serde_json::from_str(&txt).unwrap();
    let uid = create_resp["user_id"].as_str().unwrap().to_string();

    let txt = mcp_call_tool(&app, &tid, &svc, &sid, "get_user", json!({"user_id": uid})).await;
    let got: serde_json::Value = serde_json::from_str(&txt).unwrap();
    let profile = &got["profile"];
    assert!(
        profile.is_object(),
        "stringified profile must still round-trip as JSON object, got: {profile:?}"
    );
    assert_eq!(profile["kind"].as_str().unwrap(), "stringified");
}
