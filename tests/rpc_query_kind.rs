//! #950 Phase 1 — `kind='query'` stored RPCs over REST.
//!
//! A query-kind RPC is a curated `FilterAst` template executed through the
//! `/list` pipeline **under the caller's identity**, so owner-scope and RLS
//! policies apply by construction. These tests pin the whole authorization
//! matrix from the wire, plus the argument gates and the wire envelope.
//!
//! The two load-bearing cases:
//!   * `anon_reads_policy_rows_through_query_rpc` — THE unlock. The same
//!     configuration is refused outright today (`RPC_ANON_OWNER_SCOPED`)
//!     because drust cannot apply RLS to raw stored-RPC SQL.
//!   * `user_readscope_all_without_caps_is_denied` — the cap-RETENTION rule.
//!     `read_scope="all"` applies no row filter, so `user_caps[select]` IS the
//!     row gate there and the RPC grant must NOT skip it.
//!
//! Spec: `docs/superpowers/specs/2026-08-10-rpc-rls-readmode-design.md`
//! §授權語意 / §錯誤目錄 (normative).

#[path = "helpers.rs"]
mod helpers;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::safety::audit_db::{AuditWriter, open_audit_db_read, open_audit_db_write};
use drust::storage::pool::SharedTenantPool;
use helpers::{grab_pool, register_and_login_via_app, spin_up_dual_role_self_register};
use serde_json::{Value, json};
use std::path::PathBuf;
use tower::ServiceExt;

/// Process-wide audit writer for this test binary (same shape as
/// `tests/rpc_v2_mutation.rs`), so the `rpc_mode` tag on a query-kind call can
/// be read back out of the audit DB.
fn ensure_global_audit_writer() -> &'static PathBuf {
    static AUDIT_PATH: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    AUDIT_PATH.get_or_init(|| {
        let dir = Box::new(tempfile::tempdir().unwrap());
        let path = dir.path().join("test_rpc_query_kind_audit.sqlite");
        let conn = open_audit_db_write(&path).unwrap();
        let (tx_ready, rx_ready) = std::sync::mpsc::channel::<()>();
        std::thread::Builder::new()
            .name("test-rpc-query-kind-audit-writer".into())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("build writer runtime");
                rt.block_on(async move {
                    let writer = AuditWriter::new(conn);
                    drust::safety::audit_db::init_globals(writer);
                    let _ = tx_ready.send(());
                    std::future::pending::<()>().await;
                });
            })
            .expect("spawn audit writer thread");
        rx_ready.recv().expect("audit writer init signal");
        let path_clone = path.clone();
        Box::leak(dir);
        path_clone
    })
}

/// Audit rows for `tenant`, `extra` flattened to top level (so `row["rpc_mode"]`
/// works) — verbatim shape from `tests/rpc_v2_mutation.rs::read_audit_lines`.
async fn read_audit_lines(tenant: &str) -> Vec<Value> {
    let path = ensure_global_audit_writer();
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    let r = open_audit_db_read(path).unwrap();
    let _ = r.execute_batch("PRAGMA wal_checkpoint(PASSIVE);");
    let mut stmt = r
        .prepare("SELECT tenant, status, op, extra FROM audit WHERE tenant = ?1 ORDER BY id ASC")
        .unwrap();
    stmt.query_map(rusqlite::params![tenant], |r| {
        let tenant: Option<String> = r.get(0)?;
        let status: Option<String> = r.get(1)?;
        let op: Option<String> = r.get(2)?;
        let extra_json: Option<String> = r.get(3)?;
        let mut map = serde_json::Map::new();
        if let Some(t) = tenant {
            map.insert("tenant".into(), Value::String(t));
        }
        if let Some(s) = status {
            map.insert("status".into(), Value::String(s));
        }
        if let Some(o) = op {
            map.insert("op".into(), Value::String(o));
        }
        if let Some(extra_str) = extra_json
            && let Ok(Value::Object(extra_map)) = serde_json::from_str::<Value>(&extra_str)
        {
            for (k, v) in extra_map {
                map.entry(k).or_insert(v);
            }
        }
        Ok(Value::Object(map))
    })
    .unwrap()
    .filter_map(Result::ok)
    .collect()
}

// ── MCP plumbing (the create face is service-only MCP / admin) ─────────

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

// ── REST plumbing ──────────────────────────────────────────────────────

fn rest_req(
    method: &str,
    tid: &str,
    path: &str,
    body: Option<Value>,
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

async fn read_json(resp: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

/// `POST /t/<id>/rpc/<name>` → (status, body).
async fn call_rpc(
    app: &axum::Router,
    tid: &str,
    token: &str,
    name: &str,
    body: Value,
) -> (StatusCode, Value) {
    call_rpc_qs(app, tid, token, name, body, "").await
}

/// `POST /t/<id>/rpc/<name>?<qs>` → (status, body).
async fn call_rpc_qs(
    app: &axum::Router,
    tid: &str,
    token: &str,
    name: &str,
    body: Value,
    qs: &str,
) -> (StatusCode, Value) {
    let path = if qs.is_empty() {
        format!("/rpc/{name}")
    } else {
        format!("/rpc/{name}?{qs}")
    };
    let resp = app
        .clone()
        .oneshot(rest_req("POST", tid, &path, Some(body), token))
        .await
        .unwrap();
    let status = resp.status();
    (status, read_json(resp).await)
}

// ── Fixtures ───────────────────────────────────────────────────────────

/// `posts(status, title, score, owner_id)` plus the `_system_collection_meta`
/// row the case under test needs. Written straight to the tenant DB BEFORE the
/// router ever reads the collection, so the router's schema cache can never
/// hold a pre-config view (the harness pool is a separate registry/cache — see
/// `tests/policy_read_enforcement.rs`).
async fn seed_posts(
    dir: &tempfile::TempDir,
    tenant: &str,
    owner_field: Option<&str>,
    read_scope: Option<&str>,
    anon_caps: &str,
    user_caps: &str,
) -> SharedTenantPool {
    let pool = grab_pool(tenant, dir).await;
    let owner = owner_field.map(|s| s.to_string());
    let scope = read_scope.map(|s| s.to_string());
    let anon = anon_caps.to_string();
    let user = user_caps.to_string();
    pool.with_writer(move |c| {
        c.execute_batch(
            "CREATE TABLE posts (
                 id         INTEGER PRIMARY KEY AUTOINCREMENT,
                 status     TEXT,
                 title      TEXT,
                 score      INTEGER DEFAULT 0,
                 owner_id   TEXT REFERENCES _system_users(id),
                 created_at TEXT NOT NULL DEFAULT (datetime('now')),
                 updated_at TEXT NOT NULL DEFAULT (datetime('now'))
             );",
        )?;
        c.execute(
            "INSERT INTO _system_collection_meta
                 (collection_name, anon_caps_json, user_caps_json, owner_field, read_scope)
                 VALUES ('posts', ?1, ?2, ?3, ?4)",
            rusqlite::params![anon, user, owner, scope],
        )?;
        Ok(())
    })
    .await
    .unwrap();
    pool
}

/// Write a select-policy USING straight to the tenant DB (same pre-router
/// ordering rule as `seed_posts`).
async fn set_select_policy(pool: &SharedTenantPool, coll: &str, policy_json: Value) {
    let policy: drust::query::policy::Policy = serde_json::from_value(policy_json).unwrap();
    let coll_owned = coll.to_string();
    pool.with_writer(move |c| {
        drust::storage::schema::write_policy(
            c,
            &coll_owned,
            drust::storage::schema::DmlVerb::Select,
            Some(&policy),
        )
    })
    .await
    .unwrap();
    pool.schema_cache.invalidate(coll);
}

/// Create a `kind='query'` RPC through the MCP create face (service-only).
async fn create_query_rpc(
    app: &axum::Router,
    tid: &str,
    svc: &str,
    sid: &str,
    name: &str,
    params: Value,
    query: Value,
    anon_callable: bool,
) -> String {
    mcp_call_tool(
        app,
        tid,
        svc,
        sid,
        "create_rpc",
        json!({
            "name": name,
            "params": params,
            "kind": "query",
            "query": query,
            "anon_callable": anon_callable,
        }),
    )
    .await
}

async fn insert_post(app: &axum::Router, tid: &str, svc: &str, data: Value) {
    let resp = app
        .clone()
        .oneshot(rest_req(
            "POST",
            tid,
            "/records/posts",
            Some(json!({ "data": data })),
            svc,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED, "insert failed");
}

async fn user_id_for(pool: &SharedTenantPool, email: &str) -> String {
    let e = email.to_string();
    pool.with_reader(move |c| {
        c.query_row(
            "SELECT id FROM _system_users WHERE email = ?1",
            rusqlite::params![e],
            |r| r.get::<_, String>(0),
        )
    })
    .await
    .unwrap()
}

fn titles(v: &Value) -> Vec<String> {
    v["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["title"].as_str().unwrap_or_default().to_string())
        .collect()
}

// ── 1. THE unlock: anon × policy-protected, non-owner-scoped ───────────

#[tokio::test]
async fn anon_reads_policy_rows_through_query_rpc() {
    let (app, tid, svc, anon, dir) = spin_up_dual_role_self_register("qk-unlock").await;
    // anon_caps=[] on purpose: the RPC's own anon_callable flag is the grant.
    let pool = seed_posts(&dir, &tid, None, None, "[]", "[]").await;
    set_select_policy(&pool, "posts", json!({"using": {"status": "published"}})).await;

    let sid = mcp_init(&app, &tid, &svc).await;
    let out = create_query_rpc(
        &app,
        &tid,
        &svc,
        &sid,
        "recent_posts",
        json!([]),
        json!({"collection": "posts", "sort": {"field": "id", "dir": "asc"}}),
        true,
    )
    .await;
    assert!(out.contains("created"), "create query rpc: {out}");

    insert_post(
        &app,
        &tid,
        &svc,
        json!({"status":"published","title":"pub"}),
    )
    .await;
    insert_post(&app, &tid, &svc, json!({"status":"draft","title":"priv"})).await;

    let (status, v) = call_rpc(&app, &tid, &anon, "recent_posts", json!({})).await;
    assert_eq!(status, StatusCode::OK, "anon query rpc body: {v}");
    assert_eq!(titles(&v), vec!["pub".to_string()], "policy must filter");
    assert_eq!(v["total"], 1);
    assert_eq!(v["page"], 1);
    assert_eq!(v["perPage"], 20);
    assert!(
        v.get("rows").is_none() && v.get("column_names").is_none(),
        "query kind must use the /list envelope, not the sql one: {v}"
    );
}

// ── 2. anon × owner-scoped stays refused ───────────────────────────────

#[tokio::test]
async fn anon_on_owner_scoped_is_forbidden() {
    let (app, tid, svc, anon, dir) = spin_up_dual_role_self_register("qk-anon-owner").await;
    let pool = seed_posts(
        &dir,
        &tid,
        Some("owner_id"),
        Some("own"),
        "[\"select\"]",
        "[\"select\"]",
    )
    .await;
    set_select_policy(&pool, "posts", json!({"using": {"status": "published"}})).await;

    let sid = mcp_init(&app, &tid, &svc).await;
    let out = create_query_rpc(
        &app,
        &tid,
        &svc,
        &sid,
        "my_posts",
        json!([]),
        json!({"collection": "posts"}),
        true,
    )
    .await;
    assert!(out.contains("created"), "create query rpc: {out}");

    let (status, v) = call_rpc(&app, &tid, &anon, "my_posts", json!({})).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body: {v}");
    assert_eq!(v["error_code"], "ANON_FORBIDDEN_OWNER_SCOPED");
}

// ── 3. user × owner-scoped read_scope="own" → own rows only ────────────

#[tokio::test]
async fn user_own_scope_sees_only_own_rows() {
    let (app, tid, svc, _anon, dir) = spin_up_dual_role_self_register("qk-own").await;
    let pool = seed_posts(&dir, &tid, Some("owner_id"), Some("own"), "[]", "[]").await;

    let ta = register_and_login_via_app(&app, &tid, "a@x.com", "longpassword").await;
    let _tb = register_and_login_via_app(&app, &tid, "b@x.com", "longpassword").await;
    let uid_a = user_id_for(&pool, "a@x.com").await;
    let uid_b = user_id_for(&pool, "b@x.com").await;

    let sid = mcp_init(&app, &tid, &svc).await;
    let out = create_query_rpc(
        &app,
        &tid,
        &svc,
        &sid,
        "my_posts",
        json!([]),
        json!({"collection": "posts"}),
        true,
    )
    .await;
    assert!(out.contains("created"), "create query rpc: {out}");

    insert_post(&app, &tid, &svc, json!({"title":"a1","owner_id":uid_a})).await;
    insert_post(&app, &tid, &svc, json!({"title":"b1","owner_id":uid_b})).await;

    let (status, v) = call_rpc(&app, &tid, &ta, "my_posts", json!({})).await;
    assert_eq!(status, StatusCode::OK, "body: {v}");
    assert_eq!(titles(&v), vec!["a1".to_string()]);
    assert_eq!(v["total"], 1);
}

// ── 4. cap RETENTION: read_scope="all" + user_caps=[] → 403 ────────────

#[tokio::test]
async fn user_readscope_all_without_caps_is_denied() {
    let (app, tid, svc, _anon, dir) = spin_up_dual_role_self_register("qk-all-nocap").await;
    // user_caps=[] with read_scope="all": no row filter applies, so the cap is
    // the row gate and RpcGrant must NOT skip it.
    let pool = seed_posts(&dir, &tid, Some("owner_id"), Some("all"), "[]", "[]").await;

    let ta = register_and_login_via_app(&app, &tid, "a@x.com", "longpassword").await;
    let uid_a = user_id_for(&pool, "a@x.com").await;

    let sid = mcp_init(&app, &tid, &svc).await;
    let out = create_query_rpc(
        &app,
        &tid,
        &svc,
        &sid,
        "all_posts",
        json!([]),
        json!({"collection": "posts"}),
        true,
    )
    .await;
    assert!(out.contains("created"), "create query rpc: {out}");
    insert_post(&app, &tid, &svc, json!({"title":"a1","owner_id":uid_a})).await;

    let (status, v) = call_rpc(&app, &tid, &ta, "all_posts", json!({})).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body: {v}");
    assert_eq!(v["error_code"], "ANON_CAP_DENIED");
    assert!(
        v.get("records").is_none(),
        "a denied call must not leak rows: {v}"
    );
}

// ── 5. same, with user_caps=["select"] → all rows (parity with /list) ──

#[tokio::test]
async fn user_readscope_all_with_caps_sees_all_rows() {
    let (app, tid, svc, _anon, dir) = spin_up_dual_role_self_register("qk-all-cap").await;
    let pool = seed_posts(
        &dir,
        &tid,
        Some("owner_id"),
        Some("all"),
        "[]",
        "[\"select\"]",
    )
    .await;

    let ta = register_and_login_via_app(&app, &tid, "a@x.com", "longpassword").await;
    let _tb = register_and_login_via_app(&app, &tid, "b@x.com", "longpassword").await;
    let uid_a = user_id_for(&pool, "a@x.com").await;
    let uid_b = user_id_for(&pool, "b@x.com").await;

    let sid = mcp_init(&app, &tid, &svc).await;
    let out = create_query_rpc(
        &app,
        &tid,
        &svc,
        &sid,
        "all_posts",
        json!([]),
        json!({"collection": "posts", "sort": {"field": "id", "dir": "asc"}}),
        true,
    )
    .await;
    assert!(out.contains("created"), "create query rpc: {out}");
    insert_post(&app, &tid, &svc, json!({"title":"a1","owner_id":uid_a})).await;
    insert_post(&app, &tid, &svc, json!({"title":"b1","owner_id":uid_b})).await;

    let (status, v) = call_rpc(&app, &tid, &ta, "all_posts", json!({})).await;
    assert_eq!(status, StatusCode::OK, "body: {v}");
    assert_eq!(titles(&v), vec!["a1".to_string(), "b1".to_string()]);
}

// ── 6. anon_callable=0 → the existing role deny ────────────────────────

#[tokio::test]
async fn anon_callable_false_denies_anon() {
    let (app, tid, svc, anon, dir) = spin_up_dual_role_self_register("qk-nocall").await;
    seed_posts(&dir, &tid, None, None, "[\"select\"]", "[\"select\"]").await;

    let sid = mcp_init(&app, &tid, &svc).await;
    let out = create_query_rpc(
        &app,
        &tid,
        &svc,
        &sid,
        "svc_only",
        json!([]),
        json!({"collection": "posts"}),
        false,
    )
    .await;
    assert!(out.contains("created"), "create query rpc: {out}");
    insert_post(&app, &tid, &svc, json!({"title":"a1"})).await;

    let (status, v) = call_rpc(&app, &tid, &anon, "svc_only", json!({})).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body: {v}");
    assert_eq!(v["error_code"], "ANON_DENIED");

    // …and the service token still gets through the same RPC.
    let (status, v) = call_rpc(&app, &tid, &svc, "svc_only", json!({})).await;
    assert_eq!(status, StatusCode::OK, "body: {v}");
    assert_eq!(v["total"], 1);
}

// ── 7. RpcGrant existence proof: anon_caps=[], no policy → whole table ─

#[tokio::test]
async fn rpc_grant_opens_a_capless_non_owner_collection() {
    let (app, tid, svc, anon, dir) = spin_up_dual_role_self_register("qk-grant").await;
    seed_posts(&dir, &tid, None, None, "[]", "[]").await;

    let sid = mcp_init(&app, &tid, &svc).await;
    let out = create_query_rpc(
        &app,
        &tid,
        &svc,
        &sid,
        "all_posts",
        json!([]),
        json!({"collection": "posts", "sort": {"field": "id", "dir": "asc"}}),
        true,
    )
    .await;
    assert!(out.contains("created"), "create query rpc: {out}");
    insert_post(&app, &tid, &svc, json!({"title":"a1"})).await;
    insert_post(&app, &tid, &svc, json!({"title":"a2"})).await;

    // The documented trade-off (spec §否決的替代): an anon-callable query RPC
    // over a non-owner-scoped, policy-free collection exposes every row.
    let (status, v) = call_rpc(&app, &tid, &anon, "all_posts", json!({})).await;
    assert_eq!(status, StatusCode::OK, "body: {v}");
    assert_eq!(titles(&v), vec!["a1".to_string(), "a2".to_string()]);

    // …while plain `/list` on the same collection still obeys anon_caps.
    let resp = app
        .clone()
        .oneshot(rest_req(
            "POST",
            &tid,
            "/collections/posts/list",
            Some(json!({})),
            &anon,
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "the grant must not leak into /list"
    );
}

// ── 8. AST injection: an object argument is refused ────────────────────

#[tokio::test]
async fn object_param_is_rejected_as_not_scalar() {
    let (app, tid, svc, _anon, dir) = spin_up_dual_role_self_register("qk-notscalar").await;
    seed_posts(&dir, &tid, None, None, "[\"select\"]", "[\"select\"]").await;

    let sid = mcp_init(&app, &tid, &svc).await;
    let out = create_query_rpc(
        &app,
        &tid,
        &svc,
        &sid,
        "by_title",
        json!([{"name":"who","type":"text","required":true}]),
        json!({"collection": "posts", "filter": {"title": {"$param": "who"}}}),
        true,
    )
    .await;
    assert!(out.contains("created"), "create query rpc: {out}");

    let (status, v) = call_rpc(
        &app,
        &tid,
        &svc,
        "by_title",
        json!({"who": {"$fts": {"index": "i", "query": "x"}}}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {v}");
    assert_eq!(v["error_code"], "RPC_PARAM_NOT_SCALAR");

    // An array argument is the same gate.
    let (status, v) = call_rpc(&app, &tid, &svc, "by_title", json!({"who": [1, 2]})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {v}");
    assert_eq!(v["error_code"], "RPC_PARAM_NOT_SCALAR");
}

// ── 9. param type / unknown key mirror the sql arm exactly ─────────────

#[tokio::test]
async fn param_type_and_unknown_key_mirror_the_sql_arm() {
    let (app, tid, svc, _anon, dir) = spin_up_dual_role_self_register("qk-params").await;
    seed_posts(&dir, &tid, None, None, "[\"select\"]", "[\"select\"]").await;

    let sid = mcp_init(&app, &tid, &svc).await;
    let out = create_query_rpc(
        &app,
        &tid,
        &svc,
        &sid,
        "by_score",
        json!([{"name":"min","type":"integer","required":true}]),
        json!({"collection": "posts", "filter": {"score": {"gte": {"$param": "min"}}}}),
        true,
    )
    .await;
    assert!(out.contains("created"), "create query rpc: {out}");

    let (status, v) = call_rpc(&app, &tid, &svc, "by_score", json!({"min": "nope"})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {v}");
    assert_eq!(v["error_code"], "PARAM_TYPE_MISMATCH");

    let (status, v) = call_rpc(&app, &tid, &svc, "by_score", json!({"nope": 1})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {v}");
    assert_eq!(v["error_code"], "PARAM_UNKNOWN");
}

// ── 10. schema drift after save → 409 RPC_QUERY_STALE ──────────────────

#[tokio::test]
async fn dropped_field_makes_the_template_stale() {
    let (app, tid, svc, _anon, dir) = spin_up_dual_role_self_register("qk-stale").await;
    seed_posts(&dir, &tid, None, None, "[\"select\"]", "[\"select\"]").await;

    let sid = mcp_init(&app, &tid, &svc).await;
    let out = create_query_rpc(
        &app,
        &tid,
        &svc,
        &sid,
        "published",
        json!([]),
        json!({"collection": "posts", "filter": {"status": "published"}}),
        true,
    )
    .await;
    assert!(out.contains("created"), "create query rpc: {out}");
    insert_post(&app, &tid, &svc, json!({"status":"published","title":"a1"})).await;

    let (status, _) = call_rpc(&app, &tid, &svc, "published", json!({})).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "sanity: template works before drift"
    );

    // Drop the templated column THROUGH the app so the router's schema cache
    // is invalidated the way a real caller would see it.
    let out = mcp_call_tool(
        &app,
        &tid,
        &svc,
        &sid,
        "drop_field",
        json!({"collection": "posts", "field": "status"}),
    )
    .await;
    assert!(!out.to_lowercase().contains("error"), "drop_field: {out}");

    let (status, v) = call_rpc(&app, &tid, &svc, "published", json!({})).await;
    assert_eq!(status, StatusCode::CONFLICT, "body: {v}");
    assert_eq!(v["error_code"], "RPC_QUERY_STALE");
}

// ── 11. paging is query-string; dry_run is refused ─────────────────────

#[tokio::test]
async fn paging_and_dry_run_wire_contract() {
    let (app, tid, svc, _anon, dir) = spin_up_dual_role_self_register("qk-wire").await;
    seed_posts(&dir, &tid, None, None, "[\"select\"]", "[\"select\"]").await;

    let sid = mcp_init(&app, &tid, &svc).await;
    let out = create_query_rpc(
        &app,
        &tid,
        &svc,
        &sid,
        "all_posts",
        json!([]),
        json!({"collection": "posts", "sort": {"field": "id", "dir": "asc"}}),
        true,
    )
    .await;
    assert!(out.contains("created"), "create query rpc: {out}");
    for i in 0..3 {
        insert_post(&app, &tid, &svc, json!({"title": format!("a{i}")})).await;
    }

    // per_page over the ceiling is a typed 422, never a silent clamp.
    let (status, v) = call_rpc_qs(&app, &tid, &svc, "all_posts", json!({}), "per_page=501").await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "body: {v}");
    assert_eq!(v["error_code"], "PAGE_RANGE_INVALID");

    // A real page window echoes back in the envelope.
    let (status, v) = call_rpc_qs(
        &app,
        &tid,
        &svc,
        "all_posts",
        json!({}),
        "page=2&per_page=2",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {v}");
    assert_eq!(v["page"], 2);
    assert_eq!(v["perPage"], 2);
    assert_eq!(v["total"], 3);
    assert_eq!(titles(&v), vec!["a2".to_string()]);

    // dry_run has no meaning for a read-only template.
    let (status, v) = call_rpc_qs(&app, &tid, &svc, "all_posts", json!({}), "dry_run=true").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {v}");
    assert_eq!(v["error_code"], "RPC_KIND_INVALID");
}

// ── 12. equivalence with POST /list ────────────────────────────────────

#[tokio::test]
async fn query_rpc_equals_post_list_for_the_same_filter() {
    let (app, tid, svc, _anon, dir) = spin_up_dual_role_self_register("qk-equiv").await;
    seed_posts(&dir, &tid, None, None, "[\"select\"]", "[\"select\"]").await;

    let sid = mcp_init(&app, &tid, &svc).await;
    let filter = json!({"status": "published"});
    let out = create_query_rpc(
        &app,
        &tid,
        &svc,
        &sid,
        "published",
        json!([]),
        json!({"collection": "posts", "filter": filter,
               "sort": {"field": "id", "dir": "asc"}}),
        true,
    )
    .await;
    assert!(out.contains("created"), "create query rpc: {out}");
    insert_post(&app, &tid, &svc, json!({"status":"published","title":"p1"})).await;
    insert_post(&app, &tid, &svc, json!({"status":"draft","title":"d1"})).await;
    insert_post(&app, &tid, &svc, json!({"status":"published","title":"p2"})).await;

    let resp = app
        .clone()
        .oneshot(rest_req(
            "POST",
            &tid,
            "/collections/posts/list",
            Some(json!({"filter": filter, "sort": {"field":"id","dir":"asc"}})),
            &svc,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let list_body = read_json(resp).await;

    let (status, rpc_body) = call_rpc(&app, &tid, &svc, "published", json!({})).await;
    assert_eq!(status, StatusCode::OK, "body: {rpc_body}");

    assert_eq!(
        rpc_body["records"], list_body["records"],
        "the query arm must return the /list result set verbatim"
    );
    let keys = |v: &Value| {
        let mut k: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
        k.sort();
        k
    };
    assert_eq!(
        keys(&rpc_body),
        keys(&list_body),
        "the query arm must use the /list envelope"
    );
}

// ══════════════════════════════════════════════════════════════════════
// T4 review round (T4b) — F1/F3/F4/F6
// ══════════════════════════════════════════════════════════════════════

/// Seed a `_system_rpc` row straight through the registry, bypassing both
/// create faces. Used to stand up rows a face now refuses — the LEGACY shape a
/// runtime gate has to keep catching.
async fn seed_query_rpc_directly(
    pool: &SharedTenantPool,
    name: &str,
    params_json: &str,
    query_json: &str,
    anon_callable: bool,
) {
    let (name, params_json, query_json) = (
        name.to_string(),
        params_json.to_string(),
        query_json.to_string(),
    );
    pool.with_writer(move |c| {
        drust::rpc::registry::create(
            c,
            drust::rpc::registry::RpcCreate {
                name: &name,
                sql: "",
                params_json: &params_json,
                description: None,
                anon_callable,
                mode: drust::rpc::registry::RpcMode::Read,
                kind: drust::rpc::registry::RpcKind::Query,
                query_json: Some(&query_json),
            },
        )
        .map_err(|e| {
            rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(1), Some(e.to_string()))
        })
    })
    .await
    .unwrap();
}

// ── F1: a caller-suppliable `user_id` param is an identity spoof ───────

#[tokio::test]
async fn create_face_refuses_a_user_id_param_on_a_query_rpc() {
    let (app, tid, svc, _anon, dir) = spin_up_dual_role_self_register("qk-userid-create").await;
    let pool = seed_posts(&dir, &tid, None, None, "[]", "[]").await;

    let sid = mcp_init(&app, &tid, &svc).await;
    let out = create_query_rpc(
        &app,
        &tid,
        &svc,
        &sid,
        "my_rows",
        json!([{"name":"user_id","type":"text","required":true}]),
        json!({"collection": "posts", "filter": {"owner_id": {"$param": "user_id"}}}),
        true,
    )
    .await;
    assert!(
        out.contains("$auth"),
        "the refusal must point at the operand that IS bound: {out}"
    );
    assert!(
        out.contains("RPC_KIND_INVALID"),
        "typed code missing: {out}"
    );
    let n: i64 = pool
        .with_reader(|c| {
            c.query_row(
                "SELECT COUNT(*) FROM _system_rpc WHERE name = 'my_rows'",
                [],
                |r| r.get(0),
            )
        })
        .await
        .unwrap();
    assert_eq!(n, 0, "no row may land");

    // The sanctioned form saves and works.
    let out = create_query_rpc(
        &app,
        &tid,
        &svc,
        &sid,
        "my_rows_auth",
        json!([]),
        json!({"collection": "posts", "filter": {"owner_id": {"$auth": "id"}}}),
        true,
    )
    .await;
    assert!(out.contains("created"), "$auth form must save: {out}");
}

#[tokio::test]
async fn legacy_user_id_param_row_is_refused_at_call_time() {
    // Defense in depth: the create face now refuses this shape, but a row that
    // predates the refusal (or a hand-edited DB) must not stay spoofable — the
    // template would filter on a body-supplied user id, so ANY caller could
    // read ANY user's rows through it.
    let (app, tid, svc, anon, dir) = spin_up_dual_role_self_register("qk-userid-legacy").await;
    let pool = seed_posts(&dir, &tid, None, None, "[]", "[]").await;
    let ta = register_and_login_via_app(&app, &tid, "a@x.com", "longpassword").await;
    let uid_a = user_id_for(&pool, "a@x.com").await;
    let _ = ta;

    seed_query_rpc_directly(
        &pool,
        "my_rows",
        r#"[{"name":"user_id","type":"text","required":true}]"#,
        r#"{"collection":"posts","filter":{"owner_id":{"$param":"user_id"}}}"#,
        true,
    )
    .await;
    insert_post(&app, &tid, &svc, json!({"title":"secret","owner_id":uid_a})).await;

    let (status, v) = call_rpc(&app, &tid, &anon, "my_rows", json!({"user_id": uid_a})).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a spoofable stored row must fail closed, body: {v}"
    );
    assert_eq!(v["error_code"], "RPC_KIND_INVALID");
    assert!(v.get("records").is_none(), "no rows may come back: {v}");
}

// ── F3: a stale-schema DB error must not echo the generated SQL ────────

#[tokio::test]
async fn db_error_does_not_leak_the_generated_sql() {
    let (app, tid, svc, anon, dir) = spin_up_dual_role_self_register("qk-sqlleak").await;
    let pool = seed_posts(&dir, &tid, None, None, "[]", "[]").await;
    set_select_policy(&pool, "posts", json!({"using": {"status": "published"}})).await;

    let sid = mcp_init(&app, &tid, &svc).await;
    let out = create_query_rpc(
        &app,
        &tid,
        &svc,
        &sid,
        "published",
        json!([]),
        json!({"collection": "posts", "filter": {"status": "published"}}),
        true,
    )
    .await;
    assert!(out.contains("created"), "create query rpc: {out}");
    insert_post(&app, &tid, &svc, json!({"status":"published","title":"a1"})).await;

    // The router's SCHEMA cache is already warm (the create face and the insert
    // both loaded it) — but no reader has PREPARED the list SQL yet. Now drop
    // the table out of band through the harness pool (a separate registry, so
    // the router's schema cache stays stale). The next call compiles a SELECT
    // against the cached schema and prepares it fresh, and rusqlite renders
    // that failure as `SqlInputError`, whose Display carries the whole
    // statement — RLS policy clause included.
    //
    // Two mechanics this repro depends on: DROP the TABLE, not a column
    // (SQLite's legacy double-quoted-string misfeature turns an unresolvable
    // `"col"` into the string literal 'col', so a dropped column never errors),
    // and do NOT pre-run the query (`run_bound_select` uses `prepare_cached`,
    // and a warm statement cache fails at step with a bare `SqliteFailure`
    // instead — no SQL, and nothing for this test to catch).
    pool.with_writer(|c| c.execute_batch("DROP TABLE posts;"))
        .await
        .unwrap();

    let (status, v) = call_rpc(&app, &tid, &anon, "published", json!({})).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "body: {v}");
    assert_eq!(v["error_code"], "DB_ERROR");
    let msg = v["message"].as_str().unwrap_or_default();
    assert!(
        msg.contains("no such table"),
        "the operator still needs the cause: {msg}"
    );
    assert!(
        !msg.to_uppercase().contains("SELECT"),
        "the generated SQL (owner/policy clauses included) leaked to an anon caller: {msg}"
    );
    // Honest scope: the drift reachable from HERE (a dropped table) is an
    // offset-less `SqliteFailure`, which carries no statement to begin with —
    // SQLite's legacy double-quoted-string misfeature swallows the dropped-
    // COLUMN case entirely, so this test alone cannot prove the redaction. The
    // stripping itself is pinned on a real `SqlInputError` by
    // `records_list::tests::db_error_response_never_echoes_the_generated_statement`.
}

// ── F4: a bad ?page= is a typed 422, and the sql arms ignore it ────────

#[tokio::test]
async fn unparsable_paging_is_typed_and_only_binds_the_query_arm() {
    let (app, tid, svc, _anon, dir) = spin_up_dual_role_self_register("qk-badpage").await;
    seed_posts(&dir, &tid, None, None, "[\"select\"]", "[\"select\"]").await;

    let sid = mcp_init(&app, &tid, &svc).await;
    let out = mcp_call_tool(
        &app,
        &tid,
        &svc,
        &sid,
        "create_rpc",
        json!({"name": "ping", "sql": "SELECT 1 AS x", "params": []}),
    )
    .await;
    assert!(out.contains("created"), "create sql rpc: {out}");
    let out = create_query_rpc(
        &app,
        &tid,
        &svc,
        &sid,
        "all_posts",
        json!([]),
        json!({"collection": "posts"}),
        true,
    )
    .await;
    assert!(out.contains("created"), "create query rpc: {out}");

    // A sql-kind RPC never reads paging — a junk value must stay ignored.
    let (status, v) = call_rpc_qs(&app, &tid, &svc, "ping", json!({}), "page=abc").await;
    assert_eq!(status, StatusCode::OK, "sql arm must ignore paging: {v}");
    assert_eq!(v["column_names"][0], "x", "the sql rpc really ran: {v}");
    assert_eq!(v["rows"][0][0], 1, "the sql rpc really ran: {v}");

    // The query arm reads it, so a junk value is the same typed 422 an
    // out-of-range value gets — a JSON envelope, not axum's bare rejection.
    for qs in [
        "page=abc",
        "per_page=abc",
        "page=-1",
        "per_page=99999999999",
    ] {
        let (status, v) = call_rpc_qs(&app, &tid, &svc, "all_posts", json!({}), qs).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{qs} → body: {v}");
        assert_eq!(v["error_code"], "PAGE_RANGE_INVALID", "{qs}");
    }
}

// ── F6: counters, audit tag, and a param literally named `page` ────────

#[tokio::test]
async fn query_call_bumps_the_counter_and_tags_the_audit_row() {
    ensure_global_audit_writer();
    let (app, tid, svc, _anon, dir) = spin_up_dual_role_self_register("qk-counters").await;
    let pool = seed_posts(&dir, &tid, None, None, "[]", "[]").await;
    let ta = register_and_login_via_app(&app, &tid, "a@x.com", "longpassword").await;

    let sid = mcp_init(&app, &tid, &svc).await;
    let out = create_query_rpc(
        &app,
        &tid,
        &svc,
        &sid,
        "all_posts",
        json!([]),
        json!({"collection": "posts"}),
        true,
    )
    .await;
    assert!(out.contains("created"), "create query rpc: {out}");

    let (status, _) = call_rpc(&app, &tid, &ta, "all_posts", json!({})).await;
    assert_eq!(status, StatusCode::OK);

    // The bump is fire-and-forget on the writer mutex — poll briefly.
    let mut counts = (0i64, 0i64);
    for _ in 0..40 {
        counts = pool
            .with_reader(|c| {
                c.query_row(
                    "SELECT anon_calls, service_calls FROM _system_rpc WHERE name = 'all_posts'",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
            })
            .await
            .unwrap();
        if counts.0 > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    assert_eq!(
        counts,
        (1, 0),
        "a user call must bump anon_calls exactly like the sql read arm"
    );

    let rows = read_audit_lines(&tid).await;
    assert!(
        rows.iter().any(|r| r["rpc_mode"].as_str() == Some("query")),
        "no audit row tagged rpc_mode=query: {rows:?}"
    );
}

#[tokio::test]
async fn a_param_named_page_does_not_collide_with_paging() {
    // The reason paging lives on the query string: the body IS the declared
    // param map, so `page` must remain a usable param name.
    let (app, tid, svc, _anon, dir) = spin_up_dual_role_self_register("qk-page-param").await;
    seed_posts(&dir, &tid, None, None, "[\"select\"]", "[\"select\"]").await;

    let sid = mcp_init(&app, &tid, &svc).await;
    let out = create_query_rpc(
        &app,
        &tid,
        &svc,
        &sid,
        "by_title",
        json!([{"name":"page","type":"text","required":true}]),
        json!({"collection": "posts", "filter": {"title": {"$param": "page"}},
               "sort": {"field": "id", "dir": "asc"}}),
        true,
    )
    .await;
    assert!(out.contains("created"), "create query rpc: {out}");
    insert_post(&app, &tid, &svc, json!({"title":"a1"})).await;
    insert_post(&app, &tid, &svc, json!({"title":"a2"})).await;

    // Body `page` is the filter argument; query-string `page` is the window.
    let (status, v) = call_rpc(&app, &tid, &svc, "by_title", json!({"page": "a1"})).await;
    assert_eq!(status, StatusCode::OK, "body: {v}");
    assert_eq!(titles(&v), vec!["a1".to_string()]);
    assert_eq!(v["page"], 1);

    let (status, v) = call_rpc_qs(
        &app,
        &tid,
        &svc,
        "by_title",
        json!({"page": "a1"}),
        "page=2&per_page=1",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {v}");
    assert_eq!(v["total"], 1, "the filter still applied");
    assert_eq!(v["page"], 2);
    assert!(v["records"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn create_face_refuses_a_protected_collection_template() {
    let (app, tid, svc, _anon, dir) = spin_up_dual_role_self_register("qk-protected").await;
    seed_posts(&dir, &tid, None, None, "[]", "[]").await;

    let sid = mcp_init(&app, &tid, &svc).await;
    let out = create_query_rpc(
        &app,
        &tid,
        &svc,
        &sid,
        "peek_users",
        json!([]),
        json!({"collection": "_system_users"}),
        true,
    )
    .await;
    assert!(
        out.contains("PROTECTED_COLLECTION"),
        "typed code missing: {out}"
    );

    let out = create_query_rpc(
        &app,
        &tid,
        &svc,
        &sid,
        "peek_nothing",
        json!([]),
        json!({"collection": "nope"}),
        true,
    )
    .await;
    assert!(
        out.contains("COLLECTION_NOT_FOUND"),
        "typed code missing: {out}"
    );
}

// ══════════════════════════════════════════════════════════════════════
// T5 — the guard matrix: CLEAR guards, cron refusal, update-face validation
// ══════════════════════════════════════════════════════════════════════

/// `(anon_callable, query_json)` straight from `_system_rpc`.
async fn rpc_row(pool: &SharedTenantPool, name: &str) -> (bool, Option<String>) {
    let n = name.to_string();
    pool.with_reader(move |c| {
        c.query_row(
            "SELECT anon_callable, query_json FROM _system_rpc WHERE name = ?1",
            rusqlite::params![n],
            |r| Ok((r.get::<_, i64>(0)? != 0, r.get::<_, Option<String>>(1)?)),
        )
    })
    .await
    .unwrap()
}

/// Any REST call that returns JSON → (status, body).
async fn rest(
    app: &axum::Router,
    method: &str,
    tid: &str,
    path: &str,
    body: Option<Value>,
    token: &str,
) -> (StatusCode, Value) {
    let resp = app
        .clone()
        .oneshot(rest_req(method, tid, path, body, token))
        .await
        .unwrap();
    let status = resp.status();
    (status, read_json(resp).await)
}

/// THE widening gate. An anon-callable query RPC is a GRANT of exactly the
/// rows the select policy leaves visible; clearing that policy turns it into a
/// grant of the WHOLE table, and no pre-#950 guard runs on a clear. So the
/// clear is refused until the RPC is disarmed — two steps, never silent.
#[tokio::test]
async fn clearing_a_select_policy_is_refused_while_an_anon_query_rpc_targets_it() {
    let (app, tid, svc, _anon, dir) = spin_up_dual_role_self_register("qk-clear-policy").await;
    let pool = seed_posts(&dir, &tid, None, None, "[]", "[]").await;
    set_select_policy(&pool, "posts", json!({"using": {"status": "published"}})).await;

    let sid = mcp_init(&app, &tid, &svc).await;
    let out = create_query_rpc(
        &app,
        &tid,
        &svc,
        &sid,
        "recent_posts",
        json!([]),
        json!({"collection": "posts"}),
        true,
    )
    .await;
    assert!(out.contains("created"), "create query rpc: {out}");

    // REST DELETE of the select policy → refused, typed, and NOTHING cleared.
    let (status, v) = rest(
        &app,
        "DELETE",
        &tid,
        "/collections/posts/policies/select",
        None,
        &svc,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "body: {v}");
    assert_eq!(v["error_code"], "RPC_QUERY_GRANT_ACTIVE", "body: {v}");
    assert!(
        v["message"]
            .as_str()
            .unwrap_or_default()
            .contains("recent_posts"),
        "must name the blocking rpc: {v}"
    );
    let (_, stored) = rest(&app, "GET", &tid, "/collections/posts/policies", None, &svc).await;
    assert_eq!(
        stored["stored"]["select"]["using"]["status"], "published",
        "a refused clear must leave the policy in place: {stored}"
    );

    // The MCP face refuses identically (parallel-site parity).
    let out = mcp_call_tool(
        &app,
        &tid,
        &svc,
        &sid,
        "clear_policy",
        json!({"collection": "posts", "op": "select"}),
    )
    .await;
    assert!(
        out.contains(r#""error_code":"RPC_QUERY_GRANT_ACTIVE""#),
        "the sentinel must be the machine-readable code: {out}"
    );

    // Other ops' clears are UNAFFECTED — the grant only rides the select path.
    let (status, v) = rest(
        &app,
        "DELETE",
        &tid,
        "/collections/posts/policies/insert",
        None,
        &svc,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "insert-op clear must pass: {v}");

    // Two-step remedy: disarm the RPC, then the clear goes through.
    let out = mcp_call_tool(
        &app,
        &tid,
        &svc,
        &sid,
        "update_rpc",
        json!({"name": "recent_posts", "anon_callable": false}),
    )
    .await;
    assert!(out.contains("updated"), "disarm: {out}");
    let (status, v) = rest(
        &app,
        "DELETE",
        &tid,
        "/collections/posts/policies/select",
        None,
        &svc,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {v}");
    let (_, stored) = rest(&app, "GET", &tid, "/collections/posts/policies", None, &svc).await;
    assert!(
        stored["stored"]["select"].is_null(),
        "the clear must have landed: {stored}"
    );
}

/// Same widening, the other clause: dropping `owner_field` turns a per-user
/// grant into a whole-table one. Both faces refuse.
#[tokio::test]
async fn clearing_owner_field_is_refused_while_an_anon_query_rpc_targets_it() {
    let (app, tid, svc, _anon, dir) = spin_up_dual_role_self_register("qk-clear-owner").await;
    let pool = seed_posts(&dir, &tid, Some("owner_id"), Some("own"), "[]", "[]").await;

    let sid = mcp_init(&app, &tid, &svc).await;
    let out = create_query_rpc(
        &app,
        &tid,
        &svc,
        &sid,
        "my_posts",
        json!([]),
        json!({"collection": "posts"}),
        true,
    )
    .await;
    assert!(out.contains("created"), "create query rpc: {out}");

    let (status, v) = rest(
        &app,
        "DELETE",
        &tid,
        "/collections/posts/owner-field",
        None,
        &svc,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "body: {v}");
    assert_eq!(v["error_code"], "RPC_QUERY_GRANT_ACTIVE", "body: {v}");

    let out = mcp_call_tool(
        &app,
        &tid,
        &svc,
        &sid,
        "set_owner_field",
        json!({"collection": "posts", "field": null}),
    )
    .await;
    assert!(out.contains("RPC_QUERY_GRANT_ACTIVE"), "mcp face: {out}");
    // T5b (B3) — and it arrives as the WIRE error_code, not buried behind
    // `PrepareError`'s Display prefix (bail_mcp reads up to the first colon).
    assert!(
        out.contains(r#""error_code":"RPC_QUERY_GRANT_ACTIVE""#),
        "the sentinel must be the machine-readable code: {out}"
    );

    // Still owner-scoped after two refusals.
    let owner: Option<String> = pool
        .with_reader(|c| {
            c.query_row(
                "SELECT owner_field FROM _system_collection_meta WHERE collection_name = 'posts'",
                [],
                |r| r.get(0),
            )
        })
        .await
        .unwrap();
    assert_eq!(owner.as_deref(), Some("owner_id"), "nothing may be cleared");

    // Disarm, then clear.
    let out = mcp_call_tool(
        &app,
        &tid,
        &svc,
        &sid,
        "update_rpc",
        json!({"name": "my_posts", "anon_callable": false}),
    )
    .await;
    assert!(out.contains("updated"), "disarm: {out}");
    let (status, v) = rest(
        &app,
        "DELETE",
        &tid,
        "/collections/posts/owner-field",
        None,
        &svc,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {v}");
}

/// A collection with NO owner_field must stay clearable (idempotent DELETE) —
/// the guard fires only on a real `Some → None` transition, so an anon query
/// RPC cannot freeze a no-op call.
#[tokio::test]
async fn clearing_an_already_null_owner_field_is_not_blocked() {
    let (app, tid, svc, _anon, dir) = spin_up_dual_role_self_register("qk-clear-noop").await;
    seed_posts(&dir, &tid, None, None, "[]", "[]").await;

    let sid = mcp_init(&app, &tid, &svc).await;
    let out = create_query_rpc(
        &app,
        &tid,
        &svc,
        &sid,
        "all_posts",
        json!([]),
        json!({"collection": "posts"}),
        true,
    )
    .await;
    assert!(out.contains("created"), "{out}");

    let (status, v) = rest(
        &app,
        "DELETE",
        &tid,
        "/collections/posts/owner-field",
        None,
        &svc,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "no transition, nothing widens: {v}");
}

/// `update_rpc` gains a `query` param — the only way to edit a stored template
/// — and it runs through the SAME save-time validator the create face uses.
#[tokio::test]
async fn update_rpc_edits_the_template_and_validates_it() {
    let (app, tid, svc, _anon, dir) = spin_up_dual_role_self_register("qk-update-tpl").await;
    let pool = seed_posts(&dir, &tid, None, None, "[]", "[]").await;

    let sid = mcp_init(&app, &tid, &svc).await;
    let out = create_query_rpc(
        &app,
        &tid,
        &svc,
        &sid,
        "feed",
        json!([]),
        json!({"collection": "posts"}),
        false,
    )
    .await;
    assert!(out.contains("created"), "{out}");

    // A good edit lands.
    let out = mcp_call_tool(
        &app,
        &tid,
        &svc,
        &sid,
        "update_rpc",
        json!({"name": "feed",
               "query": {"collection": "posts", "filter": {"status": "published"}}}),
    )
    .await;
    assert!(out.contains("updated"), "template edit: {out}");
    let (_, stored) = rpc_row(&pool, "feed").await;
    let stored: Value = serde_json::from_str(&stored.expect("template stored")).unwrap();
    assert_eq!(stored["filter"]["status"], "published", "edit must land");

    // A bad edit is refused by the same validator the create face runs, and
    // the STORED template survives.
    let out = mcp_call_tool(
        &app,
        &tid,
        &svc,
        &sid,
        "update_rpc",
        json!({"name": "feed",
               "query": {"collection": "posts", "sort": {"field": "ghost", "dir": "asc"}}}),
    )
    .await;
    assert!(
        !out.contains("updated"),
        "an unknown sort field must be refused: {out}"
    );
    let (_, stored) = rpc_row(&pool, "feed").await;
    let stored: Value = serde_json::from_str(&stored.expect("template stored")).unwrap();
    assert_eq!(
        stored["filter"]["status"], "published",
        "a refused edit must not overwrite the stored template"
    );
}

/// THE flip. A template saved service-only was never judged as an anon grant;
/// flipping `anon_callable` on IS that grant moment, so the STORED template is
/// re-validated then. The sharp case is a legacy row declaring a `user_id`
/// param — caller-supplied, so it spoofs identity the moment anon can call it.
#[tokio::test]
async fn update_rpc_revalidates_the_stored_template_on_an_anon_callable_flip() {
    let (app, tid, svc, _anon, dir) = spin_up_dual_role_self_register("qk-update-flip").await;
    let pool = seed_posts(&dir, &tid, None, None, "[]", "[]").await;
    // Seeded past both create faces — the shape they now refuse.
    seed_query_rpc_directly(
        &pool,
        "spoofable",
        r#"[{"name":"user_id","type":"text","required":true}]"#,
        r#"{"collection":"posts","filter":{"owner_id":{"$param":"user_id"}}}"#,
        false,
    )
    .await;

    let sid = mcp_init(&app, &tid, &svc).await;
    let out = mcp_call_tool(
        &app,
        &tid,
        &svc,
        &sid,
        "update_rpc",
        json!({"name": "spoofable", "anon_callable": true}),
    )
    .await;
    assert!(
        out.contains("RPC_KIND_INVALID") && out.contains("$auth"),
        "the flip must re-run the create-time validator: {out}"
    );
    let (anon_callable, _) = rpc_row(&pool, "spoofable").await;
    assert!(!anon_callable, "the flip must not have landed");

    // Repairability: an update that does NOT widen (description, or disarming)
    // must still work on the same row — otherwise a stale template would be
    // permanently unfixable and permanently un-disarmable.
    let out = mcp_call_tool(
        &app,
        &tid,
        &svc,
        &sid,
        "update_rpc",
        json!({"name": "spoofable", "description": "legacy"}),
    )
    .await;
    assert!(
        out.contains("updated"),
        "non-widening update must pass: {out}"
    );
}

/// A PUT of the policy SET replaces it, so omitting `select` CLEARS a stored
/// select policy — the same widening `DELETE /policies/select` is guarded
/// against, reached by a different verb. Guarding only the DELETE would leave
/// this door open (the enumeration lesson: one guarded write site is no guard).
#[tokio::test]
async fn a_put_that_omits_select_is_the_same_clear_and_is_guarded() {
    let (app, tid, svc, _anon, dir) = spin_up_dual_role_self_register("qk-clear-put").await;
    let pool = seed_posts(&dir, &tid, None, None, "[]", "[]").await;

    let sid = mcp_init(&app, &tid, &svc).await;
    let out = create_query_rpc(
        &app,
        &tid,
        &svc,
        &sid,
        "feed",
        json!([]),
        json!({"collection": "posts"}),
        true,
    )
    .await;
    assert!(out.contains("created"), "{out}");

    // No stored select policy yet → no transition → a PUT is unaffected.
    let (status, v) = rest(
        &app,
        "PUT",
        &tid,
        "/collections/posts/policies",
        Some(json!({"insert": {"check": {"status": "draft"}}})),
        &svc,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "nothing to widen yet: {v}");

    // Now a select policy exists (written straight to the DB — attaching one
    // through the route is a different guard's business).
    set_select_policy(&pool, "posts", json!({"using": {"status": "published"}})).await;

    let (status, v) = rest(
        &app,
        "PUT",
        &tid,
        "/collections/posts/policies",
        Some(json!({"insert": {"check": {"status": "draft"}}})),
        &svc,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "body: {v}");
    assert_eq!(v["error_code"], "RPC_QUERY_GRANT_ACTIVE", "body: {v}");
    let (_, stored) = rest(&app, "GET", &tid, "/collections/posts/policies", None, &svc).await;
    assert_eq!(
        stored["stored"]["select"]["using"]["status"], "published",
        "a refused PUT must write NOTHING: {stored}"
    );
}

// ══════════════════════════════════════════════════════════════════════
// T5b review round — B1: the clause-less select policy is a COVERT CLEAR
// ══════════════════════════════════════════════════════════════════════

/// THE exploit the T5 guard missed. A select policy carrying no `using` is a
/// policy ROW that filters NOTHING: `validate_policy` accepted it,
/// `effective_policy_using` returns None (no read filter), yet
/// `collection_has_policy` still reports true — so every attach face read it
/// as "attaching a policy", the clear guard keyed on ROW presence never fired,
/// and one PUT silently promoted an anon query RPC from "the policy's rows" to
/// the whole table.
///
/// Two independent layers must now stop it, and this test pins the OUTER one
/// end to end: the rows an anon caller can read must be identical before and
/// after the attempted covert clear.
#[tokio::test]
async fn a_clause_less_select_policy_cannot_covertly_clear_the_read_filter() {
    let (app, tid, svc, anon, dir) = spin_up_dual_role_self_register("qk-covert").await;
    let pool = seed_posts(&dir, &tid, None, None, "[]", "[]").await;
    set_select_policy(&pool, "posts", json!({"using": {"status": "published"}})).await;

    let sid = mcp_init(&app, &tid, &svc).await;
    let out = create_query_rpc(
        &app,
        &tid,
        &svc,
        &sid,
        "feed",
        json!([]),
        json!({"collection": "posts", "sort": {"field": "id", "dir": "asc"}}),
        true,
    )
    .await;
    assert!(out.contains("created"), "{out}");

    insert_post(
        &app,
        &tid,
        &svc,
        json!({"status": "published", "title": "public"}),
    )
    .await;
    insert_post(
        &app,
        &tid,
        &svc,
        json!({"status": "draft", "title": "SECRET"}),
    )
    .await;

    // Baseline: the policy is the only thing keeping SECRET away from anon.
    let (status, v) = call_rpc(&app, &tid, &anon, "feed", json!({})).await;
    assert_eq!(status, StatusCode::OK, "body: {v}");
    assert_eq!(titles(&v), vec!["public".to_string()], "baseline: {v}");

    // The covert clear: a select policy with NO `using`.
    let (status, v) = rest(
        &app,
        "PUT",
        &tid,
        "/collections/posts/policies",
        Some(json!({"select": {}})),
        &svc,
    )
    .await;
    assert!(
        status.is_client_error(),
        "a clause-less select policy must be refused, got {status}: {v}"
    );
    // The ROOT layer answers here — the shape itself is invalid, so the report
    // must say that rather than the grant guard's "disarm the RPC first"
    // (a remedy that would NOT make this PUT succeed).
    assert_eq!(v["error_code"], "POLICY_INVALID", "body: {v}");

    // THE assertion: anon still cannot see the draft row.
    let (status, v) = call_rpc(&app, &tid, &anon, "feed", json!({})).await;
    assert_eq!(status, StatusCode::OK, "body: {v}");
    assert_eq!(
        titles(&v),
        vec!["public".to_string()],
        "the read filter must survive the covert clear: {v}"
    );

    // …and the stored policy is untouched, so nothing was half-written.
    let (_, stored) = rest(&app, "GET", &tid, "/collections/posts/policies", None, &svc).await;
    assert_eq!(
        stored["stored"]["select"]["using"]["status"], "published",
        "a refused PUT must write NOTHING: {stored}"
    );
}

/// The MCP twin of the same covert clear: `set_policy(select)` with no `using`.
#[tokio::test]
async fn mcp_set_policy_select_without_using_is_refused() {
    let (app, tid, svc, _anon, dir) = spin_up_dual_role_self_register("qk-covert-mcp").await;
    let pool = seed_posts(&dir, &tid, None, None, "[]", "[]").await;
    set_select_policy(&pool, "posts", json!({"using": {"status": "published"}})).await;

    let sid = mcp_init(&app, &tid, &svc).await;
    let out = create_query_rpc(
        &app,
        &tid,
        &svc,
        &sid,
        "feed",
        json!([]),
        json!({"collection": "posts"}),
        true,
    )
    .await;
    assert!(out.contains("created"), "{out}");

    let out = mcp_call_tool(
        &app,
        &tid,
        &svc,
        &sid,
        "set_policy",
        json!({"collection": "posts", "op": "select"}),
    )
    .await;
    assert!(
        !out.contains("\"ok\""),
        "a select policy with no `using` must be refused: {out}"
    );
    let (_, stored) = rest(&app, "GET", &tid, "/collections/posts/policies", None, &svc).await;
    assert_eq!(
        stored["stored"]["select"]["using"]["status"], "published",
        "the stored filter must survive: {stored}"
    );
}

// ══════════════════════════════════════════════════════════════════════
// T5b review round — B4: the admin save face must stay REPAIRABLE
// ══════════════════════════════════════════════════════════════════════

/// Full mgmt router + one tenant + a known admin PAT (the `tests/cron_admin_ui.rs`
/// harness shape), so the admin RPC save FORM is exercised end to end.
async fn admin_app(tid: &str) -> (axum::Router, String, SharedTenantPool, tempfile::TempDir) {
    use drust::auth::admin_token;
    use drust::storage::meta::{bootstrap_admin, open_meta};
    use drust::storage::pool::TenantRegistry;
    use std::sync::Arc;

    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let mut conn = open_meta(&data_dir.join("meta.sqlite")).unwrap();
    bootstrap_admin(&mut conn, "root", "pw").unwrap();
    conn.execute(
        "INSERT INTO tenants (id, name) VALUES (?1, 'RPC Tenant')",
        rusqlite::params![tid],
    )
    .unwrap();
    let _ = drust::storage::tenant_db::open_write(&data_dir, tid).unwrap();
    drust::db::migrations::run_migrations(&conn, &data_dir).unwrap();
    conn.execute(
        "UPDATE _admin_tokens SET revoked_at = datetime('now') \
         WHERE admin_id = 1 AND revoked_at IS NULL",
        [],
    )
    .unwrap();
    let pat = admin_token::generate_token();
    conn.execute(
        "INSERT INTO _admin_tokens (admin_id, token_hash) VALUES (1, ?1)",
        rusqlite::params![admin_token::hash_token(&pat)],
    )
    .unwrap();

    let tenants = Arc::new(TenantRegistry::new(data_dir.clone(), 2));
    let pool = tenants.get_or_create(tid).unwrap();
    let bus = drust::tenant::events::EventBus::new();
    let mcp = Arc::new(drust::mcp::http_registry::McpHttpRegistry::new(Arc::new(
        drust::mcp::server::McpRegistry::new(tenants.clone()),
    )));
    let state = drust::mgmt::routes::MgmtState::test_default(
        Arc::new(tokio::sync::Mutex::new(conn)),
        data_dir.clone(),
        tenants.clone(),
        mcp,
        bus,
        drust::tenant::rooms::RoomBus::new(),
    );
    (state.with_data_dir(data_dir), pat, pool, dir)
}

/// Form-encoded POST with the admin PAT bearer → (status, body). The save
/// error path re-renders the page (200 + banner), so callers need the body.
async fn admin_post_form(
    app: &axum::Router,
    uri: String,
    pat: &str,
    body: String,
) -> (StatusCode, String) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {pat}"))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 8 << 20)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// B4 — the admin form validated the template on EVERY save, so a query row
/// whose collection had been dropped could not be DISARMED through the admin
/// UI: the save that sets `anon_callable=false` was itself refused by the
/// stale-template check, leaving an anon-callable RPC nobody could turn off
/// from that face. The MCP face already narrows validation to the two
/// WIDENING triggers; the admin face must match.
#[tokio::test]
async fn admin_save_can_disarm_a_query_rpc_whose_collection_is_gone() {
    let tid = "qk-admin-repair";
    let (app, pat, pool, _dir) = admin_app(tid).await;
    pool.with_writer(|c| {
        c.execute_batch("CREATE TABLE posts (id INTEGER PRIMARY KEY, title TEXT);")
    })
    .await
    .unwrap();
    seed_query_rpc_directly(&pool, "feed", "[]", r#"{"collection":"posts"}"#, true).await;

    // The collection goes away underneath the RPC — the template is now stale.
    pool.with_writer(|c| c.execute_batch("DROP TABLE posts;"))
        .await
        .unwrap();
    pool.schema_cache.invalidate("posts");

    // Disarm through the admin form: same stored template, checkbox off.
    let body = "name=feed&sql=&params_json=%5B%5D&description=&kind=query\
                &query_json=%7B%22collection%22%3A%22posts%22%7D";
    let (status, page) = admin_post_form(
        &app,
        format!("/admin/tenants/{tid}/_rpc/feed/save"),
        &pat,
        body.to_string(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "disarming must not be blocked by the stale template: {}",
        page.chars().take(600).collect::<String>()
    );
    let (anon_callable, _) = rpc_row(&pool, "feed").await;
    assert!(!anon_callable, "the disarm must have landed");
}

/// The other half of the same narrowing: a save that CHANGES the template is
/// still validated, so the repairability above is not a hole.
#[tokio::test]
async fn admin_save_still_validates_a_changed_template() {
    let tid = "qk-admin-validate";
    let (app, pat, pool, _dir) = admin_app(tid).await;
    pool.with_writer(|c| {
        c.execute_batch("CREATE TABLE posts (id INTEGER PRIMARY KEY, title TEXT);")
    })
    .await
    .unwrap();
    seed_query_rpc_directly(&pool, "feed", "[]", r#"{"collection":"posts"}"#, false).await;

    // A DIFFERENT template naming a collection that does not exist.
    let body = "name=feed&sql=&params_json=%5B%5D&description=&kind=query\
                &query_json=%7B%22collection%22%3A%22ghost%22%7D";
    let (status, page) = admin_post_form(
        &app,
        format!("/admin/tenants/{tid}/_rpc/feed/save"),
        &pat,
        body.to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "a refusal re-renders the form");
    assert!(
        page.contains("COLLECTION_NOT_FOUND"),
        "a changed template must still be validated"
    );
    let (_, stored) = rpc_row(&pool, "feed").await;
    assert_eq!(
        stored.as_deref(),
        Some(r#"{"collection":"posts"}"#),
        "a refused save must not overwrite the stored template"
    );

    // And setting anon_callable=true re-validates even with the SAME template.
    pool.with_writer(|c| c.execute_batch("DROP TABLE posts;"))
        .await
        .unwrap();
    pool.schema_cache.invalidate("posts");
    let body = "name=feed&sql=&params_json=%5B%5D&description=&kind=query\
                &anon_callable=1&query_json=%7B%22collection%22%3A%22posts%22%7D";
    let (status, page) = admin_post_form(
        &app,
        format!("/admin/tenants/{tid}/_rpc/feed/save"),
        &pat,
        body.to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the grant moment must be refused");
    assert!(
        page.contains("COLLECTION_NOT_FOUND"),
        "flipping anon_callable on must re-validate the stored template"
    );
    let (anon_callable, _) = rpc_row(&pool, "feed").await;
    assert!(!anon_callable, "the flip must not have landed");
}

// ══════════════════════════════════════════════════════════════════════
// T5c review round — the LEGACY clause-less select policy residual
// ══════════════════════════════════════════════════════════════════════

/// Write a clause-less `{select:{}}` policy STRAIGHT to the tenant DB via
/// `write_policy`, bypassing `validate_policy` — the legacy/hand-edited shape
/// the T5b write-face reject cannot retroactively remove.
async fn set_clause_less_select_policy(pool: &SharedTenantPool, coll: &str) {
    let policy: drust::query::policy::Policy = serde_json::from_value(json!({})).unwrap();
    assert!(policy.using.is_none(), "fixture must be clause-less");
    let coll_owned = coll.to_string();
    pool.with_writer(move |c| {
        drust::storage::schema::write_policy(
            c,
            &coll_owned,
            drust::storage::schema::DmlVerb::Select,
            Some(&policy),
        )
    })
    .await
    .unwrap();
    pool.schema_cache.invalidate(coll);
}

/// `POST /t/<id>/collections/<c>/list` as `tok` → the `records` array.
async fn list_as(app: &axum::Router, tid: &str, tok: &str, coll: &str) -> Vec<Value> {
    let (status, v) = rest(
        app,
        "POST",
        tid,
        &format!("/collections/{coll}/list"),
        Some(json!({})),
        tok,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "list {coll}: {v}");
    v["records"].as_array().cloned().unwrap_or_default()
}

/// THE residual pin. A LEGACY clause-less select policy already stored still
/// leaked the whole table to anon through a query RPC — `effective_policy_using`
/// returned None (no filter) on every read face. The read-path deny makes a
/// select-policy ROW mean "reads restricted" even with no `using`: anon must
/// now see ZERO rows, not `["public","SECRET"]`.
#[tokio::test]
async fn legacy_clause_less_select_policy_denies_anon_query_rpc_reads() {
    let (app, tid, svc, anon, dir) = spin_up_dual_role_self_register("qk-legacy-deny").await;
    let pool = seed_posts(&dir, &tid, None, None, "[]", "[]").await;
    set_clause_less_select_policy(&pool, "posts").await;

    let sid = mcp_init(&app, &tid, &svc).await;
    let out = create_query_rpc(
        &app,
        &tid,
        &svc,
        &sid,
        "feed",
        json!([]),
        json!({"collection": "posts", "sort": {"field": "id", "dir": "asc"}}),
        true,
    )
    .await;
    assert!(out.contains("created"), "{out}");

    insert_post(
        &app,
        &tid,
        &svc,
        json!({"status": "published", "title": "public"}),
    )
    .await;
    insert_post(
        &app,
        &tid,
        &svc,
        json!({"status": "draft", "title": "SECRET"}),
    )
    .await;

    // Service still reads both — service bypasses policy.
    let (_s, v) = call_rpc(&app, &tid, &svc, "feed", json!({})).await;
    assert_eq!(
        v["total"], 2,
        "service bypasses the clause-less policy: {v}"
    );

    // Anon sees ZERO rows (was ["public","SECRET"] — the residual leak).
    let (status, v) = call_rpc(&app, &tid, &anon, "feed", json!({})).await;
    assert_eq!(status, StatusCode::OK, "body: {v}");
    assert!(
        titles(&v).is_empty(),
        "a clause-less select policy must deny every row to anon: {v}"
    );
    assert_eq!(v["total"], 0, "deny-all total: {v}");
}

/// The same deny must cover the NON-RPC read faces, or the fix is partial:
/// `/list` as anon (with `anon_caps[select]` granted) → zero rows too.
#[tokio::test]
async fn legacy_clause_less_select_policy_denies_anon_list_reads() {
    let (app, tid, svc, anon, dir) = spin_up_dual_role_self_register("qk-legacy-list").await;
    // anon_caps[select] granted — the cap is open, so ONLY the policy deny
    // keeps anon out. Without the read-path deny anon would see both rows.
    let pool = seed_posts(&dir, &tid, None, None, r#"["select"]"#, "[]").await;
    set_clause_less_select_policy(&pool, "posts").await;

    insert_post(
        &app,
        &tid,
        &svc,
        json!({"status": "published", "title": "public"}),
    )
    .await;
    insert_post(
        &app,
        &tid,
        &svc,
        json!({"status": "draft", "title": "SECRET"}),
    )
    .await;

    assert!(
        list_as(&app, &tid, &anon, "posts").await.is_empty(),
        "clause-less select policy must deny /list reads for anon too"
    );
    // Service bypasses — sees both.
    assert_eq!(
        list_as(&app, &tid, &svc, "posts").await.len(),
        2,
        "service bypasses the clause-less policy on /list"
    );
}

/// Repairability: a tenant with a legacy clause-less select policy can still
/// FIX it by PUTting a real `using` (which passes validate) — reads then filter
/// instead of deny — OR clear it. The clear is guarded only while an anon query
/// RPC targets the collection (the T5c reconciliation).
#[tokio::test]
async fn legacy_clause_less_select_policy_is_repairable() {
    let (app, tid, svc, anon, dir) = spin_up_dual_role_self_register("qk-legacy-repair").await;
    let pool = seed_posts(&dir, &tid, None, None, r#"["select"]"#, "[]").await;
    set_clause_less_select_policy(&pool, "posts").await;
    insert_post(
        &app,
        &tid,
        &svc,
        json!({"status": "published", "title": "public"}),
    )
    .await;
    insert_post(
        &app,
        &tid,
        &svc,
        json!({"status": "draft", "title": "SECRET"}),
    )
    .await;

    // FIX by PUTting a real using — a valid select policy, so it passes.
    let (status, v) = rest(
        &app,
        "PUT",
        &tid,
        "/collections/posts/policies",
        Some(json!({"select": {"using": {"status": "published"}}})),
        &svc,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "repair via using must pass: {v}");
    // Now anon reads the published row (filter, not deny).
    assert_eq!(
        list_as(&app, &tid, &anon, "posts")
            .await
            .iter()
            .map(|r| r["title"].as_str().unwrap_or_default().to_string())
            .collect::<Vec<_>>(),
        vec!["public".to_string()],
        "after repair, the filter applies instead of deny-all"
    );

    // Reset to clause-less, then CLEAR it — no anon query RPC targets it, so the
    // clear goes through and anon reads everything (the deny is genuinely gone).
    set_clause_less_select_policy(&pool, "posts").await;
    let (status, v) = rest(
        &app,
        "DELETE",
        &tid,
        "/collections/posts/policies/select",
        None,
        &svc,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "clearing with no active RPC is fine: {v}"
    );
    assert_eq!(
        list_as(&app, &tid, &anon, "posts").await.len(),
        2,
        "after clear, no policy → anon reads all (anon_caps[select] granted)"
    );
}

/// The reconciliation: clearing a LEGACY clause-less select policy while an
/// anon query RPC targets the collection IS a widening (deny-all → open), so
/// the guard fires — even though the row has no `using`.
#[tokio::test]
async fn clearing_a_legacy_clause_less_policy_is_guarded_when_a_query_rpc_targets_it() {
    let (app, tid, svc, _anon, dir) = spin_up_dual_role_self_register("qk-legacy-guard").await;
    let pool = seed_posts(&dir, &tid, None, None, "[]", "[]").await;
    set_clause_less_select_policy(&pool, "posts").await;

    let sid = mcp_init(&app, &tid, &svc).await;
    let out = create_query_rpc(
        &app,
        &tid,
        &svc,
        &sid,
        "feed",
        json!([]),
        json!({"collection": "posts"}),
        true,
    )
    .await;
    assert!(out.contains("created"), "{out}");

    // DELETE the (clause-less) select policy → refused: it denies reads, so
    // dropping it widens the anon RPC to the whole table.
    let (status, v) = rest(
        &app,
        "DELETE",
        &tid,
        "/collections/posts/policies/select",
        None,
        &svc,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "body: {v}");
    assert_eq!(v["error_code"], "RPC_QUERY_GRANT_ACTIVE", "body: {v}");

    // MCP clear_policy refuses identically.
    let out = mcp_call_tool(
        &app,
        &tid,
        &svc,
        &sid,
        "clear_policy",
        json!({"collection": "posts", "op": "select"}),
    )
    .await;
    assert!(out.contains("RPC_QUERY_GRANT_ACTIVE"), "mcp face: {out}");

    // Still stored after both refusals.
    let (_, stored) = rest(&app, "GET", &tid, "/collections/posts/policies", None, &svc).await;
    assert!(
        !stored["stored"]["select"].is_null(),
        "a refused clear must leave the policy row in place: {stored}"
    );
}
