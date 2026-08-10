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
