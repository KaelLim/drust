//! v1.30 C5 / S4 — create-time validation under the mode-matched authorizer.
//!
//! Asserts spec §8 table for `validate_rpc_sql(_, _, mode)`:
//! - Write-mode REJECTS DDL / ATTACH / writes to _system_* at prepare
//!   time, so they cannot enter the stored-RPC catalog.
//! - Write-mode ACCEPTS a legitimate INSERT/UPDATE/DELETE on a user table.
//! - Read-mode still rejects any write (existing C1 contract).
//!
//! Defense-in-depth (spec §11): the same `attach_writable_authorizer`
//! gates the runtime path in `src/rpc/handler.rs::call_rpc` (C4) — so a
//! body that passes the registry check will also pass runtime auth, and
//! a body that pre-existed registry-side gets rejected at runtime anyway.

use drust::rpc::prepare::{PrepareError, validate_rpc_sql};
use drust::rpc::registry::RpcMode;
use drust::storage::tenant_db::open_write;
use rusqlite::Connection;
use tempfile::TempDir;

/// Seed a fresh per-test tenant DB with a canonical non-protected
/// `orders` table. Mirrors `tests/authorizer_writable.rs::seed`.
fn seed(name: &str) -> (TempDir, Connection) {
    let d = TempDir::new().unwrap();
    let conn = open_write(d.path(), name).unwrap();
    // `user_id` column present so owner-scoped / :user_id RPC bodies are
    // preparable (audit3 F2 removed the early :user_id return, so the guard now
    // prepares every anon-callable body to discover referenced tables).
    conn.execute_batch("CREATE TABLE orders (id INTEGER PRIMARY KEY, qty INTEGER, user_id TEXT);")
        .unwrap();
    (d, conn)
}

#[test]
fn write_with_drop_table_rejected_at_create() {
    let (_d, conn) = seed("c5_drop");
    let err = validate_rpc_sql(&conn, "DROP TABLE orders", RpcMode::Write).unwrap_err();
    let PrepareError::Rejected(msg) = err;
    // The authorizer denies DropTable, so prepare returns "not authorized".
    let lc = msg.to_lowercase();
    assert!(
        lc.contains("authoriz") || lc.contains("prohibited"),
        "expected authorizer denial, got: {msg}"
    );
}

#[test]
fn write_with_insert_into_system_files_rejected() {
    let (_d, conn) = seed("c5_sysfiles");
    // Columns mirror src/storage/tenant_db.rs:58-72 so the prepare
    // failure is from the authorizer (Insert on protected table), NOT
    // from SQLite complaining about an unknown column.
    let sql = "INSERT INTO _system_files (key, original_name, size_bytes, uploader) \
               VALUES ('a', 'a', 1, 'a')";
    let err = validate_rpc_sql(&conn, sql, RpcMode::Write).unwrap_err();
    let PrepareError::Rejected(msg) = err;
    let lc = msg.to_lowercase();
    assert!(
        lc.contains("authoriz") || lc.contains("prohibited"),
        "expected authorizer denial on _system_files insert, got: {msg}"
    );
}

#[test]
fn write_with_attach_database_rejected() {
    let (_d, conn) = seed("c5_attach");
    let err =
        validate_rpc_sql(&conn, "ATTACH DATABASE '/tmp/x.db' AS y", RpcMode::Write).unwrap_err();
    let PrepareError::Rejected(msg) = err;
    let lc = msg.to_lowercase();
    assert!(
        lc.contains("authoriz") || lc.contains("prohibited"),
        "expected authorizer denial on ATTACH, got: {msg}"
    );
}

#[test]
fn read_with_insert_still_rejected() {
    let (_d, conn) = seed("c5_read_insert");
    // Existing C1 contract: read-mode rejects any write.
    let err =
        validate_rpc_sql(&conn, "INSERT INTO orders (qty) VALUES (1)", RpcMode::Read).unwrap_err();
    let PrepareError::Rejected(msg) = err;
    let lc = msg.to_lowercase();
    assert!(
        lc.contains("authoriz") || lc.contains("prohibited"),
        "expected read-mode authorizer denial on INSERT, got: {msg}"
    );
}

#[test]
fn write_with_valid_mutation_accepts() {
    let (_d, conn) = seed("c5_valid_insert");
    // Spec §8 row "valid Write body" — INSERT/UPDATE/DELETE on a
    // non-protected user table under the writable authorizer must pass
    // prepare. Bind placeholder `:q` exercises the same path the
    // runtime executor uses.
    validate_rpc_sql(
        &conn,
        "INSERT INTO orders (qty) VALUES (:q)",
        RpcMode::Write,
    )
    .expect("valid write-mode INSERT must pass prepare-time validation");

    // Bonus: UPDATE + DELETE for symmetry with C2's authorizer tests.
    validate_rpc_sql(
        &conn,
        "UPDATE orders SET qty = :q WHERE id = :id",
        RpcMode::Write,
    )
    .expect("valid write-mode UPDATE must pass");
    validate_rpc_sql(&conn, "DELETE FROM orders WHERE id = :id", RpcMode::Write)
        .expect("valid write-mode DELETE must pass");
}

// ── v1.41.3: anon-callable read RPC over an owner-scoped collection ──
//
// An anon-callable READ RPC that SELECTs an owner-scoped collection without
// binding :user_id would return EVERY user's rows to an anonymous caller
// (drust does not rewrite stored-RPC SQL, so no owner row-filter is injected).
// The create-time guard must refuse it; the safe shapes must still create.

use drust::rpc::params::{ParamSpec, ParamType};
use drust::rpc::prepare::{
    RPC_ANON_OWNER_SCOPED, guard_anon_owner_scoped_rpc, guard_anon_owner_scoped_rpc_update,
};
use drust::rpc::registry;
use drust::storage::schema::set_owner_field;

/// Seed `orders` as owner-scoped (owner_field set on its meta row).
fn seed_owner_scoped(name: &str) -> (TempDir, Connection) {
    let (d, conn) = seed(name);
    set_owner_field(&conn, "orders", Some("user_id"), Some("own")).unwrap();
    (d, conn)
}

fn user_id_param() -> Vec<ParamSpec> {
    vec![ParamSpec {
        name: "user_id".into(),
        ty: ParamType::Text,
        required: true,
        default: None,
    }]
}

#[test]
fn anon_callable_read_over_owner_scoped_without_user_id_rejected() {
    let (_d, conn) = seed_owner_scoped("anon_owner_no_uid");
    let sql = "SELECT id, qty FROM orders";
    // Sanity: the body itself is a valid read.
    validate_rpc_sql(&conn, sql, RpcMode::Read).expect("plain SELECT is valid read SQL");
    // Guard must REJECT: anon_callable + owner-scoped + no :user_id.
    let err = guard_anon_owner_scoped_rpc(&conn, sql, &[], true, RpcMode::Read).unwrap_err();
    let PrepareError::Rejected(msg) = err;
    assert!(
        msg.contains(RPC_ANON_OWNER_SCOPED),
        "expected {RPC_ANON_OWNER_SCOPED} rejection, got: {msg}"
    );
}

#[test]
fn anon_callable_read_over_owner_scoped_with_user_id_param_accepts() {
    let (_d, conn) = seed_owner_scoped("anon_owner_with_uid");
    // Same RPC but it declares a :user_id param → still creates fine.
    guard_anon_owner_scoped_rpc(
        &conn,
        "SELECT id, qty FROM orders WHERE user_id = :user_id",
        &user_id_param(),
        true,
        RpcMode::Read,
    )
    .expect(":user_id-bound anon read RPC over owner-scoped collection must still create");
}

#[test]
fn service_only_read_over_owner_scoped_accepts() {
    let (_d, conn) = seed_owner_scoped("svc_only_owner");
    // anon_callable=false → service-only → no leak → must create fine.
    guard_anon_owner_scoped_rpc(
        &conn,
        "SELECT id, qty FROM orders",
        &[],
        false,
        RpcMode::Read,
    )
    .expect("service-only read RPC over owner-scoped collection must create");
}

#[test]
fn anon_callable_read_over_non_owner_collection_accepts() {
    // `orders` left non-owner-scoped (no set_owner_field call).
    let (_d, conn) = seed("anon_non_owner");
    guard_anon_owner_scoped_rpc(
        &conn,
        "SELECT id, qty FROM orders",
        &[],
        true,
        RpcMode::Read,
    )
    .expect("anon read RPC over a non-owner collection must create");
}

// ── v1.41.3 (review): WRITE-mode anon-callable RPC over owner-scoped ──
//
// An anon-callable WRITE RPC over an owner-scoped collection lets anon MUTATE
// every user's rows (the write executor injects no owner filter) — strictly
// worse than the read leak. The guard must fire in write mode too.

#[test]
fn anon_callable_write_over_owner_scoped_without_user_id_rejected() {
    let (_d, conn) = seed_owner_scoped("anon_write_owner_no_uid");
    let err = guard_anon_owner_scoped_rpc(
        &conn,
        "UPDATE orders SET qty = :q WHERE id = :id",
        &[],
        true,
        RpcMode::Write,
    )
    .unwrap_err();
    let PrepareError::Rejected(msg) = err;
    assert!(
        msg.contains(RPC_ANON_OWNER_SCOPED),
        "write-mode guard must reject, got: {msg}"
    );
}

#[test]
fn anon_callable_write_over_owner_scoped_with_user_id_accepts() {
    let (_d, conn) = seed_owner_scoped("anon_write_owner_uid");
    // Declares :user_id → sanctioned escape hatch → still creates.
    guard_anon_owner_scoped_rpc(
        &conn,
        "UPDATE orders SET qty = :q WHERE user_id = :user_id",
        &user_id_param(),
        true,
        RpcMode::Write,
    )
    .expect(":user_id-bound anon write RPC over owner-scoped must create");
}

#[test]
fn anon_callable_write_over_non_owner_collection_accepts() {
    // `orders` left non-owner-scoped → a write RPC over it does not leak.
    let (_d, conn) = seed("anon_write_non_owner");
    guard_anon_owner_scoped_rpc(
        &conn,
        "UPDATE orders SET qty = :q WHERE id = :id",
        &[],
        true,
        RpcMode::Write,
    )
    .expect("anon write RPC over a non-owner collection must create");
}

// ── v1.41.3 (review): UPDATE path must re-check effective values ──
//
// `update_rpc` is partial; a flag-flip (anon_callable=true, sql=None) or an
// sql-swap (sql=<owner-scoped>, anon_callable=None) must be re-checked against
// the STORED row, else an update reopens the leak the create-time guard closes.

#[test]
fn update_flip_anon_callable_on_owner_scoped_rejected() {
    let (_d, conn) = seed_owner_scoped("upd_flip");
    // Seed a service-only (anon_callable=false) read RPC over the owner-scoped
    // collection — legal to create because it is service-only.
    registry::create(
        &conn,
        "r",
        "SELECT id, qty FROM orders",
        "[]",
        None,
        false,
        RpcMode::Read,
    )
    .unwrap();
    // Flip anon_callable=true via update, sql/params omitted → must be rejected
    // against the stored owner-scoped SQL.
    let err = guard_anon_owner_scoped_rpc_update(&conn, "r", None, None, Some(true)).unwrap_err();
    let PrepareError::Rejected(msg) = err;
    assert!(
        msg.contains(RPC_ANON_OWNER_SCOPED),
        "flag-flip update must reject, got: {msg}"
    );
}

#[test]
fn update_swap_sql_to_owner_scoped_rejected() {
    let (_d, conn) = seed_owner_scoped("upd_swap");
    // Seed an anon-callable RPC that reads NO owner table (legal at create).
    registry::create(&conn, "r", "SELECT 1", "[]", None, true, RpcMode::Read).unwrap();
    // Swap in owner-scoped SQL via update, anon_callable omitted (stays true) →
    // must be rejected against the effective (new) SQL.
    let err = guard_anon_owner_scoped_rpc_update(
        &conn,
        "r",
        Some("SELECT id, qty FROM orders"),
        None,
        None,
    )
    .unwrap_err();
    let PrepareError::Rejected(msg) = err;
    assert!(
        msg.contains(RPC_ANON_OWNER_SCOPED),
        "sql-swap update must reject, got: {msg}"
    );
}

#[test]
fn update_benign_changes_pass() {
    let (_d, conn) = seed_owner_scoped("upd_benign");
    registry::create(
        &conn,
        "r",
        "SELECT id, qty FROM orders",
        "[]",
        None,
        false,
        RpcMode::Read,
    )
    .unwrap();
    // No anon flip, no sql change → stays service-only → ok.
    guard_anon_owner_scoped_rpc_update(&conn, "r", None, None, None)
        .expect("no-op update must pass");
    // Flip anon=true BUT also declare :user_id + filter on it → sanctioned → ok.
    let uid = user_id_param();
    guard_anon_owner_scoped_rpc_update(
        &conn,
        "r",
        Some("SELECT id, qty FROM orders WHERE user_id = :user_id"),
        Some(&uid),
        Some(true),
    )
    .expect("anon + :user_id update must pass");
}

#[test]
fn update_missing_rpc_is_noop() {
    let (_d, conn) = seed_owner_scoped("upd_missing");
    // No stored row named "ghost" → guard is a no-op (the update itself 404s).
    guard_anon_owner_scoped_rpc_update(&conn, "ghost", None, None, Some(true))
        .expect("missing stored RPC must be a guard no-op");
}

// ── v1.41.3 (review): config-time owner-scope-change guard ──
//
// Making a collection owner-scoped while an anon-callable RPC already reads it
// without :user_id would silently turn that RPC into a cross-user leak (the
// create/update guard never re-runs on the config change). The owner-scope
// config path (set_owner_field, MCP + REST) must refuse it BEFORE the write.

use drust::rpc::prepare::{guard_owner_scope_change_against_anon_rpcs, scan_unsafe_anon_rpcs};

const USER_ID_PARAMS_JSON: &str = r#"[{"name":"user_id","type":"text","required":true}]"#;

#[test]
fn owner_scope_change_blocked_by_existing_anon_rpc() {
    // `orders` is NOT yet owner-scoped; an anon RPC reads it without :user_id.
    let (_d, conn) = seed("osc_blocked");
    registry::create(
        &conn,
        "list_orders",
        "SELECT id, qty FROM orders",
        "[]",
        None,
        true,
        RpcMode::Read,
    )
    .unwrap();
    // Attempting to make `orders` owner-scoped must be refused, naming the RPC.
    let err = guard_owner_scope_change_against_anon_rpcs(&conn, "orders").unwrap_err();
    let PrepareError::Rejected(msg) = err;
    assert!(
        msg.contains(RPC_ANON_OWNER_SCOPED) && msg.contains("list_orders"),
        "expected refusal naming list_orders, got: {msg}"
    );
}

#[test]
fn owner_scope_change_allowed_when_anon_rpc_binds_user_id() {
    let (_d, conn) = seed("osc_uid");
    registry::create(
        &conn,
        "my_orders",
        "SELECT id, qty FROM orders WHERE user_id = :user_id",
        USER_ID_PARAMS_JSON,
        None,
        true,
        RpcMode::Read,
    )
    .unwrap();
    guard_owner_scope_change_against_anon_rpcs(&conn, "orders")
        .expect(":user_id-bound anon RPC must not block the owner-scope change");
}

#[test]
fn owner_scope_change_allowed_for_service_only_or_unrelated_rpc() {
    let (_d, conn) = seed("osc_svc");
    // Service-only RPC reading `orders` → no anon leak → allowed.
    registry::create(
        &conn,
        "svc_orders",
        "SELECT id, qty FROM orders",
        "[]",
        None,
        false,
        RpcMode::Read,
    )
    .unwrap();
    // Anon RPC reading a DIFFERENT table → does not block `orders` owner-scope.
    conn.execute_batch("CREATE TABLE logs (id INTEGER PRIMARY KEY, msg TEXT);")
        .unwrap();
    registry::create(
        &conn,
        "list_logs",
        "SELECT id, msg FROM logs",
        "[]",
        None,
        true,
        RpcMode::Read,
    )
    .unwrap();
    guard_owner_scope_change_against_anon_rpcs(&conn, "orders")
        .expect("service-only + unrelated anon RPC must not block the change");
}

// ── v1.41.3 (review): legacy one-time unsafe-RPC scan ──
//
// A pre-guard anon-callable RPC over an already-owner-scoped collection without
// :user_id leaks at call time. The startup migration neutralizes such rows; the
// scan reports them.

#[test]
fn scan_flags_legacy_unsafe_anon_rpc() {
    // `orders` IS owner-scoped; a legacy anon RPC reads it without :user_id.
    let (_d, conn) = seed_owner_scoped("scan_unsafe");
    registry::create(
        &conn,
        "leak",
        "SELECT id, qty FROM orders",
        "[]",
        None,
        true,
        RpcMode::Read,
    )
    .unwrap();
    let names = scan_unsafe_anon_rpcs(&conn).unwrap();
    assert_eq!(names, vec!["leak".to_string()]);
}

#[test]
fn scan_ignores_safe_rpcs() {
    let (_d, conn) = seed_owner_scoped("scan_safe");
    // Service-only over owner-scoped → safe.
    registry::create(
        &conn,
        "svc",
        "SELECT id, qty FROM orders",
        "[]",
        None,
        false,
        RpcMode::Read,
    )
    .unwrap();
    // Anon over owner-scoped WITH :user_id → safe.
    registry::create(
        &conn,
        "mine",
        "SELECT id, qty FROM orders WHERE user_id = :user_id",
        USER_ID_PARAMS_JSON,
        None,
        true,
        RpcMode::Read,
    )
    .unwrap();
    let names = scan_unsafe_anon_rpcs(&conn).unwrap();
    assert!(names.is_empty(), "expected no unsafe RPCs, got: {names:?}");
}

// ──────────────────────────────────────────────────────────────────────────────
// audit3 (2026-06-23) F2 — RPC anon-guard was blind to RLS select policies.
//
// drust never rewrites stored-RPC SQL, so an anon_callable RPC over a
// policy-protected collection (owner_field may be NULL) returns/mutates the very
// rows the policy hides. The guard now also rejects policy-protected tables, and
// — unlike owner_field — a :user_id param does NOT exempt the policy case.
// ──────────────────────────────────────────────────────────────────────────────

use drust::rpc::prepare::guard_policy_change_against_anon_rpcs;
use drust::storage::schema::{DmlVerb, write_policy};

/// Seed `orders` (non-owner-scoped) carrying a select RLS policy.
fn seed_with_policy(name: &str) -> (TempDir, Connection) {
    let (d, conn) = seed(name);
    use drust::query::policy::Policy;
    use drust::query::vector_filter::FilterAst;
    let p = Policy {
        using: Some(serde_json::from_str::<FilterAst>(r#"{"published":true}"#).unwrap()),
        check: None,
    };
    write_policy(&conn, "orders", DmlVerb::Select, Some(&p)).unwrap();
    (d, conn)
}

#[test]
fn anon_callable_read_over_policy_collection_rejected() {
    let (_d, conn) = seed_with_policy("anon_policy_no_uid");
    let sql = "SELECT id, qty FROM orders";
    validate_rpc_sql(&conn, sql, RpcMode::Read).expect("plain SELECT is valid read SQL");
    let err = guard_anon_owner_scoped_rpc(&conn, sql, &[], true, RpcMode::Read).unwrap_err();
    let PrepareError::Rejected(msg) = err;
    assert!(
        msg.contains(RPC_ANON_OWNER_SCOPED),
        "anon RPC over policy-protected collection must be rejected, got: {msg}"
    );
}

#[test]
fn anon_callable_read_over_policy_collection_with_user_id_still_rejected() {
    // :user_id escapes owner_field but NOT a policy (a policy need not key on the
    // caller) — must still reject.
    let (_d, conn) = seed_with_policy("anon_policy_with_uid");
    let err = guard_anon_owner_scoped_rpc(
        &conn,
        "SELECT id, qty FROM orders WHERE user_id = :user_id",
        &user_id_param(),
        true,
        RpcMode::Read,
    )
    .unwrap_err();
    let PrepareError::Rejected(msg) = err;
    assert!(
        msg.contains(RPC_ANON_OWNER_SCOPED),
        ":user_id must not exempt a policy-protected collection, got: {msg}"
    );
}

#[test]
fn service_only_read_over_policy_collection_accepts() {
    let (_d, conn) = seed_with_policy("svc_policy");
    guard_anon_owner_scoped_rpc(
        &conn,
        "SELECT id, qty FROM orders",
        &[],
        false,
        RpcMode::Read,
    )
    .expect("service-only RPC over a policy-protected collection must create");
}

#[test]
fn guard_policy_change_rejects_when_anon_rpc_references_collection() {
    // An anon_callable RPC exists over a (currently policy-free, non-owner)
    // collection; attaching a policy later must be refused.
    let (_d, conn) = seed("policychange_blocked");
    registry::create(
        &conn,
        "reader",
        "SELECT id, qty FROM orders",
        "[]",
        None,
        true,
        RpcMode::Read,
    )
    .unwrap();
    let err = guard_policy_change_against_anon_rpcs(&conn, "orders").unwrap_err();
    let PrepareError::Rejected(msg) = err;
    assert!(
        msg.contains(RPC_ANON_OWNER_SCOPED),
        "attaching a policy while an anon RPC references the collection must reject, got: {msg}"
    );
}

#[test]
fn guard_policy_change_accepts_for_service_only_rpc() {
    let (_d, conn) = seed("policychange_ok");
    registry::create(
        &conn,
        "reader",
        "SELECT id, qty FROM orders",
        "[]",
        None,
        false, // service-only → no anon leak
        RpcMode::Read,
    )
    .unwrap();
    guard_policy_change_against_anon_rpcs(&conn, "orders")
        .expect("a service-only RPC must not block attaching a policy");
}

#[test]
fn scan_unsafe_flags_user_id_rpc_over_policy_collection() {
    // Legacy: an anon_callable RPC WITH a :user_id param over a policy-protected
    // collection is unsafe (policy not applied at call time). The startup scan
    // must flag it even though :user_id used to skip the scan.
    let (_d, conn) = seed_with_policy("scan_policy_uid");
    registry::create(
        &conn,
        "mine",
        "SELECT id, qty FROM orders WHERE user_id = :user_id",
        USER_ID_PARAMS_JSON,
        None,
        true,
        RpcMode::Read,
    )
    .unwrap();
    let names = scan_unsafe_anon_rpcs(&conn).unwrap();
    assert!(
        names.contains(&"mine".to_string()),
        "scan must flag a :user_id anon RPC over a policy-protected collection, got: {names:?}"
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// v1.48.1 — MCP create_rpc `mode` param (spec 測試 cases 1-4, 7).
//
// Dispatched through the real per-tenant MCP endpoint (JSON-RPC tools/call via
// app.oneshot, mirroring tests/mcp_merged_tools.rs) so param deserialization +
// the handler's mode thread-through are exercised end-to-end.
// ──────────────────────────────────────────────────────────────────────────────

mod helpers;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use serde_json::json;
use tower::ServiceExt;

fn mcp_req_with_session(
    tid: &str,
    token: &str,
    sid: &str,
    body: serde_json::Value,
) -> Request<Body> {
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
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
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
                "params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0"}}
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
    args: serde_json::Value,
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

fn rest_req(
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

async fn rpc_row_count(pool: &drust::storage::pool::SharedTenantPool, name: &str) -> i64 {
    let name = name.to_string();
    pool.with_reader(move |c| {
        c.query_row(
            "SELECT COUNT(*) FROM _system_rpc WHERE name = ?1",
            rusqlite::params![name],
            |r| r.get(0),
        )
    })
    .await
    .unwrap()
}

async fn stored_rpc_mode(pool: &drust::storage::pool::SharedTenantPool, name: &str) -> String {
    let name = name.to_string();
    pool.with_reader(move |c| {
        c.query_row(
            "SELECT COALESCE(mode, 'read') FROM _system_rpc WHERE name = ?1",
            rusqlite::params![name],
            |r| r.get(0),
        )
    })
    .await
    .unwrap()
}

// Spec case 1 — mode:"write" with an INSERT body creates; the stored row
// carries mode='write'; a REST POST then really inserts a row.
#[tokio::test]
async fn mcp_create_rpc_mode_write_then_rest_executes() {
    let (app, tid, svc, _anon, dir) = helpers::spin_up_dual_role_self_register("t-mcpmode-1").await;
    let pool = helpers::grab_pool(&tid, &dir).await;
    pool.with_writer(|c| {
        c.execute_batch("CREATE TABLE orders (id INTEGER PRIMARY KEY AUTOINCREMENT, qty INTEGER);")
    })
    .await
    .unwrap();
    let sid = mcp_init(&app, &tid, &svc).await;

    let out = mcp_call_tool(
        &app,
        &tid,
        &svc,
        &sid,
        "create_rpc",
        json!({
            "name": "add_order",
            "sql": "INSERT INTO orders (qty) VALUES (:q)",
            "params": [{"name":"q","type":"integer","required":true}],
            "mode": "write"
        }),
    )
    .await;
    assert!(out.contains("created"), "create_rpc mode=write: {out}");
    assert_eq!(stored_rpc_mode(&pool, "add_order").await, "write");

    // End-to-end: the write RPC executes via REST and lands a row.
    let r = app
        .oneshot(rest_req(
            "POST",
            &tid,
            "/rpc/add_order",
            Some(json!({"q": 5})),
            &svc,
        ))
        .await
        .unwrap();
    assert!(
        r.status().is_success(),
        "REST write-RPC call failed: {}",
        r.status()
    );
    let n: i64 = pool
        .with_reader(|c| c.query_row("SELECT COUNT(*) FROM orders", [], |r| r.get(0)))
        .await
        .unwrap();
    assert_eq!(n, 1, "write RPC must have inserted one row");
}

// Spec case 2 — mode:"write" with DDL is refused at create time by the
// writable authorizer; no catalog row lands.
#[tokio::test]
async fn mcp_create_rpc_mode_write_ddl_rejected_at_create() {
    let (app, tid, svc, _anon, dir) = helpers::spin_up_dual_role_self_register("t-mcpmode-2").await;
    let pool = helpers::grab_pool(&tid, &dir).await;
    let sid = mcp_init(&app, &tid, &svc).await;

    let out = mcp_call_tool(
        &app,
        &tid,
        &svc,
        &sid,
        "create_rpc",
        json!({
            "name": "evil_ddl",
            "sql": "CREATE TABLE hax (id INTEGER)",
            "params": [],
            "mode": "write"
        }),
    )
    .await;
    let lc = out.to_lowercase();
    assert!(
        lc.contains("authoriz") || lc.contains("prohibited"),
        "DDL under write mode must be refused at create: {out}"
    );
    assert_eq!(rpc_row_count(&pool, "evil_ddl").await, 0);
}

// Spec case 3 — a garbage mode string is invalid_params; nothing is stored.
#[tokio::test]
async fn mcp_create_rpc_garbage_mode_invalid_params() {
    let (app, tid, svc, _anon, dir) = helpers::spin_up_dual_role_self_register("t-mcpmode-3").await;
    let pool = helpers::grab_pool(&tid, &dir).await;
    let sid = mcp_init(&app, &tid, &svc).await;

    let out = mcp_call_tool(
        &app,
        &tid,
        &svc,
        &sid,
        "create_rpc",
        json!({
            "name": "whatever",
            "sql": "SELECT 1",
            "params": [],
            "mode": "exec"
        }),
    )
    .await;
    assert!(
        out.contains("mode must be"),
        "garbage mode must reject with invalid_params: {out}"
    );
    assert_eq!(rpc_row_count(&pool, "whatever").await, 0);
}

// Spec case 4 — omitted mode defaults to read: an INSERT body is still
// rejected by the read-only authorizer (byte-identical regression guard).
#[tokio::test]
async fn mcp_create_rpc_omitted_mode_stays_read_only() {
    let (app, tid, svc, _anon, dir) = helpers::spin_up_dual_role_self_register("t-mcpmode-4").await;
    let pool = helpers::grab_pool(&tid, &dir).await;
    pool.with_writer(|c| {
        c.execute_batch("CREATE TABLE orders (id INTEGER PRIMARY KEY AUTOINCREMENT, qty INTEGER);")
    })
    .await
    .unwrap();
    let sid = mcp_init(&app, &tid, &svc).await;

    let out = mcp_call_tool(
        &app,
        &tid,
        &svc,
        &sid,
        "create_rpc",
        json!({
            "name": "sneak_write",
            "sql": "INSERT INTO orders (qty) VALUES (1)",
            "params": []
        }),
    )
    .await;
    let lc = out.to_lowercase();
    assert!(
        lc.contains("authoriz") || lc.contains("prohibited"),
        "omitted mode must stay read-only and reject the INSERT: {out}"
    );
    assert_eq!(rpc_row_count(&pool, "sneak_write").await, 0);
}

// Spec case 7 — anon_callable + mode:"write" over an owner-scoped collection
// is refused by the anon guard on the MCP face too.
#[tokio::test]
async fn mcp_create_rpc_write_anon_callable_over_owner_scoped_rejected() {
    let (app, tid, svc, _anon, dir) = helpers::spin_up_dual_role_self_register("t-mcpmode-7").await;
    let pool = helpers::grab_pool(&tid, &dir).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE orders (id INTEGER PRIMARY KEY AUTOINCREMENT, \
             user_id TEXT REFERENCES _system_users(id), qty INTEGER);",
        )
    })
    .await
    .unwrap();
    let sid = mcp_init(&app, &tid, &svc).await;
    let set = mcp_call_tool(
        &app,
        &tid,
        &svc,
        &sid,
        "set_owner_field",
        json!({"collection":"orders","field":"user_id","read_scope":"own"}),
    )
    .await;
    assert!(set.contains("owner_field"), "owner-scope setup: {set}");

    let out = mcp_call_tool(
        &app,
        &tid,
        &svc,
        &sid,
        "create_rpc",
        json!({
            "name": "anon_bump",
            "sql": "UPDATE orders SET qty = qty + 1",
            "params": [],
            "anon_callable": true,
            "mode": "write"
        }),
    )
    .await;
    assert!(
        out.contains(RPC_ANON_OWNER_SCOPED),
        "anon write RPC over owner-scoped collection must be refused: {out}"
    );
    assert_eq!(rpc_row_count(&pool, "anon_bump").await, 0);
}
