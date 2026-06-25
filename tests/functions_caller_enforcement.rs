//! T7 — the **enforcement parity oracle** for caller-identity function invocation.
//!
//! Where `functions_caller_escalation.rs` proves "no god-mode leak", this file
//! proves the positive half: a non-`Privileged` invocation enforces EXACTLY the
//! same caps / owner_field / RLS / file-caps the caller would hit calling REST
//! directly, and `Privileged` (service invoke AND event triggers) stays god-mode.
//!
//! These run the production host-call path: a probe runner injected into the real
//! `Executor::run_one` builds the per-tenant `DrustMcp` via `HostStateSeed::build_mcp`
//! (the `functions: None` depth=1 wiring) and dispatches to the same `enforce::*`
//! fns the wasm host calls (`runtime.rs`), keyed on `caller.to_auth_ctx()` /
//! `caller.role()`. The matrix mirrors `records_list.rs::post_list` and
//! `records.rs` (owner stamp / foreign-row not-found) — the existing REST suite
//! is the byte-equivalence oracle for those handlers; here we assert the function
//! host reaches the same decisions.

use drust::auth::middleware::AuthCtx;
use drust::functions::caller::CallerCtx;
use drust::functions::enforce;
use drust::functions::executor::{Executor, FunctionRunner, Invocation, RunOutcome, RunStatus};
use drust::functions::runtime::HostStateSeed;
use drust::mcp::server::DrustMcp;
use drust::query::list_builder::ListRequest;
use drust::storage::schema::{DmlVerb, FileVerb};
use drust::tenant::file_caps::TenantFileCaps;
use std::sync::Arc;

// ───────────────────────────── shared harness ─────────────────────────────

/// A standalone (registry, mcp) over a fresh tenant dir with an in-memory
/// Garage — the enforcement core needs a real pool + schema cache + storage.
/// Mirrors `enforce::tests::mcp_with_garage` but lives here so the integration
/// file is self-contained (and shares the registry the executor uses).
async fn tenant_mcp(
    tenant: &str,
) -> (
    Arc<drust::storage::pool::TenantRegistry>,
    DrustMcp,
    tempfile::TempDir,
) {
    let tmp = tempfile::tempdir().unwrap();
    let tenants = Arc::new(drust::storage::pool::TenantRegistry::new(
        tmp.path().to_path_buf(),
        2,
    ));
    let _ = tenants.get_or_open(tenant).unwrap();
    let garage = Arc::new(drust::storage::garage::GarageClient::from_store(
        Arc::new(object_store::memory::InMemory::new()),
        "unused",
    ));
    let rooms_cfg = drust::tenant::rooms::RoomsConfig::test_defaults();
    let bucket = rooms_cfg.bucket();
    let mcp = DrustMcp::new(
        tenant,
        tenants.get_or_open(tenant).unwrap(),
        drust::tenant::events::EventBus::new(),
        drust::tenant::WebhookDispatcher::new(tenants.clone(), None),
        Some(garage),
        String::new(),
        Arc::new([0u8; 32]),
        None,
        52_428_800,
        1_000_000,
        Arc::new(tokio::sync::Mutex::new(
            drust::safety::audit_db::open_audit_db_memory().unwrap(),
        )),
        drust::tenant::rooms::RoomBus::new(),
        bucket,
        rooms_cfg,
        None,
        None,
    );
    (tenants, mcp, tmp)
}

fn field(name: &str, ty: &str) -> drust::mcp::tools::schema::FieldSpec {
    drust::mcp::tools::schema::FieldSpec {
        name: name.into(),
        sql_type: ty.into(),
        nullable: true,
        unique: false,
        default_value: None,
        foreign_key: None,
        dim: None,
        description: None,
        ..Default::default()
    }
}

fn anon() -> AuthCtx {
    AuthCtx::Anon
}
fn user(id: &str) -> AuthCtx {
    AuthCtx::User {
        user_id: id.into(),
        token_hash: String::new(),
    }
}
fn service() -> AuthCtx {
    AuthCtx::Service { admin_id: None }
}

/// Create an owner-scoped collection whose owner column FKs `_system_users(id)`,
/// set `owner_field` + `read_scope`, invalidate the cache. Mirrors
/// `enforce::tests::make_owner_scoped`.
async fn make_owner_scoped(mcp: &DrustMcp, coll: &str, read_scope: &str) {
    let coll_c = coll.to_string();
    let scope_c = read_scope.to_string();
    let coll_q = coll.replace('"', "\"\"");
    mcp.inner()
        .pool
        .with_writer(move |c| {
            c.execute_batch(&format!(
                "PRAGMA foreign_keys = ON;
                 CREATE TABLE \"{coll_q}\" (
                     id         INTEGER PRIMARY KEY AUTOINCREMENT,
                     owner      TEXT REFERENCES _system_users(id) ON DELETE RESTRICT,
                     title      TEXT,
                     created_at TEXT DEFAULT (datetime('now')),
                     updated_at TEXT DEFAULT (datetime('now'))
                 );"
            ))?;
            drust::storage::schema::set_owner_field(c, &coll_c, Some("owner"), Some(&scope_c))
        })
        .await
        .unwrap();
    mcp.inner().pool.schema_cache.invalidate(coll);
}

async fn seed_user(mcp: &DrustMcp, id: &str) {
    let id = id.to_string();
    mcp.inner()
        .pool
        .with_writer(move |c| {
            c.execute(
                "INSERT INTO _system_users (id, email, password_hash, created_at, updated_at) \
                 VALUES (?1, ?1, 'x', datetime('now'), datetime('now'))",
                rusqlite::params![id],
            )
            .map(|_| ())
        })
        .await
        .unwrap();
}

// ─────────────────── headline: user invoke owner-stamps + RLS ───────────────────

/// User invoke owner-stamps INSERT and the per-row owner filter denies a foreign
/// UPDATE (not-found) — the data-plane behavior PocketBase users expect, now
/// reached from inside a function rather than only via REST.
#[tokio::test(flavor = "multi_thread")]
async fn user_invoke_owner_stamp_and_foreign_update_denied() {
    let (_reg, mcp, _t) = tenant_mcp("t-enf-owner").await;
    make_owner_scoped(&mcp, "todos", "own").await;
    seed_user(&mcp, "u-1").await;
    seed_user(&mcp, "u-2").await;

    // u-1 inserts; forged owner is overwritten with the caller's id.
    let inserted = enforce::enforced_insert(
        &mcp,
        &user("u-1"),
        "todos",
        serde_json::json!({"title":"mine","owner":"u-evil"}),
    )
    .await
    .unwrap();
    assert_eq!(
        inserted["record"]["owner"], "u-1",
        "owner_field must be stamped to the caller: {inserted}"
    );
    let id = inserted["record"]["id"].as_i64().unwrap();

    // u-2 cannot update u-1's row → not-found (no mutation).
    let foreign = enforce::enforced_update(
        &mcp,
        &user("u-2"),
        "todos",
        id,
        serde_json::json!({"title":"hacked"}),
    )
    .await;
    let e = foreign.unwrap_err().to_string();
    assert!(
        e.contains("RECORD_NOT_FOUND") || e.contains("no such record"),
        "foreign-row update must be not-found, got: {e}"
    );

    // u-1 CAN update its own row.
    let own = enforce::enforced_update(
        &mcp,
        &user("u-1"),
        "todos",
        id,
        serde_json::json!({"title":"renamed"}),
    )
    .await;
    assert!(own.is_ok(), "owner may update own row: {own:?}");
}

/// A User update carrying ONLY the owner_field strips to empty data;
/// `enforced_update` must return a clean `TYPE_MISMATCH` (mirrors the REST
/// `update_handler` post-strip guard), not a malformed `SET ` SQL error.
#[tokio::test(flavor = "multi_thread")]
async fn user_invoke_update_empty_after_owner_strip_is_typed_error() {
    let (_reg, mcp, _t) = tenant_mcp("t-enf-emptystrip").await;
    make_owner_scoped(&mcp, "todos", "own").await;
    seed_user(&mcp, "u-1").await;

    let inserted = enforce::enforced_insert(
        &mcp,
        &user("u-1"),
        "todos",
        serde_json::json!({"title":"mine","owner":"u-1"}),
    )
    .await
    .unwrap();
    let id = inserted["record"]["id"].as_i64().unwrap();

    // Only the owner_field — stripped to `{}` on the User-owner-scoped path.
    let res = enforce::enforced_update(
        &mcp,
        &user("u-1"),
        "todos",
        id,
        serde_json::json!({"owner":"u-1"}),
    )
    .await;
    let e = res.unwrap_err().to_string();
    assert!(
        e.contains("TYPE_MISMATCH") && e.contains("at least one field"),
        "empty-after-strip update must be a clean typed error, got: {e}"
    );
}

/// RLS USING on SELECT hides non-matching rows from a user reader; RLS CHECK on
/// INSERT rolls back a non-conforming write. Both flow through `enforce::*`.
#[tokio::test(flavor = "multi_thread")]
async fn user_invoke_rls_using_and_check_applied() {
    let (_reg, mcp, _t) = tenant_mcp("t-enf-rls").await;
    drust::mcp::tools::schema::create_collection(
        &mcp,
        "docs",
        &[field("kind", "text"), field("n", "integer")],
    )
    .await
    .unwrap();
    drust::mcp::tools::schema::set_user_caps(&mcp, "docs", &[DmlVerb::Select, DmlVerb::Insert])
        .await
        .unwrap();
    // SELECT USING: only kind='public' rows are visible to a user.
    drust::mcp::tools::policy::set_policy(
        &mcp,
        "docs",
        "select",
        Some(serde_json::json!({ "kind": { "eq": "public" } })),
        None,
    )
    .await
    .unwrap();
    // INSERT CHECK: n must be > 0.
    drust::mcp::tools::policy::set_policy(
        &mcp,
        "docs",
        "insert",
        None,
        Some(serde_json::json!({ "n": { "gt": 0 } })),
    )
    .await
    .unwrap();

    // service seeds one public + one private row.
    enforce::enforced_insert(
        &mcp,
        &service(),
        "docs",
        serde_json::json!({"kind":"public","n":1}),
    )
    .await
    .unwrap();
    enforce::enforced_insert(
        &mcp,
        &service(),
        "docs",
        serde_json::json!({"kind":"private","n":1}),
    )
    .await
    .unwrap();

    // user SELECT sees only the public row (USING applied).
    let listed = enforce::enforced_list(&mcp, &user("u-1"), "docs", ListRequest::default())
        .await
        .unwrap();
    assert_eq!(
        listed["total"], 1,
        "RLS USING must hide the private row: {listed}"
    );
    assert_eq!(listed["records"][0]["kind"], "public");

    // user INSERT failing the CHECK rolls back.
    let bad = enforce::enforced_insert(
        &mcp,
        &user("u-1"),
        "docs",
        serde_json::json!({"kind":"public","n":0}),
    )
    .await;
    assert!(
        bad.unwrap_err().to_string().contains("POLICY_CHECK_FAILED"),
        "insert CHECK n>0 must reject n=0"
    );
    // a conforming user INSERT is accepted.
    let good = enforce::enforced_insert(
        &mcp,
        &user("u-1"),
        "docs",
        serde_json::json!({"kind":"public","n":5}),
    )
    .await;
    assert!(good.is_ok(), "conforming insert accepted: {good:?}");
}

// ───────────────────── read parity: enforced_list vs the /list matrix ─────────────────────

/// `enforced_list` (the function-host read path) must reach the SAME allow/deny
/// decision as `POST /list` for every (owner_field, read_scope, caps, role)
/// cell. The matrix here is the canonical `records_list.rs::post_list` table
/// (transcribed in the module CAUTION of `project_drust_rls_spec`): we drive the
/// function-host fn and assert the documented outcome per cell.
#[tokio::test(flavor = "multi_thread")]
async fn read_parity_anon_caps_gate() {
    let (_reg, mcp, _t) = tenant_mcp("t-enf-readanon").await;
    drust::mcp::tools::schema::create_collection(&mcp, "n", &[field("b", "text")])
        .await
        .unwrap();
    // default anon_caps = [select] → anon CAN list.
    let ok = enforce::enforced_list(&mcp, &anon(), "n", ListRequest::default()).await;
    assert!(ok.is_ok(), "default [select] anon list allowed: {ok:?}");
    // revoke select → anon denied (matches POST /list ANON_CAP_DENIED).
    drust::mcp::tools::schema::set_anon_caps(&mcp, "n", &[])
        .await
        .unwrap();
    let denied = enforce::enforced_list(&mcp, &anon(), "n", ListRequest::default()).await;
    assert!(
        denied.unwrap_err().to_string().contains("ANON_CAP_DENIED"),
        "revoked anon select → ANON_CAP_DENIED"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn read_parity_anon_owner_scoped_denied() {
    let (_reg, mcp, _t) = tenant_mcp("t-enf-readanonowner").await;
    make_owner_scoped(&mcp, "p", "own").await;
    // anon on an owner-scoped collection → ANON_FORBIDDEN_OWNER_SCOPED (matches
    // POST /list); even granting anon_caps cannot open it.
    let denied = enforce::enforced_list(&mcp, &anon(), "p", ListRequest::default()).await;
    assert!(
        denied
            .unwrap_err()
            .to_string()
            .contains("ANON_FORBIDDEN_OWNER_SCOPED"),
        "anon owner-scoped read must be forbidden"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn read_parity_user_read_scope_own_filters_rows() {
    let (_reg, mcp, _t) = tenant_mcp("t-enf-readown").await;
    make_owner_scoped(&mcp, "todos", "own").await;
    seed_user(&mcp, "u-1").await;
    seed_user(&mcp, "u-2").await;
    enforce::enforced_insert(
        &mcp,
        &user("u-1"),
        "todos",
        serde_json::json!({"title":"a"}),
    )
    .await
    .unwrap();
    enforce::enforced_insert(
        &mcp,
        &user("u-1"),
        "todos",
        serde_json::json!({"title":"b"}),
    )
    .await
    .unwrap();
    enforce::enforced_insert(
        &mcp,
        &user("u-2"),
        "todos",
        serde_json::json!({"title":"c"}),
    )
    .await
    .unwrap();
    // read_scope=own → u-1 sees only its 2 rows (owner clause auto-applied,
    // matching POST /list). No user_caps[select] needed on the own path.
    let listed = enforce::enforced_list(&mcp, &user("u-1"), "todos", ListRequest::default())
        .await
        .unwrap();
    assert_eq!(
        listed["total"], 2,
        "read_scope=own filters to caller's rows: {listed}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn read_parity_user_read_scope_all_gated_by_user_caps() {
    let (_reg, mcp, _t) = tenant_mcp("t-enf-readall").await;
    make_owner_scoped(&mcp, "pub", "all").await;
    // read_scope=all → no owner filter → must be gated by user_caps[select]
    // (the audit3 F1 lockstep rule POST /list enforces).
    drust::mcp::tools::schema::set_user_caps(&mcp, "pub", &[])
        .await
        .unwrap();
    let denied = enforce::enforced_list(&mcp, &user("u-1"), "pub", ListRequest::default()).await;
    assert!(
        denied.unwrap_err().to_string().contains("ANON_CAP_DENIED"),
        "read_scope=all user read with no user_caps[select] must be denied"
    );
    drust::mcp::tools::schema::set_user_caps(&mcp, "pub", &[DmlVerb::Select])
        .await
        .unwrap();
    let ok = enforce::enforced_list(&mcp, &user("u-1"), "pub", ListRequest::default()).await;
    assert!(
        ok.is_ok(),
        "granting user_caps[select] opens the read_scope=all read"
    );
}

// ─────────────────────────── file caps parity ───────────────────────────

/// `get_file_bytes` (read) and `put_file` (upload) are gated by
/// `file_anon_caps` / `file_user_caps` exactly as the REST file routes are.
#[tokio::test(flavor = "multi_thread")]
async fn file_caps_gate_read_and_upload() {
    let (_reg, mcp, _t) = tenant_mcp("t-enf-files").await;
    // service seeds a private file via the raw path.
    enforce::put_file_raw(
        &mcp,
        "f.bin",
        b"hi".to_vec(),
        "application/octet-stream",
        "private",
        0,
    )
    .await
    .unwrap();

    // anon read with no file caps → denied.
    let no_caps = TenantFileCaps::default();
    let denied = enforce::enforced_get_file_bytes(
        &mcp,
        drust::tenant::router::TokenRole::Anon,
        &no_caps,
        "f.bin",
        4 * 1024 * 1024,
    )
    .await;
    assert!(denied.unwrap_err().contains("FILE_READ_DENIED"));

    // grant anon read → allowed.
    let mut anon_read = TenantFileCaps::default();
    anon_read.anon.insert(FileVerb::Read);
    let bytes = enforce::enforced_get_file_bytes(
        &mcp,
        drust::tenant::router::TokenRole::Anon,
        &anon_read,
        "f.bin",
        4 * 1024 * 1024,
    )
    .await
    .unwrap();
    assert_eq!(bytes, b"hi");

    // user upload with no file caps → denied.
    let denied_up = enforce::enforced_put_file(
        &mcp,
        drust::tenant::router::TokenRole::User,
        &no_caps,
        "u.bin",
        b"x".to_vec(),
        "application/octet-stream",
        "private",
        0,
    )
    .await;
    assert!(denied_up.unwrap_err().contains("FILE_UPLOAD_DENIED"));

    // grant user upload → allowed.
    let mut user_up = TenantFileCaps::default();
    user_up.user.insert(FileVerb::Upload);
    let ok = enforce::enforced_put_file(
        &mcp,
        drust::tenant::router::TokenRole::User,
        &user_up,
        "u.bin",
        b"x".to_vec(),
        "application/octet-stream",
        "private",
        0,
    )
    .await;
    assert!(ok.is_ok(), "granted user upload cap → allowed: {ok:?}");

    // service (Privileged) bypasses file caps entirely.
    let svc_read = enforce::get_file_bytes_raw(&mcp, "f.bin", 4 * 1024 * 1024)
        .await
        .unwrap();
    assert_eq!(svc_read, b"hi", "service raw read bypasses caps");
}

// ────────────── god-mode parity: service invoke & event path ──────────────

/// A runner that performs ONE host INSERT under whatever caller it receives,
/// mirroring `runtime.rs`'s branch. Used to prove the END-TO-END executor path
/// (queue → run_one → DiD assert → runner) keeps `Privileged` god-mode for both
/// service invoke and event triggers (the dispatcher always sets `Privileged`).
struct GodModeProbe {
    seed: HostStateSeed,
    ok: Arc<std::sync::atomic::AtomicBool>,
}
#[async_trait::async_trait]
impl FunctionRunner for GodModeProbe {
    async fn run(
        &self,
        tenant: &str,
        _p: &std::path::Path,
        _e: &str,
        caller: CallerCtx,
    ) -> RunOutcome {
        let mcp = self.seed.build_mcp(tenant).unwrap();
        let data = serde_json::json!({ "body": "god" });
        let res = match &caller {
            CallerCtx::Privileged => drust::mcp::tools::write::insert_record(&mcp, "locked", data)
                .await
                .map_err(|e| e.to_string()),
            other => enforce::enforced_insert(&mcp, &other.to_auth_ctx(), "locked", data)
                .await
                .map_err(|e| e.to_string()),
        };
        match res {
            Ok(_) => {
                self.ok.store(true, std::sync::atomic::Ordering::SeqCst);
                RunOutcome {
                    status: RunStatus::Ok,
                    result: "{}".into(),
                    log_text: String::new(),
                }
            }
            Err(e) => RunOutcome {
                status: RunStatus::Error,
                result: e,
                log_text: String::new(),
            },
        }
    }
}

/// Build an executor over `GodModeProbe` with a `locked` collection that grants
/// NO caps (so only Privileged can write it) and a function row with both invoke
/// flags OFF (event/service path does not consult them).
async fn god_mode_stack(
    tenant: &str,
    ok: Arc<std::sync::atomic::AtomicBool>,
) -> (Arc<Executor>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let tenants = Arc::new(drust::storage::pool::TenantRegistry::new(data.clone(), 2));
    let _ = drust::storage::tenant_db::open_write(&data, tenant).unwrap();
    let pool = tenants.get_or_open(tenant).unwrap();
    let svc = drust::mcp::server::McpRegistry::new(tenants.clone())
        .get_or_create(tenant)
        .await
        .unwrap();
    drust::mcp::tools::schema::create_collection(&svc, "locked", &[field("body", "text")])
        .await
        .unwrap();
    // default anon/user caps = [select] → neither can INSERT `locked`.
    drust::functions::schema::create_function(
        &pool,
        drust::functions::schema::CreateFunctionParams {
            name: "g".into(),
            wasm_sha256: "00".repeat(32),
            size_bytes: 1,
            triggers_json: "[]".into(),
            description: String::new(),
        },
        10,
    )
    .await
    .unwrap();

    let rooms_cfg = drust::tenant::rooms::RoomsConfig::test_defaults();
    let bucket = rooms_cfg.bucket();
    let seed = HostStateSeed {
        tenants: tenants.clone(),
        bus: drust::tenant::events::EventBus::new(),
        webhooks: drust::tenant::WebhookDispatcher::new(tenants.clone(), None),
        garage: None,
        public_base_url: String::new(),
        url_sign_secret: Arc::new([0u8; 32]),
        meta: None,
        max_upload_bytes: 52_428_800,
        index_large_table_rows: 1_000_000,
        audit_meta_read: Arc::new(tokio::sync::Mutex::new(
            drust::safety::audit_db::open_audit_db_memory().unwrap(),
        )),
        bus_rooms: drust::tenant::rooms::RoomBus::new(),
        bucket,
        rooms_cfg,
        disk_min_free_pct: 0,
    };
    let runner = Arc::new(GodModeProbe { seed, ok });
    let fn_cfg = drust::functions::FnConfig::test_default();
    let (tx, _rx) = tokio::sync::mpsc::channel(64);
    let dispatcher =
        drust::functions::dispatcher::FunctionDispatcher::new(tenants.clone(), tx, fn_cfg.clone());
    let executor = Executor::new(
        runner,
        tenants.clone(),
        fn_cfg,
        data.clone(),
        dispatcher.depth.clone(),
    );
    (executor, dir)
}

#[tokio::test(flavor = "multi_thread")]
async fn service_invoke_is_god_mode() {
    let ok = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (exec, _dir) = god_mode_stack("t-enf-svc", ok.clone()).await;
    let out = exec
        .run_one(Invocation {
            tenant_id: "t-enf-svc".into(),
            function_name: "g".into(),
            trigger: "manual".into(),
            event_json: "{}".into(),
            caller: CallerCtx::Privileged,
        })
        .await;
    assert_eq!(
        out.status,
        RunStatus::Ok,
        "service invoke god-mode insert: {}",
        out.result
    );
    assert!(ok.load(std::sync::atomic::Ordering::SeqCst));
}

/// The event-trigger path: the dispatcher ALWAYS builds `CallerCtx::Privileged`,
/// so a record/file event runs god-mode regardless of the invoke flags. We model
/// it by submitting a `Privileged` invocation with an "record.created" trigger
/// (the shape the dispatcher emits) and asserting the no-cap write succeeds.
#[tokio::test(flavor = "multi_thread")]
async fn event_path_is_god_mode() {
    let ok = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (exec, _dir) = god_mode_stack("t-enf-evt", ok.clone()).await;
    let out = exec
        .run_one(Invocation {
            tenant_id: "t-enf-evt".into(),
            function_name: "g".into(),
            trigger: "record.created:locked".into(),
            event_json: r#"{"record":{"id":1}}"#.into(),
            caller: CallerCtx::Privileged, // dispatcher's invariant
        })
        .await;
    assert_eq!(
        out.status,
        RunStatus::Ok,
        "event-path god-mode insert: {}",
        out.result
    );
    assert!(ok.load(std::sync::atomic::Ordering::SeqCst));
}
