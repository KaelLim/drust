#![allow(dead_code)]

use axum::Router;
use drust::auth::bearer::{generate_token, hash_token};
use drust::mcp::http_registry::McpHttpRegistry;
use drust::mcp::server::McpRegistry;
use drust::storage::meta::open_meta;
use drust::storage::pool::{SharedTenantPool, TenantRegistry};
use drust::tenant::router::TenantAuthState;
use drust::tenant::{TenantStack, WebhookDispatcher, build_tenant_router, events::EventBus};
use std::sync::Arc;
use tokio::sync::Mutex;

pub fn test_mcp_http(tenants: Arc<TenantRegistry>, bus: EventBus) -> Arc<McpHttpRegistry> {
    Arc::new(McpHttpRegistry::new(Arc::new(McpRegistry::with_bus(
        tenants, bus,
    ))))
}

pub async fn spin_up_tenant(tenant: &str) -> (Router, String, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let conn = open_meta(&data.join("meta.sqlite")).unwrap();
    conn.execute(
        "INSERT INTO tenants (id, name) VALUES (?1, 'x')",
        rusqlite::params![tenant],
    )
    .unwrap();
    let tok = generate_token();
    conn.execute(
        "INSERT INTO tokens (tenant_id, token_hash) VALUES (?1, ?2)",
        rusqlite::params![tenant, hash_token(&tok)],
    )
    .unwrap();
    let _ = drust::storage::tenant_db::open_write(&data, tenant).unwrap();
    drust::db::migrations::run_migrations(&conn, &data).unwrap();
    let tenants = Arc::new(TenantRegistry::new(data.clone(), 2));
    let bus = EventBus::new();
    let webhooks = WebhookDispatcher::new(tenants.clone(), None);
    let meta = Arc::new(Mutex::new(conn));
    let state = TenantAuthState::test_default(meta, tenants.clone());
    let (functions, functions_exec, fn_cfg) = drust::functions::test_stack_parts(tenants.clone());
    let stack = TenantStack {
        auth: state,
        bus: bus.clone(),
        bus_rooms: drust::tenant::rooms::RoomBus::new(),
        bucket: drust::tenant::rooms::RoomsConfig::test_defaults().bucket(),
        rooms_cfg: drust::tenant::rooms::RoomsConfig::test_defaults(),
        mcp: test_mcp_http(tenants, bus),
        files: None,
        webhooks,
        functions,
        functions_exec,
        fn_cfg,
        cors_origins: Vec::new(),
    };
    let app = build_tenant_router(stack);
    (app, tok, dir)
}

/// Like `spin_up_tenant` but injects a custom `FunctionRunner` and binds one
/// `_system_functions` row (triggers = `triggers_json`) on the tenant, so
/// dispatch tests can observe REST write → function invocation end to end.
/// Also creates a `posts` collection (text `title`) for the writes to hit.
pub async fn spin_up_tenant_with_fn_runner(
    tenant: &str,
    runner: Arc<dyn drust::functions::executor::FunctionRunner>,
    triggers_json: &str,
) -> (Router, String, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let conn = open_meta(&data.join("meta.sqlite")).unwrap();
    conn.execute(
        "INSERT INTO tenants (id, name) VALUES (?1, 'x')",
        rusqlite::params![tenant],
    )
    .unwrap();
    let tok = generate_token();
    conn.execute(
        "INSERT INTO tokens (tenant_id, token_hash) VALUES (?1, ?2)",
        rusqlite::params![tenant, hash_token(&tok)],
    )
    .unwrap();
    let _ = drust::storage::tenant_db::open_write(&data, tenant).unwrap();
    drust::db::migrations::run_migrations(&conn, &data).unwrap();
    let tenants = Arc::new(TenantRegistry::new(data.clone(), 2));
    let bus = EventBus::new();
    let webhooks = WebhookDispatcher::new(tenants.clone(), None);
    let meta = Arc::new(Mutex::new(conn));
    let state = TenantAuthState::test_default(meta, tenants.clone());

    // Manual dispatcher + executor build with the injected runner — same
    // shape as `drust::functions::test_stack_parts` minus the noop runner.
    let fn_cfg = drust::functions::FnConfig::test_default();
    let (tx, rx) = tokio::sync::mpsc::channel(64);
    let functions =
        drust::functions::dispatcher::FunctionDispatcher::new(tenants.clone(), tx, fn_cfg.clone());
    let functions_exec = drust::functions::executor::Executor::new(
        runner,
        tenants.clone(),
        fn_cfg.clone(),
        data.clone(),
        functions.depth.clone(),
    );
    functions_exec.spawn_loop(rx);

    // `posts` collection via the canonical MCP schema tool (same pool /
    // schema_cache the REST path reads).
    let mcp_reg = drust::mcp::server::McpRegistry::new(tenants.clone());
    let svc = mcp_reg.get_or_create(tenant).await.unwrap();
    drust::mcp::tools::schema::create_collection(
        &svc,
        "posts",
        &[drust::mcp::tools::schema::FieldSpec {
            name: "title".into(),
            sql_type: "text".into(),
            nullable: false,
            unique: false,
            default_value: None,
            foreign_key: None,
            dim: None,
            description: None,
            ..Default::default()
        }],
    )
    .await
    .unwrap();

    // One function row bound per `triggers_json`, then refresh the cache.
    let pool = tenants.get_or_open(tenant).unwrap();
    drust::functions::schema::create_function(
        &pool,
        drust::functions::schema::CreateFunctionParams {
            name: "hook".into(),
            wasm_sha256: "00".repeat(32),
            size_bytes: 1,
            triggers_json: triggers_json.into(),
            description: String::new(),
        },
        10,
    )
    .await
    .unwrap();
    functions.bindings.invalidate(tenant);

    // Wire a files router backed by an in-memory Garage + the SAME functions
    // dispatcher, so Mode A / Mode B upload-completion triggers are observable
    // end to end.
    let garage = Arc::new(drust::storage::garage::GarageClient::from_store(
        Arc::new(object_store::memory::InMemory::new()),
        "unused",
    ));
    let mut files_state = drust::mgmt::tenant_files::TenantFilesState::test_default(
        Some(garage),
        data.clone(),
        tenants.clone(),
    );
    files_state.disk_min_free_pct = 0;
    files_state.functions = functions.clone();

    let stack = TenantStack {
        auth: state,
        bus: bus.clone(),
        bus_rooms: drust::tenant::rooms::RoomBus::new(),
        bucket: drust::tenant::rooms::RoomsConfig::test_defaults().bucket(),
        rooms_cfg: drust::tenant::rooms::RoomsConfig::test_defaults(),
        mcp: test_mcp_http(tenants, bus),
        files: Some(files_state),
        webhooks,
        functions,
        functions_exec,
        fn_cfg,
        cors_origins: Vec::new(),
    };
    let app = build_tenant_router(stack);
    (app, tok, dir)
}

/// Like `spin_up_tenant` (noop runner) but also mints an anon token AND a real
/// `drust_user_*` session token (so service-only gating can be proven against
/// the user-session branch of `bearer_auth_layer`, not just anon), and seeds
/// one `_system_functions` row named `f1` (sha `00…`, triggers `[]`), so the
/// functions REST CRUD tests can exercise list/get/patch/invoke/logs/delete
/// without a wasm toolchain. Returns
/// `(router, service_token, anon_token, user_token, tmp)`.
pub async fn spin_up_tenant_with_fn_seed(
    tenant: &str,
) -> (Router, String, String, String, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let conn = open_meta(&data.join("meta.sqlite")).unwrap();
    conn.execute(
        "INSERT INTO tenants (id, name) VALUES (?1, 'x')",
        rusqlite::params![tenant],
    )
    .unwrap();
    let service = generate_token();
    conn.execute(
        "INSERT INTO tokens (tenant_id, token_hash, role) VALUES (?1, ?2, 'service')",
        rusqlite::params![tenant, hash_token(&service)],
    )
    .unwrap();
    let anon = generate_token();
    conn.execute(
        "INSERT INTO tokens (tenant_id, token_hash, role) VALUES (?1, ?2, 'anon')",
        rusqlite::params![tenant, hash_token(&anon)],
    )
    .unwrap();
    let _ = drust::storage::tenant_db::open_write(&data, tenant).unwrap();
    drust::db::migrations::run_migrations(&conn, &data).unwrap();
    let tenants = Arc::new(TenantRegistry::new(data.clone(), 2));
    let bus = EventBus::new();
    let webhooks = WebhookDispatcher::new(tenants.clone(), None);
    let meta = Arc::new(Mutex::new(conn));
    let state = TenantAuthState::test_default(meta, tenants.clone());
    let (functions, functions_exec, fn_cfg) = drust::functions::test_stack_parts(tenants.clone());

    // Seed one function row `f1`, then refresh the binding cache.
    let pool = tenants.get_or_open(tenant).unwrap();
    drust::functions::schema::create_function(
        &pool,
        drust::functions::schema::CreateFunctionParams {
            name: "f1".into(),
            wasm_sha256: "00".repeat(32),
            size_bytes: 1,
            triggers_json: "[]".into(),
            description: String::new(),
        },
        10,
    )
    .await
    .unwrap();
    functions.bindings.invalidate(tenant);

    // Seed one `_system_users` row + an active session so the test can hit the
    // user-session branch of `bearer_auth_layer` with a real `drust_user_*`
    // bearer (distinct code path from the anon token).
    let user_token = pool
        .with_writer(|c| {
            c.execute(
                "INSERT INTO _system_users (id, email, password_hash, created_at, updated_at) \
                 VALUES ('u-fn-seed', 'u@x', 'h', datetime('now'), datetime('now'))",
                [],
            )?;
            drust::auth::user_session::create_session(c, "u-fn-seed", None, 30)
        })
        .await
        .unwrap();

    let stack = TenantStack {
        auth: state,
        bus: bus.clone(),
        bus_rooms: drust::tenant::rooms::RoomBus::new(),
        bucket: drust::tenant::rooms::RoomsConfig::test_defaults().bucket(),
        rooms_cfg: drust::tenant::rooms::RoomsConfig::test_defaults(),
        mcp: test_mcp_http(tenants, bus),
        files: None,
        webhooks,
        functions,
        functions_exec,
        fn_cfg,
        cors_origins: Vec::new(),
    };
    let app = build_tenant_router(stack);
    (app, service, anon, user_token, dir)
}

pub async fn grab_pool(tenant: &str, dir: &tempfile::TempDir) -> SharedTenantPool {
    let reg = TenantRegistry::new(dir.path().to_path_buf(), 2);
    reg.get_or_open(tenant).unwrap()
}

/// Minimal stack for the cron dispatch tests (tests/cron_dispatch.rs): a
/// registry over a tempdir with one opened tenant (`get_or_open` runs
/// `open_write` → full `_system_*` schema), one seeded `_system_functions`
/// row `f1` (sha `00…`, triggers `[]` — the injected mock runner never reads
/// the artifact), and an `Executor` wired to that runner. No router / meta /
/// dispatcher — `run_due_job` talks to the registry + executor directly, the
/// same pieces `spin_up_tenant_with_fn_runner` builds for the REST path.
pub async fn cron_test_stack(
    tenant: &str,
    runner: Arc<dyn drust::functions::executor::FunctionRunner>,
) -> (
    Arc<TenantRegistry>,
    Arc<drust::functions::executor::Executor>,
    tempfile::TempDir,
) {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let tenants = Arc::new(TenantRegistry::new(data.clone(), 2));
    let pool = tenants.get_or_open(tenant).unwrap();

    drust::functions::schema::create_function(
        &pool,
        drust::functions::schema::CreateFunctionParams {
            name: "f1".into(),
            wasm_sha256: "00".repeat(32),
            size_bytes: 1,
            triggers_json: "[]".into(),
            description: String::new(),
        },
        10,
    )
    .await
    .unwrap();

    let fn_cfg = drust::functions::FnConfig::test_default();
    let depth = Arc::new(dashmap::DashMap::new());
    let executor =
        drust::functions::executor::Executor::new(runner, tenants.clone(), fn_cfg, data, depth);
    (tenants, executor, dir)
}

/// Returned by [`spin_up_isolation_stack`]: the dispatcher to fire record
/// events at, plus an SSE-reach counter incremented by a bus subscriber task.
pub struct IsolationStack {
    pub dispatcher: Arc<drust::functions::dispatcher::FunctionDispatcher>,
    pub sse_events_seen: Arc<std::sync::atomic::AtomicUsize>,
    /// Keeps the tenant data dir alive for the lifetime of the stack.
    pub _dir: tempfile::TempDir,
}

/// Build the full functions dispatcher + executor over a REAL `HostStateSeed`
/// (so the injected `WritingRunner` exercises the depth=1 `functions: None`
/// wiring), with a `fn_out` collection and one function row bound to
/// `{"collection":"fn_out","events":["created"]}` — the SAME collection the
/// `WritingRunner` writes into. A bus subscriber task increments
/// `sse_events_seen` so the test can prove the function's own insert reached
/// SSE. `counter` (returned) is bumped once per completed run; if a function
/// write could re-trigger, the binding would re-fire and `counter` would
/// exceed 1.
///
/// Every piece composes earlier tasks' primitives — the HostStateSeed field
/// sourcing mirrors `tests/functions_wasm_real.rs::real_runner`, the
/// dispatcher/executor wiring mirrors `spin_up_tenant_with_fn_runner`.
pub async fn spin_up_isolation_stack(
    tenant: &str,
    runner_factory: impl FnOnce(
        drust::functions::runtime::HostStateSeed,
        Arc<std::sync::atomic::AtomicUsize>,
    ) -> Arc<dyn drust::functions::executor::FunctionRunner>,
) -> (IsolationStack, Arc<std::sync::atomic::AtomicUsize>) {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let tenants = Arc::new(TenantRegistry::new(data.clone(), 2));
    let _ = drust::storage::tenant_db::open_write(&data, tenant).unwrap();
    let bus = EventBus::new();
    let webhooks = WebhookDispatcher::new(tenants.clone(), None);

    // `fn_out` collection — the runner's host insert target AND the bound
    // trigger collection (the deliberate self-write loop the depth=1 guard
    // must break).
    let pool = tenants.get_or_open(tenant).unwrap();
    create_collection_via_pool(&pool, "fn_out", &[("payload", "text")]).await;

    // One function row bound to fn_out/created, then prime the cache.
    drust::functions::schema::create_function(
        &pool,
        drust::functions::schema::CreateFunctionParams {
            name: "self_writer".into(),
            wasm_sha256: "00".repeat(32),
            size_bytes: 1,
            triggers_json: r#"[{"collection":"fn_out","events":["created"]}]"#.into(),
            description: String::new(),
        },
        10,
    )
    .await
    .unwrap();

    // Real HostStateSeed — `build_mcp` constructs the per-tenant DrustMcp with
    // functions: None (the recursion guard under test). Field sourcing mirrors
    // tests/functions_wasm_real.rs::real_runner.
    let rooms_cfg = drust::tenant::rooms::RoomsConfig::test_defaults();
    let bucket = rooms_cfg.bucket();
    let seed = drust::functions::runtime::HostStateSeed {
        tenants: tenants.clone(),
        bus: bus.clone(),
        webhooks: webhooks.clone(),
        garage: None,
        public_base_url: String::new(),
        url_sign_secret: Arc::new([0u8; 32]),
        meta: None,
        max_upload_bytes: 52_428_800,
        index_large_table_rows: 1_000_000,
        audit_meta_read: Arc::new(Mutex::new(
            drust::safety::audit_db::open_audit_db_memory().unwrap(),
        )),
        bus_rooms: drust::tenant::rooms::RoomBus::new(),
        bucket,
        rooms_cfg,
        disk_min_free_pct: 20,
    };

    let counter = Arc::new(AtomicUsize::new(0));
    let runner = runner_factory(seed, counter.clone());

    let fn_cfg = drust::functions::FnConfig::test_default();
    let (tx, rx) = tokio::sync::mpsc::channel(64);
    let dispatcher =
        drust::functions::dispatcher::FunctionDispatcher::new(tenants.clone(), tx, fn_cfg.clone());
    let executor = drust::functions::executor::Executor::new(
        runner,
        tenants.clone(),
        fn_cfg,
        data.clone(),
        dispatcher.depth.clone(),
    );
    executor.spawn_loop(rx);
    dispatcher.bindings.invalidate(tenant);

    // SSE-reach probe: subscribe on (tenant, fn_out) and count published
    // events. The function's own insert_record into fn_out publishes here;
    // the original dispatch event is NOT published by the dispatcher, so this
    // counts exactly the function-initiated write.
    let sse_events_seen = Arc::new(AtomicUsize::new(0));
    let mut rx_sse = bus.subscribe(tenant, "fn_out");
    let seen = sse_events_seen.clone();
    tokio::spawn(async move {
        while rx_sse.recv().await.is_ok() {
            seen.fetch_add(1, Ordering::SeqCst);
        }
    });

    (
        IsolationStack {
            dispatcher,
            sse_events_seen,
            _dir: dir,
        },
        counter,
    )
}

/// Build a full tenant router with the functions REST surface mounted, a
/// service token, a SMALL per-tenant function cap (`max_per_tenant`), and a
/// `data_root` the caller can inspect (the returned `TempDir`). Used by the
/// route-level artifact-GC test, which POSTs real wasm fixtures through
/// `create` and asserts on-disk `{sha}.wasm` presence/absence.
///
/// Returns `(router, service_token, data_root_tempdir)`. Artifacts land under
/// `<data_root>/tenants/<tenant>/_functions/`.
pub async fn spin_up_functions_route_stack(
    tenant: &str,
    max_per_tenant: u32,
) -> (Router, String, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let conn = open_meta(&data.join("meta.sqlite")).unwrap();
    conn.execute(
        "INSERT INTO tenants (id, name) VALUES (?1, 'x')",
        rusqlite::params![tenant],
    )
    .unwrap();
    let service = generate_token();
    conn.execute(
        "INSERT INTO tokens (tenant_id, token_hash, role) VALUES (?1, ?2, 'service')",
        rusqlite::params![tenant, hash_token(&service)],
    )
    .unwrap();
    let _ = drust::storage::tenant_db::open_write(&data, tenant).unwrap();
    drust::db::migrations::run_migrations(&conn, &data).unwrap();
    let tenants = Arc::new(TenantRegistry::new(data.clone(), 2));
    let bus = EventBus::new();
    let webhooks = WebhookDispatcher::new(tenants.clone(), None);
    let meta = Arc::new(Mutex::new(conn));
    let state = TenantAuthState::test_default(meta, tenants.clone());

    // (dispatcher, executor, cfg) with the small cap. `test_stack_parts`
    // hardwires max_per_tenant=10, so build the triple inline with a patched
    // FnConfig — same noop-runner shape; the route create() path never invokes
    // the runner.
    let mut fn_cfg = drust::functions::FnConfig::test_default();
    fn_cfg.max_per_tenant = max_per_tenant;
    let (tx, rx) = tokio::sync::mpsc::channel(64);
    let functions =
        drust::functions::dispatcher::FunctionDispatcher::new(tenants.clone(), tx, fn_cfg.clone());
    struct NoopRunner;
    #[async_trait::async_trait]
    impl drust::functions::executor::FunctionRunner for NoopRunner {
        async fn run(
            &self,
            _t: &str,
            _p: &std::path::Path,
            _e: &str,
            _caller: drust::functions::caller::CallerCtx,
        ) -> drust::functions::executor::RunOutcome {
            drust::functions::executor::RunOutcome {
                status: drust::functions::executor::RunStatus::Ok,
                result: "{}".into(),
                log_text: String::new(),
            }
        }
    }
    let functions_exec = drust::functions::executor::Executor::new(
        Arc::new(NoopRunner),
        tenants.clone(),
        fn_cfg.clone(),
        data.clone(),
        functions.depth.clone(),
    );
    functions_exec.spawn_loop(rx);

    let stack = TenantStack {
        auth: state,
        bus: bus.clone(),
        bus_rooms: drust::tenant::rooms::RoomBus::new(),
        bucket: drust::tenant::rooms::RoomsConfig::test_defaults().bucket(),
        rooms_cfg: drust::tenant::rooms::RoomsConfig::test_defaults(),
        mcp: test_mcp_http(tenants, bus),
        files: None,
        webhooks,
        functions,
        functions_exec,
        fn_cfg,
        cors_origins: Vec::new(),
    };
    let app = build_tenant_router(stack);
    (app, service, dir)
}

/// Create a collection directly against a pool, in the same shape the
/// canonical MCP `create_collection` tool produces (`id` PK +
/// `created_at`/`updated_at` + the named fields). The host-API write path
/// (`insert_record` / `read_record`) derives schema from `sqlite_master` +
/// PRAGMA, not `_system_collection_meta`, so a raw `CREATE TABLE` is all the
/// real-wasm fixtures need. `fields` is `(name, sql_type)` where sql_type is
/// the same lowercase keyword `FieldSpec.sql_type` accepts (text/integer/
/// real/blob); unknown types fall back to TEXT affinity.
pub async fn create_collection_via_pool(
    pool: &SharedTenantPool,
    collection: &str,
    fields: &[(&str, &str)],
) {
    let mut cols = vec!["id INTEGER PRIMARY KEY AUTOINCREMENT".to_string()];
    for (name, ty) in fields {
        let sql_ty = match ty.to_ascii_lowercase().as_str() {
            "integer" | "int" => "INTEGER",
            "real" | "float" => "REAL",
            "blob" => "BLOB",
            _ => "TEXT",
        };
        cols.push(format!("\"{}\" {}", name.replace('"', "\"\""), sql_ty));
    }
    cols.push("created_at TEXT NOT NULL DEFAULT (datetime('now'))".into());
    cols.push("updated_at TEXT NOT NULL DEFAULT (datetime('now'))".into());
    let sql = format!(
        "CREATE TABLE IF NOT EXISTS \"{}\" ({})",
        collection.replace('"', "\"\""),
        cols.join(", ")
    );
    pool.with_writer(move |c| c.execute_batch(&sql))
        .await
        .unwrap();
}

/// Fixed multipart boundary used by `multipart_file_body`; the
/// `content-type` header on the request must carry this exact boundary.
pub const MULTIPART_BOUNDARY: &str = "drustfnboundary99";
/// Matching `content-type` header value for `multipart_file_body` requests.
pub const MULTIPART_CONTENT_TYPE: &str = "multipart/form-data; boundary=drustfnboundary99";

/// Build a minimal multipart/form-data body carrying one file part.
/// Mirrors the canonical boundary builder from `tests/admin_files_upgrade.rs`.
pub fn multipart_file_body(
    field_name: &str,
    filename: &str,
    bytes: &[u8],
    content_type: &str,
) -> Vec<u8> {
    let b = MULTIPART_BOUNDARY;
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(format!("--{b}\r\n").as_bytes());
    body.extend_from_slice(
        format!(
            "Content-Disposition: form-data; name=\"{field_name}\"; filename=\"{filename}\"\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(format!("Content-Type: {content_type}\r\n\r\n").as_bytes());
    body.extend_from_slice(bytes);
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(format!("--{b}--\r\n").as_bytes());
    body
}

/// Like `spin_up_tenant` but inserts the token with an explicit role
/// (`"anon"` or `"service"`).
pub async fn spin_up_tenant_with_role(
    tenant: &str,
    role: &str,
) -> (Router, String, tempfile::TempDir) {
    let (app, tok, _cache, dir) = spin_up_tenant_with_role_cached(tenant, role).await;
    (app, tok, dir)
}

/// Like `spin_up_tenant_with_role`, but ALSO returns the stack's `AuthCache`
/// handle (v1.35 Finding #3). Tests that flip auth-relevant `meta.sqlite`
/// columns OUT-OF-BAND (raw SQL — no production handler, so no invalidation
/// hook fires) must mirror the handlers' invalidation themselves, e.g.
/// `cache.clear_tenant(tenant)` after the flip; otherwise the flipped value
/// is invisible until the safety TTL expires.
pub async fn spin_up_tenant_with_role_cached(
    tenant: &str,
    role: &str,
) -> (
    Router,
    String,
    Arc<drust::tenant::auth_cache::AuthCache>,
    tempfile::TempDir,
) {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let conn = open_meta(&data.join("meta.sqlite")).unwrap();
    conn.execute(
        "INSERT INTO tenants (id, name) VALUES (?1, 'x')",
        rusqlite::params![tenant],
    )
    .unwrap();
    let tok = generate_token();
    conn.execute(
        "INSERT INTO tokens (tenant_id, token_hash, role) VALUES (?1, ?2, ?3)",
        rusqlite::params![tenant, hash_token(&tok), role],
    )
    .unwrap();
    let _ = drust::storage::tenant_db::open_write(&data, tenant).unwrap();
    drust::db::migrations::run_migrations(&conn, &data).unwrap();
    let tenants = Arc::new(TenantRegistry::new(data.clone(), 2));
    let bus = EventBus::new();
    let webhooks = WebhookDispatcher::new(tenants.clone(), None);
    let meta = Arc::new(Mutex::new(conn));
    let state = TenantAuthState::test_default(meta, tenants.clone());
    let cache = state.auth_cache.clone();
    let (functions, functions_exec, fn_cfg) = drust::functions::test_stack_parts(tenants.clone());
    let stack = TenantStack {
        auth: state,
        bus: bus.clone(),
        bus_rooms: drust::tenant::rooms::RoomBus::new(),
        bucket: drust::tenant::rooms::RoomsConfig::test_defaults().bucket(),
        rooms_cfg: drust::tenant::rooms::RoomsConfig::test_defaults(),
        mcp: test_mcp_http(tenants, bus),
        files: None,
        webhooks,
        functions,
        functions_exec,
        fn_cfg,
        cors_origins: Vec::new(),
    };
    let app = build_tenant_router(stack);
    (app, tok, cache, dir)
}

/// Like `spin_up_tenant_with_role` but uses a specific `index_large_table_rows`
/// threshold. Useful for regression-testing that the configured threshold is
/// plumbed end-to-end (REST + MCP + admin) rather than a hardcoded default.
pub async fn spin_up_tenant_with_threshold(
    tenant: &str,
    role: &str,
    index_large_table_rows: u64,
) -> (Router, String, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let conn = open_meta(&data.join("meta.sqlite")).unwrap();
    conn.execute(
        "INSERT INTO tenants (id, name) VALUES (?1, 'x')",
        rusqlite::params![tenant],
    )
    .unwrap();
    let tok = generate_token();
    conn.execute(
        "INSERT INTO tokens (tenant_id, token_hash, role) VALUES (?1, ?2, ?3)",
        rusqlite::params![tenant, hash_token(&tok), role],
    )
    .unwrap();
    let _ = drust::storage::tenant_db::open_write(&data, tenant).unwrap();
    drust::db::migrations::run_migrations(&conn, &data).unwrap();
    let tenants = Arc::new(TenantRegistry::new(data.clone(), 2));
    let bus = EventBus::new();
    let webhooks = WebhookDispatcher::new(tenants.clone(), None);
    let meta = Arc::new(Mutex::new(conn));
    let mut state = TenantAuthState::test_default(meta, tenants.clone());
    state.index_large_table_rows = index_large_table_rows;
    let (functions, functions_exec, fn_cfg) = drust::functions::test_stack_parts(tenants.clone());
    let stack = TenantStack {
        auth: state,
        bus: bus.clone(),
        bus_rooms: drust::tenant::rooms::RoomBus::new(),
        bucket: drust::tenant::rooms::RoomsConfig::test_defaults().bucket(),
        rooms_cfg: drust::tenant::rooms::RoomsConfig::test_defaults(),
        mcp: test_mcp_http(tenants, bus),
        files: None,
        webhooks,
        functions,
        functions_exec,
        fn_cfg,
        cors_origins: Vec::new(),
    };
    let app = build_tenant_router(stack);
    (app, tok, dir)
}

/// Seed a `posts` collection with an `author_id INTEGER` field on tenant
/// `tenant` by writing directly through the pool.  The pool is opened from
/// the same TempDir that `spin_up_tenant*` created.
pub async fn seed_posts_collection(
    _app: &Router,
    _tok: &str,
    tenant: &str,
    dir: &tempfile::TempDir,
) {
    let pool = grab_pool(tenant, dir).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE IF NOT EXISTS posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                author_id INTEGER
            );",
        )
    })
    .await
    .unwrap();
}

pub async fn spin_up_tenant_self_register(tenant: &str) -> (Router, String, tempfile::TempDir) {
    let (router, tid, dir) = spin_up_tenant(tenant).await;
    let meta_path = dir.path().join("meta.sqlite");
    rusqlite::Connection::open(&meta_path)
        .unwrap()
        .execute(
            "UPDATE tenants SET allow_self_register = 1 WHERE id = ?1",
            rusqlite::params![tenant],
        )
        .unwrap();
    (router, tid, dir)
}

/// Register a user and log them in via the tenant auth endpoints, returning
/// the session token. Uses `oneshot` — no live server required.
pub async fn register_and_login_via_app(app: &Router, tid: &str, email: &str, pw: &str) -> String {
    use axum::body::Body;
    use axum::http::{Request, header};
    use tower::ServiceExt;

    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{tid}/auth/register"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({"email": email, "password": pw}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{tid}/auth/login"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({"email": email, "password": pw}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(resp.into_body(), 65_536)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    v["token"].as_str().unwrap().to_string()
}

/// Spin up a tenant with a service token AND an anon token, with
/// `allow_self_register = 1` enabled.
///
/// Returns `(app, tenant_id, service_token, anon_token, dir)`.
pub async fn spin_up_dual_role_self_register(
    tenant: &str,
) -> (Router, String, String, String, tempfile::TempDir) {
    let (app, svc_tok, dir) = spin_up_tenant_with_role(tenant, "service").await;
    // Enable self-registration on the tenant.
    let meta_path = dir.path().join("meta.sqlite");
    rusqlite::Connection::open(&meta_path)
        .unwrap()
        .execute(
            "UPDATE tenants SET allow_self_register = 1 WHERE id = ?1",
            rusqlite::params![tenant],
        )
        .unwrap();
    // Insert a second token with role = 'anon' for the same tenant.
    let anon_tok = generate_token();
    let anon_hash = hash_token(&anon_tok);
    rusqlite::Connection::open(&meta_path)
        .unwrap()
        .execute(
            "INSERT INTO tokens (tenant_id, token_hash, role) VALUES (?1, ?2, 'anon')",
            rusqlite::params![tenant, anon_hash],
        )
        .unwrap();
    (app, tenant.to_string(), svc_tok, anon_tok, dir)
}

pub fn seed_tenant_fs(dir: &tempfile::TempDir, tenant: &str) {
    use drust::storage::meta::open_meta;
    let data = dir.path().to_path_buf();
    let conn = open_meta(&data.join("meta.sqlite")).unwrap();
    conn.execute(
        "INSERT OR IGNORE INTO tenants (id, name) VALUES (?1, 'x')",
        rusqlite::params![tenant],
    )
    .unwrap();
    let _ = drust::storage::tenant_db::open_write(&data, tenant).unwrap();
    drust::db::migrations::run_migrations(&conn, &data).unwrap();
}

/// Build a real `TenantsState` for `tenant` (service token seeded) that
/// shares `cache`, so auth-cache hook tests can fire admin handlers directly
/// and observe the cache.
pub async fn tenants_state_with_cache(
    tenant: &str,
    cache: Arc<drust::tenant::auth_cache::AuthCache>,
) -> (drust::mgmt::tenants::TenantsState, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let conn = open_meta(&data.join("meta.sqlite")).unwrap();
    conn.execute(
        "INSERT INTO tenants (id, name) VALUES (?1, 'x')",
        rusqlite::params![tenant],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO tokens (tenant_id, token_hash, role) VALUES (?1, 'seed', 'service')",
        rusqlite::params![tenant],
    )
    .unwrap();
    let _ = drust::storage::tenant_db::open_write(&data, tenant).unwrap();
    drust::db::migrations::run_migrations(&conn, &data).unwrap();
    let tenants = Arc::new(TenantRegistry::new(data.clone(), 2));
    let bus = EventBus::new();
    let meta = Arc::new(Mutex::new(conn));
    let mut state = drust::mgmt::tenants::TenantsState::test_default(
        meta,
        data,
        tenants.clone(),
        test_mcp_http(tenants, bus.clone()),
        bus,
        drust::tenant::rooms::RoomBus::new(),
    );
    state.auth_cache = cache;
    (state, dir)
}

/// Build a real `MgmtState` sharing `cache`, with one `admins` row id=`admin_id`
/// so admin-PAT reroll's INSERT satisfies its FK. For hook-2 tests.
pub async fn mgmt_state_with_cache_and_admin(
    admin_id: i64,
    cache: Arc<drust::tenant::auth_cache::AuthCache>,
) -> (drust::mgmt::routes::MgmtState, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let conn = open_meta(&data.join("meta.sqlite")).unwrap();
    // run_migrations creates _admin_tokens, which the reroll handler
    // UPDATEs + INSERTs into.
    drust::db::migrations::run_migrations(&conn, &data).unwrap();
    conn.execute(
        "INSERT INTO admins (id, username, email, password_hash) VALUES (?1, 'a', 'a@x', 'x')",
        rusqlite::params![admin_id],
    )
    .unwrap();
    let tenants = Arc::new(TenantRegistry::new(data.clone(), 2));
    let bus = EventBus::new();
    let meta = Arc::new(Mutex::new(conn));
    let mut state = drust::mgmt::routes::MgmtState::test_default(
        meta,
        data,
        tenants.clone(),
        test_mcp_http(tenants, bus.clone()),
        bus,
        drust::tenant::rooms::RoomBus::new(),
    );
    state.auth_cache = cache;
    (state, dir)
}

/// Seed a tenant with one `_system_users` row + an active session; returns
/// `(pool, tempdir, user_id)`. For the MCP hook-7/8 auth-cache tests that
/// call the tool fns in `drust::mcp::tools::user` directly.
pub async fn seed_user_for_mcp(tenant: &str) -> (SharedTenantPool, tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    seed_tenant_fs(&dir, tenant);
    let tenants = TenantRegistry::new(dir.path().to_path_buf(), 2);
    let pool = tenants.get_or_open(tenant).unwrap();
    let uid = "u-mcp-cache".to_string();
    let uid2 = uid.clone();
    pool.with_writer(move |c| {
        c.execute(
            "INSERT INTO _system_users (id, email, password_hash, created_at, updated_at) \
             VALUES (?1, 'u@x', 'h', datetime('now'), datetime('now'))",
            rusqlite::params![uid2],
        )?;
        c.execute(
            "INSERT INTO _system_sessions \
             (token_hash, user_id, created_at, expires_at, last_seen_at) \
             VALUES ('sess-hash-mcp', ?1, datetime('now'), datetime('now', '+1 day'), \
             datetime('now'))",
            rusqlite::params![uid2],
        )
    })
    .await
    .unwrap();
    (pool, dir, uid)
}

/// Real `TenantAuthState` for `tenant` sharing `cache`. For hook-7/8/9 REST tests.
pub async fn auth_state_with_cache(
    tenant: &str,
    cache: Arc<drust::tenant::auth_cache::AuthCache>,
) -> (TenantAuthState, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let conn = open_meta(&data.join("meta.sqlite")).unwrap();
    conn.execute(
        "INSERT INTO tenants (id, name) VALUES (?1, 'x')",
        rusqlite::params![tenant],
    )
    .unwrap();
    let _ = drust::storage::tenant_db::open_write(&data, tenant).unwrap();
    drust::db::migrations::run_migrations(&conn, &data).unwrap();
    let tenants = Arc::new(TenantRegistry::new(data, 2));
    let meta = Arc::new(Mutex::new(conn));
    let mut state = TenantAuthState::test_default(meta, tenants);
    state.auth_cache = cache;
    (state, dir)
}

/// Like `auth_state_with_cache`, but seeds one `_system_users` row in the
/// tenant db and returns its id. The state carries the fresh cache that
/// `test_default` builds — reach it via `state.auth_cache.clone()`. For the
/// hook-8 (user-delete cascade) REST test.
pub async fn auth_state_with_seeded_user(
    tenant: &str,
) -> (TenantAuthState, tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let conn = open_meta(&data.join("meta.sqlite")).unwrap();
    conn.execute(
        "INSERT INTO tenants (id, name) VALUES (?1, 'x')",
        rusqlite::params![tenant],
    )
    .unwrap();
    let _ = drust::storage::tenant_db::open_write(&data, tenant).unwrap();
    drust::db::migrations::run_migrations(&conn, &data).unwrap();
    let tenants = Arc::new(TenantRegistry::new(data, 2));
    let pool = tenants.get_or_open(tenant).unwrap();
    let uid = "u-del-cache".to_string();
    let uid2 = uid.clone();
    pool.with_writer(move |c| {
        c.execute(
            "INSERT INTO _system_users (id, email, password_hash, created_at, updated_at) \
             VALUES (?1, 'u@x', 'h', datetime('now'), datetime('now'))",
            rusqlite::params![uid2],
        )
    })
    .await
    .unwrap();
    let meta = Arc::new(Mutex::new(conn));
    let state = TenantAuthState::test_default(meta, tenants);
    (state, dir, uid)
}
