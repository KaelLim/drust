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

/// Build the MCP surface a `TenantStack` mounts.
///
/// #955 — takes `bus_rooms` because the registry used to mint its OWN
/// (`McpRegistry::with_bus` defaulted it from `test_rooms_defaults`), which put
/// every MCP tool that evicts — `delete_user`, `revoke_user_sessions` and
/// `set_publish_policy` — on a bus no socket in the stack was ever on. Pass the
/// same instance `shared_bus_rooms` returned; never a fresh one.
///
/// No count here on purpose: `RoomBus::evict_tenant`'s doc owns the
/// authoritative call-site list and the recipe to re-derive it. The count this
/// comment used to repeat ("2 of the 5") was stale the day it shipped.
pub fn test_mcp_http(
    tenants: Arc<TenantRegistry>,
    bus: EventBus,
    bus_rooms: drust::tenant::rooms::RoomBus,
) -> Arc<McpHttpRegistry> {
    Arc::new(McpHttpRegistry::new(Arc::new(McpRegistry::with_bus(
        tenants, bus, bus_rooms,
    ))))
}

/// Like [`test_mcp_http`], but wired the way `main.rs` wires production: the
/// stack's own meta handle and auth cache, so an MCP tool that revokes a
/// session clears the cache REST authenticates from. Pass the bus returned by
/// [`shared_bus_rooms`] as `bus_rooms`.
pub fn test_mcp_http_live(
    tenants: Arc<TenantRegistry>,
    bus: EventBus,
    bus_rooms: drust::tenant::rooms::RoomBus,
    meta: Arc<Mutex<rusqlite::Connection>>,
    auth_cache: Arc<drust::tenant::auth_cache::AuthCache>,
) -> Arc<McpHttpRegistry> {
    Arc::new(McpHttpRegistry::new(Arc::new(
        McpRegistry::with_bus_and_storage(
            tenants.clone(),
            bus,
            WebhookDispatcher::new(tenants.clone(), None),
            None,
            String::new(),
            Arc::new([0u8; 32]),
            Some(meta),
            52_428_800,
            1_000_000,
            Arc::new(Mutex::new(
                drust::safety::audit_db::open_audit_db_memory().unwrap(),
            )),
            bus_rooms,
            drust::tenant::rooms::RoomsConfig::test_defaults().bucket(),
            drust::tenant::rooms::RoomsConfig::test_defaults(),
            auth_cache,
            drust::functions::dispatcher::FunctionDispatcher::new(
                tenants,
                tokio::sync::mpsc::channel(8).0,
                drust::functions::FnConfig::test_default(),
            ),
        ),
    )))
}

/// #955 — mint the ONE `RoomBus` a test stack must share between its
/// `TenantAuthState` and its `TenantStack`, and wire it into the state.
///
/// **Call this at every `TenantStack` construction site — in this file and in
/// every other `tests/*.rs` — and never build a stack's `bus_rooms` inline.**
/// `TenantAuthState::test_default` creates its OWN `RoomBus::default()`
/// (`src/tenant/router.rs`), so a stack that also passes a fresh
/// `RoomBus::new()` ends up with TWO buses: the #952 `revoke_user_realtime`
/// funnel (logout, logout-all, password change, OAuth account-claim, admin
/// revoke-sessions, admin delete-user) and the #955 token reroll /
/// tenant-delete paths evict the state's bus, while the WS handler and SSE
/// subscribers live on the stack's. Production wires one instance into all
/// three consumers — auth state, stack, MCP registry (`src/main.rs`) — so a
/// split-bus test evicts a bus no socket is on: the failure mode is a test that
/// goes GREEN while proving nothing, and no assertion or gate fires.
///
/// Pass the returned bus BOTH as the stack's `bus_rooms:` field and as
/// [`test_mcp_http`]'s third argument — the MCP tools `delete_user` /
/// `revoke_user_sessions` evict through the registry's copy, and until the #955
/// T2 review round 4 that copy was always a private one.
///
/// `every_test_stack_shares_one_room_bus_with_its_auth_state`
/// (`tests/rooms_ws.rs`) scans every `tests/*.rs` for stack literals that skip
/// this, and checks `test_mcp_http`'s signature; read that test's doc for the
/// two things it still does NOT cover (inline registries, admin-plane states).
pub fn shared_bus_rooms(state: &mut TenantAuthState) -> drust::tenant::rooms::RoomBus {
    let bus_rooms = drust::tenant::rooms::RoomBus::new();
    state.bus_rooms = bus_rooms.clone();
    bus_rooms
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
    let mut state = TenantAuthState::test_default(meta, tenants.clone());
    let bus_rooms = shared_bus_rooms(&mut state);
    let (functions, functions_exec, fn_cfg) = drust::functions::test_stack_parts(tenants.clone());
    let stack = TenantStack {
        auth: state,
        bus: bus.clone(),
        bus_rooms: bus_rooms.clone(),
        bucket: drust::tenant::rooms::RoomsConfig::test_defaults().bucket(),
        rooms_cfg: drust::tenant::rooms::RoomsConfig::test_defaults(),
        mcp: test_mcp_http(tenants, bus, bus_rooms.clone()),
        files: None,
        webhooks,
        functions,
        functions_exec,
        fn_cfg,
        cron: std::sync::Arc::new(drust::cron::CronState::test_default()),
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
    let mut state = TenantAuthState::test_default(meta, tenants.clone());
    let bus_rooms = shared_bus_rooms(&mut state);

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
    let pool = tenants.get_or_create(tenant).unwrap();
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
        bus_rooms: bus_rooms.clone(),
        bucket: drust::tenant::rooms::RoomsConfig::test_defaults().bucket(),
        rooms_cfg: drust::tenant::rooms::RoomsConfig::test_defaults(),
        mcp: test_mcp_http(tenants, bus, bus_rooms.clone()),
        files: Some(files_state),
        webhooks,
        functions,
        functions_exec,
        fn_cfg,
        cron: std::sync::Arc::new(drust::cron::CronState::test_default()),
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
    let mut state = TenantAuthState::test_default(meta, tenants.clone());
    let bus_rooms = shared_bus_rooms(&mut state);
    let (functions, functions_exec, fn_cfg) = drust::functions::test_stack_parts(tenants.clone());

    // Seed one function row `f1`, then refresh the binding cache.
    let pool = tenants.get_or_create(tenant).unwrap();
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
        bus_rooms: bus_rooms.clone(),
        bucket: drust::tenant::rooms::RoomsConfig::test_defaults().bucket(),
        rooms_cfg: drust::tenant::rooms::RoomsConfig::test_defaults(),
        mcp: test_mcp_http(tenants, bus, bus_rooms.clone()),
        files: None,
        webhooks,
        functions,
        functions_exec,
        fn_cfg,
        cron: std::sync::Arc::new(drust::cron::CronState::test_default()),
        cors_origins: Vec::new(),
    };
    let app = build_tenant_router(stack);
    (app, service, anon, user_token, dir)
}

pub async fn grab_pool(tenant: &str, dir: &tempfile::TempDir) -> SharedTenantPool {
    let reg = TenantRegistry::new(dir.path().to_path_buf(), 2);
    reg.get_or_create(tenant).unwrap()
}

/// Cron REST stack (tests/cron_rest.rs): like `spin_up_tenant_with_fn_seed`
/// (service + anon + real user-session bearers, one seeded `_system_functions`
/// row `f1` as a create-target), but ALSO returns the `Arc<CronState>` handle
/// the router holds, so tests can observe index reload-on-write. Returns
/// `(router, service_token, anon_token, user_token, cron_state, tmp)`.
pub async fn spin_up_cron_stack(
    tenant: &str,
) -> (
    Router,
    String,
    String,
    String,
    Arc<drust::cron::CronState>,
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
    let mut state = TenantAuthState::test_default(meta, tenants.clone());
    let bus_rooms = shared_bus_rooms(&mut state);
    let (functions, functions_exec, fn_cfg) = drust::functions::test_stack_parts(tenants.clone());

    // Seed one function row `f1` — the function-target the create tests use.
    let pool = tenants.get_or_create(tenant).unwrap();
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

    // One `_system_users` row + session so the service-only gate can be proven
    // against the user branch of `bearer_auth_layer`, not just anon.
    let user_token = pool
        .with_writer(|c| {
            c.execute(
                "INSERT INTO _system_users (id, email, password_hash, created_at, updated_at) \
                 VALUES ('u-cron-seed', 'u@x', 'h', datetime('now'), datetime('now'))",
                [],
            )?;
            drust::auth::user_session::create_session(c, "u-cron-seed", None, 30)
        })
        .await
        .unwrap();

    let cron = Arc::new(drust::cron::CronState::test_default());
    let stack = TenantStack {
        auth: state,
        bus: bus.clone(),
        bus_rooms: bus_rooms.clone(),
        bucket: drust::tenant::rooms::RoomsConfig::test_defaults().bucket(),
        rooms_cfg: drust::tenant::rooms::RoomsConfig::test_defaults(),
        mcp: test_mcp_http(tenants, bus, bus_rooms.clone()),
        files: None,
        webhooks,
        functions,
        functions_exec,
        fn_cfg,
        cron: cron.clone(),
        cors_origins: Vec::new(),
    };
    let app = build_tenant_router(stack);
    (app, service, anon, user_token, cron, dir)
}

/// Minimal stack for the cron dispatch tests (tests/cron_dispatch.rs): a
/// registry over a tempdir with one opened tenant (`get_or_create` runs
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
    let pool = tenants.get_or_create(tenant).unwrap();

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
    let pool = tenants.get_or_create(tenant).unwrap();
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
        // The one inline `RoomBus` left in this file, deliberately: this is a
        // `HostStateSeed`, not a `TenantStack`, and this helper builds no
        // `TenantAuthState` — so there is no second bus for it to diverge
        // from, and nothing for `shared_bus_rooms` to wire it into. If this
        // helper ever grows an auth state, route it through that helper.
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
    let mut state = TenantAuthState::test_default(meta, tenants.clone());
    let bus_rooms = shared_bus_rooms(&mut state);

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
        bus_rooms: bus_rooms.clone(),
        bucket: drust::tenant::rooms::RoomsConfig::test_defaults().bucket(),
        rooms_cfg: drust::tenant::rooms::RoomsConfig::test_defaults(),
        mcp: test_mcp_http(tenants, bus, bus_rooms.clone()),
        files: None,
        webhooks,
        functions,
        functions_exec,
        fn_cfg,
        cron: std::sync::Arc::new(drust::cron::CronState::test_default()),
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
    let (app, tok, cache, _tenants, dir) = spin_up_tenant_with_role_parts(tenant, role).await;
    (app, tok, cache, dir)
}

/// Like `spin_up_tenant_with_role_cached`, but ALSO returns the stack's own
/// `TenantRegistry`. `grab_pool` builds a SEPARATE registry, so its pool is a
/// different `TenantPool` instance (own writer mutex, own semaphores) from the
/// one the router serves; a test that must act on the router's pool — e.g.
/// hold its untrusted write-RPC admission slot — takes it from this registry.
pub async fn spin_up_tenant_with_role_parts(
    tenant: &str,
    role: &str,
) -> (
    Router,
    String,
    Arc<drust::tenant::auth_cache::AuthCache>,
    Arc<TenantRegistry>,
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
    let mut state = TenantAuthState::test_default(meta, tenants.clone());
    let bus_rooms = shared_bus_rooms(&mut state);
    let cache = state.auth_cache.clone();
    let (functions, functions_exec, fn_cfg) = drust::functions::test_stack_parts(tenants.clone());
    let stack = TenantStack {
        auth: state,
        bus: bus.clone(),
        bus_rooms: bus_rooms.clone(),
        bucket: drust::tenant::rooms::RoomsConfig::test_defaults().bucket(),
        rooms_cfg: drust::tenant::rooms::RoomsConfig::test_defaults(),
        mcp: test_mcp_http(tenants.clone(), bus, bus_rooms.clone()),
        files: None,
        webhooks,
        functions,
        functions_exec,
        fn_cfg,
        cron: std::sync::Arc::new(drust::cron::CronState::test_default()),
        cors_origins: Vec::new(),
    };
    let app = build_tenant_router(stack);
    (app, tok, cache, tenants, dir)
}

/// #955 — everything a rooms WS test needs to drive BOTH the socket and the
/// surfaces that revoke it, against one shared backing state.
///
/// Built by [`spin_up_tenant_rooms`]; see there for why the plain
/// `spin_up_tenant_with_role*` helpers are not usable for eviction tests.
pub struct RoomsHarness {
    pub app: Router,
    /// Bearer for the tenant token minted with the requested role.
    pub token: String,
    /// The SAME `RoomBus` instance the WS handler and the revoke paths use —
    /// call `evict_tenant` on it to simulate an eviction, or drive a real
    /// revocation surface and watch it move.
    pub bus_rooms: drust::tenant::rooms::RoomBus,
    pub meta: Arc<Mutex<rusqlite::Connection>>,
    pub auth_cache: Arc<drust::tenant::auth_cache::AuthCache>,
    pub tenants: Arc<TenantRegistry>,
    /// The SAME `McpRegistry` the stack's `/t/<id>/mcp` surface serves from —
    /// exposed so a test can prove (not assume) that the MCP tools evict the
    /// bus this harness's sockets are on. `McpHttpRegistry` keeps its inner
    /// registry private, so without this handle the only available check would
    /// be a source-text one.
    pub mcp: Arc<McpRegistry>,
    pub data_dir: std::path::PathBuf,
    /// Keeps the temp data directory alive for the test's lifetime.
    pub dir: tempfile::TempDir,
}

/// #955 rooms WS harness — like `spin_up_tenant_with_role_cached`, plus three
/// things eviction tests cannot work without:
///
/// 1. **The shared `RoomBus` handed BACK to the caller**, so a test can evict
///    the very bus its socket is on (or watch a real revocation surface move
///    it). The sharing itself is no longer special: [`shared_bus_rooms`] does
///    it at every stack site in the suite, and since the T2 review round 4 the
///    same instance also reaches the stack's MCP registry (via
///    [`test_mcp_http`]), so an eviction driven through the MCP `delete_user` /
///    `revoke_user_sessions` tools reaches this harness's socket too. It is
///    listed here only because the returned handle is what makes an eviction
///    test writable at all.
/// 2. **Caller-supplied `rooms_cfg`**, because the idle-close test needs
///    `keepalive_secs = 1` (`test_defaults` must stay 30: a 1 s tick makes
///    every other WS test's recv loop eat Ping frames).
/// 3. **`allow_self_register = 1`** and the meta / auth-cache / registry
///    handles, so a test can mint a real end-user session over REST and drive
///    admin handlers against the same state.
pub async fn spin_up_tenant_rooms(
    tenant: &str,
    role: &str,
    rooms_cfg: drust::tenant::rooms::RoomsConfig,
) -> RoomsHarness {
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
    // Lets a test mint an end-user session over the real REST auth routes and
    // then revoke it, which is the only way to exercise eviction through a
    // production surface rather than by poking the bus.
    conn.execute(
        "UPDATE tenants SET allow_self_register = 1 WHERE id = ?1",
        rusqlite::params![tenant],
    )
    .unwrap();
    let tenants = Arc::new(TenantRegistry::new(data.clone(), 2));
    let bus = EventBus::new();
    let webhooks = WebhookDispatcher::new(tenants.clone(), None);
    let meta = Arc::new(Mutex::new(conn));
    let mut state = TenantAuthState::test_default(meta.clone(), tenants.clone());
    // One bus on both sides — see `shared_bus_rooms`.
    let bus_rooms = shared_bus_rooms(&mut state);
    let auth_cache = state.auth_cache.clone();
    let (functions, functions_exec, fn_cfg) = drust::functions::test_stack_parts(tenants.clone());
    // Built here rather than through `test_mcp_http` only so the handle can be
    // returned; the wiring is identical (same bus, same EventBus).
    let mcp = Arc::new(McpRegistry::with_bus(
        tenants.clone(),
        bus.clone(),
        bus_rooms.clone(),
    ));
    let stack = TenantStack {
        auth: state,
        bus: bus.clone(),
        bus_rooms: bus_rooms.clone(),
        bucket: rooms_cfg.bucket(),
        rooms_cfg: rooms_cfg.clone(),
        mcp: Arc::new(McpHttpRegistry::new(mcp.clone())),
        files: None,
        webhooks,
        functions,
        functions_exec,
        fn_cfg,
        cron: std::sync::Arc::new(drust::cron::CronState::test_default()),
        cors_origins: Vec::new(),
    };
    let app = build_tenant_router(stack);
    RoomsHarness {
        app,
        token: tok,
        bus_rooms,
        meta,
        auth_cache,
        tenants,
        mcp,
        data_dir: data,
        dir,
    }
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
    let bus_rooms = shared_bus_rooms(&mut state);
    let (functions, functions_exec, fn_cfg) = drust::functions::test_stack_parts(tenants.clone());
    let stack = TenantStack {
        auth: state,
        bus: bus.clone(),
        bus_rooms: bus_rooms.clone(),
        bucket: drust::tenant::rooms::RoomsConfig::test_defaults().bucket(),
        rooms_cfg: drust::tenant::rooms::RoomsConfig::test_defaults(),
        mcp: test_mcp_http(tenants, bus, bus_rooms.clone()),
        files: None,
        webhooks,
        functions,
        functions_exec,
        fn_cfg,
        cron: std::sync::Arc::new(drust::cron::CronState::test_default()),
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
    let (app, tid, svc_tok, anon_tok, _tenants, dir) =
        spin_up_dual_role_self_register_with_registry(tenant).await;
    (app, tid, svc_tok, anon_tok, dir)
}

/// [`spin_up_dual_role_self_register`] plus the router's own `TenantRegistry`
/// (see [`spin_up_tenant_with_role_parts`] for why `grab_pool` is not it).
///
/// Returns `(app, tenant_id, service_token, anon_token, registry, dir)`.
pub async fn spin_up_dual_role_self_register_with_registry(
    tenant: &str,
) -> (
    Router,
    String,
    String,
    String,
    Arc<TenantRegistry>,
    tempfile::TempDir,
) {
    let (app, svc_tok, _cache, tenants, dir) =
        spin_up_tenant_with_role_parts(tenant, "service").await;
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
    (app, tenant.to_string(), svc_tok, anon_tok, tenants, dir)
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
    let (mut state, _inner, dir) = tenants_state_with_mcp(tenant).await;
    state.auth_cache = cache;
    (state, dir)
}

/// E5 — the `tenants_state_with_cache` fixture, but also handing back the
/// inner `McpRegistry` (the layer whose `DrustMcp` holds the
/// `Arc<TenantPool>`), so a lifecycle test can observe eviction at the
/// registry layer without going through the `/t/<id>/mcp` route.
pub async fn tenants_state_with_mcp(
    tenant: &str,
) -> (
    drust::mgmt::tenants::TenantsState,
    Arc<McpRegistry>,
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
    conn.execute(
        "INSERT INTO tokens (tenant_id, token_hash, role) VALUES (?1, 'seed', 'service')",
        rusqlite::params![tenant],
    )
    .unwrap();
    let _ = drust::storage::tenant_db::open_write(&data, tenant).unwrap();
    drust::db::migrations::run_migrations(&conn, &data).unwrap();
    // v1.50 — a real meta.sqlite always has ≥1 admin after bootstrap, and
    // `tenants.owner_admin_id` (FK → admins.id, enforced: open_meta sets
    // PRAGMA foreign_keys=ON) is stamped on create. Seed an owner AFTER
    // migrations (the `role` column is added by apply_migrations) so the
    // recycle-create path in this helper's tests satisfies the FK.
    conn.execute(
        "INSERT INTO admins (id, username, password_hash, role) VALUES (1, 'admin', 'x', 'owner')",
        [],
    )
    .unwrap();
    let tenants = Arc::new(TenantRegistry::new(data.clone(), 2));
    let bus = EventBus::new();
    // #955 — one bus for the whole fixture: the admin-plane state and the MCP
    // registry it mounts must evict the same instance. There is no
    // `TenantAuthState` here, so `shared_bus_rooms` has nothing to wire into.
    let bus_rooms = drust::tenant::rooms::RoomBus::new();
    let meta = Arc::new(Mutex::new(conn));
    // Same construction as `test_mcp_http`, with the inner registry's Arc kept.
    let inner = Arc::new(McpRegistry::with_bus(
        tenants.clone(),
        bus.clone(),
        bus_rooms.clone(),
    ));
    let mcp = Arc::new(McpHttpRegistry::new(inner.clone()));
    let state = drust::mgmt::tenants::TenantsState::test_default(
        meta,
        data,
        tenants.clone(),
        mcp,
        bus,
        bus_rooms,
    );
    (state, inner, dir)
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
    // #955 — see the note in `tenants_state_with_cache`: one bus per fixture.
    let bus_rooms = drust::tenant::rooms::RoomBus::new();
    let meta = Arc::new(Mutex::new(conn));
    let mut state = drust::mgmt::routes::MgmtState::test_default(
        meta,
        data,
        tenants.clone(),
        test_mcp_http(tenants, bus.clone(), bus_rooms.clone()),
        bus,
        bus_rooms,
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
    let pool = tenants.get_or_create(tenant).unwrap();
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
    let pool = tenants.get_or_create(tenant).unwrap();
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

// ─── account-level MCP endpoint (`/mcp`) ─────────────────────────────────────

/// The public URL the account MCP harness configures (`DRUST_PUBLIC_URL`).
pub const MCP_PUBLIC_URL: &str = "https://drust.test";

/// One admin with one live MCP OAuth grant. No `Debug`: carries a live token.
pub struct McpAccess {
    pub admin_id: i64,
    pub grant_id: i64,
    pub access: String,
}

/// One tenant's id and its service and anon keys. No `Debug`: carries keys.
pub struct TenantKeys {
    pub id: String,
    pub svc: String,
    pub anon: String,
}

/// What [`spin_up_account_mcp_with`] builds.
pub struct AccountMcpOpts {
    /// `(username, role)`, in order.
    pub admins: Vec<(&'static str, &'static str)>,
    /// `(id, owner)`, the owner an index into `admins`; `None` is an orphan.
    pub tenants: Vec<(&'static str, Option<usize>)>,
    /// Mount the files router on an in-memory object store.
    pub files: bool,
    /// `DRUST_MCP` resolves to enabled.
    pub mcp_enabled: bool,
}

/// The management router and the tenant router over ONE meta connection,
/// merged the way `main` merges them. `tid`/`svc`/`anon` are `tenant_keys[0]`,
/// `access`/`admin_id`/`grant_id` are `accesses[0]`. No `Debug`: carries
/// tokens.
pub struct AccountMcpHarness {
    pub app: Router,
    pub tid: String,
    pub svc: String,
    pub anon: String,
    pub access: String,
    pub admin_id: i64,
    pub grant_id: i64,
    pub accesses: Vec<McpAccess>,
    pub tenant_keys: Vec<TenantKeys>,
    pub meta: Arc<Mutex<rusqlite::Connection>>,
    pub tenants: Arc<TenantRegistry>,
    /// The one rooms bus the stack, its auth state and its MCP registry share.
    pub bus_rooms: drust::tenant::rooms::RoomBus,
    pub dir: tempfile::TempDir,
}

/// Insert an OAuth-only admin and one live grant with an access token. Call it
/// before `conn` is wrapped in its `Arc<Mutex<_>>`.
pub fn seed_mcp_access(conn: &rusqlite::Connection, role: &str, username: &str) -> McpAccess {
    conn.execute(
        "INSERT INTO admins (username, password_hash, email, role) \
         VALUES (?1, '$oauth-only$', ?1 || '@example.test', ?2)",
        rusqlite::params![username, role],
    )
    .unwrap();
    let admin_id = conn.last_insert_rowid();
    let s = drust::mgmt::mcp_oauth::store::seed_access_for_tests(conn, admin_id).unwrap();
    McpAccess {
        admin_id,
        grant_id: s.grant_id,
        access: s.access,
    }
}

/// An `initialize` request for protocol revision `version`.
pub fn mcp_init(version: &str) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": version,
            "capabilities": {},
            "clientInfo": {"name": "t", "version": "0"}
        }
    })
}

/// One request through `app`. Defaults: `Host: 127.0.0.1`,
/// `Accept: application/json, text/event-stream`,
/// `Content-Type: application/json`. A `headers` entry (lowercase name)
/// replaces the default of that name; an empty value sends no such header.
/// The body must end within 10 s.
pub async fn http_raw(
    app: &Router,
    method: &str,
    uri: &str,
    headers: &[(&str, &str)],
    body: Option<serde_json::Value>,
) -> (axum::http::StatusCode, axum::http::HeaderMap, Vec<u8>) {
    use tower::ServiceExt;
    let mut all: Vec<(&str, &str)> = vec![
        ("host", "127.0.0.1"),
        ("accept", "application/json, text/event-stream"),
        ("content-type", "application/json"),
    ];
    for (k, v) in headers {
        all.retain(|(d, _)| d != k);
        all.push((k, v));
    }
    let mut b = axum::http::Request::builder().method(method).uri(uri);
    for (k, v) in all {
        if !v.is_empty() {
            b = b.header(k, v);
        }
    }
    let body = match body {
        Some(v) => axum::body::Body::from(v.to_string()),
        None => axum::body::Body::empty(),
    };
    let resp = app.clone().oneshot(b.body(body).unwrap()).await.unwrap();
    let status = resp.status();
    let hs = resp.headers().clone();
    let bytes = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        axum::body::to_bytes(resp.into_body(), 16 * 1024 * 1024),
    )
    .await
    .expect("response body did not end")
    .unwrap();
    (status, hs, bytes.to_vec())
}

/// [`http_raw`] on `/mcp`.
pub async fn mcp_raw(
    app: &Router,
    method: &str,
    headers: &[(&str, &str)],
    body: Option<serde_json::Value>,
) -> (axum::http::StatusCode, axum::http::HeaderMap, Vec<u8>) {
    http_raw(app, method, "/mcp", headers, body).await
}

/// POST one JSON-RPC message to `/mcp`, with `Authorization: Bearer <token>`
/// when `token` is set. Returns the messages of the answer: every non-empty
/// `data:` line of an event stream, the whole body of a JSON answer, none
/// otherwise.
pub async fn mcp_rpc(
    app: &Router,
    token: Option<&str>,
    body: serde_json::Value,
) -> (
    axum::http::StatusCode,
    axum::http::HeaderMap,
    Vec<serde_json::Value>,
) {
    let auth = token.map(|t| format!("Bearer {t}"));
    let hs: Vec<(&str, &str)> = auth
        .as_deref()
        .map(|a| vec![("authorization", a)])
        .unwrap_or_default();
    let (status, headers, bytes) = mcp_raw(app, "POST", &hs, Some(body)).await;
    let ct = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let messages = if ct.starts_with("text/event-stream") {
        String::from_utf8(bytes)
            .unwrap()
            .lines()
            .filter_map(|l| l.strip_prefix("data:"))
            .map(str::trim)
            .filter(|d| !d.is_empty())
            .map(|d| serde_json::from_str(d).unwrap())
            .collect()
    } else if ct.starts_with("application/json") {
        vec![serde_json::from_slice(&bytes).unwrap()]
    } else {
        Vec::new()
    };
    (status, headers, messages)
}

/// `tools/call` of `tool` with `args` plus `"tenant": tenant`; returns the
/// first message of the answer.
pub async fn mcp_call(
    app: &Router,
    token: &str,
    tenant: &str,
    tool: &str,
    args: serde_json::Value,
) -> serde_json::Value {
    let mut args = args;
    args.as_object_mut()
        .expect("tool arguments are an object")
        .insert("tenant".into(), serde_json::json!(tenant));
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": args}
    });
    let (_, _, mut m) = mcp_rpc(app, Some(token), body).await;
    assert!(!m.is_empty(), "tools/call {tool}: no message in the answer");
    m.swap_remove(0)
}

/// The first content text of a `tools/call` result.
pub async fn mcp_tool_text(
    app: &Router,
    token: &str,
    tenant: &str,
    tool: &str,
    args: serde_json::Value,
) -> String {
    let m = mcp_call(app, token, tenant, tool, args).await;
    m["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("tools/call {tool}: no content text"))
        .to_string()
}

/// One owner (`mcp-owner`) owning `tenant`, MCP enabled, no files router.
pub async fn spin_up_account_mcp(tenant: &'static str) -> AccountMcpHarness {
    spin_up_account_mcp_with(AccountMcpOpts {
        admins: vec![("mcp-owner", "owner")],
        tenants: vec![(tenant, Some(0))],
        files: false,
        mcp_enabled: true,
    })
    .await
}

/// See [`AccountMcpOpts`]. `run_migrations` runs a second time after the
/// seeding (it is idempotent), which also backfills each admin's unlabeled UI
/// PAT.
pub async fn spin_up_account_mcp_with(opts: AccountMcpOpts) -> AccountMcpHarness {
    use drust::mgmt::mcp_oauth::config::McpOauthConfig;
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let conn = open_meta(&data.join("meta.sqlite")).unwrap();
    drust::db::migrations::run_migrations(&conn, &data).unwrap();
    let accesses: Vec<McpAccess> = opts
        .admins
        .iter()
        .map(|(username, role)| seed_mcp_access(&conn, role, username))
        .collect();
    let mut tenant_keys = Vec::new();
    for (id, owner) in &opts.tenants {
        conn.execute(
            "INSERT INTO tenants (id, name, owner_admin_id) VALUES (?1, ?1, ?2)",
            rusqlite::params![id, owner.map(|i| accesses[i].admin_id)],
        )
        .unwrap();
        let svc = generate_token();
        let anon = generate_token();
        for (tok, role) in [(&svc, "service"), (&anon, "anon")] {
            conn.execute(
                "INSERT INTO tokens (tenant_id, token_hash, role) VALUES (?1, ?2, ?3)",
                rusqlite::params![id, hash_token(tok), role],
            )
            .unwrap();
        }
        let _ = drust::storage::tenant_db::open_write(&data, id).unwrap();
        tenant_keys.push(TenantKeys {
            id: id.to_string(),
            svc,
            anon,
        });
    }
    drust::db::migrations::run_migrations(&conn, &data).unwrap();
    let meta = Arc::new(Mutex::new(conn));
    let tenants = Arc::new(TenantRegistry::new(data.clone(), 2));
    let bus = EventBus::new();
    let mut state = TenantAuthState::test_default(meta.clone(), tenants.clone());
    let bus_rooms = shared_bus_rooms(&mut state);
    let mcp = test_mcp_http_live(
        tenants.clone(),
        bus.clone(),
        bus_rooms.clone(),
        meta.clone(),
        state.auth_cache.clone(),
    );
    let webhooks = WebhookDispatcher::new(tenants.clone(), None);
    let (functions, functions_exec, fn_cfg) = drust::functions::test_stack_parts(tenants.clone());
    let (garage, files_state) = if opts.files {
        let garage = Some(Arc::new(drust::storage::garage::GarageClient::from_store(
            Arc::new(object_store::memory::InMemory::new()),
            "unused",
        )));
        let mut fs = drust::mgmt::tenant_files::TenantFilesState::test_default(
            garage.clone(),
            data.clone(),
            tenants.clone(),
        );
        fs.disk_min_free_pct = 0;
        (garage, Some(fs))
    } else {
        (None, None)
    };
    let stack = TenantStack {
        auth: state,
        bus: bus.clone(),
        bus_rooms: bus_rooms.clone(),
        bucket: drust::tenant::rooms::RoomsConfig::test_defaults().bucket(),
        rooms_cfg: drust::tenant::rooms::RoomsConfig::test_defaults(),
        mcp: mcp.clone(),
        files: files_state,
        webhooks,
        functions,
        functions_exec,
        fn_cfg,
        cron: std::sync::Arc::new(drust::cron::CronState::test_default()),
        cors_origins: Vec::new(),
    };
    let mut mgmt = drust::mgmt::routes::MgmtState::test_default(
        meta.clone(),
        data.clone(),
        tenants.clone(),
        mcp,
        bus,
        bus_rooms.clone(),
    );
    mgmt.log_dir = data.join("audit");
    std::fs::create_dir_all(&mgmt.log_dir).unwrap();
    mgmt.mcp_oauth = Arc::new(if opts.mcp_enabled {
        McpOauthConfig::for_tests(MCP_PUBLIC_URL)
    } else {
        McpOauthConfig::disabled()
    });
    mgmt.garage = garage;
    let app = Router::new()
        .merge(mgmt.with_data_dir(data.clone()))
        .merge(build_tenant_router(stack));
    let first = &accesses[0];
    let keys = &tenant_keys[0];
    AccountMcpHarness {
        app,
        tid: keys.id.clone(),
        svc: keys.svc.clone(),
        anon: keys.anon.clone(),
        access: first.access.clone(),
        admin_id: first.admin_id,
        grant_id: first.grant_id,
        accesses,
        tenant_keys,
        meta,
        tenants,
        bus_rooms,
        dir,
    }
}
