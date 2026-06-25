//! T7 — the **escalation oracle** for caller-identity function invocation.
//!
//! This file proves the load-bearing security invariant of the feature: there
//! is NO construction path from an anon/user invocation to `CallerCtx::Privileged`
//! (god-mode). A bug that let an anon/user invoke reach `Privileged` would be a
//! CRITICAL cross-privilege escalation, so the assertions here are the type- and
//! behavior-level oracle that complements the compile-time "no `Default`" design.
//!
//! Two layers of proof:
//!   1. **Mapping** — `routes::invoke` maps `AuthCtx::Anon → CallerCtx::Anon`,
//!      `User → User{user_id}`, `Service → Privileged`. The `CallerCtx`
//!      accessors (`to_auth_ctx` / `role`) never yield Service/Privileged power
//!      for a non-`Privileged` variant.
//!   2. **Behavior** — a function host op (INSERT) run under an Anon/User
//!      `CallerCtx` on a no-cap collection is DENIED, while the same op under
//!      `Privileged` succeeds. This drives the EXACT branch the wasm host runs
//!      (`runtime.rs`: Privileged → god-mode `mcp::tools::write`; Anon/User →
//!      `enforce::*` with `caller.to_auth_ctx()`), via a runner injected into the
//!      real `Executor::run_one` pipeline (incl. the DiD-layer-2 invoke-flag
//!      re-assert), so the result is the production decision, not a stub.

use drust::auth::middleware::AuthCtx;
use drust::functions::caller::CallerCtx;
use drust::functions::executor::{Executor, FunctionRunner, Invocation, RunOutcome, RunStatus};
use drust::functions::runtime::HostStateSeed;
use drust::storage::schema::DmlVerb;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

// ───────────────────────── escalation: mapping layer ─────────────────────────

/// `to_auth_ctx` never grants Service power except for `Privileged`. This is the
/// single construction point of an `AuthCtx` from a `CallerCtx` (the host fns
/// call it on the non-`Privileged` branch); if it ever mapped Anon/User to
/// `Service`, every host op would silently run god-mode.
#[test]
fn to_auth_ctx_never_escalates_non_privileged() {
    assert!(matches!(
        CallerCtx::Privileged.to_auth_ctx(),
        AuthCtx::Service { .. }
    ));
    assert!(matches!(CallerCtx::Anon.to_auth_ctx(), AuthCtx::Anon));
    assert!(matches!(
        CallerCtx::User {
            user_id: "u1".into()
        }
        .to_auth_ctx(),
        AuthCtx::User { .. }
    ));
    // The crux: neither non-privileged variant maps to Service.
    assert!(!matches!(
        CallerCtx::Anon.to_auth_ctx(),
        AuthCtx::Service { .. }
    ));
    assert!(!matches!(
        CallerCtx::User {
            user_id: "u1".into()
        }
        .to_auth_ctx(),
        AuthCtx::Service { .. }
    ));
}

/// `role()` (the value `enforce::*` keys the cap-gate on) is Service ONLY for
/// `Privileged`. A non-`Privileged` role of `Service` would bypass `has_dml_cap`.
#[test]
fn role_is_service_only_for_privileged() {
    use drust::tenant::router::TokenRole;
    assert_eq!(CallerCtx::Privileged.role(), TokenRole::Service);
    assert_ne!(CallerCtx::Anon.role(), TokenRole::Service);
    assert_ne!(
        CallerCtx::User {
            user_id: "u".into()
        }
        .role(),
        TokenRole::Service
    );
}

/// The route mapping the spec pins: `routes::invoke` derives the `CallerCtx`
/// from `TenantRef.role` + `AuthCtx` with NO fallthrough to `Privileged`. We
/// reproduce that exact match here (it is not a public fn) and assert each arm.
/// A User bearer that somehow carried no resolvable `user_id` must FAIL CLOSED,
/// never escalate.
#[test]
fn route_mapping_has_no_privileged_fallthrough() {
    use drust::tenant::router::TokenRole;

    // The mapping in routes::invoke, transcribed; Option models "could this
    // arm produce a CallerCtx, and which one".
    fn map(role: TokenRole, auth: &AuthCtx) -> Option<CallerCtx> {
        match role {
            TokenRole::Service => Some(CallerCtx::Privileged),
            TokenRole::Anon => Some(CallerCtx::Anon),
            TokenRole::User => auth.user_id().map(|uid| CallerCtx::User {
                user_id: uid.to_string(),
            }),
        }
    }

    // Service → Privileged.
    assert!(matches!(
        map(TokenRole::Service, &AuthCtx::Service { admin_id: None }),
        Some(CallerCtx::Privileged)
    ));
    // Anon → Anon (never Privileged).
    assert!(matches!(
        map(TokenRole::Anon, &AuthCtx::Anon),
        Some(CallerCtx::Anon)
    ));
    // User with id → User (never Privileged).
    assert!(matches!(
        map(
            TokenRole::User,
            &AuthCtx::User {
                user_id: "u9".into(),
                token_hash: String::new()
            }
        ),
        Some(CallerCtx::User { .. })
    ));
    // User without a resolvable id → None (fail-closed denial), NOT Privileged.
    let none = map(
        TokenRole::User,
        &AuthCtx::Anon, // user_id() == None
    );
    assert!(
        none.is_none(),
        "a User role with no user_id must fail closed, never default to Privileged"
    );
}

// ─────────────────────── escalation: behavior layer ───────────────────────

/// A runner that drives the SAME host-call branch the wasm runtime uses
/// (`runtime.rs::insert_record`): `Privileged` → god-mode `mcp::tools::write`;
/// any non-`Privileged` caller → `enforce::enforced_insert` keyed on
/// `caller.to_auth_ctx()`. It records whether the single INSERT it attempts
/// succeeded, so the test can assert the per-identity decision the production
/// host would make. It NEVER reconstructs `Privileged` from the caller — it
/// only ever forwards the caller it was handed.
struct InsertProbeRunner {
    seed: HostStateSeed,
    collection: String,
    /// Set true iff the host INSERT succeeded under the received caller.
    insert_ok: Arc<AtomicBool>,
}

#[async_trait::async_trait]
impl FunctionRunner for InsertProbeRunner {
    async fn run(
        &self,
        tenant: &str,
        _p: &std::path::Path,
        _e: &str,
        caller: CallerCtx,
    ) -> RunOutcome {
        let mcp = self.seed.build_mcp(tenant).unwrap();
        let data = serde_json::json!({ "body": "x" });
        // Faithful transcription of runtime.rs's insert_record branch.
        let res = match &caller {
            CallerCtx::Privileged => {
                drust::mcp::tools::write::insert_record(&mcp, &self.collection, data)
                    .await
                    .map_err(|e| e.to_string())
            }
            other => {
                let ctx = other.to_auth_ctx();
                drust::functions::enforce::enforced_insert(&mcp, &ctx, &self.collection, data)
                    .await
                    .map_err(|e| e.to_string())
            }
        };
        match res {
            Ok(_) => {
                self.insert_ok.store(true, Ordering::SeqCst);
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

/// Build a tenant pool with a `notes` collection (default `anon_caps=[select]`,
/// default `user_caps=[select]` → NO insert cap for either), wire an executor
/// over `InsertProbeRunner`, seed a function row that has BOTH invoke flags ON
/// (so the executor's DiD-layer-2 re-assert admits anon AND user — the gate is
/// not what we're testing here; the ENFORCEMENT CORE is), and return the parts.
async fn build_probe(
    tenant: &str,
    insert_ok: Arc<AtomicBool>,
) -> (
    Arc<Executor>,
    Arc<drust::storage::pool::TenantRegistry>,
    tempfile::TempDir,
) {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let tenants = Arc::new(drust::storage::pool::TenantRegistry::new(data.clone(), 2));
    let _ = drust::storage::tenant_db::open_write(&data, tenant).unwrap();

    let pool = tenants.get_or_open(tenant).unwrap();
    // `notes` with a text body; default caps grant neither anon nor user INSERT.
    let mcp_reg = drust::mcp::server::McpRegistry::new(tenants.clone());
    let svc = mcp_reg.get_or_create(tenant).await.unwrap();
    drust::mcp::tools::schema::create_collection(
        &svc,
        "notes",
        &[drust::mcp::tools::schema::FieldSpec {
            name: "body".into(),
            sql_type: "text".into(),
            nullable: true,
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

    // Function row `probe` with BOTH invoke flags ON.
    drust::functions::schema::create_function(
        &pool,
        drust::functions::schema::CreateFunctionParams {
            name: "probe".into(),
            wasm_sha256: "00".repeat(32),
            size_bytes: 1,
            triggers_json: "[]".into(),
            description: String::new(),
        },
        10,
    )
    .await
    .unwrap();
    drust::functions::schema::set_invoke_acl(&pool, "probe", true, true)
        .await
        .unwrap();

    let bus = drust::tenant::events::EventBus::new();
    let webhooks = drust::tenant::WebhookDispatcher::new(tenants.clone(), None);
    let rooms_cfg = drust::tenant::rooms::RoomsConfig::test_defaults();
    let bucket = rooms_cfg.bucket();
    let seed = HostStateSeed {
        tenants: tenants.clone(),
        bus,
        webhooks,
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
    let runner = Arc::new(InsertProbeRunner {
        seed,
        collection: "notes".into(),
        insert_ok,
    });

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
    (executor, tenants, dir)
}

fn invoke(tenant: &str, caller: CallerCtx) -> Invocation {
    Invocation {
        tenant_id: tenant.into(),
        function_name: "probe".into(),
        trigger: "manual".into(),
        event_json: "{}".into(),
        caller,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn anon_invoke_cannot_insert_without_cap() {
    let ok = Arc::new(AtomicBool::new(false));
    let (exec, _reg, _dir) = build_probe("t-esc-anon", ok.clone()).await;
    let out = exec.run_one(invoke("t-esc-anon", CallerCtx::Anon)).await;
    assert_eq!(
        out.status,
        RunStatus::Error,
        "anon insert on no-cap collection must be denied (no god-mode leak)"
    );
    assert!(
        out.result.contains("ANON_CAP_DENIED"),
        "expected cap deny, got: {}",
        out.result
    );
    assert!(
        !ok.load(Ordering::SeqCst),
        "anon INSERT must NOT have succeeded"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn user_invoke_cannot_insert_without_cap() {
    let ok = Arc::new(AtomicBool::new(false));
    let (exec, _reg, _dir) = build_probe("t-esc-user", ok.clone()).await;
    let out = exec
        .run_one(invoke(
            "t-esc-user",
            CallerCtx::User {
                user_id: "u-1".into(),
            },
        ))
        .await;
    assert_eq!(
        out.status,
        RunStatus::Error,
        "user insert on no-user_caps collection must be denied (no god-mode leak)"
    );
    assert!(
        out.result.contains("ANON_CAP_DENIED"),
        "expected user cap deny, got: {}",
        out.result
    );
    assert!(
        !ok.load(Ordering::SeqCst),
        "user INSERT must NOT have succeeded"
    );
}

/// The control: the SAME function, same collection, same no-cap config — but
/// invoked as `Privileged` (service/event/cron) — DOES insert. This proves the
/// anon/user denials above are caused by the identity gate, not by a broken
/// host path: god-mode still works, anon/user is genuinely fenced.
#[tokio::test(flavor = "multi_thread")]
async fn privileged_invoke_inserts_god_mode() {
    let ok = Arc::new(AtomicBool::new(false));
    let (exec, _reg, _dir) = build_probe("t-esc-priv", ok.clone()).await;
    let out = exec
        .run_one(invoke("t-esc-priv", CallerCtx::Privileged))
        .await;
    assert_eq!(
        out.status,
        RunStatus::Ok,
        "privileged (god-mode) insert must succeed even with no caps granted: {}",
        out.result
    );
    assert!(
        ok.load(Ordering::SeqCst),
        "privileged INSERT must have succeeded"
    );
}

/// Granting the cap flips the anon decision to allow — proving the anon path is
/// driven by `anon_caps`, exactly as REST is, with no privileged shortcut.
#[tokio::test(flavor = "multi_thread")]
async fn anon_invoke_inserts_after_cap_grant() {
    let ok = Arc::new(AtomicBool::new(false));
    let (exec, reg, _dir) = build_probe("t-esc-grant", ok.clone()).await;
    // Grant anon insert on `notes` through the SAME registry the runner's
    // HostStateSeed holds, so the schema_cache invalidation is visible to the
    // pool the host op reads (a second registry would have its own cache).
    let svc = drust::mcp::server::McpRegistry::new(reg.clone())
        .get_or_create("t-esc-grant")
        .await
        .unwrap();
    drust::mcp::tools::schema::set_anon_caps(&svc, "notes", &[DmlVerb::Select, DmlVerb::Insert])
        .await
        .unwrap();

    let out = exec.run_one(invoke("t-esc-grant", CallerCtx::Anon)).await;
    assert_eq!(
        out.status,
        RunStatus::Ok,
        "anon insert must succeed after granting the insert cap: {}",
        out.result
    );
    assert!(ok.load(Ordering::SeqCst), "anon INSERT must have succeeded");
}
