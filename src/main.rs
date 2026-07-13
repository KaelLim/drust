use axum::http::{HeaderName, HeaderValue};
use axum::{Router, routing::get};
use drust::config::Config;
use drust::mcp::http_registry::McpHttpRegistry;
use drust::mcp::server::McpRegistry;
use drust::mgmt::routes::MgmtState;
use drust::mgmt::tenant_files::TenantFilesState;
use drust::safety::rate_limit::RateLimiter;
use drust::safety::rate_limit_ip::IpRateLimit;
use drust::storage::meta::{bootstrap_admin, open_meta};
use drust::storage::pool::TenantRegistry;
use drust::tenant::{TenantStack, build_tenant_router, events::EventBus, router::TenantAuthState};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tower_http::set_header::SetResponseHeaderLayer;

/// DEPLOY-4: gate the `x-drust-version` response header on env.
///
/// Pure + total so the decision is unit-testable in debug without
/// touching the process environment. The header is OPT-OUT: it is
/// emitted by default (env unset) and only suppressed when the
/// operator sets `DRUST_HIDE_VERSION` (to any value, incl. empty),
/// because deploy/live-smoke verification curls `x-drust-version`.
fn version_header_enabled(env_set: bool) -> bool {
    !env_set
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,drust=debug,tower_http=info".into()),
        )
        .init();

    // i18n bundles must be initialised before any request handler can
    // construct a `Translator` (which expects BUNDLES populated).
    drust::mgmt::i18n::init_bundles();

    let cfg = Config::from_env()?;
    // DRUST_BASE_PATH: configurable external URL prefix. Unset → "/drust"
    // (base_path() default, prod unchanged); set to "" → root (Docker/drust.com);
    // set to "/x" → that prefix. Must run before any router/cookie/redirect build.
    if let Ok(v) = std::env::var("DRUST_BASE_PATH") {
        drust::base_path::set(&v);
    }
    std::fs::create_dir_all(&cfg.data_dir)?;
    std::fs::create_dir_all(&cfg.log_dir)?;
    // Point the disk guards + admin disk panel at the real data filesystem
    // (host /var/lib/drust, Docker /data) instead of the hardcoded
    // /var/lib/garage, which is absent inside the container.
    drust::storage::disk::init_disk_check_root(cfg.data_dir.clone());

    let mut meta = open_meta(&cfg.data_dir.join("meta.sqlite"))?;
    if let Some((u, p)) = &cfg.init_admin {
        let did = bootstrap_admin(&mut meta, u, p)?;
        if did {
            tracing::info!(username = %u, "bootstrapped initial admin");
        }
    }
    // Run schema migrations on every boot. Idempotent + per-tenant isolated.
    let migration_report = drust::db::migrations::run_migrations(&meta, &cfg.data_dir)
        .expect("meta-level migration failed; refusing to boot");
    tracing::info!(
        meta_done = migration_report.meta_done,
        tenants_ok = migration_report.tenants_ok.len(),
        tenants_failed = migration_report.tenants_failed.len(),
        "migration complete"
    );
    for (tid, err) in &migration_report.tenants_failed {
        tracing::warn!(tenant = %tid, error = %err, "tenant migration failed; tenant will return 503");
    }
    let meta = Arc::new(Mutex::new(meta));

    let audit_db_path = cfg.data_dir.join("meta_logs.sqlite");
    let audit_write_conn = drust::safety::audit_db::open_audit_db_write(&audit_db_path)?;
    let audit_writer = drust::safety::audit_db::AuditWriter::new(audit_write_conn);
    drust::safety::audit_db::init_globals(audit_writer);
    if std::env::var("AUDIT_DUAL_WRITE").is_ok() {
        tracing::warn!(
            "AUDIT_DUAL_WRITE env var is set but no longer used (retired in v1.25.2). Safe to remove from .env."
        );
    }
    tracing::info!(
        path = %audit_db_path.display(),
        "audit SQLite ready"
    );

    // v1.24.2 — daily retention: DELETE rows older than the configured
    // window; VACUUM on day 1 OR when last_vacuum_ts is in a previous
    // month. Anchored to wall-clock 03:00 UTC via sleep_until so the
    // cadence doesn't drift with process uptime, and a restart on day 1
    // doesn't skip the month's VACUUM. See F4 in the v1.24 hardening spec.
    // v1.47 — window comes from DRUST_AUDIT_LOG_RETENTION_DAYS (default
    // 90; 0 = keep forever, DELETE skipped, monthly VACUUM unchanged).
    let audit_retention_days = drust::safety::audit_db::audit_log_retention_days();
    if audit_retention_days == 0 {
        tracing::info!(
            "audit-log retention disabled (DRUST_AUDIT_LOG_RETENTION_DAYS=0); keeping rows forever, monthly VACUUM still runs"
        );
    } else {
        tracing::info!(days = audit_retention_days, "audit-log retention window");
    }
    let audit_meta_for_retention = std::sync::Arc::new(tokio::sync::Mutex::new(
        drust::safety::audit_db::open_audit_db_read(&audit_db_path)?,
    ));
    tokio::spawn(async move {
        loop {
            let now = chrono::Utc::now();
            let next = drust::safety::audit_db::next_0300_utc(now);
            let dur = (next - now)
                .to_std()
                .unwrap_or(std::time::Duration::from_secs(60));
            tokio::time::sleep(dur).await;

            let fired = chrono::Utc::now();
            let cutoff = (audit_retention_days > 0).then(|| {
                (fired - chrono::Duration::days(audit_retention_days as i64))
                    .format("%Y-%m-%dT%H:%M:%S%.3fZ")
                    .to_string()
            });

            let last =
                drust::safety::audit_db::read_last_vacuum_ts(&audit_meta_for_retention).await;
            let do_vacuum = drust::safety::audit_db::should_vacuum(fired, last);

            match drust::safety::audit_db::writer_for_init_use() {
                Some(w) => {
                    w.send_retention(cutoff, do_vacuum).await;
                    if do_vacuum {
                        w.send_set_meta("last_vacuum_ts".to_string(), fired.to_rfc3339())
                            .await;
                    }
                }
                None => tracing::error!("audit retention: global writer not initialised"),
            }
        }
    });

    // v1.24.2 — drop summary: every 60s, log an info-level summary of
    // audit-channel drops since the last report. Complements the sampled
    // WARN in try_send and the admin UI counter. See F3 in the spec.
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut last_reported: u64 = 0;
        loop {
            tick.tick().await;
            let total = drust::safety::audit_db::dropped_total();
            let delta = total.saturating_sub(last_reported);
            if delta > 0 {
                tracing::info!(delta, total, "audit: channel-drop summary (60s)");
                last_reported = total;
            }
        }
    });

    // Read-only connection for the admin UI; threaded into MgmtState below.
    let audit_meta_read = std::sync::Arc::new(tokio::sync::Mutex::new(
        drust::safety::audit_db::open_audit_db_read(&audit_db_path)?,
    ));

    let tenants = Arc::new(TenantRegistry::new(
        cfg.data_dir.clone(),
        cfg.tenant_read_pool_size,
    ));

    // v1.15.0 stats sampler — denormalizes per-tenant db_bytes + files_bytes
    // into meta.sqlite so /admin/tenants doesn't open per-tenant SQLite
    // on every request. Background task, default 5 min interval. v1.32.1
    // (D3): reuses the TenantRegistry reader pool + batches meta UPDATEs,
    // hence the spawn moved below the registry construction.
    let stats_interval_secs: u64 = std::env::var("DRUST_STATS_SAMPLE_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(300);
    {
        let meta_for_sampler = meta.clone();
        let registry_for_sampler = tenants.clone();
        tokio::spawn(async move {
            drust::mgmt::stats::run_stats_sampler(
                meta_for_sampler,
                registry_for_sampler,
                stats_interval_secs,
            )
            .await;
        });
    }
    let bus = EventBus::new();
    let bus_rooms = drust::tenant::rooms::RoomBus::new();
    let rooms_cfg = drust::tenant::rooms::RoomsConfig::from_env();
    let bucket = rooms_cfg.bucket();

    // v1.31 broadcast rooms sweeper — best-effort GC of empty channels.
    // Runs every DRUST_BROADCAST_SWEEPER_INTERVAL_SECS (default 300, 0 disables).
    // No correctness dependence; pure memory hygiene.
    if rooms_cfg.sweeper_interval_secs > 0 {
        let sweep_interval = rooms_cfg.sweeper_interval_secs;
        let bus_for_sweeper = bus_rooms.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(sweep_interval));
            // v1.31.1 F13 — after VM suspend, Burst (default) fires N catch-up
            // ticks back-to-back. Skip preserves "every N seconds" semantics.
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            tick.tick().await; // consume immediate tick
            loop {
                tick.tick().await;
                let removed = bus_for_sweeper.sweep_empty();
                if removed > 0 {
                    tracing::debug!(removed, "broadcast rooms sweeper");
                }
            }
        });
    }

    let webhooks = drust::tenant::WebhookDispatcher::new(tenants.clone(), None);

    // v1.36 — edge functions: dispatcher (producer) + executor (consumer).
    // The executor consuming `fn_rx` is spawned below, once the host-state
    // seed's inputs (garage, url_sign_secret, …) exist.
    let fn_cfg = drust::functions::FnConfig::from_env();
    let (fn_tx, fn_rx) = tokio::sync::mpsc::channel::<drust::functions::executor::Invocation>(
        1024, // global channel bound; per-tenant fairness is the depth counter's job
    );
    let functions = drust::functions::dispatcher::FunctionDispatcher::new(
        tenants.clone(),
        fn_tx,
        fn_cfg.clone(),
    );

    let garage = match &cfg.storage {
        Some(sc) => match drust::storage::garage::GarageClient::new(sc) {
            Ok(client) => match client.ping().await {
                Ok(()) => {
                    tracing::info!(bucket = %sc.public_bucket, "Garage reachable");
                    Some(Arc::new(client))
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Garage ping failed — storage features degraded");
                    Some(Arc::new(client))
                }
            },
            Err(e) => {
                tracing::error!(error = %e, "failed to construct Garage client — storage disabled");
                None
            }
        },
        None => {
            tracing::info!("GARAGE_S3_ENDPOINT unset; storage module disabled");
            None
        }
    };

    let max_upload_bytes = cfg
        .storage
        .as_ref()
        .map(|s| s.max_upload_bytes)
        .unwrap_or(52_428_800);

    let garage_client_key_id = cfg
        .storage
        .as_ref()
        .map(|s| s.access_key.clone())
        .unwrap_or_default();

    let disk_min_free_pct = cfg
        .storage
        .as_ref()
        .map(|s| s.disk_min_free_pct)
        .unwrap_or(20);

    // HMAC secret for drust-minted signed URLs. In-memory only: a restart
    // invalidates live signed URLs, which is acceptable since the default
    // TTL is 1 hour.
    let url_sign_secret: Arc<[u8; 32]> = {
        use rand::RngCore;
        let mut b = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut b);
        Arc::new(b)
    };

    // v1.35 — process-local auth cache, constructed ONCE and shared by Arc
    // clone into TenantAuthState (read path) and the invalidation-hook owners
    // (TenantsState / MgmtState / McpRegistry). Prod safety TTL: 10 s.
    let auth_cache = Arc::new(drust::tenant::auth_cache::AuthCache::new(
        std::time::Duration::from_secs(10),
        200_000,
    ));

    // v1.36 — edge functions executor: HostStateSeed mirrors the DrustMcp
    // constructor args below (minus auth_cache — host calls carry no token —
    // and minus functions, which is the depth-1 recursion guard).
    let fn_seed = drust::functions::runtime::HostStateSeed {
        tenants: tenants.clone(),
        bus: bus.clone(),
        webhooks: webhooks.clone(),
        garage: garage.clone(),
        public_base_url: cfg.public_base_url.clone(),
        url_sign_secret: url_sign_secret.clone(),
        meta: Some(meta.clone()),
        max_upload_bytes,
        index_large_table_rows: cfg.index_large_table_rows,
        audit_meta_read: audit_meta_read.clone(),
        bus_rooms: bus_rooms.clone(),
        bucket: bucket.clone(),
        rooms_cfg: rooms_cfg.clone(),
        disk_min_free_pct,
    };
    let fn_runner = drust::functions::runtime::WasmRunner::new(fn_cfg.clone(), fn_seed);
    let fn_executor = drust::functions::executor::Executor::new(
        fn_runner,
        tenants.clone(),
        fn_cfg.clone(),
        cfg.data_dir.clone(), // same root the tenant pools use
        functions.depth.clone(),
    );
    fn_executor.spawn_loop(fn_rx);

    // v1.48 — cron state: in-memory schedule index + env knobs, threaded into
    // the tenant stack (REST config surface), McpRegistry (MCP tools) and
    // MgmtState (admin page + soft-delete invalidation hook). The scheduler
    // below snapshots the SAME index those surfaces reload on every write.
    let cron_state = Arc::new(drust::cron::CronState {
        index: Arc::new(drust::cron::index::CronIndex::new()),
        cfg: drust::cron::CronConfig::from_env(),
    });
    if cron_state.cfg.disabled {
        tracing::info!("cron scheduler disabled (DRUST_CRON_DISABLED=1)");
    } else {
        let cron_deps = Arc::new(drust::cron::scheduler::CronDeps {
            registry: tenants.clone(),
            index: cron_state.index.clone(),
            executor: fn_executor.clone(),
            in_flight: Arc::new(dashmap::DashMap::new()),
            tenant_gate: dashmap::DashMap::new(),
            permits: Arc::new(tokio::sync::Semaphore::new(cron_state.cfg.concurrency)),
            cfg: cron_state.cfg.clone(),
        });
        // Boot scan reuses the shared meta handle (one short lock to list
        // live tenant ids, reader-lane reload per tenant — never creates
        // cron tables), then the minute tick arms on the same task.
        let boot_meta = meta.clone();
        let cron_index = cron_state.index.clone();
        let cron_registry = tenants.clone();
        tokio::spawn(async move {
            cron_index.boot_scan(boot_meta, cron_registry).await;
            drust::cron::scheduler::spawn_scheduler(cron_deps).await;
        });
        tracing::info!(
            max_jobs_per_tenant = cron_state.cfg.max_jobs_per_tenant,
            concurrency = cron_state.cfg.concurrency,
            "cron scheduler armed"
        );
    }

    let mcp_reg = Arc::new(
        McpRegistry::with_bus_and_storage(
            tenants.clone(),
            bus.clone(),
            webhooks.clone(),
            garage.clone(),
            cfg.public_base_url.clone(),
            url_sign_secret.clone(),
            Some(meta.clone()),
            max_upload_bytes,
            cfg.index_large_table_rows,
            audit_meta_read.clone(),
            bus_rooms.clone(),
            bucket.clone(),
            rooms_cfg.clone(),
            auth_cache.clone(),
            functions.clone(),
        )
        // v1.48 — the MCP cron tools reload the SAME schedule index the
        // minute-tick scheduler snapshots; a detached default would strand
        // MCP-created jobs until the next boot scan.
        .with_cron(cron_state.clone()),
    );
    let mcp_http = Arc::new(McpHttpRegistry::new(mcp_reg));

    let public_url = std::env::var("DRUST_PUBLIC_URL").unwrap_or_default();
    let oauth_registry_inner = drust::oauth::ProviderRegistry::from_env();

    // v1.29.0: DRUST_ADMIN_OAUTH_ALLOWED_EMAILS is deprecated. The allowlist
    // is now derived from admins.email (managed via /admin/team). Parse it
    // here only to emit a deprecation warning; it no longer flows into state.
    {
        let legacy_allowlist = drust::oauth::config::parse_allowlist(
            &std::env::var("DRUST_ADMIN_OAUTH_ALLOWED_EMAILS").unwrap_or_default(),
        );
        if !legacy_allowlist.is_empty() {
            tracing::warn!(
                "DRUST_ADMIN_OAUTH_ALLOWED_EMAILS is deprecated since v1.29.0; \
                 allowlist is now derived from admins.email (manage via /admin/team). \
                 Remove this env var from .env to silence this warning."
            );
        }
    }

    // Defensive: if any provider is configured but public_url is missing,
    // disable all OAuth (button hidden, /start returns oauth_misconfigured).
    let oauth_registry =
        if !oauth_registry_inner.enabled_names().is_empty() && public_url.is_empty() {
            tracing::warn!(
                "OAuth provider(s) configured but DRUST_PUBLIC_URL missing; disabling OAuth"
            );
            std::sync::Arc::new(drust::oauth::ProviderRegistry::from_env_empty())
        } else {
            std::sync::Arc::new(oauth_registry_inner)
        };

    let (lu_max, lu_chunk, lu_sessions, lu_ttl) = match &cfg.storage {
        Some(sc) => (
            sc.large_upload_max_bytes,
            sc.large_upload_chunk_max_bytes,
            sc.large_upload_max_sessions_per_tenant,
            sc.large_upload_session_ttl_secs,
        ),
        None => (2_147_483_648, 67_108_864, 5, 86_400),
    };
    let mgmt_state = MgmtState {
        meta: meta.clone(),
        audit_meta_read: audit_meta_read.clone(),
        session_ttl_days: cfg.session_ttl_days,
        garage: garage.clone(),
        public_base_url: cfg.public_base_url.clone(),
        max_upload_bytes,
        garage_client_key_id,
        disk_min_free_pct,
        log_dir: cfg.log_dir.clone(),
        url_sign_secret: url_sign_secret.clone(),
        tenants: tenants.clone(),
        mcp: mcp_http.clone(),
        bus: bus.clone(),
        bus_rooms: bus_rooms.clone(),
        index_large_table_rows: cfg.index_large_table_rows,
        public_url: public_url.clone(),
        oauth_registry,
        admin_login_rl: Arc::new(IpRateLimit::new(5, Duration::from_secs(60), 4096)),
        admin_oauth_callback_rl: Arc::new(IpRateLimit::new(5, Duration::from_secs(60), 4096)),
        cli_device_rl: Arc::new(IpRateLimit::new(5, Duration::from_secs(60), 4096)),
        cli_poll_rl: Arc::new(IpRateLimit::new(60, Duration::from_secs(60), 4096)),
        large_upload_max_bytes: lu_max,
        large_upload_chunk_max_bytes: lu_chunk,
        large_upload_max_sessions_per_tenant: lu_sessions,
        large_upload_session_ttl_secs: lu_ttl,
        auth_cache: auth_cache.clone(),
        functions: functions.clone(),
        functions_exec: fn_executor.clone(),
        fn_data_root: cfg.data_dir.clone(),
        cron: cron_state.clone(),
    };
    let mgmt_router = mgmt_state.with_data_dir(cfg.data_dir.clone());

    // v1.44 (CLI Phase 2, T1) — hourly reaper for expired device-flow codes.
    // Unconditional (device codes are independent of Garage). Reaping is
    // best-effort cleanup; `expires_at` is the source of truth, so a missed
    // tick just means rows linger until the next sweep.
    {
        let meta_for_reaper = meta.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(3600));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            tick.tick().await; // consume immediate tick
            loop {
                tick.tick().await;
                let reaped =
                    drust::mgmt::cli_device::sweep_expired_device_codes(&meta_for_reaper).await;
                if reaped > 0 {
                    tracing::info!(reaped, "cli device-code reaper swept expired codes");
                }
            }
        });
    }

    let limiter = Arc::new(RateLimiter::with_cap(
        cfg.rate_limit_per_token,
        Duration::from_secs(cfg.rate_limit_window_secs),
        cfg.rate_limit_map_cap,
    ));
    let _cleanup_handle = limiter
        .clone()
        .spawn_cleanup(Duration::from_secs(cfg.rate_limit_cleanup_interval_secs));
    let tenant_files_state = garage.as_ref().map(|g| TenantFilesState {
        garage: Some(g.clone()),
        data_root: cfg.data_dir.clone(),
        disk_min_free_pct,
        max_upload_bytes,
        public_base_url: cfg.public_base_url.clone(),
        url_sign_secret: url_sign_secret.clone(),
        tenants: tenants.clone(),
        large_upload_max_bytes: lu_max,
        large_upload_chunk_max_bytes: lu_chunk,
        large_upload_max_sessions_per_tenant: lu_sessions,
        large_upload_session_ttl_secs: lu_ttl,
        functions: functions.clone(),
    });

    // v1.33 — Mode B abandoned-upload janitor. Hourly sweep of expired
    // _system_upload_sessions across all tenants (spool file + row reclaim).
    // Gated on storage being configured — no Mode B sessions can exist
    // otherwise (create returns 503).
    if cfg.storage.is_some() {
        let registry_for_janitor = tenants.clone();
        let meta_for_janitor = meta.clone();
        let data_root = cfg.data_dir.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(3600));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            tick.tick().await; // consume immediate tick
            loop {
                tick.tick().await;
                let ids: Vec<String> = {
                    let conn = meta_for_janitor.lock().await;
                    conn.prepare("SELECT id FROM tenants WHERE deleted_at IS NULL")
                        .and_then(|mut s| {
                            s.query_map([], |r| r.get::<_, String>(0))
                                .and_then(|it| it.collect())
                        })
                        .unwrap_or_default()
                };
                let now = chrono::Utc::now().to_rfc3339();
                let mut total = 0usize;
                for tid in ids {
                    if let Ok(pool) = registry_for_janitor.get_or_open(&tid) {
                        total += drust::tenant::uploads::session::sweep_tenant(
                            &pool, &tid, &data_root, &now,
                        )
                        .await;
                    }
                }
                if total > 0 {
                    tracing::info!(reclaimed = total, "upload janitor swept abandoned sessions");
                }
            }
        });
    }

    // v1.46 — record-history retention janitor. Daily prune of per-tenant
    // _system_record_history rows older than DRUST_AUDIT_HISTORY_RETENTION_DAYS
    // (default 7; 0 disables). Anchored to 03:00 UTC like the meta_logs audit
    // retention; iterates live tenants through the shared registry so each
    // DELETE serializes on the per-tenant writer mutex.
    tokio::spawn(drust::storage::record_history::spawn_retention_task(
        meta.clone(),
        tenants.clone(),
    ));

    let tenant_stack = TenantStack {
        auth: TenantAuthState {
            meta: meta.clone(),
            registry: tenants.clone(),
            limiter,
            index_large_table_rows: cfg.index_large_table_rows,
            register_rl: Arc::new(IpRateLimit::new(3, Duration::from_secs(60), 4096)),
            login_rl: Arc::new(IpRateLimit::new(5, Duration::from_secs(60), 4096)),
            oauth_callback_rl: Arc::new(IpRateLimit::new(5, Duration::from_secs(60), 4096)),
            file_upload_rl: Arc::new(IpRateLimit::new(30, Duration::from_secs(60), 4096)),
            file_delete_rl: Arc::new(IpRateLimit::new(30, Duration::from_secs(60), 4096)),
            fn_invoke_rl: Arc::new(IpRateLimit::new(30, Duration::from_secs(60), 4096)),
            public_url,
            oauth_adapter_override: Arc::new(std::collections::HashMap::new()),
            // HMAC secret binding per-tenant OAuth `state` to `redirect_uri`.
            // In-memory only: a restart invalidates in-flight OAuth flows,
            // acceptable given the 5-minute PKCE cookie TTL. Same shape as
            // `url_sign_secret` above.
            tenant_oauth_state_secret: {
                use rand::RngCore;
                let mut b = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut b);
                Arc::new(b)
            },
            auth_cache: auth_cache.clone(),
        },
        bus: bus.clone(),
        bus_rooms: bus_rooms.clone(),
        bucket: bucket.clone(),
        rooms_cfg: rooms_cfg.clone(),
        mcp: mcp_http,
        files: tenant_files_state,
        webhooks: webhooks.clone(),
        functions: functions.clone(),
        functions_exec: fn_executor.clone(),
        fn_cfg: fn_cfg.clone(),
        cron: cron_state.clone(),
        cors_origins: cfg.cors_origins.clone(),
    };
    let tenant_router = build_tenant_router(tenant_stack);

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .merge(mgmt_router)
        .merge(tenant_router);
    // DEPLOY-4: emit `x-drust-version` by default; suppress it only when
    // the operator opts out via DRUST_HIDE_VERSION (fingerprint reduction).
    // Both arms are `Router` — axum's `Router::layer` is type-preserving.
    let app = if version_header_enabled(std::env::var("DRUST_HIDE_VERSION").is_ok()) {
        app.layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("x-drust-version"),
            HeaderValue::from_static(env!("CARGO_PKG_VERSION")),
        ))
    } else {
        app
    };

    let listener = tokio::net::TcpListener::bind(cfg.bind).await?;
    tracing::info!(addr = %cfg.bind, "drust listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    tracing::info!("drust http server stopped; draining audit queues");
    // v1.32.1 — JSONL writer retired (D1). Only the SQLite writer remains;
    // flush its in-flight buffer before exit.
    drust::safety::audit_db::drain_writer().await;
    tracing::info!("audit drain complete; exit");
    Ok(())
}

/// Graceful-shutdown trigger. Resolves on SIGINT (Ctrl-C) or SIGTERM
/// (systemd `stop`). Without this, axum::serve runs forever and
/// requests/audit lines mid-flight on shutdown are dropped.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! { _ = ctrl_c => (), _ = term => () }
}

#[cfg(test)]
mod deploy4_version_header_tests {
    use super::version_header_enabled;

    // DEPLOY-4: the `x-drust-version` header is OPT-OUT. Default (env
    // unset → env_set==false) must keep emitting it; setting
    // DRUST_HIDE_VERSION (env_set==true) suppresses it.
    #[test]
    fn version_header_present_by_default_when_env_unset() {
        // env unset => is_ok() == false => header enabled (present)
        assert!(
            version_header_enabled(false),
            "default (DRUST_HIDE_VERSION unset) MUST keep emitting x-drust-version"
        );
    }

    #[test]
    fn version_header_hidden_when_env_set() {
        // env set => is_ok() == true => header disabled (hidden)
        assert!(
            !version_header_enabled(true),
            "DRUST_HIDE_VERSION set MUST suppress the x-drust-version header"
        );
    }
}
