use axum::{Router, routing::get};
use axum::http::{HeaderName, HeaderValue};
use drust::config::Config;
use drust::mcp::http_registry::McpHttpRegistry;
use drust::mcp::server::McpRegistry;
use drust::mgmt::routes::MgmtState;
use drust::mgmt::tenant_files::TenantFilesState;
use drust::safety::audit::AuditLog;
use drust::safety::rate_limit::RateLimiter;
use drust::safety::rate_limit_ip::IpRateLimit;
use drust::storage::meta::{bootstrap_admin, open_meta};
use drust::storage::pool::TenantRegistry;
use drust::tenant::{TenantStack, build_tenant_router, events::EventBus, router::TenantAuthState};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tower_http::set_header::SetResponseHeaderLayer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,drust=debug,tower_http=info".into()),
        )
        .init();

    let cfg = Config::from_env()?;
    std::fs::create_dir_all(&cfg.data_dir)?;
    std::fs::create_dir_all(&cfg.log_dir)?;

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

    // v1.15.0 stats sampler — denormalizes per-tenant db_bytes + files_bytes
    // into meta.sqlite so /admin/tenants doesn't open per-tenant SQLite
    // on every request. Background task, default 5 min interval.
    let stats_interval_secs: u64 = std::env::var("DRUST_STATS_SAMPLE_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(300);
    {
        let meta_for_sampler = meta.clone();
        let data_root_for_sampler = cfg.data_dir.clone();
        tokio::spawn(async move {
            drust::mgmt::stats::run_stats_sampler(
                meta_for_sampler,
                data_root_for_sampler,
                stats_interval_secs,
            )
            .await;
        });
    }

    let tenants = Arc::new(TenantRegistry::new(
        cfg.data_dir.clone(),
        cfg.tenant_read_pool_size,
    ));
    let bus = EventBus::new();
    let webhooks = drust::tenant::WebhookDispatcher::new(cfg.data_dir.clone());

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

    let mcp_reg = Arc::new(McpRegistry::with_bus_and_storage(
        tenants.clone(),
        bus.clone(),
        webhooks.clone(),
        garage.clone(),
        cfg.public_base_url.clone(),
        url_sign_secret.clone(),
        Some(meta.clone()),
        max_upload_bytes,
        cfg.index_large_table_rows,
    ));
    let mcp_http = Arc::new(McpHttpRegistry::new(mcp_reg));

    let public_url = std::env::var("DRUST_PUBLIC_URL").unwrap_or_default();
    let oauth_registry_inner = drust::oauth::ProviderRegistry::from_env();
    let oauth_allowlist_inner = drust::oauth::config::parse_allowlist(
        &std::env::var("DRUST_ADMIN_OAUTH_ALLOWED_EMAILS").unwrap_or_default(),
    );

    // Defensive: if any provider is configured but public_url/allowlist
    // is missing, disable all OAuth (button hidden, /start returns
    // oauth_misconfigured).
    let oauth_registry = if !oauth_registry_inner.enabled_names().is_empty()
        && (public_url.is_empty() || oauth_allowlist_inner.is_empty())
    {
        tracing::warn!(
            "OAuth provider(s) configured but DRUST_PUBLIC_URL or \
             DRUST_ADMIN_OAUTH_ALLOWED_EMAILS missing; disabling OAuth"
        );
        std::sync::Arc::new(drust::oauth::ProviderRegistry::from_env_empty())
    } else {
        std::sync::Arc::new(oauth_registry_inner)
    };
    let oauth_allowlist = std::sync::Arc::new(oauth_allowlist_inner);

    let mgmt_state = MgmtState {
        meta: meta.clone(),
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
        index_large_table_rows: cfg.index_large_table_rows,
        public_url: public_url.clone(),
        oauth_registry,
        oauth_allowlist,
        admin_login_rl: Arc::new(IpRateLimit::new(5, Duration::from_secs(60), 4096)),
        admin_oauth_callback_rl: Arc::new(IpRateLimit::new(5, Duration::from_secs(60), 4096)),
    };
    let mgmt_router = mgmt_state.with_data_dir(cfg.data_dir.clone());

    let limiter = Arc::new(RateLimiter::with_cap(
        cfg.rate_limit_per_token,
        Duration::from_secs(cfg.rate_limit_window_secs),
        cfg.rate_limit_map_cap,
    ));
    let _cleanup_handle = limiter.clone().spawn_cleanup(Duration::from_secs(
        cfg.rate_limit_cleanup_interval_secs,
    ));
    let (audit_inner, audit_handle) = AuditLog::start(cfg.log_dir.clone());
    let audit = Arc::new(audit_inner);
    let tenant_files_state = garage.as_ref().map(|g| TenantFilesState {
        garage: Some(g.clone()),
        data_root: cfg.data_dir.clone(),
        disk_min_free_pct,
        max_upload_bytes,
        public_base_url: cfg.public_base_url.clone(),
        url_sign_secret: url_sign_secret.clone(),
    });

    let tenant_stack = TenantStack {
        auth: TenantAuthState {
            meta: meta.clone(),
            registry: tenants.clone(),
            limiter,
            audit: audit.clone(),
            index_large_table_rows: cfg.index_large_table_rows,
            register_rl: Arc::new(IpRateLimit::new(3, Duration::from_secs(60), 4096)),
            login_rl: Arc::new(IpRateLimit::new(5, Duration::from_secs(60), 4096)),
            oauth_callback_rl: Arc::new(IpRateLimit::new(5, Duration::from_secs(60), 4096)),
            public_url,
            oauth_adapter_override: Arc::new(std::collections::HashMap::new()),
        },
        bus: bus.clone(),
        mcp: mcp_http,
        files: tenant_files_state,
        webhooks: webhooks.clone(),
        cors_origins: cfg.cors_origins.clone(),
    };
    let tenant_router = build_tenant_router(tenant_stack);

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .merge(mgmt_router)
        .merge(tenant_router)
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("x-drust-version"),
            HeaderValue::from_static(env!("CARGO_PKG_VERSION")),
        ));

    let listener = tokio::net::TcpListener::bind(cfg.bind).await?;
    tracing::info!(addr = %cfg.bind, "drust listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    tracing::info!("drust http server stopped; draining audit queue");
    // axum::serve has dropped its Service, so all the Arc<AuditLog>
    // clones threaded into request state are gone. Drop our local Arc
    // to release the last sender; the writer's rx.recv() will then
    // return None and drain the remaining queue before exiting.
    drop(audit);
    audit_handle.join().await;
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
        if let Ok(mut s) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! { _ = ctrl_c => (), _ = term => () }
}
