use axum::{Router, routing::get};
use drust::config::Config;
use drust::mcp::http_registry::McpHttpRegistry;
use drust::mcp::server::McpRegistry;
use drust::mgmt::routes::MgmtState;
use drust::mgmt::tenant_files::TenantFilesState;
use drust::safety::audit::AuditLog;
use drust::safety::rate_limit::RateLimiter;
use drust::storage::meta::{bootstrap_admin, open_meta};
use drust::storage::pool::TenantRegistry;
use drust::tenant::{TenantStack, build_tenant_router, events::EventBus, router::TenantAuthState};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

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
    let meta = Arc::new(Mutex::new(meta));

    let tenants = Arc::new(TenantRegistry::new(
        cfg.data_dir.clone(),
        cfg.tenant_read_pool_size,
    ));
    let bus = EventBus::new();

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
        garage.clone(),
        cfg.public_base_url.clone(),
        url_sign_secret.clone(),
        Some(meta.clone()),
        max_upload_bytes,
    ));
    let mcp_http = Arc::new(McpHttpRegistry::new(mcp_reg));

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
    let audit = Arc::new(AuditLog::new(cfg.log_dir.clone()));
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
            audit,
        },
        bus: bus.clone(),
        mcp: mcp_http,
        files: tenant_files_state,
        cors_origins: cfg.cors_origins.clone(),
    };
    let tenant_router = build_tenant_router(tenant_stack);

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .merge(mgmt_router)
        .merge(tenant_router);

    let listener = tokio::net::TcpListener::bind(cfg.bind).await?;
    tracing::info!(addr = %cfg.bind, "drust listening");
    axum::serve(listener, app).await?;
    Ok(())
}
