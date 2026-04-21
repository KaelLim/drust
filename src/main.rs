use axum::{Router, routing::get};
use drust::config::Config;
use drust::mcp::http_registry::McpHttpRegistry;
use drust::mcp::server::McpRegistry;
use drust::mgmt::routes::MgmtState;
use drust::storage::meta::{bootstrap_admin, open_meta};
use drust::storage::pool::TenantRegistry;
use drust::safety::audit::AuditLog;
use drust::safety::rate_limit::RateLimiter;
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
    let mcp_reg = Arc::new(McpRegistry::with_bus(tenants.clone(), bus.clone()));
    let mcp_http = Arc::new(McpHttpRegistry::new(mcp_reg));

    let mgmt_state = MgmtState {
        meta: meta.clone(),
        session_ttl_days: cfg.session_ttl_days,
    };
    let mgmt_router = mgmt_state.with_data_dir(cfg.data_dir.clone());

    let limiter = Arc::new(RateLimiter::new(
        cfg.rate_limit_per_token,
        Duration::from_secs(cfg.rate_limit_window_secs),
    ));
    let audit = Arc::new(AuditLog::new(cfg.log_dir.clone()));
    let tenant_stack = TenantStack {
        auth: TenantAuthState {
            meta: meta.clone(),
            registry: tenants.clone(),
            limiter,
            audit,
        },
        bus: bus.clone(),
        mcp: mcp_http,
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
