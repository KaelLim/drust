use axum::{Router, routing::get};
use drust::config::Config;
use drust::mcp::server::McpRegistry;
use drust::mgmt::routes::MgmtState;
use drust::storage::meta::{bootstrap_admin, open_meta};
use drust::storage::pool::TenantRegistry;
use drust::tenant::{TenantStack, build_tenant_router, events::EventBus, router::TenantAuthState};
use std::sync::Arc;
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
    // MCP registry provides per-tenant DrustMcp instances.
    // rmcp HTTP wiring (StreamableHttpService per tenant at /t/:tenant/mcp) is deferred to a
    // follow-up task — the 11 MCP tool fns are exercised via in-process integration tests today.
    let _mcp_reg = Arc::new(McpRegistry::with_bus(tenants.clone(), bus.clone()));

    let mgmt_state = MgmtState {
        meta: meta.clone(),
        session_ttl_days: cfg.session_ttl_days,
    };
    let mgmt_router = mgmt_state.with_data_dir(cfg.data_dir.clone());

    let tenant_stack = TenantStack {
        auth: TenantAuthState {
            meta: meta.clone(),
            registry: tenants.clone(),
        },
        bus: bus.clone(),
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
