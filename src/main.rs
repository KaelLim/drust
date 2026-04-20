use axum::{routing::get, Router};
use drust::auth::middleware::AdminSessionState;
use drust::config::Config;
use drust::mgmt::routes::{build_mgmt_router, MgmtState};
use drust::storage::meta::{bootstrap_admin, open_meta};
use std::sync::Arc;
use tokio::sync::Mutex;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,drust=debug".into()),
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
    let mgmt_state = MgmtState { meta: meta.clone(), session_ttl_days: cfg.session_ttl_days };
    let session_state = AdminSessionState { meta: meta.clone() };

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .merge(build_mgmt_router(mgmt_state));

    // (protected admin routes added in later tasks wrap with admin_session_layer)
    let _ = session_state;

    let listener = tokio::net::TcpListener::bind(cfg.bind).await?;
    tracing::info!(addr = %cfg.bind, "drust listening");
    axum::serve(listener, app).await?;
    Ok(())
}
