use axum::{routing::get, Router};
use drust::config::Config;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,drust=debug".into()),
        )
        .init();

    let cfg = Config::from_env()?;
    tracing::info!(addr = %cfg.bind, data = %cfg.data_dir.display(), "drust booting");

    let app = Router::new().route("/health", get(|| async { "ok" }));
    let listener = tokio::net::TcpListener::bind(cfg.bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
