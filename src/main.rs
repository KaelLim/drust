use axum::{routing::get, Router};
use std::net::SocketAddr;

const BIND_ADDR: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
    47826,
);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,drust=debug".into()),
        )
        .init();

    let app = Router::new().route("/health", get(|| async { "ok" }));

    let listener = tokio::net::TcpListener::bind(BIND_ADDR).await?;
    tracing::info!(addr = %BIND_ADDR, "drust listening");
    axum::serve(listener, app).await?;
    Ok(())
}
