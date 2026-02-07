use anyhow::Result;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "auth_api=info,tower_http=info".into()),
        )
        .init();

    let addr = auth_api::default_auth_addr();
    let state = auth_api::load_state_from_env();

    info!(%addr, "starting auth api");
    auth_api::run(addr, state).await
}
