use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "main_api=info,tower_http=info,h2=warn".into()),
        )
        .init();

    main_api::run(main_api::ServerConfig::default()).await
}
