use authsvc_server::{app, config::Config, observability};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::from_env()?;
    observability::init_tracing(config.otel_endpoint.as_deref())?;
    let metrics_handle = observability::init_metrics();

    let state = app::build_state(config.clone()).await?;
    let router = app::build_router(state, metrics_handle);

    let addr = format!("{}:{}", config.host, config.port);
    tracing::info!("authsvc listening on {addr}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, router).await?;
    Ok(())
}
