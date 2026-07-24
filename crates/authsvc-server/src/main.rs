use authsvc_server::{app, config::Config, observability, stores::PostgresStore};
use sqlx::postgres::PgPoolOptions;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::from_env()?;
    observability::init_tracing(config.otel_endpoint.as_deref())?;

    if std::env::var("MIGRATE_ONLY").ok().as_deref() == Some("true") {
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&config.database_url)
            .await?;
        PostgresStore::new(pool).migrate().await?;
        tracing::info!("database migrations complete");
        return Ok(());
    }

    let metrics_handle = observability::init_metrics();

    let state = app::build_state_and_spawn_jobs(config.clone()).await?;
    let router = app::build_router(state, metrics_handle);

    let addr = format!("{}:{}", config.host, config.port);
    tracing::info!("authsvc listening on {addr}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            tracing::error!("failed to install Ctrl+C handler: {err}");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            Err(err) => {
                tracing::error!("failed to install SIGTERM handler: {err}");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
    tracing::info!("shutdown signal received, draining connections");
}
