use std::net::SocketAddr;
use std::sync::{Mutex, Once};
use std::time::Duration;

use authsvc_server::{app, config::Config, observability};
use reqwest::Client;
use serde_json::json;
use serial_test::serial;

static TRACING: Once = Once::new();
static ENV_LOCK: Mutex<()> = Mutex::new(());
static METRICS: std::sync::OnceLock<metrics_exporter_prometheus::PrometheusHandle> =
    std::sync::OnceLock::new();

fn init_test_tracing() {
    TRACING.call_once(|| {
        let _ = observability::init_tracing(None);
    });
}

fn test_metrics_handle() -> metrics_exporter_prometheus::PrometheusHandle {
    METRICS
        .get_or_init(observability::init_metrics)
        .clone()
}

pub async fn test_urls() -> Option<(String, String)> {
    if let (Ok(db), Ok(redis)) = (
        std::env::var("DATABASE_URL"),
        std::env::var("REDIS_URL"),
    ) {
        return Some((db, redis));
    }

    const BREW_DB: &str = "postgres://authsvc:authsvc@127.0.0.1:5432/authsvc";
    const BREW_REDIS: &str = "redis://127.0.0.1:6379";
    if homebrew_stores_ready(BREW_DB, BREW_REDIS).await {
        return Some((BREW_DB.into(), BREW_REDIS.into()));
    }
    None
}

async fn homebrew_stores_ready(db_url: &str, redis_url: &str) -> bool {
    let pg_ok = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(2))
        .connect(db_url)
        .await
        .is_ok();
    if !pg_ok {
        return false;
    }
    let redis_host = redis_url
        .trim_start_matches("redis://")
        .split('/')
        .next()
        .unwrap_or("127.0.0.1:6379");
    let (host, port) = redis_host.split_once(':').unwrap_or(("127.0.0.1", "6379"));
    let port: u16 = port.parse().unwrap_or(6379);
    tokio::net::TcpStream::connect((host, port)).await.is_ok()
}

pub async fn spawn_server(db_url: String, redis_url: String) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    spawn_server_with_env(db_url, redis_url, &[]).await
}

pub async fn spawn_server_with_env(
    db_url: String,
    redis_url: String,
    extra_env: &[(&str, &str)],
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let _env_guard = ENV_LOCK.lock().expect("env lock");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local addr");

    std::env::set_var("DATABASE_URL", &db_url);
    std::env::set_var("REDIS_URL", &redis_url);
    std::env::set_var("HOST", "127.0.0.1");
    std::env::set_var("PORT", addr.port().to_string());
    std::env::set_var("ISSUER", format!("http://localhost:{}", addr.port()));
    std::env::set_var("WEBAUTHN_RP_ID", "localhost");
    std::env::set_var("BOOTSTRAP_SECRET", "test-bootstrap-secret");
    std::env::set_var("RATE_LIMIT_PER_MINUTE", "10000");
    std::env::remove_var("DISABLE_PASSWORD_GRANT");
    for (k, v) in extra_env {
        std::env::set_var(k, v);
    }

    init_test_tracing();
    let metrics_handle = test_metrics_handle();
    let config = Config::from_env().expect("config");
    let state = app::build_state(config).await.expect("state");
    let router = app::build_router(state, metrics_handle);
    drop(_env_guard);

    let handle = tokio::spawn(async move {
        axum::serve(listener, router).await.expect("serve");
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    (addr, handle)
}

pub fn test_base(addr: SocketAddr) -> String {
    format!("http://localhost:{}", addr.port())
}

pub async fn login_password(
    client: &Client,
    base: &str,
    email: &str,
    password: &str,
    client_id: &str,
    client_secret: &str,
) -> String {
    let tokens = client
        .post(format!("{base}/oauth/token"))
        .json(&json!({
            "grant_type": "password",
            "client_id": client_id,
            "client_secret": client_secret,
            "username": email,
            "password": password
        }))
        .send()
        .await
        .expect("login")
        .error_for_status()
        .expect("login status")
        .json::<serde_json::Value>()
        .await
        .expect("login json");
    tokens["access_token"]
        .as_str()
        .expect("access token")
        .to_string()
}
