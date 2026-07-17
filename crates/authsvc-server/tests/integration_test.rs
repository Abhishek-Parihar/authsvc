use std::net::SocketAddr;
use std::sync::Once;

use authsvc_server::{app, config::Config, observability};
use reqwest::Client;
use serde_json::json;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::{
    postgres::Postgres,
    redis::Redis,
};

static TRACING: Once = Once::new();
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

async fn test_urls() -> Option<(String, String)> {
    if let (Ok(db), Ok(redis)) = (
        std::env::var("DATABASE_URL"),
        std::env::var("REDIS_URL"),
    ) {
        return Some((db, redis));
    }

    if !std::path::Path::new("/var/run/docker.sock").exists() {
        return None;
    }

    let pg = Postgres::default().start().await.ok()?;
    let redis = Redis::default().start().await.ok()?;

    let db_url = format!(
        "postgres://postgres:postgres@{}:{}/postgres",
        pg.get_host().await.ok()?,
        pg.get_host_port_ipv4(5432).await.ok()?
    );
    let redis_url = format!(
        "redis://{}:{}",
        redis.get_host().await.ok()?,
        redis.get_host_port_ipv4(6379).await.ok()?
    );

    Some((db_url, redis_url))
}

async fn spawn_server(db_url: String, redis_url: String) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local addr");

    std::env::set_var("DATABASE_URL", &db_url);
    std::env::set_var("REDIS_URL", &redis_url);
    std::env::set_var("HOST", "127.0.0.1");
    std::env::set_var("PORT", addr.port().to_string());
    std::env::set_var("ISSUER", format!("http://{addr}"));
    std::env::set_var("BOOTSTRAP_SECRET", "test-bootstrap-secret");
    std::env::set_var("RATE_LIMIT_PER_MINUTE", "10000");

    init_test_tracing();
    let metrics_handle = test_metrics_handle();
    let config = Config::from_env().expect("config");
    let state = app::build_state(config).await.expect("state");
    let router = app::build_router(state, metrics_handle);

    let handle = tokio::spawn(async move {
        axum::serve(listener, router).await.expect("serve");
    });

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    (addr, handle)
}

#[tokio::test]
async fn register_login_refresh_authz_revoke_flow() {
    let Some((db_url, redis_url)) = test_urls().await else {
        eprintln!("SKIP integration test: set DATABASE_URL+REDIS_URL or start Docker");
        return;
    };
    let (addr, _server) = spawn_server(db_url, redis_url).await;
    let base = format!("http://{addr}");
    let client = Client::new();

    // Register user (bootstrap secret required after first user exists)
    let reg = client
        .post(format!("{base}/v1/auth/register"))
        .header("Authorization", "Bearer test-bootstrap-secret")
        .json(&json!({
            "email": format!("perf-user-{}@example.com", uuid::Uuid::new_v4()),
            "password": "test-password-123",
            "display_name": "Perf User"
        }))
        .send()
        .await
        .expect("register")
        .error_for_status()
        .expect("register status")
        .json::<serde_json::Value>()
        .await
        .expect("register json");

    let email = reg["email"].as_str().expect("email");
    let user_id = reg["id"].as_str().expect("user id");

    // Create OAuth client (bootstrap secret)
    let client_resp = client
        .post(format!("{base}/v1/clients"))
        .header("Authorization", "Bearer test-bootstrap-secret")
        .json(&json!({
            "name": "integration-test",
            "redirect_uris": ["http://localhost/callback"]
        }))
        .send()
        .await
        .expect("create client")
        .error_for_status()
        .expect("client status")
        .json::<serde_json::Value>()
        .await
        .expect("client json");

    let client_id = client_resp["client_id"].as_str().expect("client_id");
    let client_secret = client_resp["client_secret"].as_str().expect("client_secret");

    // Password grant login
    let tokens = client
        .post(format!("{base}/oauth/token"))
        .json(&json!({
            "grant_type": "password",
            "client_id": client_id,
            "client_secret": client_secret,
            "username": email,
            "password": "test-password-123"
        }))
        .send()
        .await
        .expect("token")
        .error_for_status()
        .expect("token status")
        .json::<serde_json::Value>()
        .await
        .expect("token json");

    let access_token = tokens["access_token"].as_str().expect("access");
    let refresh_token = tokens["refresh_token"].as_str().expect("refresh");

    // Userinfo
    let userinfo = client
        .get(format!("{base}/oauth/userinfo"))
        .header("Authorization", format!("Bearer {access_token}"))
        .send()
        .await
        .expect("userinfo")
        .error_for_status()
        .expect("userinfo status")
        .json::<serde_json::Value>()
        .await
        .expect("userinfo json");
    assert_eq!(userinfo["sub"].as_str().unwrap(), user_id);

    // Authz check
    let authz = client
        .post(format!("{base}/v1/authz/check"))
        .json(&json!({
            "subject_id": user_id,
            "tenant_id": reg["tenant_id"].as_str().unwrap(),
            "resource": "clients",
            "action": "write"
        }))
        .send()
        .await
        .expect("authz")
        .error_for_status()
        .expect("authz status")
        .json::<serde_json::Value>()
        .await
        .expect("authz json");
    assert_eq!(authz["allowed"], true);

    // Refresh token
    let refreshed = client
        .post(format!("{base}/oauth/token"))
        .json(&json!({
            "grant_type": "refresh_token",
            "client_id": client_id,
            "client_secret": client_secret,
            "refresh_token": refresh_token
        }))
        .send()
        .await
        .expect("refresh")
        .error_for_status()
        .expect("refresh status")
        .json::<serde_json::Value>()
        .await
        .expect("refresh json");
    let new_refresh = refreshed["refresh_token"].as_str().expect("new refresh");

    // Revoke
    client
        .post(format!("{base}/oauth/revoke"))
        .json(&json!({
            "token": new_refresh,
            "client_id": client_id,
            "client_secret": client_secret
        }))
        .send()
        .await
        .expect("revoke")
        .error_for_status()
        .expect("revoke status");

    // Reuse revoked refresh token should fail
    let reuse = client
        .post(format!("{base}/oauth/token"))
        .json(&json!({
            "grant_type": "refresh_token",
            "client_id": client_id,
            "client_secret": client_secret,
            "refresh_token": new_refresh
        }))
        .send()
        .await
        .expect("reuse");
    assert_eq!(reuse.status(), reqwest::StatusCode::UNAUTHORIZED);

    // Ready probe
    let ready = client
        .get(format!("{base}/ready"))
        .send()
        .await
        .expect("ready")
        .error_for_status()
        .expect("ready status");
    assert!(ready.status().is_success());

    // Metrics endpoint
    let metrics_body = client
        .get(format!("{base}/metrics"))
        .send()
        .await
        .expect("metrics")
        .text()
        .await
        .expect("metrics body");
    assert!(metrics_body.contains("authsvc_login_total"));
}
