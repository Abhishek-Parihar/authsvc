//! SAML ACS integration test using a signed IdP response fixture.

use std::net::SocketAddr;
use std::sync::{Mutex, Once};
use std::time::Duration;

use authsvc_server::{app, config::Config, observability};
use base64::Engine;
use reqwest::Client;
use serde_json::json;
use serial_test::serial;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::{postgres::Postgres, redis::Redis};

static TRACING: Once = Once::new();
static ENV_LOCK: Mutex<()> = Mutex::new(());

const SIGNED_RESPONSE: &str =
    include_str!("../../authsvc-idp/tests/fixtures/saml/response_signed_by_idp_ecdsa.xml");
const IDP_PUBLIC_KEY_PEM: &str =
    include_str!("../../authsvc-idp/tests/fixtures/keys/ec/saml-idp-ecdsa-pubkey.pem");

fn init_test_tracing() {
    TRACING.call_once(|| {
        let _ = observability::init_tracing(None);
    });
}

async fn test_urls() -> Option<(String, String)> {
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

async fn spawn_server(db_url: String, redis_url: String) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let _env_guard = ENV_LOCK.lock().expect("env lock");

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

    if let Ok(pool) = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(2))
        .connect(&db_url)
        .await
    {
        let _ = sqlx::query("UPDATE accounts SET enforce_mfa = FALSE")
            .execute(&pool)
            .await;
    }

    init_test_tracing();
    let metrics_handle = observability::init_metrics();
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

#[tokio::test]
#[serial]
async fn saml_acs_accepts_signed_response_fixture() {
    let Some((db_url, redis_url)) = test_urls().await else {
        eprintln!("SKIP saml integration test: run `make brew-up` or set DATABASE_URL+REDIS_URL");
        return;
    };

    let (addr, _server) = spawn_server(db_url, redis_url).await;
    let base = format!("http://{addr}");
    let client = Client::new();

    let client_resp = client
        .post(format!("{base}/v1/clients"))
        .header("Authorization", "Bearer test-bootstrap-secret")
        .json(&json!({
            "name": format!("saml-test-{}", uuid::Uuid::new_v4()),
            "redirect_uris": ["http://localhost:3000/callback"]
        }))
        .send()
        .await
        .expect("create client")
        .error_for_status()
        .expect("create client status")
        .json::<serde_json::Value>()
        .await
        .expect("client json");

    let client_id = client_resp["client_id"]
        .as_str()
        .expect("client_id")
        .to_string();

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .expect("pool");
    let account_id: uuid::Uuid = sqlx::query_scalar("SELECT id FROM accounts LIMIT 1")
        .fetch_one(&pool)
        .await
        .expect("account");

    let saml_config = json!({
        "type": "saml",
        "provider": "saml",
        "idp_sso_url": "https://idp.example/sso",
        "idp_cert_pem": IDP_PUBLIC_KEY_PEM,
        "require_signature": true,
        "unsolicited": true
    });
    sqlx::query("SELECT set_config('app.account_id', $1::text, false)")
        .bind(account_id.to_string())
        .execute(&pool)
        .await
        .expect("set account context");
    sqlx::query(
        r#"
        INSERT INTO account_idp_configs (id, account_id, provider, enabled, config_json)
        VALUES ($1, $2, 'saml', TRUE, $3)
        ON CONFLICT (account_id, provider)
        DO UPDATE SET enabled = EXCLUDED.enabled, config_json = EXCLUDED.config_json
        "#,
    )
    .bind(uuid::Uuid::new_v4())
    .bind(account_id)
    .bind(saml_config)
    .execute(&pool)
    .await
    .expect("insert saml config");

    let federation_state = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO federation_states (state, account_id, provider, expires_at) VALUES ($1,$2,$3,$4)",
    )
    .bind(&federation_state)
    .bind(account_id)
    .bind("saml")
    .bind(chrono::Utc::now() + chrono::Duration::minutes(10))
    .execute(&pool)
    .await
    .expect("store federation state");

    let saml_response =
        base64::engine::general_purpose::STANDARD.encode(SIGNED_RESPONSE.as_bytes());

    let tokens = client
        .post(format!("{base}/saml/acs"))
        .form(&[
            ("SAMLResponse", saml_response.as_str()),
            ("RelayState", federation_state.as_str()),
            ("client_id", client_id.as_str()),
        ])
        .send()
        .await
        .expect("saml acs")
        .error_for_status()
        .expect("saml acs status")
        .json::<serde_json::Value>()
        .await
        .expect("tokens json");

    assert!(tokens["access_token"].as_str().is_some());
    assert!(tokens["refresh_token"].as_str().is_some());
}
