use std::net::SocketAddr;
use std::sync::{Mutex, Once};
use std::time::Duration;

use authsvc_server::{app, config::Config, observability, services::archival};
use deadpool_redis::redis::AsyncCommands;
use reqwest::Client;
use serde_json::json;
use serial_test::serial;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::{postgres::Postgres, redis::Redis};
use uuid::Uuid;

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
    spawn_server_with_env(db_url, redis_url, &[]).await
}

async fn spawn_server_with_env(
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
    std::env::set_var("ISSUER", format!("http://{addr}"));
    std::env::set_var("BOOTSTRAP_SECRET", "test-bootstrap-secret");
    std::env::set_var("RATE_LIMIT_PER_MINUTE", "10000");
    std::env::remove_var("DISABLE_PASSWORD_GRANT");
    for (k, v) in extra_env {
        std::env::set_var(k, v);
    }

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
    let metrics_handle = test_metrics_handle();
    let config = Config::from_env().expect("config");
    let state = app::build_state(config).await.expect("state");
    let router = app::build_router(state, metrics_handle);

    drop(_env_guard);

    let handle = tokio::spawn(async move {
        axum::serve(listener, router).await.expect("serve");
    });

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    (addr, handle)
}

async fn build_test_state(
    db_url: &str,
    redis_url: &str,
    extra_env: &[(&str, &str)],
) -> std::sync::Arc<authsvc_server::services::AppState> {
    let _env_guard = ENV_LOCK.lock().expect("env lock");
    std::env::set_var("DATABASE_URL", db_url);
    std::env::set_var("REDIS_URL", redis_url);
    std::env::set_var("HOST", "127.0.0.1");
    std::env::set_var("PORT", "18080");
    std::env::set_var("ISSUER", "http://127.0.0.1:18080");
    std::env::set_var("BOOTSTRAP_SECRET", "test-bootstrap-secret");
    std::env::set_var("RATE_LIMIT_PER_MINUTE", "10000");
    std::env::remove_var("DISABLE_PASSWORD_GRANT");
    for (k, v) in extra_env {
        std::env::set_var(k, v);
    }
    init_test_tracing();
    let config = Config::from_env().expect("config");
    app::build_state(config).await.expect("state")
}

#[tokio::test]
#[serial]
async fn audit_retention_purges_old_events() {
    let Some((db_url, redis_url)) = test_urls().await else {
        eprintln!("SKIP compliance test: run `make brew-up` or set DATABASE_URL+REDIS_URL");
        return;
    };

    let state = build_test_state(
        &db_url,
        &redis_url,
        &[("AUDIT_RETENTION_DAYS", "365"), ("DSAR_ARTIFACT_RETENTION_DAYS", "30")],
    )
    .await;

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&db_url)
        .await
        .expect("db pool");

    let account_id: Uuid = sqlx::query_scalar("SELECT id FROM accounts LIMIT 1")
        .fetch_one(&pool)
        .await
        .expect("account id");

    let old_id = Uuid::new_v4();
    let recent_id = Uuid::new_v4();
    let mut tx = pool.begin().await.expect("begin tx");
    sqlx::query("SELECT set_config('app.account_id', $1, true)")
        .bind(account_id.to_string())
        .execute(&mut *tx)
        .await
        .expect("set tenant context");
    sqlx::query(
        "INSERT INTO audit_events (id, account_id, actor_id, action, metadata, created_at)
         VALUES ($1, $2, 'test-actor', 'test.old', '{}', NOW() - INTERVAL '400 days')",
    )
    .bind(old_id)
    .bind(account_id)
    .execute(&mut *tx)
    .await
    .expect("insert old audit");
    sqlx::query(
        "INSERT INTO audit_events (id, account_id, actor_id, action, metadata, created_at)
         VALUES ($1, $2, 'test-actor', 'test.recent', '{}', NOW())",
    )
    .bind(recent_id)
    .bind(account_id)
    .execute(&mut *tx)
    .await
    .expect("insert recent audit");
    tx.commit().await.expect("commit tx");

    archival::run_archival(&state).await.expect("archival");

    let mut tx = pool.begin().await.expect("begin verify tx");
    sqlx::query("SELECT set_config('app.account_id', $1, true)")
        .bind(account_id.to_string())
        .execute(&mut *tx)
        .await
        .expect("set tenant context");
    let old_exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM audit_events WHERE id = $1)")
        .bind(old_id)
        .fetch_one(&mut *tx)
        .await
        .expect("old exists");
    let recent_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM audit_events WHERE id = $1)")
            .bind(recent_id)
            .fetch_one(&mut *tx)
            .await
            .expect("recent exists");
    tx.commit().await.expect("commit verify tx");

    assert!(!old_exists, "audit event older than retention should be purged");
    assert!(recent_exists, "recent audit event should be retained");
}

#[tokio::test]
#[serial]
async fn dsar_delete_erases_related_user_data() {
    let Some((db_url, redis_url)) = test_urls().await else {
        eprintln!("SKIP compliance test: run `make brew-up` or set DATABASE_URL+REDIS_URL");
        return;
    };

    let (addr, _server) = spawn_server(db_url.clone(), redis_url.clone()).await;
    let base = format!("http://{addr}");
    let client = Client::new();

    let reg = client
        .post(format!("{base}/v1/auth/register"))
        .header("Authorization", "Bearer test-bootstrap-secret")
        .json(&json!({
            "email": format!("compliance-erasure-{}@example.com", Uuid::new_v4()),
            "password": "test-password-123",
            "display_name": "Compliance User"
        }))
        .send()
        .await
        .expect("register")
        .error_for_status()
        .expect("register status")
        .json::<serde_json::Value>()
        .await
        .expect("register json");

    let user_id = Uuid::parse_str(reg["id"].as_str().expect("user id")).expect("uuid");
    let email = reg["email"].as_str().expect("email");

    let client_resp = client
        .post(format!("{base}/v1/clients"))
        .header("Authorization", "Bearer test-bootstrap-secret")
        .json(&json!({
            "name": "compliance-erasure",
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
    let client_id = client_resp["client_id"].as_str().unwrap();
    let client_secret = client_resp["client_secret"].as_str().unwrap();

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
        .expect("login")
        .error_for_status()
        .expect("login status")
        .json::<serde_json::Value>()
        .await
        .expect("login json");
    let access_token = tokens["access_token"].as_str().unwrap();

    client
        .get(format!("{base}/v1/users/{user_id}/export"))
        .header("Authorization", format!("Bearer {access_token}"))
        .send()
        .await
        .expect("export")
        .error_for_status()
        .expect("export status");

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&db_url)
        .await
        .expect("db pool");

    sqlx::query(
        "INSERT INTO user_identities (id, user_id, provider, provider_subject, email)
         VALUES ($1, $2, 'google', $3, 'linked@example.com')",
    )
    .bind(Uuid::new_v4())
    .bind(user_id)
    .bind(format!("google-subject-{user_id}"))
    .execute(&pool)
    .await
    .expect("insert identity");

    sqlx::query(
        "INSERT INTO user_mfa_secrets (user_id, encrypted_secret, recovery_codes_hash)
         VALUES ($1, 'encrypted-test', '{}')",
    )
    .bind(user_id)
    .execute(&pool)
    .await
    .expect("insert mfa");

    sqlx::query(
        "INSERT INTO webauthn_credentials (id, user_id, credential_id, public_key, name)
         VALUES ($1, $2, $3, $4, 'test-key')",
    )
    .bind(Uuid::new_v4())
    .bind(user_id)
    .bind(vec![1u8, 2, 3])
    .bind(vec![4u8, 5, 6])
    .execute(&pool)
    .await
    .expect("insert webauthn");

    let session_id = Uuid::new_v4();
    let mut redis_conn = deadpool_redis::Config::from_url(redis_url.clone())
        .create_pool(Some(deadpool_redis::Runtime::Tokio1))
        .expect("redis pool")
        .get()
        .await
        .expect("redis conn");
    let session_key = format!("session:{session_id}");
    redis_conn
        .set_ex::<_, _, ()>(&session_key, user_id.to_string(), 3600)
        .await
        .expect("set session");

    client
        .delete(format!("{base}/v1/users/{user_id}/privacy"))
        .header("Authorization", format!("Bearer {access_token}"))
        .send()
        .await
        .expect("delete")
        .error_for_status()
        .expect("delete status");

    let identity_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM user_identities WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&pool)
            .await
            .expect("identity count");
    let mfa_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM user_mfa_secrets WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&pool)
            .await
            .expect("mfa count");
    let webauthn_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&pool)
            .await
            .expect("webauthn count");
    let member_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM account_members WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&pool)
            .await
            .expect("member count");
    let export_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM data_export_requests WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&pool)
            .await
            .expect("export count");
    let email: String = sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .expect("user email");
    let session_val: Option<String> = redis_conn
        .get(&session_key)
        .await
        .expect("get session");

    assert_eq!(identity_count, 0);
    assert_eq!(mfa_count, 0);
    assert_eq!(webauthn_count, 0);
    assert_eq!(member_count, 0);
    assert_eq!(export_count, 0);
    assert!(email.starts_with("deleted-"));
    assert!(session_val.is_none(), "redis session should be revoked");
}
