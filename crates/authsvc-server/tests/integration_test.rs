use std::net::SocketAddr;
use std::sync::{Mutex, Once};
use std::time::Duration;

use authsvc_server::{app, config::Config, observability};
use reqwest::Client;
use serde_json::json;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::{
    postgres::Postgres,
    redis::Redis,
};
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

#[tokio::test]
#[serial]
async fn register_login_refresh_authz_revoke_flow() {
    let Some((db_url, redis_url)) = test_urls().await else {
        eprintln!("SKIP integration test: run `make brew-up` or set DATABASE_URL+REDIS_URL");
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
            "account_id": reg["account_id"].as_str().unwrap(),
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

#[tokio::test]
#[serial]
async fn jwt_key_rotation_preserves_grace_validation() {
    let Some((db_url, redis_url)) = test_urls().await else {
        eprintln!("SKIP integration test: run `make brew-up` or set DATABASE_URL+REDIS_URL");
        return;
    };
    let (addr, _server) = spawn_server(db_url, redis_url).await;
    let base = format!("http://{addr}");
    let client = Client::new();

    let reg = client
        .post(format!("{base}/v1/auth/register"))
        .header("Authorization", "Bearer test-bootstrap-secret")
        .json(&json!({
            "email": format!("rotate-user-{}@example.com", uuid::Uuid::new_v4()),
            "password": "test-password-123"
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

    let client_resp = client
        .post(format!("{base}/v1/clients"))
        .header("Authorization", "Bearer test-bootstrap-secret")
        .json(&json!({
            "name": "rotate-test",
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

    let pre_rotation_token = tokens["access_token"].as_str().expect("access");

    let jwks_before = client
        .get(format!("{base}/.well-known/jwks.json"))
        .send()
        .await
        .expect("jwks")
        .json::<serde_json::Value>()
        .await
        .expect("jwks json");
    let keys_before = jwks_before["keys"].as_array().expect("keys").len();

    client
        .post(format!("{base}/v1/keys/rotate"))
        .header("Authorization", "Bearer test-bootstrap-secret")
        .send()
        .await
        .expect("rotate")
        .error_for_status()
        .expect("rotate status");

    let jwks_after = client
        .get(format!("{base}/.well-known/jwks.json"))
        .send()
        .await
        .expect("jwks after")
        .json::<serde_json::Value>()
        .await
        .expect("jwks after json");
    let keys_after = jwks_after["keys"].as_array().expect("keys").len();
    assert!(keys_after >= keys_before);

    let userinfo = client
        .get(format!("{base}/oauth/userinfo"))
        .header("Authorization", format!("Bearer {pre_rotation_token}"))
        .send()
        .await
        .expect("userinfo after rotate")
        .error_for_status()
        .expect("userinfo after rotate status")
        .json::<serde_json::Value>()
        .await
        .expect("userinfo json");
    assert_eq!(userinfo["email"].as_str().unwrap(), email);
}

#[tokio::test]
#[serial]
async fn api_key_grant_and_admin_access() {
    let Some((db_url, redis_url)) = test_urls().await else {
        eprintln!("SKIP integration test: run `make brew-up` or set DATABASE_URL+REDIS_URL");
        return;
    };
    let (addr, _server) = spawn_server(db_url, redis_url).await;
    let base = format!("http://{addr}");
    let client = Client::new();

    let reg = client
        .post(format!("{base}/v1/auth/register"))
        .header("Authorization", "Bearer test-bootstrap-secret")
        .json(&json!({
            "email": format!("apikey-user-{}@example.com", uuid::Uuid::new_v4()),
            "password": "test-password-123"
        }))
        .send()
        .await
        .expect("register")
        .error_for_status()
        .expect("register status")
        .json::<serde_json::Value>()
        .await
        .expect("register json");

    let account_id = reg["account_id"].as_str().expect("account_id");

    let key_resp = client
        .post(format!("{base}/v1/api-keys"))
        .header("Authorization", "Bearer test-bootstrap-secret")
        .json(&json!({
            "account_id": account_id,
            "name": "svc-key",
            "scopes": ["admin", "read"]
        }))
        .send()
        .await
        .expect("create api key")
        .error_for_status()
        .expect("api key status")
        .json::<serde_json::Value>()
        .await
        .expect("api key json");

    let api_key = key_resp["api_key"].as_str().expect("api_key");

    let tokens = client
        .post(format!("{base}/oauth/token"))
        .json(&json!({
            "grant_type": "api_key",
            "api_key": api_key
        }))
        .send()
        .await
        .expect("api key token")
        .error_for_status()
        .expect("api key token status")
        .json::<serde_json::Value>()
        .await
        .expect("api key token json");

    assert!(tokens["access_token"].as_str().is_some());
    assert!(tokens["refresh_token"].is_null());

    let clients = client
        .get(format!("{base}/v1/clients"))
        .header("Authorization", format!("ApiKey {api_key}"))
        .send()
        .await
        .expect("list clients")
        .error_for_status()
        .expect("list clients status");
    assert!(clients.status().is_success());
}

#[tokio::test]
#[serial]
async fn federation_start_returns_authorization_url() {
    let Some((db_url, redis_url)) = test_urls().await else {
        eprintln!("SKIP integration test: run `make brew-up` or set DATABASE_URL+REDIS_URL");
        return;
    };

    std::env::set_var("GOOGLE_CLIENT_ID", "test-google-client");
    std::env::set_var("GOOGLE_CLIENT_SECRET", "test-google-secret");

    let (addr, _server) = spawn_server(db_url, redis_url).await;
    let base = format!("http://{addr}");
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("client");

    let resp = client
        .get(format!("{base}/oauth/federate/google"))
        .send()
        .await
        .expect("federate start");

    assert!(resp.status().is_redirection());

    let url = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .expect("redirect location");
    assert!(url.contains("google"));
}

#[tokio::test]
#[serial]
async fn dsar_export_and_delete_user() {
    let Some((db_url, redis_url)) = test_urls().await else {
        eprintln!("SKIP integration test: run `make brew-up` or set DATABASE_URL+REDIS_URL");
        return;
    };
    let (addr, _server) = spawn_server(db_url.clone(), redis_url).await;
    let base = format!("http://{addr}");
    let client = Client::new();

    let reg = client
        .post(format!("{base}/v1/auth/register"))
        .header("Authorization", "Bearer test-bootstrap-secret")
        .json(&json!({
            "email": format!("dsar-user-{}@example.com", uuid::Uuid::new_v4()),
            "password": "test-password-123",
            "display_name": "DSAR User"
        }))
        .send()
        .await
        .expect("register")
        .error_for_status()
        .expect("register status")
        .json::<serde_json::Value>()
        .await
        .expect("register json");

    let user_id = reg["id"].as_str().expect("user id");
    let email = reg["email"].as_str().expect("email");

    let client_resp = client
        .post(format!("{base}/v1/clients"))
        .header("Authorization", "Bearer test-bootstrap-secret")
        .json(&json!({
            "name": "dsar-test",
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
    let access_token = tokens["access_token"].as_str().expect("access token");

    let export = client
        .get(format!("{base}/v1/users/{user_id}/export"))
        .header("Authorization", format!("Bearer {access_token}"))
        .send()
        .await
        .expect("export")
        .error_for_status()
        .expect("export status")
        .json::<serde_json::Value>()
        .await
        .expect("export json");

    assert_eq!(export["user"]["email"].as_str().unwrap(), email);
    assert!(export["memberships"].is_array());

    let delete = client
        .delete(format!("{base}/v1/users/{user_id}/privacy"))
        .header("Authorization", format!("Bearer {access_token}"))
        .send()
        .await
        .expect("delete")
        .error_for_status()
        .expect("delete status")
        .json::<serde_json::Value>()
        .await
        .expect("delete json");
    assert_eq!(delete["deleted"], true);

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&db_url)
        .await
        .expect("db pool");
    let row: (String,) = sqlx::query_as("SELECT email FROM users WHERE id = $1")
        .bind(uuid::Uuid::parse_str(user_id).unwrap())
        .fetch_one(&pool)
        .await
        .expect("user row");
    assert!(row.0.starts_with("deleted-"));
}

#[tokio::test]
#[serial]
async fn enforce_mfa_blocks_login_without_enrollment() {
    let Some((db_url, redis_url)) = test_urls().await else {
        eprintln!("SKIP integration test: run `make brew-up` or set DATABASE_URL+REDIS_URL");
        return;
    };
    let (addr, _server) = spawn_server(db_url.clone(), redis_url).await;
    let base = format!("http://{addr}");
    let client = Client::new();

    let reg = client
        .post(format!("{base}/v1/auth/register"))
        .header("Authorization", "Bearer test-bootstrap-secret")
        .json(&json!({
            "email": format!("mfa-policy-{}@example.com", uuid::Uuid::new_v4()),
            "password": "test-password-123"
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
    let account_id = reg["account_id"].as_str().expect("account_id");

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&db_url)
        .await
        .expect("db pool");
    sqlx::query("UPDATE accounts SET enforce_mfa = TRUE WHERE id = $1")
        .bind(uuid::Uuid::parse_str(account_id).unwrap())
        .execute(&pool)
        .await
        .expect("enforce mfa");

    let client_resp = client
        .post(format!("{base}/v1/clients"))
        .header("Authorization", "Bearer test-bootstrap-secret")
        .json(&json!({
            "name": "mfa-policy-test",
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

    let login = client
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
        .expect("login");
    assert_eq!(login.status(), reqwest::StatusCode::FORBIDDEN);

    sqlx::query("UPDATE accounts SET enforce_mfa = FALSE WHERE id = $1")
        .bind(uuid::Uuid::parse_str(account_id).unwrap())
        .execute(&pool)
        .await
        .expect("reset enforce_mfa");
}

#[tokio::test]
#[serial]
async fn password_grant_disabled_when_configured() {
    let Some((db_url, redis_url)) = test_urls().await else {
        eprintln!("SKIP integration test: run `make brew-up` or set DATABASE_URL+REDIS_URL");
        return;
    };
    let (addr, _server) =
        spawn_server_with_env(db_url, redis_url, &[("DISABLE_PASSWORD_GRANT", "true")]).await;
    let base = format!("http://{addr}");
    let client = Client::new();

    let client_resp = client
        .post(format!("{base}/v1/clients"))
        .header("Authorization", "Bearer test-bootstrap-secret")
        .json(&json!({
            "name": "pwd-grant-disabled",
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

    let token = client
        .post(format!("{base}/oauth/token"))
        .json(&json!({
            "grant_type": "password",
            "client_id": client_id,
            "client_secret": client_secret,
            "username": "nobody@example.com",
            "password": "wrong"
        }))
        .send()
        .await
        .expect("password grant");
    assert_eq!(token.status(), reqwest::StatusCode::BAD_REQUEST);
    let body = token.json::<serde_json::Value>().await.expect("body");
    assert!(body["error_description"]
        .as_str()
        .unwrap()
        .contains("password grant disabled"));
}

#[tokio::test]
#[serial]
async fn enterprise_security_migrations_applied() {
    let Some((db_url, _redis_url)) = test_urls().await else {
        eprintln!("SKIP integration test: run `make brew-up` or set DATABASE_URL+REDIS_URL");
        return;
    };

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&db_url)
        .await
        .expect("db pool");

    // Run migrations (idempotent if server already ran them).
    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .expect("migrate");

    let role_exists: (bool,) =
        sqlx::query_as("SELECT EXISTS(SELECT FROM pg_roles WHERE rolname = 'authsvc_app')")
            .fetch_one(&pool)
            .await
            .expect("role check");
    if !role_exists.0 {
        eprintln!(
            "NOTE: authsvc_app role not present (expected when migrator lacks CREATEROLE)"
        );
    }

    let rls_enabled: (bool,) = sqlx::query_as(
        "SELECT relrowsecurity FROM pg_class WHERE relname = 'account_members'",
    )
    .fetch_one(&pool)
    .await
    .expect("rls check");
    assert!(rls_enabled.0, "RLS should be enabled on account_members");

    let policy_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM pg_policies WHERE tablename IN ('account_members', 'audit_events')",
    )
    .fetch_one(&pool)
    .await
    .expect("policy count");
    assert!(
        policy_count.0 >= 2,
        "tenant isolation policies should exist"
    );

    let encrypted_col: (bool,) = sqlx::query_as(
        "SELECT EXISTS(
            SELECT FROM information_schema.columns
            WHERE table_name = 'signing_keys' AND column_name = 'encrypted_private_pem'
        )",
    )
    .fetch_one(&pool)
    .await
    .expect("signing key column");
    assert!(
        encrypted_col.0,
        "signing_keys.encrypted_private_pem column should exist"
    );
}

#[tokio::test]
#[serial]
async fn rls_isolates_account_members_between_tenants() {
    let Some((db_url, _redis_url)) = test_urls().await else {
        eprintln!("SKIP integration test: run `make brew-up` or set DATABASE_URL+REDIS_URL");
        return;
    };

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&db_url)
        .await
        .expect("db pool");
    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .expect("migrate");

    let account_a = uuid::Uuid::new_v4();
    let account_b = uuid::Uuid::new_v4();
    let user_id = uuid::Uuid::new_v4();
    let slug_a = format!("rls-a-{}", &account_a.to_string()[..8]);
    let slug_b = format!("rls-b-{}", &account_b.to_string()[..8]);

    sqlx::query("INSERT INTO accounts (id, slug, name) VALUES ($1, $2, 'RLS A'), ($3, $4, 'RLS B')")
        .bind(account_a)
        .bind(&slug_a)
        .bind(account_b)
        .bind(&slug_b)
        .execute(&pool)
        .await
        .expect("insert accounts");

    sqlx::query(
        "INSERT INTO users (id, email, password_hash, email_verified, mfa_enabled, status)
         VALUES ($1, $2, 'hash', TRUE, FALSE, 'active')",
    )
    .bind(user_id)
    .bind(format!("rls-user-{user_id}@example.com"))
    .execute(&pool)
    .await
    .expect("insert user");

    let mut tx = pool.begin().await.expect("begin tx");
    sqlx::query("SELECT set_config('app.account_id', $1, true)")
        .bind(account_b.to_string())
        .execute(&mut *tx)
        .await
        .expect("set tenant context for insert");
    sqlx::query(
        "INSERT INTO account_members (account_id, user_id, status) VALUES ($1, $2, 'active')",
    )
    .bind(account_b)
    .bind(user_id)
    .execute(&mut *tx)
    .await
    .expect("insert membership");
    tx.commit().await.expect("commit insert");

    let hidden = count_members_for_tenant(&pool, account_a, user_id).await;
    assert_eq!(hidden, 0, "tenant A must not see tenant B memberships");

    let visible = count_members_for_tenant(&pool, account_b, user_id).await;
    assert_eq!(visible, 1, "tenant B should see its own membership");

    sqlx::query("DELETE FROM account_members WHERE user_id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM accounts WHERE id = ANY($1)")
        .bind(vec![account_a, account_b])
        .execute(&pool)
        .await
        .ok();
}

#[tokio::test]
#[serial]
async fn scim_user_crud_flow() {
    let Some((db_url, redis_url)) = test_urls().await else {
        eprintln!("SKIP integration test: run `make brew-up` or set DATABASE_URL+REDIS_URL");
        return;
    };
    let (addr, _server) = spawn_server(db_url, redis_url).await;
    let base = format!("http://{addr}");
    let client = Client::new();

    let reg = client
        .post(format!("{base}/v1/auth/register"))
        .header("Authorization", "Bearer test-bootstrap-secret")
        .json(&json!({
            "email": format!("scim-admin-{}@example.com", uuid::Uuid::new_v4()),
            "password": "test-password-123"
        }))
        .send()
        .await
        .expect("register")
        .error_for_status()
        .expect("register status")
        .json::<serde_json::Value>()
        .await
        .expect("register json");

    let account_id = reg["account_id"].as_str().expect("account_id");

    let token_resp = client
        .post(format!("{base}/v1/scim-tokens"))
        .header("Authorization", "Bearer test-bootstrap-secret")
        .json(&json!({ "name": "scim-test" }))
        .send()
        .await
        .expect("scim token")
        .error_for_status()
        .expect("scim token status")
        .json::<serde_json::Value>()
        .await
        .expect("scim token json");
    let scim_token = token_resp["token"].as_str().expect("scim token");

    let email = format!("scim-user-{}@example.com", uuid::Uuid::new_v4());
    let created = client
        .post(format!("{base}/scim/v2/Users"))
        .header("Authorization", format!("Bearer {scim_token}"))
        .json(&json!({ "userName": email, "displayName": "SCIM User" }))
        .send()
        .await
        .expect("scim create")
        .error_for_status()
        .expect("scim create status")
        .json::<serde_json::Value>()
        .await
        .expect("scim create json");
    let user_id = created["id"].as_str().expect("scim user id");

    let listed = client
        .get(format!("{base}/scim/v2/Users"))
        .header("Authorization", format!("Bearer {scim_token}"))
        .send()
        .await
        .expect("scim list")
        .error_for_status()
        .expect("scim list status")
        .json::<serde_json::Value>()
        .await
        .expect("scim list json");
    assert!(listed["totalResults"].as_i64().unwrap_or(0) >= 1);

    let patched = client
        .patch(format!("{base}/scim/v2/Users/{user_id}"))
        .header("Authorization", format!("Bearer {scim_token}"))
        .json(&json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [
                {"op": "replace", "path": "displayName", "value": "SCIM Patched"},
                {"op": "replace", "path": "active", "value": true}
            ]
        }))
        .send()
        .await
        .expect("scim patch")
        .error_for_status()
        .expect("scim patch status")
        .json::<serde_json::Value>()
        .await
        .expect("scim patch json");
    assert_eq!(patched["displayName"].as_str(), Some("SCIM Patched"));

    client
        .delete(format!("{base}/scim/v2/Users/{user_id}"))
        .header("Authorization", format!("Bearer {scim_token}"))
        .send()
        .await
        .expect("scim delete")
        .error_for_status()
        .expect("scim delete status");
}

#[tokio::test]
#[serial]
async fn device_authorization_grant_flow() {
    let Some((db_url, redis_url)) = test_urls().await else {
        eprintln!("SKIP: no database");
        return;
    };
    let (addr, _server) = spawn_server(db_url, redis_url).await;
    let base = format!("http://{addr}");
    let client = Client::new();

    let email = format!("device-{}@example.com", uuid::Uuid::new_v4());
    client
        .post(format!("{base}/v1/auth/register"))
        .header("Authorization", "Bearer test-bootstrap-secret")
        .json(&json!({
            "email": email,
            "password": "test-password-123"
        }))
        .send()
        .await
        .expect("register")
        .error_for_status()
        .expect("register status");

    let client_resp = client
        .post(format!("{base}/v1/clients"))
        .header("Authorization", "Bearer test-bootstrap-secret")
        .json(&json!({
            "name": "device-client",
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

    let device = client
        .post(format!("{base}/oauth/device_authorization"))
        .json(&json!({
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": "openid profile"
        }))
        .send()
        .await
        .expect("device auth")
        .error_for_status()
        .expect("device auth status")
        .json::<serde_json::Value>()
        .await
        .expect("device auth json");

    let user_code = device["user_code"].as_str().expect("user_code");
    let device_code = device["device_code"].as_str().expect("device_code");

    let pending = client
        .post(format!("{base}/oauth/token"))
        .json(&json!({
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": client_id,
            "device_code": device_code
        }))
        .send()
        .await
        .expect("poll");
    assert_eq!(pending.status(), 400);
    assert_eq!(
        pending.json::<serde_json::Value>().await.unwrap()["error"],
        "authorization_pending"
    );

    client
        .post(format!("{base}/device/approve"))
        .form(&[
            ("user_code", user_code),
            ("email", &email),
            ("password", "test-password-123"),
        ])
        .send()
        .await
        .expect("approve")
        .error_for_status()
        .expect("approve status");

    let tokens = client
        .post(format!("{base}/oauth/token"))
        .json(&json!({
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": client_id,
            "device_code": device_code
        }))
        .send()
        .await
        .expect("token")
        .error_for_status()
        .expect("token status")
        .json::<serde_json::Value>()
        .await
        .expect("token json");

    assert!(tokens["access_token"].as_str().is_some());
}

#[tokio::test]
#[serial]
async fn login_page_and_discovery_endpoints() {
    let Some((db_url, redis_url)) = test_urls().await else {
        eprintln!("SKIP: no database");
        return;
    };
    let (addr, _server) = spawn_server(db_url, redis_url).await;
    let base = format!("http://{addr}");
    let client = Client::new();

    let login = client
        .get(format!("{base}/login?login_state=test-state"))
        .send()
        .await
        .expect("login page")
        .error_for_status()
        .expect("login page status")
        .text()
        .await
        .expect("login html");
    assert!(login.contains("Sign in"));

    let doc = client
        .get(format!("{base}/.well-known/openid-configuration"))
        .send()
        .await
        .expect("discovery")
        .json::<serde_json::Value>()
        .await
        .expect("discovery json");
    assert!(doc["end_session_endpoint"].as_str().is_some());
    assert!(doc["device_authorization_endpoint"].as_str().is_some());
}

#[tokio::test]
#[serial]
async fn mfa_enroll_and_complete_login() {
    let Some((db_url, redis_url)) = test_urls().await else {
        eprintln!("SKIP integration test: run `make brew-up` or set DATABASE_URL+REDIS_URL");
        return;
    };
    let (addr, _server) = spawn_server(db_url, redis_url).await;
    let base = format!("http://{addr}");
    let client = Client::new();

    let reg = client
        .post(format!("{base}/v1/auth/register"))
        .header("Authorization", "Bearer test-bootstrap-secret")
        .json(&json!({
            "email": format!("mfa-flow-{}@example.com", uuid::Uuid::new_v4()),
            "password": "test-password-123"
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

    let client_resp = client
        .post(format!("{base}/v1/clients"))
        .header("Authorization", "Bearer test-bootstrap-secret")
        .json(&json!({
            "name": "mfa-flow",
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

    let pre_tokens = client
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
        .expect("pre-login")
        .error_for_status()
        .expect("pre-login status")
        .json::<serde_json::Value>()
        .await
        .expect("pre-login json");
    let pre_access = pre_tokens["access_token"].as_str().expect("pre access");

    let enroll = client
        .post(format!("{base}/v1/mfa/enroll"))
        .header("Authorization", format!("Bearer {pre_access}"))
        .json(&json!({ "user_id": user_id }))
        .send()
        .await
        .expect("mfa enroll")
        .error_for_status()
        .expect("mfa enroll status")
        .json::<serde_json::Value>()
        .await
        .expect("mfa enroll json");
    let otpauth_url = enroll["otpauth_url"].as_str().expect("otpauth url");
    let secret = extract_otp_secret(otpauth_url);

    let verify_code = totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        totp_rs::Secret::Encoded(secret.clone()).to_bytes().unwrap(),
    )
    .unwrap()
    .generate_current()
    .unwrap();

    client
        .post(format!("{base}/v1/mfa/verify"))
        .header("Authorization", format!("Bearer {pre_access}"))
        .json(&json!({ "user_id": user_id, "code": verify_code }))
        .send()
        .await
        .expect("mfa verify")
        .error_for_status()
        .expect("mfa verify status");

    let login = client
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
    assert_eq!(login["mfa_required"], true);
    let challenge_id = login["mfa_challenge_id"].as_str().expect("challenge");

    let code = totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        totp_rs::Secret::Encoded(secret.clone()).to_bytes().unwrap(),
    )
    .unwrap()
    .generate_current()
    .unwrap();

    let tokens = client
        .post(format!("{base}/oauth/mfa"))
        .json(&json!({ "challenge_id": challenge_id, "code": code }))
        .send()
        .await
        .expect("mfa complete")
        .error_for_status()
        .expect("mfa complete status")
        .json::<serde_json::Value>()
        .await
        .expect("mfa complete json");
    assert!(tokens["access_token"].as_str().is_some());
}

#[tokio::test]
#[serial]
async fn federation_callback_rejects_invalid_state() {
    let Some((db_url, redis_url)) = test_urls().await else {
        eprintln!("SKIP integration test: run `make brew-up` or set DATABASE_URL+REDIS_URL");
        return;
    };
    let (addr, _server) = spawn_server(db_url, redis_url).await;
    let base = format!("http://{addr}");
    let client = Client::new();

    let resp = client
        .get(format!(
            "{base}/oauth/federate/google/callback?code=fake&state=invalid&client_id=nope"
        ))
        .send()
        .await
        .expect("federate callback");
    assert!(!resp.status().is_success());
}

#[tokio::test]
#[serial]
async fn session_revoke_removes_redis_session() {
    let Some((db_url, redis_url)) = test_urls().await else {
        eprintln!("SKIP integration test: run `make brew-up` or set DATABASE_URL+REDIS_URL");
        return;
    };
    let (addr, _server) = spawn_server(db_url.clone(), redis_url.clone()).await;
    let base = format!("http://{addr}");
    let client = Client::new();

    let reg = client
        .post(format!("{base}/v1/auth/register"))
        .header("Authorization", "Bearer test-bootstrap-secret")
        .json(&json!({
            "email": format!("session-user-{}@example.com", uuid::Uuid::new_v4()),
            "password": "test-password-123"
        }))
        .send()
        .await
        .expect("register")
        .error_for_status()
        .expect("register status")
        .json::<serde_json::Value>()
        .await
        .expect("register json");
    let user_id = reg["id"].as_str().expect("user id");

    let client_resp = client
        .post(format!("{base}/v1/clients"))
        .header("Authorization", "Bearer test-bootstrap-secret")
        .json(&json!({
            "name": "session-test",
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

    let tokens = client
        .post(format!("{base}/oauth/token"))
        .json(&json!({
            "grant_type": "password",
            "client_id": client_id,
            "client_secret": client_secret,
            "username": reg["email"].as_str().unwrap(),
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
    let access_token = tokens["access_token"].as_str().expect("access");

    let session_id = uuid::Uuid::new_v4();
    let mut redis_conn = deadpool_redis::Config::from_url(redis_url)
        .create_pool(Some(deadpool_redis::Runtime::Tokio1))
        .expect("redis pool")
        .get()
        .await
        .expect("redis conn");
    deadpool_redis::redis::AsyncCommands::set_ex::<_, _, ()>(
        &mut redis_conn,
        format!("session:{session_id}"),
        user_id,
        3600,
    )
    .await
    .expect("seed session");

    let listed = client
        .get(format!("{base}/v1/users/{user_id}/sessions"))
        .header("Authorization", format!("Bearer {access_token}"))
        .send()
        .await
        .expect("list sessions")
        .error_for_status()
        .expect("list sessions status")
        .json::<serde_json::Value>()
        .await
        .expect("list sessions json");
    assert_eq!(listed["sessions"].as_array().unwrap().len(), 1);

    client
        .delete(format!("{base}/v1/sessions/{session_id}"))
        .header("Authorization", format!("Bearer {access_token}"))
        .send()
        .await
        .expect("revoke session")
        .error_for_status()
        .expect("revoke session status");

    let listed_after = client
        .get(format!("{base}/v1/users/{user_id}/sessions"))
        .header("Authorization", format!("Bearer {access_token}"))
        .send()
        .await
        .expect("list sessions after")
        .error_for_status()
        .expect("list sessions after status")
        .json::<serde_json::Value>()
        .await
        .expect("list sessions after json");
    assert!(listed_after["sessions"].as_array().unwrap().is_empty());
}

#[tokio::test]
#[serial]
async fn saml_idp_sso_login_flow() {
    let Some((db_url, redis_url)) = test_urls().await else {
        eprintln!("SKIP integration test: run `make brew-up` or set DATABASE_URL+REDIS_URL");
        return;
    };
    let (addr, _server) = spawn_server(db_url, redis_url).await;
    let base = format!("http://{addr}");
    let client = Client::builder().redirect(reqwest::redirect::Policy::none()).build().expect("client");

    let email = format!("saml-idp-{}@example.com", uuid::Uuid::new_v4());
    client
        .post(format!("{base}/v1/auth/register"))
        .header("Authorization", "Bearer test-bootstrap-secret")
        .json(&json!({
            "email": email,
            "password": "test-password-123",
            "display_name": "SAML IdP User"
        }))
        .send()
        .await
        .expect("register")
        .error_for_status()
        .expect("register status");

    let sp_entity = "https://sp.example.com";
    let acs_url = "https://sp.example.com/saml/acs";
    let sp = client
        .post(format!("{base}/v1/saml/service-providers"))
        .header("Authorization", "Bearer test-bootstrap-secret")
        .json(&json!({
            "name": "Test SP",
            "entity_id": sp_entity,
            "acs_url": acs_url,
            "want_authn_requests_signed": false
        }))
        .send()
        .await
        .expect("create sp")
        .error_for_status()
        .expect("create sp status")
        .json::<serde_json::Value>()
        .await
        .expect("create sp json");
    assert!(sp["id"].as_str().is_some());

    let metadata = client
        .get(format!("{base}/saml/idp/metadata"))
        .send()
        .await
        .expect("metadata")
        .error_for_status()
        .expect("metadata status")
        .text()
        .await
        .expect("metadata body");
    assert!(metadata.contains("IDPSSODescriptor"));

    let builder = authsvc_idp::saml_authn_request::SamlAuthnRequestBuilder::new(
        sp_entity,
        acs_url,
        &format!("{base}/saml/idp/sso"),
    );
    let (sso_url, _) = builder.build_redirect_url("relay-123").expect("redirect url");

    let sso_resp = client
        .get(&sso_url)
        .send()
        .await
        .expect("sso redirect")
        .error_for_status()
        .expect("sso status");
    let location = sso_resp
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .expect("redirect location");
    assert!(location.contains("saml_authn_id="));
    let saml_authn_id = location
        .split("saml_authn_id=")
        .nth(1)
        .expect("authn id")
        .split('&')
        .next()
        .expect("authn id value");

    let login_resp = client
        .post(format!("{base}/saml/idp/login"))
        .json(&json!({
            "saml_authn_id": saml_authn_id,
            "email": email,
            "password": "test-password-123"
        }))
        .send()
        .await
        .expect("idp login")
        .error_for_status()
        .expect("idp login status")
        .text()
        .await
        .expect("idp login body");
    assert!(login_resp.contains("SAMLResponse"));
    assert!(login_resp.contains(acs_url));
}

fn extract_otp_secret(otpauth_url: &str) -> String {
    otpauth_url
        .split('?')
        .nth(1)
        .and_then(|q| q.split('&').find_map(|p| p.strip_prefix("secret=")))
        .expect("secret in otpauth url")
        .to_string()
}

async fn count_members_for_tenant(
    pool: &sqlx::PgPool,
    account_id: uuid::Uuid,
    user_id: uuid::Uuid,
) -> i64 {
    let mut tx = pool.begin().await.expect("begin tx");
    sqlx::query("SELECT set_config('app.account_id', $1, true)")
        .bind(account_id.to_string())
        .execute(&mut *tx)
        .await
        .expect("set tenant context");
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM account_members WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await
        .expect("count members");
    tx.commit().await.expect("commit tx");
    count.0
}
