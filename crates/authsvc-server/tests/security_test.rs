mod common;

use reqwest::Client;
use serde_json::json;
use serial_test::serial;
use uuid::Uuid;

use common::{login_password, spawn_server, spawn_server_with_env, test_urls};

#[tokio::test]
#[serial]
async fn non_admin_jwt_denied_on_key_rotation() {
    let Some((db_url, redis_url)) = test_urls().await else {
        eprintln!("SKIP: no database");
        return;
    };
    let (addr, _server) = spawn_server(db_url.clone(), redis_url.clone()).await;
    let base = format!("http://{addr}");
    let client = Client::new();

    let admin_email = format!("admin-{}@example.com", Uuid::new_v4());
    let member_email = format!("member-{}@example.com", Uuid::new_v4());

    client
        .post(format!("{base}/v1/auth/register"))
        .header("Authorization", "Bearer test-bootstrap-secret")
        .json(&json!({
            "email": admin_email,
            "password": "test-password-123"
        }))
        .send()
        .await
        .expect("register admin")
        .error_for_status()
        .expect("register admin status");

    let member_reg = client
        .post(format!("{base}/v1/auth/register"))
        .header("Authorization", "Bearer test-bootstrap-secret")
        .json(&json!({
            "email": member_email,
            "password": "test-password-123"
        }))
        .send()
        .await
        .expect("register member")
        .error_for_status()
        .expect("register member status")
        .json::<serde_json::Value>()
        .await
        .expect("member json");

    let member_id = member_reg["id"].as_str().expect("member id");
    let member_account_id = member_reg["account_id"].as_str().expect("account_id");

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&db_url)
        .await
        .expect("pool");
    let mut tx = pool.begin().await.expect("begin tx");
    sqlx::query("SELECT set_config('app.account_id', $1, true)")
        .bind(member_account_id)
        .execute(&mut *tx)
        .await
        .expect("set tenant");
    let updated = sqlx::query(
        "UPDATE account_members SET role_id = NULL WHERE user_id = $1 AND account_id = $2",
    )
    .bind(Uuid::parse_str(member_id).unwrap())
    .bind(Uuid::parse_str(member_account_id).unwrap())
    .execute(&mut *tx)
    .await
    .expect("strip admin role");
    assert_eq!(updated.rows_affected(), 1, "member admin role must be cleared");
    tx.commit().await.expect("commit");

    let client_resp = client
        .post(format!("{base}/v1/clients"))
        .header("Authorization", "Bearer test-bootstrap-secret")
        .json(&json!({
            "name": "security-test",
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

    let token = login_password(
        &client,
        &base,
        &member_email,
        "test-password-123",
        client_id,
        client_secret,
    )
    .await;

    let resp = client
        .post(format!("{base}/v1/keys/rotate"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("rotate");
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
#[serial]
async fn bootstrap_still_allowed_on_admin_routes() {
    let Some((db_url, redis_url)) = test_urls().await else {
        eprintln!("SKIP: no database");
        return;
    };
    let (addr, _server) = spawn_server(db_url, redis_url).await;
    let base = format!("http://{addr}");
    let client = Client::new();

    client
        .post(format!("{base}/v1/auth/register"))
        .header("Authorization", "Bearer test-bootstrap-secret")
        .json(&json!({
            "email": format!("boot-{}@example.com", Uuid::new_v4()),
            "password": "test-password-123"
        }))
        .send()
        .await
        .expect("register")
        .error_for_status()
        .expect("register status");

    let resp = client
        .post(format!("{base}/v1/clients"))
        .header("Authorization", "Bearer test-bootstrap-secret")
        .json(&json!({
            "name": "bootstrap-client",
            "redirect_uris": ["http://localhost/callback"]
        }))
        .send()
        .await
        .expect("create client");
    assert!(resp.status().is_success());
}

#[tokio::test]
#[serial]
async fn metrics_requires_bearer_when_configured() {
    let Some((db_url, redis_url)) = test_urls().await else {
        eprintln!("SKIP: no database");
        return;
    };
    let (addr, _server) = spawn_server_with_env(
        db_url,
        redis_url,
        &[("METRICS_BEARER_TOKEN", "metrics-test-secret")],
    )
    .await;
    let base = format!("http://{addr}");
    let client = Client::new();

    let denied = client
        .get(format!("{base}/metrics"))
        .send()
        .await
        .expect("metrics");
    assert_eq!(denied.status(), 401);

    let allowed = client
        .get(format!("{base}/metrics"))
        .header("Authorization", "Bearer metrics-test-secret")
        .send()
        .await
        .expect("metrics authed");
    assert!(allowed.status().is_success());
}

#[tokio::test]
#[serial]
async fn webhook_rejects_localhost_target() {
    let Some((db_url, redis_url)) = test_urls().await else {
        eprintln!("SKIP: no database");
        return;
    };
    let (addr, _server) = spawn_server(db_url, redis_url).await;
    let base = format!("http://{addr}");
    let client = Client::new();

    let reg = client
        .post(format!("{base}/v1/auth/register"))
        .header("Authorization", "Bearer test-bootstrap-secret")
        .json(&json!({
            "email": format!("hook-{}@example.com", Uuid::new_v4()),
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

    let resp = client
        .post(format!("{base}/v1/webhooks"))
        .header("Authorization", "Bearer test-bootstrap-secret")
        .json(&json!({
            "account_id": account_id,
            "url": "http://127.0.0.1/internal",
            "events": ["user.provisioned"]
        }))
        .send()
        .await
        .expect("webhook");
    assert_eq!(resp.status(), 400);
}
