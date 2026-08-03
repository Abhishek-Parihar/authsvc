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

#[tokio::test]
#[serial]
async fn authz_check_requires_authentication() {
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
            "email": format!("authz-{}@example.com", Uuid::new_v4()),
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

    let denied = client
        .post(format!("{base}/v1/authz/check"))
        .json(&json!({
            "subject_id": reg["id"].as_str().unwrap(),
            "account_id": reg["account_id"].as_str().unwrap(),
            "resource": "users",
            "action": "read"
        }))
        .send()
        .await
        .expect("authz");
    assert_eq!(denied.status(), 401);

    let client_resp = client
        .post(format!("{base}/v1/clients"))
        .header("Authorization", "Bearer test-bootstrap-secret")
        .json(&json!({
            "name": "authz-test",
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

    let token = login_password(
        &client,
        &base,
        reg["email"].as_str().unwrap(),
        "test-password-123",
        client_resp["client_id"].as_str().unwrap(),
        client_resp["client_secret"].as_str().unwrap(),
    )
    .await;

    let allowed = client
        .post(format!("{base}/v1/authz/check"))
        .header("Authorization", format!("Bearer {token}"))
        .json(&json!({
            "subject_id": reg["id"].as_str().unwrap(),
            "account_id": reg["account_id"].as_str().unwrap(),
            "resource": "users",
            "action": "read"
        }))
        .send()
        .await
        .expect("authz authed");
    assert!(allowed.status().is_success());
}

#[tokio::test]
#[serial]
async fn introspect_requires_client_credentials() {
    let Some((db_url, redis_url)) = test_urls().await else {
        eprintln!("SKIP: no database");
        return;
    };
    let (addr, _server) = spawn_server(db_url, redis_url).await;
    let base = format!("http://{addr}");
    let client = Client::new();

    let denied = client
        .post(format!("{base}/oauth/introspect"))
        .json(&json!({"token": "not-a-real-token"}))
        .send()
        .await
        .expect("introspect");
    assert_eq!(denied.status(), 401);

    let client_resp = client
        .post(format!("{base}/v1/clients"))
        .header("Authorization", "Bearer test-bootstrap-secret")
        .json(&json!({
            "name": "introspect-test",
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

    let reg = client
        .post(format!("{base}/v1/auth/register"))
        .header("Authorization", "Bearer test-bootstrap-secret")
        .json(&json!({
            "email": format!("intro-{}@example.com", Uuid::new_v4()),
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
        .expect("token")
        .error_for_status()
        .expect("token status")
        .json::<serde_json::Value>()
        .await
        .expect("token json");

    let access_token = tokens["access_token"].as_str().unwrap();
    let introspected = client
        .post(format!("{base}/oauth/introspect"))
        .json(&json!({
            "token": access_token,
            "client_id": client_id,
            "client_secret": client_secret
        }))
        .send()
        .await
        .expect("introspect authed")
        .error_for_status()
        .expect("introspect status")
        .json::<serde_json::Value>()
        .await
        .expect("introspect json");
    assert_eq!(introspected["active"], true);
}

#[tokio::test]
#[serial]
async fn api_key_denied_on_user_routes() {
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
            "email": format!("apikey-{}@example.com", Uuid::new_v4()),
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

    let api_key = client
        .post(format!("{base}/v1/api-keys"))
        .header("Authorization", "Bearer test-bootstrap-secret")
        .json(&json!({
            "account_id": reg["account_id"].as_str().unwrap(),
            "name": "service-key",
            "scopes": ["authz"]
        }))
        .send()
        .await
        .expect("create api key")
        .error_for_status()
        .expect("api key status")
        .json::<serde_json::Value>()
        .await
        .expect("api key json");

    let resp = client
        .get(format!(
            "{base}/v1/users/{}/sessions",
            reg["id"].as_str().unwrap()
        ))
        .header(
            "Authorization",
            format!("ApiKey {}", api_key["api_key"].as_str().unwrap()),
        )
        .send()
        .await
        .expect("sessions");
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
#[serial]
async fn admin_session_cookie_auth() {
    let Some((db_url, redis_url)) = test_urls().await else {
        eprintln!("SKIP: no database");
        return;
    };
    let (addr, _server) = spawn_server(db_url, redis_url).await;
    let base = format!("http://{addr}");
    let client = Client::builder()
        .cookie_store(true)
        .build()
        .expect("client");

    let denied = client
        .get(format!("{base}/v1/clients"))
        .send()
        .await
        .expect("clients");
    assert_eq!(denied.status(), 401);

    let session = client
        .post(format!("{base}/admin/session"))
        .json(&json!({"token": "test-bootstrap-secret"}))
        .send()
        .await
        .expect("session");
    assert_eq!(session.status(), 204);

    let allowed = client
        .get(format!("{base}/v1/clients"))
        .send()
        .await
        .expect("clients authed");
    assert!(allowed.status().is_success());

    client
        .delete(format!("{base}/admin/session"))
        .send()
        .await
        .expect("logout");
}

#[tokio::test]
#[serial]
async fn device_approve_requires_csrf() {
    let Some((db_url, redis_url)) = test_urls().await else {
        eprintln!("SKIP: no database");
        return;
    };
    let (addr, _server) = spawn_server(db_url, redis_url).await;
    let base = format!("http://{addr}");
    let client = Client::new();

    let resp = client
        .post(format!("{base}/device/approve"))
        .form(&[
            ("user_code", "ABCD-EFGH"),
            ("email", "attacker@example.com"),
            ("password", "wrong"),
            ("csrf_token", "invalid-csrf"),
        ])
        .send()
        .await
        .expect("device approve");
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
#[serial]
async fn logout_open_redirect_rejected() {
    let Some((db_url, redis_url)) = test_urls().await else {
        eprintln!("SKIP: no database");
        return;
    };
    let (addr, _server) = spawn_server(db_url, redis_url).await;
    let base = format!("http://{addr}");
    let client = Client::new();

    let resp = client
        .get(format!(
            "{base}/oauth/logout?post_logout_redirect_uri=https://evil.example/phish"
        ))
        .send()
        .await
        .expect("logout");
    assert_eq!(resp.status(), 400);
}
