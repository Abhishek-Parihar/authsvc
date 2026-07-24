mod common;

use reqwest::Client;
use serde_json::json;
use serial_test::serial;
use uuid::Uuid;

use common::{login_password, spawn_server, test_base, test_urls};

#[tokio::test]
#[serial]
async fn webauthn_register_begin_returns_challenge() {
    let Some((db_url, redis_url)) = test_urls().await else {
        eprintln!("SKIP: no database");
        return;
    };
    let (addr, _server) = spawn_server(db_url, redis_url).await;
    let base = test_base(addr);
    let client = Client::new();

    let email = format!("webauthn-{}@example.com", Uuid::new_v4());
    let reg = client
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
        .expect("register status")
        .json::<serde_json::Value>()
        .await
        .expect("register json");

    let user_id = reg["id"].as_str().expect("user id");

    let client_resp = client
        .post(format!("{base}/v1/clients"))
        .header("Authorization", "Bearer test-bootstrap-secret")
        .json(&json!({
            "name": "webauthn-test",
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
        &email,
        "test-password-123",
        client_id,
        client_secret,
    )
    .await;

    let begin = client
        .post(format!("{base}/v1/webauthn/register/begin"))
        .header("Authorization", format!("Bearer {token}"))
        .json(&json!({
            "user_id": user_id,
            "name": "test-passkey"
        }))
        .send()
        .await
        .expect("webauthn begin")
        .error_for_status()
        .expect("webauthn begin status")
        .json::<serde_json::Value>()
        .await
        .expect("webauthn begin json");

    assert!(begin["challenge_id"].as_str().is_some());
    assert!(begin["options"].is_object());
    assert!(begin["rp_origin"].as_str().is_some());
}
