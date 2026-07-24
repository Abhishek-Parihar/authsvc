mod common;

use reqwest::Client;
use serde_json::json;
use serial_test::serial;

use common::{spawn_server, test_urls};

#[tokio::test]
#[serial]
async fn refresh_token_reuse_revokes_family() {
    let Some((db_url, redis_url)) = test_urls().await else {
        eprintln!("SKIP: no database");
        return;
    };
    let (addr, _server) = spawn_server(db_url, redis_url).await;
    let base = format!("http://{addr}");
    let client = Client::new();

    let email = format!("oauth-{}@example.com", uuid::Uuid::new_v4());
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
            "name": "oauth-test",
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

    let refresh = tokens["refresh_token"].as_str().expect("refresh");

    let refreshed = client
        .post(format!("{base}/oauth/token"))
        .json(&json!({
            "grant_type": "refresh_token",
            "client_id": client_id,
            "refresh_token": refresh
        }))
        .send()
        .await
        .expect("refresh")
        .error_for_status()
        .expect("refresh status");

    assert!(refreshed.json::<serde_json::Value>().await.unwrap()["access_token"]
        .as_str()
        .is_some());

    let reuse = client
        .post(format!("{base}/oauth/token"))
        .json(&json!({
            "grant_type": "refresh_token",
            "client_id": client_id,
            "refresh_token": refresh
        }))
        .send()
        .await
        .expect("reuse");
    assert!(!reuse.status().is_success());
}

#[tokio::test]
#[serial]
async fn openid_discovery_lists_endpoints() {
    let Some((db_url, redis_url)) = test_urls().await else {
        eprintln!("SKIP: no database");
        return;
    };
    let (addr, _server) = spawn_server(db_url, redis_url).await;
    let base = format!("http://{addr}");
    let client = Client::new();

    let doc = client
        .get(format!("{base}/.well-known/openid-configuration"))
        .send()
        .await
        .expect("discovery")
        .error_for_status()
        .expect("discovery status")
        .json::<serde_json::Value>()
        .await
        .expect("discovery json");

    assert!(doc["token_endpoint"].as_str().is_some());
    assert!(doc["jwks_uri"].as_str().is_some());
}
