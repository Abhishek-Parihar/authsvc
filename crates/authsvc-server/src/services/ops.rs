use authsvc_core::AuthError;
use uuid::Uuid;

use super::state::AppState;

pub async fn rotate_keys(state: &AppState) -> Result<String, AuthError> {
    state.repos.signing_keys().deactivate_signing_keys().await?;

    let kid = format!("authsvc-key-{}", &Uuid::new_v4().to_string()[..8]);
    let kid_clone = kid.clone();

    let (priv_pem, pub_pem) = tokio::task::spawn_blocking(crate::crypto::jwt::generate_rsa_keypair)
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))??;

    let encrypted =
        crate::crypto::signing_keys::encrypt_private_pem(&state.data_keys, &priv_pem).await?;

    state
        .repos
        .signing_keys()
        .store_signing_key(&kid, &pub_pem, Some(&encrypted))
        .await?;

    state
        .jwt
        .reload(state.repos.signing_keys(), &state.data_keys)
        .await?;

    state
        .audit(
            None,
            None,
            "keys.rotated",
            Some("signing_keys"),
            None,
            serde_json::json!({"kid": kid_clone}),
        )
        .await?;

    Ok(kid)
}

pub fn dispatch_webhook(
    state: &AppState,
    account_id: Uuid,
    event: &str,
    payload: serde_json::Value,
) {
    dispatch_webhook_inner(state, account_id, event, payload);
}

fn dispatch_webhook_inner(
    state: &AppState,
    account_id: Uuid,
    event: &str,
    payload: serde_json::Value,
) {
    let state = state.clone();
    let event = event.to_string();
    tokio::spawn(async move {
        if let Ok(hooks) = state
            .repos
            .webhooks()
            .list_webhooks_for_event(account_id, &event)
            .await
        {
            for (id, url, secret_enc) in hooks {
                let state = state.clone();
                let event = event.clone();
                let body = payload.clone();
                tokio::spawn(async move {
                    let secret = match crate::crypto::secrets::decrypt_string(
                        &state.data_keys,
                        "webhook_secret",
                        &secret_enc,
                    )
                    .await
                    {
                        Ok(s) => s,
                        Err(_) => secret_enc,
                    };
                    deliver_webhook(&state, id, &url, &secret, &event, body).await;
                });
            }
        }
    });
}

async fn deliver_webhook(
    state: &AppState,
    webhook_id: Uuid,
    url: &str,
    secret: &str,
    event: &str,
    payload: serde_json::Value,
) {
    let delivery_id = Uuid::new_v4();
    let body = serde_json::json!({"event": event, "payload": payload});
    let sig = sign_payload(secret, &body.to_string());
    let client = reqwest::Client::new();

    let mut last_error = None;
    for attempt in 1..=3 {
        let result = client
            .post(url)
            .header("X-Authsvc-Signature", &sig)
            .json(&body)
            .send()
            .await;

        match result {
            Ok(resp) if resp.status().is_success() => {
                let _ = state
                    .repos
                    .webhooks()
                    .record_webhook_delivery(
                        delivery_id,
                        webhook_id,
                        event,
                        "delivered",
                        attempt,
                        None,
                    )
                    .await;
                return;
            }
            Ok(resp) => {
                last_error = Some(format!("HTTP {}", resp.status()));
            }
            Err(e) => {
                last_error = Some(e.to_string());
            }
        }

        if attempt < 3 {
            tokio::time::sleep(std::time::Duration::from_millis(500 * attempt as u64)).await;
        }
    }

    let _ = state
        .repos
        .webhooks()
        .record_webhook_delivery(
            delivery_id,
            webhook_id,
            event,
            "failed",
            3,
            last_error.as_deref(),
        )
        .await;
    let _ = state
        .audit(
            None,
            None,
            "webhook.failed",
            Some("webhooks"),
            None,
            serde_json::json!({"webhook_id": webhook_id, "event": event, "error": last_error}),
        )
        .await;
}

fn sign_payload(secret: &str, body: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("hmac");
    mac.update(body.as_bytes());
    hex_encode(mac.finalize().into_bytes().as_slice())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
