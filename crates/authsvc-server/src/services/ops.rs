use authsvc_core::AuthError;
use uuid::Uuid;

use super::state::AppState;

pub async fn rotate_keys(state: &AppState) -> Result<String, AuthError> {
    state.store.deactivate_signing_keys().await?;

    let kid = format!("authsvc-key-{}", &Uuid::new_v4().to_string()[..8]);
    let kid_clone = kid.clone();

    let (priv_pem, pub_pem) = tokio::task::spawn_blocking(move || generate_rsa_keypair())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))??;

    state
        .store
        .store_signing_key(&kid, &priv_pem, &pub_pem)
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

fn generate_rsa_keypair() -> Result<(String, String), AuthError> {
    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
    use rsa::RsaPrivateKey;

    let mut rng = rand::thread_rng();
    let private = RsaPrivateKey::new(&mut rng, 2048)
        .map_err(|e| AuthError::Internal(e.to_string()))?;
    let public = rsa::RsaPublicKey::from(&private);
    let priv_pem = private
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .map_err(|e| AuthError::Internal(e.to_string()))?
        .to_string();
    let pub_pem = public
        .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
        .map_err(|e| AuthError::Internal(e.to_string()))?
        .to_string();
    Ok((priv_pem, pub_pem))
}

pub async fn dispatch_webhook(
    state: &AppState,
    tenant_id: Uuid,
    event: &str,
    payload: serde_json::Value,
) {
    if let Ok(hooks) = state.store.list_webhooks_for_event(tenant_id, event).await {
        for (_id, url, secret) in hooks {
            let body = serde_json::json!({"event": event, "payload": payload});
            let sig = sign_payload(&secret, &body.to_string());
            let client = reqwest::Client::new();
            let _ = client
                .post(&url)
                .header("X-Authsvc-Signature", sig)
                .json(&body)
                .send()
                .await;
        }
    }
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
