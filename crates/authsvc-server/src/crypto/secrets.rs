use authsvc_core::{AuthError, DataKeyStore};
use std::sync::Arc;

pub async fn encrypt_string(
    store: &Arc<dyn DataKeyStore>,
    context: &str,
    plaintext: &str,
) -> Result<String, AuthError> {
    let ciphertext = store.encrypt(plaintext.as_bytes(), context).await?;
    Ok(base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        ciphertext,
    ))
}

pub async fn decrypt_string(
    store: &Arc<dyn DataKeyStore>,
    context: &str,
    encoded: &str,
) -> Result<String, AuthError> {
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)
        .map_err(|e| AuthError::Internal(e.to_string()))?;
    let plaintext = store.decrypt(&bytes, context).await?;
    String::from_utf8(plaintext).map_err(|e| AuthError::Internal(e.to_string()))
}
