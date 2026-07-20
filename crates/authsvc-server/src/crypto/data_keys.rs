use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use authsvc_core::{AuthError, DataKeyStore};
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use std::sync::Arc;

const NONCE_LEN: usize = 12;

/// AES-256-GCM encryption using a master key from env (dev/self-hosted).
pub struct LocalDataKeyStore {
    key: [u8; 32],
}

impl LocalDataKeyStore {
    pub fn from_master_key(master_key: &str) -> Result<Self, AuthError> {
        if master_key.len() < 32 {
            return Err(AuthError::Internal(
                "DATA_ENCRYPTION_KEY must be at least 32 characters".into(),
            ));
        }
        let hash = Sha256::digest(master_key.as_bytes());
        let mut key = [0u8; 32];
        key.copy_from_slice(&hash);
        Ok(Self { key })
    }

    fn derive_nonce(context: &str) -> [u8; NONCE_LEN] {
        let mut out = [0u8; NONCE_LEN];
        let hash = Sha256::digest(context.as_bytes());
        out.copy_from_slice(&hash[..NONCE_LEN]);
        out
    }
}

#[async_trait]
impl DataKeyStore for LocalDataKeyStore {
    async fn encrypt(&self, plaintext: &[u8], context: &str) -> Result<Vec<u8>, AuthError> {
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        let nonce_bytes = Self::derive_nonce(context);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let mut ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        let mut out = nonce_bytes.to_vec();
        out.append(&mut ciphertext);
        Ok(out)
    }

    async fn decrypt(&self, ciphertext: &[u8], context: &str) -> Result<Vec<u8>, AuthError> {
        if ciphertext.len() < NONCE_LEN {
            return Err(AuthError::Internal("ciphertext too short".into()));
        }
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        let (nonce_bytes, payload) = ciphertext.split_at(NONCE_LEN);
        let expected = Self::derive_nonce(context);
        if nonce_bytes != expected {
            return Err(AuthError::Internal("encryption context mismatch".into()));
        }
        let nonce = Nonce::from_slice(nonce_bytes);
        cipher
            .decrypt(nonce, payload)
            .map_err(|e| AuthError::Internal(e.to_string()))
    }
}

/// Delegates to LocalDataKeyStore; optional KMS_HTTP_URL hook for external KMS proxies.
pub struct KmsDataKeyStore {
    inner: Arc<LocalDataKeyStore>,
    kms_url: Option<String>,
}

impl KmsDataKeyStore {
    pub fn new(master_key: &str, kms_url: Option<String>) -> Result<Self, AuthError> {
        Ok(Self {
            inner: Arc::new(LocalDataKeyStore::from_master_key(master_key)?),
            kms_url,
        })
    }
}

#[async_trait]
impl DataKeyStore for KmsDataKeyStore {
    async fn encrypt(&self, plaintext: &[u8], context: &str) -> Result<Vec<u8>, AuthError> {
        if let Some(url) = &self.kms_url {
            let client = reqwest::Client::new();
            let resp = client
                .post(format!("{url}/encrypt"))
                .json(&serde_json::json!({
                    "plaintext": base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        plaintext
                    ),
                    "context": context
                }))
                .send()
                .await
                .map_err(|e| AuthError::Internal(e.to_string()))?;
            if !resp.status().is_success() {
                return Err(AuthError::Internal("KMS encrypt failed".into()));
            }
            let body: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| AuthError::Internal(e.to_string()))?;
            let b64 = body["ciphertext"]
                .as_str()
                .ok_or_else(|| AuthError::Internal("invalid KMS response".into()))?;
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64)
                .map_err(|e| AuthError::Internal(e.to_string()))
        } else {
            self.inner.encrypt(plaintext, context).await
        }
    }

    async fn decrypt(&self, ciphertext: &[u8], context: &str) -> Result<Vec<u8>, AuthError> {
        if let Some(url) = &self.kms_url {
            let client = reqwest::Client::new();
            let resp = client
                .post(format!("{url}/decrypt"))
                .json(&serde_json::json!({
                    "ciphertext": base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        ciphertext
                    ),
                    "context": context
                }))
                .send()
                .await
                .map_err(|e| AuthError::Internal(e.to_string()))?;
            if !resp.status().is_success() {
                return Err(AuthError::Internal("KMS decrypt failed".into()));
            }
            let body: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| AuthError::Internal(e.to_string()))?;
            let b64 = body["plaintext"]
                .as_str()
                .ok_or_else(|| AuthError::Internal("invalid KMS response".into()))?;
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64)
                .map_err(|e| AuthError::Internal(e.to_string()))
        } else {
            self.inner.decrypt(ciphertext, context).await
        }
    }
}

pub fn build_data_key_store(
    data_encryption_key: Option<&str>,
    mfa_encryption_key: Option<&str>,
    kms_url: Option<&str>,
    is_production: bool,
) -> Result<Arc<dyn DataKeyStore>, AuthError> {
    let master = data_encryption_key.or(mfa_encryption_key).or_else(|| {
        if is_production {
            None
        } else {
            Some("dev-only-insecure-data-encryption-key-32chars")
        }
    });
    let master = master.ok_or_else(|| {
        AuthError::Internal("DATA_ENCRYPTION_KEY or MFA_ENCRYPTION_KEY required in production".into())
    })?;
    let store: Arc<dyn DataKeyStore> = Arc::new(KmsDataKeyStore::new(
        master,
        kms_url.map(str::to_string),
    )?);
    Ok(store)
}
