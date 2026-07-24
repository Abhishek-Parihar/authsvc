use std::sync::Arc;

use authsvc_core::{AuthError, DataKeyStore, SigningKeyStore};

use crate::crypto::secrets::{decrypt_string, encrypt_string};

const JWT_KEY_CONTEXT: &str = "jwt_signing_key";

pub async fn encrypt_private_pem(
    data_keys: &Arc<dyn DataKeyStore>,
    private_pem: &str,
) -> Result<String, AuthError> {
    encrypt_string(data_keys, JWT_KEY_CONTEXT, private_pem).await
}

pub async fn decrypt_private_pem(
    data_keys: &Arc<dyn DataKeyStore>,
    stored: &str,
) -> Result<String, AuthError> {
    if stored.starts_with("-----BEGIN") {
        return Ok(stored.to_string());
    }
    decrypt_string(data_keys, JWT_KEY_CONTEXT, stored).await
}

pub async fn ensure_signing_key(
    store: &dyn SigningKeyStore,
    data_keys: &Arc<dyn DataKeyStore>,
    env_private_pem: Option<String>,
    env_public_pem: Option<String>,
    allow_ephemeral: bool,
) -> Result<(), AuthError> {
    if store.get_active_signing_key().await?.is_some() {
        return Ok(());
    }

    let (kid, public_pem, encrypted_private) = match (env_private_pem, env_public_pem) {
        (Some(_priv_pem), Some(pub_pem)) => {
            ("authsvc-key-1".to_string(), pub_pem, None)
        }
        _ if !allow_ephemeral => {
            return Err(AuthError::Internal(
                "JWT_PRIVATE_KEY_PEM and JWT_PUBLIC_KEY_PEM required (or encrypted signing key in DB)".into(),
            ));
        }
        _ => {
            tracing::warn!("generating ephemeral RSA key pair; set JWT_*_KEY_PEM for production");
            let (priv_pem, pub_pem) = super::jwt::generate_rsa_keypair()?;
            let enc = encrypt_private_pem(data_keys, &priv_pem).await?;
            ("authsvc-key-1".to_string(), pub_pem, Some(enc))
        }
    };

    store
        .store_signing_key(
            &kid,
            &public_pem,
            encrypted_private.as_deref(),
        )
        .await
}

pub async fn resolve_active_private_pem(
    store: &dyn SigningKeyStore,
    data_keys: &Arc<dyn DataKeyStore>,
    env_private_pem: Option<&str>,
) -> Result<String, AuthError> {
    if let Some(pem) = env_private_pem {
        return Ok(pem.to_string());
    }
    let (_, _, encrypted) = store
        .get_active_signing_key()
        .await?
        .ok_or_else(|| AuthError::Internal("no active signing key".into()))?;
    let encrypted = encrypted
        .ok_or_else(|| AuthError::Internal("JWT_PRIVATE_KEY_PEM required when no encrypted key in DB".into()))?;
    decrypt_private_pem(data_keys, &encrypted).await
}
