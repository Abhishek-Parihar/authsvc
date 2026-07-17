use authsvc_core::{
    AuthError, ClientRepository, TenantRepository, UserRepository,
};
use chrono::{Duration, Utc};
use sha2::{Digest, Sha256};
use totp_rs::{Algorithm as TotpAlgorithm, Secret, TOTP};
use uuid::Uuid;

use super::{auth::TokenResponse, state::AppState};
use crate::crypto::password::{generate_refresh_token, hash_password, hash_token};

pub async fn enroll_totp(state: &AppState, user_id: Uuid) -> Result<(String, Vec<String>), AuthError> {
    let secret = Secret::generate_secret();
    let _totp = TOTP::new(
        TotpAlgorithm::SHA1,
        6,
        1,
        30,
        secret.to_bytes().map_err(|e| AuthError::Internal(e.to_string()))?,
    )
    .map_err(|e| AuthError::Internal(e.to_string()))?;

    let recovery: Vec<String> = (0..8).map(|_| generate_refresh_token()).collect();
    let recovery_hashes: Vec<String> = recovery.iter().map(|c| hash_token(c)).collect();

    let encoded = secret.to_encoded().to_string();
    let encrypted = encrypt_secret(state, &encoded)?;
    state
        .store
        .store_mfa_secret(user_id, &encrypted, &recovery_hashes)
        .await?;

    let url = format!(
        "otpauth://totp/authsvc:{user_id}?secret={encoded}&issuer=authsvc&algorithm=SHA1&digits=6&period=30"
    );
    Ok((url, recovery))
}

pub async fn verify_totp(state: &AppState, user_id: Uuid, code: &str) -> Result<(), AuthError> {
    let encrypted = state
        .store
        .get_mfa_secret(user_id)
        .await?
        .ok_or(AuthError::Validation("mfa not enrolled".into()))?;
    let secret = decrypt_secret(state, &encrypted)?;
    let totp = TOTP::new(
        TotpAlgorithm::SHA1,
        6,
        1,
        30,
        Secret::Encoded(secret)
            .to_bytes()
            .map_err(|e| AuthError::Internal(e.to_string()))?,
    )
    .map_err(|e| AuthError::Internal(e.to_string()))?;

    if totp
        .check_current(code)
        .map_err(|e| AuthError::Internal(e.to_string()))?
    {
        Ok(())
    } else {
        Err(AuthError::InvalidCredentials)
    }
}

pub async fn disable_mfa(state: &AppState, user_id: Uuid) -> Result<(), AuthError> {
    sqlx::query("DELETE FROM user_mfa_secrets WHERE user_id = $1")
        .bind(user_id)
        .execute(state.store.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
    sqlx::query("UPDATE users SET mfa_enabled = FALSE WHERE id = $1")
        .bind(user_id)
        .execute(state.store.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;
    Ok(())
}

pub async fn send_magic_link(state: &AppState, email: &str) -> Result<String, AuthError> {
    let tenant = TenantRepository::find_by_slug(&state.store, &state.config.default_tenant_slug)
        .await?
        .ok_or_else(|| AuthError::NotFound("tenant".into()))?;

    let token = generate_refresh_token();
    let hash = hash_token(&token);
    state
        .store
        .store_magic_link(
            &hash,
            tenant.id,
            &email.to_lowercase(),
            Utc::now() + Duration::minutes(15),
        )
        .await?;

    let link = format!(
        "{}/v1/auth/magic-link/verify?token={token}",
        state.config.issuer
    );
    state
        .notifier
        .send_email(
            email,
            "Your authsvc sign-in link",
            &format!("Sign in: {link}"),
        )
        .await?;
    Ok(link)
}

pub async fn verify_magic_link(
    state: &AppState,
    token: &str,
    client_id: &str,
) -> Result<TokenResponse, AuthError> {
    let hash = hash_token(token);
    let (tenant_id, email) = state
        .store
        .consume_magic_link(&hash)
        .await?
        .ok_or(AuthError::InvalidToken)?;

    let user = match state.store.find_by_email(tenant_id, &email).await? {
        Some(u) => u,
        None => {
            let pwd = generate_refresh_token();
            let hash = hash_password(&pwd)?;
            UserRepository::create(
                &state.store,
                &authsvc_core::user::CreateUser {
                    tenant_id,
                    email: email.clone(),
                    password: pwd,
                    display_name: None,
                },
                &hash,
            )
            .await?
        }
    };

    let client = ClientRepository::find_by_client_id(&state.store, client_id)
        .await?
        .ok_or(AuthError::ClientNotFound)?;

    super::auth::issue_user_tokens(state, &user, &client).await
}

fn encrypt_secret(state: &AppState, secret: &str) -> Result<String, AuthError> {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Nonce,
    };
    let key_bytes = derive_key(state);
    let cipher =
        Aes256Gcm::new_from_slice(&key_bytes).map_err(|e| AuthError::Internal(e.to_string()))?;
    let nonce = Nonce::from_slice(&[0u8; 12]);
    let ct = cipher
        .encrypt(nonce, secret.as_bytes())
        .map_err(|e| AuthError::Internal(e.to_string()))?;
    Ok(base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        ct,
    ))
}

fn decrypt_secret(state: &AppState, encrypted: &str) -> Result<String, AuthError> {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Nonce,
    };
    let key_bytes = derive_key(state);
    let cipher =
        Aes256Gcm::new_from_slice(&key_bytes).map_err(|e| AuthError::Internal(e.to_string()))?;
    let data = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        encrypted,
    )
    .map_err(|e| AuthError::Internal(e.to_string()))?;
    let nonce = Nonce::from_slice(&[0u8; 12]);
    let pt = cipher
        .decrypt(nonce, data.as_ref())
        .map_err(|e| AuthError::Internal(e.to_string()))?;
    String::from_utf8(pt).map_err(|e| AuthError::Internal(e.to_string()))
}

fn derive_key(state: &AppState) -> [u8; 32] {
    let material = state
        .config
        .mfa_encryption_key
        .as_deref()
        .unwrap_or("dev-mfa-key-change-in-production!");
    let digest = Sha256::digest(material.as_bytes());
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    key
}
