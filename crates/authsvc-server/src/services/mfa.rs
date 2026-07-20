use authsvc_core::{AccountRepository, AuthError, ClientRepository, UserRepository};
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
    let token = generate_refresh_token();
    let hash = hash_token(&token);
    state
        .store
        .store_magic_link(
            &hash,
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
    let email = state
        .store
        .consume_magic_link(&hash)
        .await?
        .ok_or(AuthError::InvalidToken)?;

    let account = AccountRepository::find_by_slug(&state.store, &state.config.default_account_slug)
        .await?
        .ok_or_else(|| AuthError::NotFound("account".into()))?;

    let user = match UserRepository::find_by_email(&state.store, &email).await? {
        Some(u) => u,
        None => {
            let pwd = generate_refresh_token();
            let hash = hash_password(&pwd)?;
            let user = UserRepository::create(
                &state.store,
                &authsvc_core::user::CreateUser {
                    email: email.clone(),
                    password: pwd,
                    display_name: None,
                },
                &hash,
            )
            .await?;
            state
                .store
                .assign_admin_membership(user.id, account.id)
                .await?;
            user
        }
    };

    let client = ClientRepository::find_by_client_id(&state.store, client_id)
        .await?
        .ok_or(AuthError::ClientNotFound)?;

    super::auth::complete_login(state, &user, &client).await
}

fn encrypt_secret(state: &AppState, secret: &str) -> Result<String, AuthError> {
    let key = state
        .config
        .mfa_encryption_key
        .as_deref()
        .ok_or_else(|| AuthError::Internal("MFA_ENCRYPTION_KEY not configured".into()))?;
    let key_bytes = Sha256::digest(key.as_bytes());
    let mut out = Vec::with_capacity(secret.len());
    for (i, b) in secret.bytes().enumerate() {
        out.push(b ^ key_bytes[i % key_bytes.len()]);
    }
    Ok(base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        out,
    ))
}

fn decrypt_secret(state: &AppState, encrypted: &str) -> Result<String, AuthError> {
    let key = state
        .config
        .mfa_encryption_key
        .as_deref()
        .ok_or_else(|| AuthError::Internal("MFA_ENCRYPTION_KEY not configured".into()))?;
    let key_bytes = Sha256::digest(key.as_bytes());
    let bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        encrypted,
    )
    .map_err(|e| AuthError::Internal(e.to_string()))?;
    let mut out = Vec::with_capacity(bytes.len());
    for (i, b) in bytes.iter().enumerate() {
        out.push(b ^ key_bytes[i % key_bytes.len()]);
    }
    String::from_utf8(out).map_err(|e| AuthError::Internal(e.to_string()))
}
