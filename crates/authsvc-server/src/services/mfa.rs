use authsvc_core::AuthError;
use chrono::{Duration, Utc};
use totp_rs::{Algorithm as TotpAlgorithm, Secret, TOTP};
use uuid::Uuid;

use super::{auth::TokenResponse, platform, state::AppState};
use crate::crypto::{
    password::{generate_refresh_token, hash_password, hash_token},
    secrets::{decrypt_string, encrypt_string},
};

const MFA_CONTEXT: &str = "mfa_secret";

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
    let encrypted = encrypt_secret(state, &encoded).await?;
    state
        .repos
        .mfa()
        .store_mfa_secret(user_id, &encrypted, &recovery_hashes, false)
        .await?;

    let url = format!(
        "otpauth://totp/authsvc:{user_id}?secret={encoded}&issuer=authsvc&algorithm=SHA1&digits=6&period=30"
    );
    Ok((url, recovery))
}

pub async fn verify_totp_and_enable(
    state: &AppState,
    user_id: Uuid,
    code: &str,
) -> Result<(), AuthError> {
    verify_totp(state, user_id, code).await?;
    state.repos.mfa().enable_mfa(user_id).await
}

pub async fn verify_recovery_code(
    state: &AppState,
    user_id: Uuid,
    code: &str,
) -> Result<(), AuthError> {
    let hash = hash_token(code);
    let ok = state
        .repos
        .mfa()
        .consume_recovery_code(user_id, &hash)
        .await?;
    if ok {
        Ok(())
    } else {
        Err(AuthError::InvalidCredentials)
    }
}

pub async fn verify_totp(state: &AppState, user_id: Uuid, code: &str) -> Result<(), AuthError> {
    let encrypted = state
        .repos
        .mfa()
        .get_mfa_secret(user_id)
        .await?
        .ok_or(AuthError::Validation("mfa not enrolled".into()))?;
    let secret = decrypt_secret(state, &encrypted).await?;
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
    state.repos.mfa().disable_mfa(user_id).await
}

pub async fn send_magic_link(state: &AppState, email: &str) -> Result<String, AuthError> {
    state
        .rate_limiter
        .check(&format!("magic_link:{}", email.to_lowercase()))
        .await?;

    let token = generate_refresh_token();
    let hash = hash_token(&token);
    state
        .repos
        .magic_link()
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
        .repos
        .magic_link()
        .consume_magic_link(&hash)
        .await?
        .ok_or(AuthError::InvalidToken)?;

    let account = platform::default_account(state).await?;

    let user = match state.repos.users().find_by_email(&email).await? {
        Some(u) => u,
        None => {
            let pwd = generate_refresh_token();
            let hash = hash_password(&pwd)?;
            let user = state
                .repos
                .users()
                .create(
                    &authsvc_core::user::CreateUser {
                        email: email.clone(),
                        password: pwd,
                        display_name: None,
                    },
                    &hash,
                )
                .await?;
            state
                .repos
                .postgres()
                .assign_admin_membership(user.id, account.id)
                .await?;
            user
        }
    };

    let client = state
        .repos
        .clients()
        .find_by_client_id(client_id)
        .await?
        .ok_or(AuthError::ClientNotFound)?;

    super::auth::complete_login(state, &user, &client).await
}

async fn encrypt_secret(state: &AppState, secret: &str) -> Result<String, AuthError> {
    encrypt_string(&state.data_keys, MFA_CONTEXT, secret).await
}

async fn decrypt_secret(state: &AppState, encrypted: &str) -> Result<String, AuthError> {
    decrypt_string(&state.data_keys, MFA_CONTEXT, encrypted).await
}
