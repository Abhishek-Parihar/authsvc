use authsvc_core::AuthError;
use rand::Rng;

use super::{
    auth::TokenResponse,
    platform,
    state::AppState,
};
use crate::crypto::password::{generate_refresh_token, hash_password, hash_token};
use chrono::{Duration, Utc};

fn generate_otp_code() -> String {
    let mut rng = rand::thread_rng();
    format!("{:06}", rng.gen_range(0..1_000_000))
}

pub async fn send_email_otp(state: &AppState, email: &str) -> Result<String, AuthError> {
    state
        .rate_limiter
        .check(&format!("email_otp:{}", email.to_lowercase()))
        .await?;

    let code = generate_otp_code();
    let code_hash = hash_token(&code);
    state
        .repos
        .otp()
        .store_email_otp(&email.to_lowercase(), &code_hash, Utc::now() + Duration::minutes(10))
        .await?;

    state
        .notifier
        .send_email(
            email,
            "Your sign-in code",
            &format!("Your verification code is: {code}"),
        )
        .await?;

    Ok(code)
}

pub async fn verify_email_otp(
    state: &AppState,
    email: &str,
    code: &str,
    client_id: &str,
) -> Result<TokenResponse, AuthError> {
    let email = email.to_lowercase();
    let code_hash = hash_token(code);
    if !state.repos.otp().consume_email_otp(&email, &code_hash).await? {
        return Err(AuthError::InvalidCredentials);
    }

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
                .memberships()
                .add_account_member(account.id, user.id, None)
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

pub async fn send_phone_otp(state: &AppState, phone: &str) -> Result<String, AuthError> {
    let phone = normalize_phone(phone);
    state
        .rate_limiter
        .check(&format!("phone_otp:{phone}"))
        .await?;

    let code = generate_otp_code();
    let code_hash = hash_token(&code);
    state
        .repos
        .otp()
        .store_phone_otp(&phone, &code_hash, Utc::now() + Duration::minutes(10))
        .await?;

    state
        .notifier
        .send_sms(&phone, &format!("Your authsvc code is {code}"))
        .await?;

    Ok(code)
}

pub async fn verify_phone_otp(
    state: &AppState,
    phone: &str,
    code: &str,
    client_id: &str,
) -> Result<TokenResponse, AuthError> {
    let phone = normalize_phone(phone);
    let code_hash = hash_token(code);
    if !state.repos.otp().consume_phone_otp(&phone, &code_hash).await? {
        return Err(AuthError::InvalidCredentials);
    }

    let account = platform::default_account(state).await?;

    let user = if let Some(user_id) = state.repos.otp().find_user_id_by_phone(&phone).await? {
        state
            .repos
            .users()
            .find_by_id(user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?
    } else {
        let email = format!("{phone}@phone.authsvc.local");
        let pwd = generate_refresh_token();
        let hash = hash_password(&pwd)?;
        let user = state
            .repos
            .users()
            .create(
                &authsvc_core::user::CreateUser {
                    email,
                    password: pwd,
                    display_name: None,
                },
                &hash,
            )
            .await?;
        state
            .repos
            .memberships()
            .add_account_member(account.id, user.id, None)
            .await?;
        state.repos.otp().link_verified_phone(user.id, &phone).await?;
        user
    };

    let client = state
        .repos
        .clients()
        .find_by_client_id(client_id)
        .await?
        .ok_or(AuthError::ClientNotFound)?;

    super::auth::complete_login(state, &user, &client).await
}

fn normalize_phone(phone: &str) -> String {
    phone
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == '+')
        .collect()
}
