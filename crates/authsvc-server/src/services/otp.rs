use authsvc_core::{
    AccountRepository, AuthError, ClientRepository, MembershipRepository, UserRepository,
};
use chrono::{Duration, Utc};
use rand::Rng;

use super::{
    auth::TokenResponse,
    state::AppState,
};
use crate::crypto::password::{generate_refresh_token, hash_password, hash_token};

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
        .store
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
    if !state.store.consume_email_otp(&email, &code_hash).await? {
        return Err(AuthError::InvalidCredentials);
    }

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
            MembershipRepository::add_account_member(&state.store, account.id, user.id, None)
                .await?;
            user
        }
    };

    let client = ClientRepository::find_by_client_id(&state.store, client_id)
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
        .store
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
    if !state.store.consume_phone_otp(&phone, &code_hash).await? {
        return Err(AuthError::InvalidCredentials);
    }

    let account = AccountRepository::find_by_slug(&state.store, &state.config.default_account_slug)
        .await?
        .ok_or_else(|| AuthError::NotFound("account".into()))?;

    let user = if let Some(user_id) = state.store.find_user_id_by_phone(&phone).await? {
        UserRepository::find_by_id(&state.store, user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?
    } else {
        let email = format!("{phone}@phone.authsvc.local");
        let pwd = generate_refresh_token();
        let hash = hash_password(&pwd)?;
        let user = UserRepository::create(
            &state.store,
            &authsvc_core::user::CreateUser {
                email,
                password: pwd,
                display_name: None,
            },
            &hash,
        )
        .await?;
        MembershipRepository::add_account_member(&state.store, account.id, user.id, None)
            .await?;
        state.store.link_verified_phone(user.id, &phone).await?;
        user
    };

    let client = ClientRepository::find_by_client_id(&state.store, client_id)
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
