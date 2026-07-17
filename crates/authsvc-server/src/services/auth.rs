use std::sync::Arc;

use authsvc_core::{
    client::CreateOAuthClient, user::CreateUser, AuthError, ClientRepository, RefreshTokenRepository,
    RoleRepository, TenantRepository, UserRepository,
};
use chrono::{Duration, Utc};
use uuid::Uuid;

use crate::{
    crypto::{
        jwt::{JwtSigner, SharedJwtSigner},
        password::{generate_refresh_token, hash_password, hash_token, verify_password, verify_secret},
    },
    stores::{PostgresStore, RedisSessionStore},
};

#[derive(Clone)]
pub struct AppState {
    pub store: PostgresStore,
    pub sessions: RedisSessionStore,
    pub jwt: SharedJwtSigner,
    pub refresh_ttl_secs: u64,
    pub session_ttl_secs: u64,
    pub default_tenant_slug: String,
}

impl AppState {
    pub async fn new(
        store: PostgresStore,
        sessions: RedisSessionStore,
        jwt: JwtSigner,
        refresh_ttl_secs: u64,
        session_ttl_secs: u64,
        default_tenant_slug: String,
    ) -> Result<Self, AuthError> {
        store.migrate().await?;
        store.ensure_default().await?;
        Ok(Self {
            store,
            sessions,
            jwt: Arc::new(jwt),
            refresh_ttl_secs,
            session_ttl_secs,
            default_tenant_slug,
        })
    }
}

#[derive(Debug, serde::Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub refresh_token: Option<String>,
    pub scope: String,
}

pub async fn register_user(
    state: &AppState,
    email: &str,
    password: &str,
    display_name: Option<String>,
) -> Result<authsvc_core::User, AuthError> {
    if password.len() < 8 {
        return Err(AuthError::Validation(
            "password must be at least 8 characters".into(),
        ));
    }

    let tenant = state
        .store
        .find_by_slug(&state.default_tenant_slug)
        .await?
        .ok_or_else(|| AuthError::NotFound("tenant".into()))?;

    let hash = hash_password(password)?;
    let user = UserRepository::create(
        &state.store,
        &CreateUser {
            tenant_id: tenant.id,
            email: email.to_lowercase(),
            password: password.to_string(),
            display_name,
        },
        &hash,
    )
    .await?;

    state.store.assign_admin_role(user.id, tenant.id).await?;
    Ok(user)
}

pub async fn password_login(
    state: &AppState,
    email: &str,
    password: &str,
    client_id: &str,
) -> Result<TokenResponse, AuthError> {
    let tenant = state
        .store
        .find_by_slug(&state.default_tenant_slug)
        .await?
        .ok_or_else(|| AuthError::NotFound("tenant".into()))?;

    let user = state
        .store
        .find_by_email(tenant.id, &email.to_lowercase())
        .await?
        .ok_or(AuthError::InvalidCredentials)?;

    if let Some(until) = user.locked_until {
        if until > Utc::now() {
            return Err(AuthError::AccountLocked(until.to_rfc3339()));
        }
    }

    let hash = user
        .password_hash
        .as_deref()
        .ok_or(AuthError::InvalidCredentials)?;
    if !verify_password(password, hash)? {
        return Err(AuthError::InvalidCredentials);
    }

    let client = state
        .store
        .find_by_client_id(client_id)
        .await?
        .ok_or(AuthError::ClientNotFound)?;

    issue_user_tokens(state, &user, &client).await
}

pub async fn client_credentials_grant(
    state: &AppState,
    client_id: &str,
    client_secret: &str,
) -> Result<TokenResponse, AuthError> {
    let client = state
        .store
        .find_by_client_id(client_id)
        .await?
        .ok_or(AuthError::InvalidClientCredentials)?;

    if !client.is_confidential {
        return Err(AuthError::InvalidClientCredentials);
    }

    let secret_hash = client
        .client_secret_hash
        .as_deref()
        .ok_or(AuthError::InvalidClientCredentials)?;

    if !verify_secret(client_secret, secret_hash)? {
        return Err(AuthError::InvalidClientCredentials);
    }

    let subject = client.id;
    let scopes = client.scopes.clone();
    let (access_token, _) = state.jwt.issue_access_token(
        subject,
        client.tenant_id,
        Some(&client.client_id),
        &scopes,
    )?;

    Ok(TokenResponse {
        access_token,
        token_type: "Bearer".into(),
        expires_in: 900,
        refresh_token: None,
        scope: scopes.join(" "),
    })
}

pub async fn refresh_token_grant(
    state: &AppState,
    refresh_token: &str,
    client_id: &str,
) -> Result<TokenResponse, AuthError> {
    let client = state
        .store
        .find_by_client_id(client_id)
        .await?
        .ok_or(AuthError::ClientNotFound)?;

    let token_hash = hash_token(refresh_token);
    let record = state
        .store
        .consume(&token_hash)
        .await?
        .ok_or(AuthError::InvalidToken)?;

    if record.client_id != client.id {
        return Err(AuthError::InvalidToken);
    }

    let user = match record.user_id {
        Some(uid) => UserRepository::find_by_id(&state.store, uid)
            .await?
            .ok_or(AuthError::UserNotFound)?,
        None => return Err(AuthError::InvalidToken),
    };

    issue_user_tokens_with_family(state, &user, &client, record.family_id).await
}

async fn issue_user_tokens(
    state: &AppState,
    user: &authsvc_core::User,
    client: &authsvc_core::OAuthClient,
) -> Result<TokenResponse, AuthError> {
    issue_user_tokens_with_family(state, user, client, Uuid::new_v4()).await
}

async fn issue_user_tokens_with_family(
    state: &AppState,
    user: &authsvc_core::User,
    client: &authsvc_core::OAuthClient,
    family_id: Uuid,
) -> Result<TokenResponse, AuthError> {
    let scopes = if client.scopes.is_empty() {
        vec!["openid".into(), "profile".into()]
    } else {
        client.scopes.clone()
    };

    let (access_token, _) = state
        .jwt
        .issue_access_token(user.id, user.tenant_id, Some(&client.client_id), &scopes)?;

    let refresh = generate_refresh_token();
    let refresh_hash = hash_token(&refresh);
    let expires_at = Utc::now() + Duration::seconds(state.refresh_ttl_secs as i64);

    state
        .store
        .store(
            &refresh_hash,
            Some(user.id),
            client.id,
            user.tenant_id,
            family_id,
            expires_at,
        )
        .await?;

    Ok(TokenResponse {
        access_token,
        token_type: "Bearer".into(),
        expires_in: 900,
        refresh_token: Some(refresh),
        scope: scopes.join(" "),
    })
}

pub async fn create_oauth_client(
    state: &AppState,
    name: &str,
) -> Result<(authsvc_core::OAuthClient, Option<String>), AuthError> {
    let tenant = state
        .store
        .find_by_slug(&state.default_tenant_slug)
        .await?
        .ok_or_else(|| AuthError::NotFound("tenant".into()))?;

    let client_id = format!("cli_{}", &Uuid::new_v4().to_string().replace('-', "")[..16]);
    ClientRepository::create(
        &state.store,
        &CreateOAuthClient {
            tenant_id: tenant.id,
            name: name.to_string(),
            grant_types: vec![
                "password".into(),
                "refresh_token".into(),
                "client_credentials".into(),
            ],
            redirect_uris: vec![],
            scopes: vec!["openid".into(), "profile".into()],
            is_confidential: true,
        },
        &client_id,
        None,
    )
    .await
}

pub async fn revoke_refresh_token(state: &AppState, token: &str) -> Result<(), AuthError> {
    let token_hash = hash_token(token);
    if let Some(record) = state.store.consume(&token_hash).await? {
        state.store.revoke_family(record.family_id).await?;
    }
    Ok(())
}
