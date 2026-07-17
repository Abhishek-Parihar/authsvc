use authsvc_core::{
    client::CreateOAuthClient, user::CreateUser, AuthError, ClientRepository, RefreshTokenRepository,
    TenantRepository, UserRepository,
};
use chrono::{Duration, Utc};
use uuid::Uuid;

use super::state::AppState;
use crate::crypto::{
    jwt::AccessTokenClaims,
    password::{generate_refresh_token, hash_password, hash_token, verify_password, verify_secret},
};

#[derive(Debug, serde::Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub refresh_token: Option<String>,
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mfa_required: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mfa_challenge_id: Option<String>,
}

pub async fn validate_bearer_token(state: &AppState, token: &str) -> Result<AccessTokenClaims, AuthError> {
    state.jwt.validate_access_token(token)
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

    let tenant = TenantRepository::find_by_slug(&state.store, &state.config.default_tenant_slug)
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
    state
        .audit(
            Some(tenant.id),
            Some(&user.id.to_string()),
            "user.created",
            Some("users"),
            None,
            serde_json::json!({"email": user.email}),
        )
        .await?;
    Ok(user)
}

pub async fn password_login(
    state: &AppState,
    email: &str,
    password: &str,
    client_id: &str,
    ip: Option<&str>,
) -> Result<TokenResponse, AuthError> {
    state.rate_limiter.check(&format!("login:{email}")).await?;

    let tenant = TenantRepository::find_by_slug(&state.store, &state.config.default_tenant_slug)
        .await?
        .ok_or_else(|| AuthError::NotFound("tenant".into()))?;

    let user = match state
        .store
        .find_by_email(tenant.id, &email.to_lowercase())
        .await?
    {
        Some(u) => u,
        None => {
            state
                .audit(
                    Some(tenant.id),
                    None,
                    "login.failed",
                    Some("users"),
                    ip,
                    serde_json::json!({"email": email}),
                )
                .await?;
            crate::observability::record_login(false);
            return Err(AuthError::InvalidCredentials);
        }
    };

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
        state.record_failed_login(email, user.id).await?;
        state
            .audit(
                Some(tenant.id),
                Some(&user.id.to_string()),
                "login.failed",
                Some("users"),
                ip,
                serde_json::json!({"email": email}),
            )
            .await?;
        crate::observability::record_login(false);
        return Err(AuthError::InvalidCredentials);
    }

    state.clear_failed_login(email).await?;

    if user.mfa_enabled {
        let challenge_id = Uuid::new_v4();
        let client = state
            .store
            .find_by_client_id(client_id)
            .await?
            .ok_or(AuthError::ClientNotFound)?;
        state
            .store
            .store_mfa_challenge(
                challenge_id,
                user.id,
                client.id,
                Utc::now() + Duration::minutes(5),
            )
            .await?;
        return Ok(TokenResponse {
            access_token: String::new(),
            token_type: "Bearer".into(),
            expires_in: 0,
            refresh_token: None,
            scope: String::new(),
            id_token: None,
            mfa_required: Some(true),
            mfa_challenge_id: Some(challenge_id.to_string()),
        });
    }

    let client = ClientRepository::find_by_client_id(&state.store, client_id)
        .await?
        .ok_or(AuthError::ClientNotFound)?;

    crate::observability::record_login(true);
    issue_user_tokens(state, &user, &client).await
}

pub async fn client_credentials_grant(
    state: &AppState,
    client_id: &str,
    client_secret: &str,
) -> Result<TokenResponse, AuthError> {
    state
        .rate_limiter
        .check(&format!("token:{client_id}"))
        .await?;

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

    let scopes = client.scopes.clone();
    let (access_token, _) = state.jwt.issue_access_token(
        client.id,
        client.tenant_id,
        Some(&client.client_id),
        &scopes,
    )?;

    Ok(TokenResponse {
        access_token,
        token_type: "Bearer".into(),
        expires_in: state.config.access_token_ttl_secs,
        refresh_token: None,
        scope: scopes.join(" "),
        id_token: None,
        mfa_required: None,
        mfa_challenge_id: None,
    })
}

pub async fn refresh_token_grant(
    state: &AppState,
    refresh_token: &str,
    client_id: &str,
) -> Result<TokenResponse, AuthError> {
    let client = ClientRepository::find_by_client_id(&state.store, client_id)
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

pub async fn issue_user_tokens(
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

    let id_token = if scopes.iter().any(|s| s == "openid") {
        Some(state.jwt.issue_id_token(user)?)
    } else {
        None
    };

    let refresh = generate_refresh_token();
    let refresh_hash = hash_token(&refresh);
    let expires_at = Utc::now() + Duration::seconds(state.config.refresh_token_ttl_secs as i64);

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

    crate::observability::record_token_issued();
    Ok(TokenResponse {
        access_token,
        token_type: "Bearer".into(),
        expires_in: state.config.access_token_ttl_secs,
        refresh_token: Some(refresh),
        scope: scopes.join(" "),
        id_token,
        mfa_required: None,
        mfa_challenge_id: None,
    })
}

pub async fn create_oauth_client(
    state: &AppState,
    name: &str,
    redirect_uris: Vec<String>,
) -> Result<(authsvc_core::OAuthClient, Option<String>), AuthError> {
    let tenant = TenantRepository::find_by_slug(&state.store, &state.config.default_tenant_slug)
        .await?
        .ok_or_else(|| AuthError::NotFound("tenant".into()))?;

    let client_id = format!("cli_{}", &Uuid::new_v4().to_string().replace('-', "")[..16]);
    ClientRepository::create(
        &state.store,
        &CreateOAuthClient {
            tenant_id: tenant.id,
            name: name.to_string(),
            grant_types: vec![
                "authorization_code".into(),
                "password".into(),
                "refresh_token".into(),
                "client_credentials".into(),
            ],
            redirect_uris,
            scopes: vec!["openid".into(), "profile".into(), "email".into()],
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
        state
            .audit(
                Some(record.tenant_id),
                record.user_id.map(|u| u.to_string()).as_deref(),
                "token.revoked",
                Some("tokens"),
                None,
                serde_json::json!({}),
            )
            .await?;
    }
    Ok(())
}
