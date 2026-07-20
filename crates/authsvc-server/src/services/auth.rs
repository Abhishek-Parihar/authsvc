use authsvc_core::{
    client::CreateOAuthClient,
    user::CreateUser,
    website::ClientType,
    AccountOption, AccountRepository, AuthError, ClientRepository, MembershipRepository,
    RefreshTokenRepository, TokenContext, UserRepository, WebsiteRepository,
};
use chrono::{Duration, Utc};
use uuid::Uuid;

use super::{login_selection, state::AppState};
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_selection_required: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selection_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accounts: Option<Vec<AccountOption>>,
}

fn empty_token_response() -> TokenResponse {
    TokenResponse {
        access_token: String::new(),
        token_type: "Bearer".into(),
        expires_in: 0,
        refresh_token: None,
        scope: String::new(),
        id_token: None,
        mfa_required: None,
        mfa_challenge_id: None,
        account_selection_required: None,
        selection_id: None,
        accounts: None,
    }
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

    let account = AccountRepository::find_by_slug(&state.store, &state.config.default_account_slug)
        .await?
        .ok_or_else(|| AuthError::NotFound("account".into()))?;

    let hash = hash_password(password)?;
    let user = UserRepository::create(
        &state.store,
        &CreateUser {
            email: email.to_lowercase(),
            password: password.to_string(),
            display_name,
        },
        &hash,
    )
    .await?;

    state
        .store
        .assign_admin_membership(user.id, account.id)
        .await?;
    state
        .audit(
            Some(account.id),
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

    let user = match UserRepository::find_by_email(&state.store, &email.to_lowercase()).await? {
        Some(u) => u,
        None => {
            state
                .audit(
                    None,
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
                None,
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
        let client = ClientRepository::find_by_client_id(&state.store, client_id)
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
        let mut resp = empty_token_response();
        resp.mfa_required = Some(true);
        resp.mfa_challenge_id = Some(challenge_id.to_string());
        return Ok(resp);
    }

    let client = ClientRepository::find_by_client_id(&state.store, client_id)
        .await?
        .ok_or(AuthError::ClientNotFound)?;

    crate::observability::record_login(true);
    complete_login(state, &user, &client).await
}

pub async fn complete_login(
    state: &AppState,
    user: &authsvc_core::User,
    client: &authsvc_core::OAuthClient,
) -> Result<TokenResponse, AuthError> {
    let options = login_selection::list_account_options(state, user.id).await?;
    let active: Vec<_> = options
        .into_iter()
        .filter(|a| a.status == "active")
        .collect();

    if active.len() > 1 {
        let selection_id =
            login_selection::create_login_selection(state, user.id, &client.client_id).await?;
        let mut resp = empty_token_response();
        resp.account_selection_required = Some(true);
        resp.selection_id = Some(selection_id.to_string());
        resp.accounts = Some(active);
        return Ok(resp);
    }

    let account_id = if let Some(acc) = active.first() {
        acc.account_id
    } else {
        state.store.website_account_id(client.website_id).await?
    };

    issue_user_tokens_for_account(state, user, client, account_id).await
}

pub async fn complete_account_selection(
    state: &AppState,
    selection_id: Uuid,
    account_id: Uuid,
) -> Result<TokenResponse, AuthError> {
    let selection = login_selection::consume_login_selection(state, selection_id).await?;
    let user = UserRepository::find_by_id(&state.store, selection.user_id)
        .await?
        .ok_or(AuthError::UserNotFound)?;
    let client = ClientRepository::find_by_client_id(&state.store, &selection.client_id)
        .await?
        .ok_or(AuthError::ClientNotFound)?;

    let member =
        MembershipRepository::get_account_member(&state.store, account_id, user.id).await?;
    if member.as_ref().map(|m| m.status.as_str()) != Some("active") {
        return Err(AuthError::Forbidden);
    }

    issue_user_tokens_for_account(state, &user, &client, account_id).await
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

    let client = ClientRepository::find_by_client_id(&state.store, client_id)
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

    let account_id = state.store.website_account_id(client.website_id).await?;
    let scopes = client.scopes.clone();
    let (access_token, _) = state.jwt.issue_access_token(
        client.id,
        account_id,
        Some(client.website_id),
        Some(&client.client_id),
        &scopes,
    )?;

    let mut resp = empty_token_response();
    resp.access_token = access_token;
    resp.expires_in = state.config.access_token_ttl_secs;
    resp.scope = scopes.join(" ");
    Ok(resp)
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

    issue_user_tokens_with_family(state, &user, &client, record.account_id, record.family_id).await
}

pub async fn issue_user_tokens(
    state: &AppState,
    user: &authsvc_core::User,
    client: &authsvc_core::OAuthClient,
) -> Result<TokenResponse, AuthError> {
    let account_id = state.store.website_account_id(client.website_id).await?;
    issue_user_tokens_for_account(state, user, client, account_id).await
}

pub async fn issue_user_tokens_for_account(
    state: &AppState,
    user: &authsvc_core::User,
    client: &authsvc_core::OAuthClient,
    account_id: Uuid,
) -> Result<TokenResponse, AuthError> {
    issue_user_tokens_with_family(state, user, client, account_id, Uuid::new_v4()).await
}

async fn resolve_token_context(
    state: &AppState,
    user_id: Uuid,
    client: &authsvc_core::OAuthClient,
    account_id: Uuid,
) -> Result<TokenContext, AuthError> {
    let member =
        MembershipRepository::get_account_member(&state.store, account_id, user_id).await?;
    if member.as_ref().map(|m| m.status.as_str()) != Some("active") {
        return Err(AuthError::Forbidden);
    }
    Ok(TokenContext {
        account_id,
        website_id: client.website_id,
    })
}

async fn issue_user_tokens_with_family(
    state: &AppState,
    user: &authsvc_core::User,
    client: &authsvc_core::OAuthClient,
    account_id: Uuid,
    family_id: Uuid,
) -> Result<TokenResponse, AuthError> {
    let ctx = resolve_token_context(state, user.id, client, account_id).await?;
    let scopes = if client.scopes.is_empty() {
        vec!["openid".into(), "profile".into()]
    } else {
        client.scopes.clone()
    };

    let (access_token, _) = state.jwt.issue_access_token(
        user.id,
        ctx.account_id,
        Some(ctx.website_id),
        Some(&client.client_id),
        &scopes,
    )?;

    let id_token = if scopes.iter().any(|s| s == "openid") {
        Some(state.jwt.issue_id_token(
            user,
            ctx.account_id,
            Some(ctx.website_id),
        )?)
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
            ctx.account_id,
            family_id,
            expires_at,
        )
        .await?;

    crate::observability::record_token_issued();
    let mut resp = empty_token_response();
    resp.access_token = access_token;
    resp.expires_in = state.config.access_token_ttl_secs;
    resp.refresh_token = Some(refresh);
    resp.scope = scopes.join(" ");
    resp.id_token = id_token;
    Ok(resp)
}

pub async fn create_oauth_client(
    state: &AppState,
    name: &str,
    redirect_uris: Vec<String>,
) -> Result<(authsvc_core::OAuthClient, Option<String>), AuthError> {
    let account = AccountRepository::find_by_slug(&state.store, &state.config.default_account_slug)
        .await?
        .ok_or_else(|| AuthError::NotFound("account".into()))?;

    let website = WebsiteRepository::find_by_slug(
        &state.store,
        account.id,
        &state.config.default_website_slug,
    )
    .await?
    .ok_or_else(|| AuthError::NotFound("website".into()))?;

    let client_id = format!("cli_{}", &Uuid::new_v4().to_string().replace('-', "")[..16]);
    ClientRepository::create(
        &state.store,
        &CreateOAuthClient {
            website_id: website.id,
            name: name.to_string(),
            client_type: ClientType::Web,
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
                Some(record.account_id),
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
