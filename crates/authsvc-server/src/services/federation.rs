use authsvc_core::AuthError;
use chrono::{Duration, Utc};
use std::sync::Arc;
use uuid::Uuid;

use super::{auth, idp_config, platform, state::AppState};
use crate::crypto::password::hash_password;

async fn resolve_provider(
    state: &AppState,
    account_id: Uuid,
    provider: &str,
    redirect_uri: &str,
) -> Result<Arc<dyn authsvc_idp::IdentityProvider>, AuthError> {
    if let Ok(idp) = idp_config::resolve_oidc_provider(state, account_id, provider, redirect_uri).await
    {
        return Ok(idp);
    }
    if let Some((_, _, config)) = state.repos.idp_configs().get(account_id, provider).await? {
        if config.get("type").and_then(|v| v.as_str()) == Some("saml") {
            return Ok(Arc::new(authsvc_idp::saml::SamlProvider::from_config(
                &config,
                &state.config.issuer,
            )?));
        }
    }
    state.idp_registry.get(provider)
}

pub async fn start_federation(
    state: &AppState,
    provider: &str,
    account_id: Option<Uuid>,
) -> Result<String, AuthError> {
    let account = match account_id {
        Some(id) => state
            .repos
            .accounts()
            .find_by_id(id)
            .await?
            .ok_or(AuthError::NotFound("account".into()))?,
        None => platform::default_account(state).await?,
    };

    let redirect = format!("{}/oauth/federate/{provider}/callback", state.config.issuer);
    let idp = resolve_provider(state, account.id, provider, &redirect).await?;
    let federation_state = Uuid::new_v4().to_string();
    state
        .repos
        .federation()
        .store_federation_state(
            &federation_state,
            account.id,
            provider,
            Utc::now() + Duration::minutes(10),
        )
        .await?;

    idp.authorization_url(&federation_state, &redirect)
}

pub async fn federation_callback(
    state: &AppState,
    state_param: &str,
    code: &str,
    client_id: &str,
    saml_request_id: Option<&str>,
) -> Result<auth::TokenResponse, AuthError> {
    let (account_id, provider) = state
        .repos
        .federation()
        .consume_federation_state(state_param)
        .await?
        .ok_or(AuthError::InvalidToken)?;

    let redirect = format!("{}/oauth/federate/{provider}/callback", state.config.issuer);
    let idp = resolve_provider(state, account_id, &provider, &redirect).await?;

    let fed = if let Some((_, _, config)) = state
        .repos
        .idp_configs()
        .get(account_id, &provider)
        .await?
    {
        if config.get("type").and_then(|v| v.as_str()) == Some("saml") {
            let saml =
                authsvc_idp::saml::SamlProvider::from_config(&config, &state.config.issuer)?;
            saml.parse_response(code, saml_request_id)?
        } else {
            idp.exchange_code(code, &redirect).await?
        }
    } else {
        idp.exchange_code(code, &redirect).await?
    };

    let user_id = if let Some(uid) = state
        .repos
        .federation()
        .find_identity(&provider, &fed.subject)
        .await?
    {
        if state
            .repos
            .memberships()
            .get_account_member(account_id, uid)
            .await?
            .is_none()
        {
            state
                .repos
                .memberships()
                .add_account_member(account_id, uid, None)
                .await?;
        }
        uid
    } else if let Some(email) = &fed.email {
        let user = match state.repos.users().find_by_email(email).await? {
            Some(u) => u,
            None => {
                let pwd = Uuid::new_v4().to_string();
                let hash = hash_password(&pwd)?;
                let user = state
                    .repos
                    .users()
                    .create(
                        &authsvc_core::user::CreateUser {
                            email: email.to_lowercase(),
                            password: pwd,
                            display_name: fed.name.clone(),
                        },
                        &hash,
                    )
                    .await?;
                state
                    .repos
                    .memberships()
                    .add_account_member(account_id, user.id, None)
                    .await?;
                user
            }
        };
        if state
            .repos
            .memberships()
            .get_account_member(account_id, user.id)
            .await?
            .is_none()
        {
            state
                .repos
                .memberships()
                .add_account_member(account_id, user.id, None)
                .await?;
        }
        state
            .repos
            .federation()
            .link_identity(user.id, &provider, &fed.subject, fed.email.as_deref())
            .await?;
        user.id
    } else {
        return Err(AuthError::Validation("federated user has no email".into()));
    };

    let user = state
        .repos
        .users()
        .find_by_id(user_id)
        .await?
        .ok_or(AuthError::UserNotFound)?;
    let client = state
        .repos
        .clients()
        .find_by_client_id(client_id)
        .await?
        .ok_or(AuthError::ClientNotFound)?;

    state
        .audit(
            Some(account_id),
            Some(&user.id.to_string()),
            "login.federated",
            Some(&provider),
            None,
            serde_json::json!({"provider": provider}),
        )
        .await?;

    auth::issue_user_tokens_for_account(state, &user, &client, account_id).await
}
