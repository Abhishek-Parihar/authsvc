use authsvc_core::{AuthError, ClientRepository, TenantRepository, UserRepository};
use chrono::{Duration, Utc};
use uuid::Uuid;

use super::{auth, state::AppState};
use crate::crypto::password::hash_password;

pub async fn start_federation(
    state: &AppState,
    provider: &str,
) -> Result<String, AuthError> {
    let tenant = TenantRepository::find_by_slug(&state.store, &state.config.default_tenant_slug)
        .await?
        .ok_or_else(|| AuthError::NotFound("tenant".into()))?;

    let idp = state.idp_registry.get(provider)?;
    let federation_state = Uuid::new_v4().to_string();
    state
        .store
        .store_federation_state(
            &federation_state,
            tenant.id,
            provider,
            Utc::now() + Duration::minutes(10),
        )
        .await?;

    let redirect = format!("{}/oauth/federate/{provider}/callback", state.config.issuer);
    idp.authorization_url(&federation_state, &redirect)
}

pub async fn federation_callback(
    state: &AppState,
    state_param: &str,
    code: &str,
    client_id: &str,
) -> Result<auth::TokenResponse, AuthError> {
    let (tenant_id, provider) = state
        .store
        .consume_federation_state(state_param)
        .await?
        .ok_or(AuthError::InvalidToken)?;

    let idp = state.idp_registry.get(&provider)?;
    let redirect = format!("{}/oauth/federate/{provider}/callback", state.config.issuer);
    let fed = idp.exchange_code(code, &redirect).await?;

    let user_id = if let Some(uid) = state.store.find_identity(&provider, &fed.subject).await? {
        uid
    } else if let Some(email) = &fed.email {
        let user = match state.store.find_by_email(tenant_id, email).await? {
            Some(u) => u,
            None => {
                let pwd = Uuid::new_v4().to_string();
                let hash = hash_password(&pwd)?;
                UserRepository::create(
                    &state.store,
                    &authsvc_core::user::CreateUser {
                        tenant_id,
                        email: email.to_lowercase(),
                        password: pwd,
                        display_name: fed.name.clone(),
                    },
                    &hash,
                )
                .await?
            }
        };
        state
            .store
            .link_identity(user.id, tenant_id, &provider, &fed.subject, fed.email.as_deref())
            .await?;
        user.id
    } else {
        return Err(AuthError::Validation("federated user has no email".into()));
    };

    let user = UserRepository::find_by_id(&state.store, user_id)
        .await?
        .ok_or(AuthError::UserNotFound)?;
    let client = state
        .store
        .find_by_client_id(client_id)
        .await?
        .ok_or(AuthError::ClientNotFound)?;

    state
        .audit(
            Some(tenant_id),
            Some(&user.id.to_string()),
            "login.federated",
            Some(&provider),
            None,
            serde_json::json!({"provider": provider}),
        )
        .await?;

    auth::issue_user_tokens(state, &user, &client).await
}
