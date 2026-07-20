use authsvc_core::{
    account::{Account, CreateAccount},
    AuthError,
};
use serde_json::{json, Value};
use uuid::Uuid;

use super::{api_keys, ops, platform, state::AppState};

pub async fn create_account(state: &AppState, slug: &str, name: &str) -> Result<Account, AuthError> {
    state
        .repos
        .accounts()
        .create(&CreateAccount {
            slug: slug.to_string(),
            name: name.to_string(),
        })
        .await
}

pub async fn get_account(state: &AppState, id: Uuid) -> Result<Account, AuthError> {
    state
        .repos
        .accounts()
        .find_by_id(id)
        .await?
        .ok_or_else(|| AuthError::NotFound("account".into()))
}

pub async fn create_website(
    state: &AppState,
    account_id: Uuid,
    slug: &str,
    name: &str,
    domain: Option<&str>,
) -> Result<Value, AuthError> {
    state
        .repos
        .admin()
        .create_website(account_id, slug, name, domain)
        .await
}

pub async fn list_default_clients(state: &AppState) -> Result<Vec<Value>, AuthError> {
    let website = platform::default_website(state).await?;
    state.repos.admin().list_clients(website.id).await
}

pub async fn delete_client(state: &AppState, id: Uuid) -> Result<(), AuthError> {
    state.repos.admin().delete_client(id).await
}

pub async fn create_role(
    state: &AppState,
    account_id: Uuid,
    name: &str,
    description: Option<&str>,
) -> Result<authsvc_core::Role, AuthError> {
    state
        .repos
        .admin()
        .create_role(account_id, name, description)
        .await
}

pub async fn create_permission(
    state: &AppState,
    account_id: Uuid,
    resource: &str,
    action: &str,
) -> Result<authsvc_core::Permission, AuthError> {
    state
        .repos
        .admin()
        .create_permission(account_id, resource, action)
        .await
}

pub async fn assign_user_role(
    state: &AppState,
    user_id: Uuid,
    role_id: Uuid,
) -> Result<(), AuthError> {
    state.repos.roles().assign_role(user_id, role_id).await?;
    if let Ok(account_id) = platform::default_account_id(state).await {
        let _ = super::cache_layer::invalidate_user_permissions(state, user_id, account_id).await;
    }
    Ok(())
}

pub async fn create_api_key(
    state: &AppState,
    account_id: Uuid,
    name: &str,
    scopes: Vec<String>,
) -> Result<(Uuid, String), AuthError> {
    api_keys::create_api_key(state, account_id, name, scopes).await
}

pub async fn revoke_api_key(state: &AppState, id: Uuid) -> Result<(), AuthError> {
    api_keys::revoke_api_key(state, id).await
}

pub async fn create_webhook(
    state: &AppState,
    account_id: Uuid,
    url: &str,
    events: Vec<String>,
) -> Result<(Uuid, String), AuthError> {
    let secret = Uuid::new_v4().to_string();
    let encrypted_secret =
        crate::crypto::secrets::encrypt_string(&state.data_keys, "webhook_secret", &secret).await?;
    let id = state
        .repos
        .webhooks()
        .create_webhook(account_id, url, &encrypted_secret, &events)
        .await?;
    Ok((id, secret))
}

pub async fn rotate_keys(state: &AppState) -> Result<String, AuthError> {
    ops::rotate_keys(state).await
}

pub async fn create_casbin_rule(
    state: &AppState,
    account_id: Uuid,
    ptype: &str,
    v0: Option<&str>,
    v1: Option<&str>,
    v2: Option<&str>,
    v3: Option<&str>,
    v4: Option<&str>,
    v5: Option<&str>,
) -> Result<i32, AuthError> {
    let id = state
        .repos
        .admin()
        .create_casbin_rule(account_id, ptype, v0, v1, v2, v3, v4, v5)
        .await?;
    state.policy.invalidate_casbin(account_id);
    Ok(id)
}

pub async fn delete_casbin_rule(state: &AppState, id: i32) -> Result<(), AuthError> {
    state.repos.admin().delete_casbin_rule(id).await
}

pub async fn list_casbin_rules(
    state: &AppState,
    account_id: Uuid,
) -> Result<
    Vec<(
        i32,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    )>,
    AuthError,
> {
    state.repos.admin().list_casbin_rules(account_id).await
}

pub async fn add_role_inheritance(
    state: &AppState,
    child_role_id: Uuid,
    parent_role_id: Uuid,
) -> Result<(), AuthError> {
    state
        .repos
        .admin()
        .add_role_inheritance(child_role_id, parent_role_id)
        .await?;
    state
        .audit(
            None,
            None,
            "roles.inherit",
            Some("role_hierarchy"),
            None,
            json!({"child_role_id": child_role_id, "parent_role_id": parent_role_id}),
        )
        .await
}

pub async fn remove_role_inheritance(
    state: &AppState,
    child_role_id: Uuid,
    parent_role_id: Uuid,
) -> Result<(), AuthError> {
    state
        .repos
        .admin()
        .remove_role_inheritance(child_role_id, parent_role_id)
        .await?;
    state
        .audit(
            None,
            None,
            "roles.uninherit",
            Some("role_hierarchy"),
            None,
            json!({"child_role_id": child_role_id, "parent_role_id": parent_role_id}),
        )
        .await
}

pub async fn default_account_id(state: &AppState) -> Result<Uuid, AuthError> {
    platform::default_account_id(state).await
}
