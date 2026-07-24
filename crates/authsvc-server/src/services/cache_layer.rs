use authsvc_core::AuthError;
use uuid::Uuid;

use super::state::AppState;

const CLIENT_TTL: u64 = 300;
const USER_TTL: u64 = 60;
const JWKS_TTL: u64 = 60;

pub async fn cached_user(
    state: &AppState,
    user_id: Uuid,
) -> Result<authsvc_core::User, AuthError> {
    let key = format!("cache:user:{user_id}");
    if let Some(user) = state
        .sessions
        .get_json::<authsvc_core::User>(&key)
        .await?
    {
        return Ok(user);
    }
    let user = state
        .repos
        .users()
        .find_by_id(user_id)
        .await?
        .ok_or(AuthError::UserNotFound)?;
    state.sessions.set_json(&key, &user, USER_TTL).await?;
    Ok(user)
}

pub async fn cached_client(
    state: &AppState,
    client_id: &str,
) -> Result<Option<authsvc_core::OAuthClient>, AuthError> {
    let key = format!("cache:client:{client_id}");
    if let Some(client) = state
        .sessions
        .get_json::<authsvc_core::OAuthClient>(&key)
        .await?
    {
        return Ok(Some(client));
    }
    let client = state.repos.clients().find_by_client_id(client_id).await?;
    if let Some(ref c) = client {
        state.sessions.set_json(&key, c, CLIENT_TTL).await?;
    }
    Ok(client)
}

pub async fn invalidate_client_cache(state: &AppState, client_id: &str) -> Result<(), AuthError> {
    state
        .sessions
        .delete_key(&format!("cache:client:{client_id}"))
        .await
}

pub async fn cached_permissions(
    state: &AppState,
    user_id: Uuid,
    account_id: Uuid,
    website_id: Option<Uuid>,
) -> Result<Vec<authsvc_core::Permission>, AuthError> {
    let key = format!("cache:perms:{user_id}:{account_id}:{website_id:?}");
    if let Some(perms) = state
        .sessions
        .get_json::<Vec<authsvc_core::Permission>>(&key)
        .await?
    {
        return Ok(perms);
    }
    let perms = state
        .repos
        .roles()
        .list_user_permissions(user_id, account_id, website_id)
        .await?;
    state.sessions.set_json(&key, &perms, JWKS_TTL).await?;
    Ok(perms)
}

pub async fn invalidate_user_permissions(
    state: &AppState,
    user_id: Uuid,
    account_id: Uuid,
) -> Result<(), AuthError> {
    state
        .sessions
        .delete_key(&format!("cache:perms:{user_id}:{account_id}:None"))
        .await
}
