use authsvc_core::{Account, AuthError, Website};

use super::state::AppState;

pub async fn default_account(state: &AppState) -> Result<Account, AuthError> {
    state
        .repos
        .accounts()
        .find_by_slug(&state.config.default_account_slug)
        .await?
        .ok_or_else(|| AuthError::NotFound("account".into()))
}

pub async fn default_website(state: &AppState) -> Result<Website, AuthError> {
    let account = default_account(state).await?;
    state
        .repos
        .websites()
        .find_by_slug(account.id, &state.config.default_website_slug)
        .await?
        .ok_or_else(|| AuthError::NotFound("website".into()))
}

pub async fn default_account_id(state: &AppState) -> Result<uuid::Uuid, AuthError> {
    Ok(default_account(state).await?.id)
}
