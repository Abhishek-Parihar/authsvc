use authsvc_core::{AccountOption, PortalStore};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginSelection {
    pub user_id: Uuid,
    pub client_id: String,
}

const SELECTION_TTL_SECS: u64 = 600;

pub async fn create_login_selection(
    state: &super::state::AppState,
    user_id: Uuid,
    client_id: &str,
) -> Result<Uuid, authsvc_core::AuthError> {
    let selection_id = Uuid::new_v4();
    state
        .sessions
        .set_json(
            &format!("login_selection:{selection_id}"),
            &LoginSelection {
                user_id,
                client_id: client_id.to_string(),
            },
            SELECTION_TTL_SECS,
        )
        .await?;
    Ok(selection_id)
}

pub async fn consume_login_selection(
    state: &super::state::AppState,
    selection_id: Uuid,
) -> Result<LoginSelection, authsvc_core::AuthError> {
    let key = format!("login_selection:{selection_id}");
    let stored: LoginSelection = state
        .sessions
        .get_json(&key)
        .await?
        .ok_or(authsvc_core::AuthError::InvalidToken)?;
    state.sessions.delete_key(&key).await?;
    Ok(stored)
}

pub async fn list_account_options(
    state: &super::state::AppState,
    user_id: Uuid,
) -> Result<Vec<AccountOption>, authsvc_core::AuthError> {
    state.repos.portal().list_user_account_options(user_id).await
}
