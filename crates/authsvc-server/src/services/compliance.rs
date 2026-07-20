use authsvc_core::AuthError;
use serde_json::{json, Value};
use uuid::Uuid;

use super::state::AppState;

pub async fn compliance_status(state: &AppState, account_id: Uuid) -> Result<Value, AuthError> {
    let enforce_mfa = state.repos.postgres().account_enforce_mfa(account_id).await?;
    let keys = state
        .repos
        .signing_keys()
        .list_signing_keys_for_jwks(state.config.jwt_key_grace_secs)
        .await?;

    let active_kid = state
        .repos
        .signing_keys()
        .get_active_signing_key()
        .await?
        .map(|(kid, _, _)| kid);

    Ok(json!({
        "account_id": account_id,
        "enforce_mfa": enforce_mfa,
        "active_signing_key": active_kid,
        "signing_keys_count": keys.len(),
        "password_grant_disabled": state.config.disable_password_grant,
        "deployment_mode": state.config.deployment_mode,
        "cookie_secure": state.config.cookie_secure,
    }))
}

pub async fn account_region(state: &AppState, account_id: Uuid) -> Result<Option<String>, AuthError> {
    state.repos.postgres().account_region(account_id).await
}
