use authsvc_core::AuthError;
use uuid::Uuid;

use super::state::AppState;

pub async fn resolve_data_plane_url(
    state: &AppState,
    account_id: Uuid,
) -> Result<Option<String>, AuthError> {
    if !state.config.is_managed_saas() {
        return Ok(None);
    }
    let region = state.repos.postgres().account_region(account_id).await?;
    Ok(region.map(|r| format!("https://{r}.authsvc.internal")))
}

pub async fn validate_region_pin(
    state: &AppState,
    account_id: Uuid,
    request_region: Option<&str>,
) -> Result<(), AuthError> {
    if !state.config.is_managed_saas() {
        return Ok(());
    }
    let account_region = state.repos.postgres().account_region(account_id).await?;
    if let (Some(expected), Some(actual)) = (&account_region, request_region) {
        if expected != actual {
            return Err(AuthError::Forbidden);
        }
    }
    Ok(())
}
