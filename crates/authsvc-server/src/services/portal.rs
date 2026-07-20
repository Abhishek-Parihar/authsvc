use authsvc_core::{AuthError, PortalInfo};

use super::state::AppState;

pub async fn resolve_portal_by_domain(
    state: &AppState,
    domain: &str,
) -> Result<PortalInfo, AuthError> {
    state
        .store
        .find_portal_by_domain(domain)
        .await?
        .ok_or_else(|| AuthError::NotFound("portal".into()))
}
