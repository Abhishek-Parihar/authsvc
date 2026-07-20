use authsvc_core::{AuthError, PortalStore};

use super::state::AppState;

pub async fn resolve_portal_by_domain(
    state: &AppState,
    domain: &str,
) -> Result<authsvc_core::PortalInfo, AuthError> {
    state
        .repos
        .portal()
        .find_portal_by_domain(domain)
        .await?
        .ok_or_else(|| AuthError::NotFound("portal".into()))
}
