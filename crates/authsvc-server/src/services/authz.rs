use authsvc_core::{AuthError, PolicyEvaluator};

use super::state::AppState;

pub async fn check_authorization(
    state: &AppState,
    req: authsvc_core::AuthzCheck,
) -> Result<authsvc_core::AuthzResult, AuthError> {
    crate::observability::record_authz_check();
    state.policy.check(&req).await
}

pub async fn complete_mfa_login(
    state: &AppState,
    challenge_id: uuid::Uuid,
    totp_code: &str,
) -> Result<super::auth::TokenResponse, AuthError> {
    use crate::services::mfa::verify_totp;

    let (user_id, client_uuid) = state
        .repos
        .mfa()
        .complete_mfa_challenge(challenge_id)
        .await?
        .ok_or(AuthError::InvalidToken)?;

    verify_totp(state, user_id, totp_code).await?;

    let user = state
        .repos
        .users()
        .find_by_id(user_id)
        .await?
        .ok_or(AuthError::UserNotFound)?;

    let client_id = state
        .repos
        .clients()
        .find_client_id_by_uuid(client_uuid)
        .await?
        .ok_or(AuthError::ClientNotFound)?;

    let client = state
        .repos
        .clients()
        .find_by_client_id(&client_id)
        .await?
        .ok_or(AuthError::ClientNotFound)?;

    super::auth::complete_login(state, &user, &client).await
}
