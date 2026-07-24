use authsvc_core::{AuthError, AuthzCheck, PolicyEvaluator};
use uuid::Uuid;

use super::state::AppState;

pub async fn check_authorization(
    state: &AppState,
    req: authsvc_core::AuthzCheck,
) -> Result<authsvc_core::AuthzResult, AuthError> {
    crate::observability::record_authz_check();
    state.policy.check(&req).await
}

/// Returns true when the user holds account-level admin (`*/*`) permission.
pub async fn user_has_admin_permission(
    state: &AppState,
    user_id: Uuid,
    account_id: Uuid,
) -> Result<bool, AuthError> {
    let result = check_authorization(
        state,
        AuthzCheck {
            subject_id: user_id,
            account_id,
            website_id: None,
            resource: "*".into(),
            action: "*".into(),
            context: None,
        },
    )
    .await?;
    Ok(result.allowed)
}

/// Caller may act on `target_user_id` when they are the subject or an account admin.
pub async fn authorize_user_access(
    state: &AppState,
    caller_user_id: Uuid,
    caller_account_id: Uuid,
    target_user_id: Uuid,
) -> Result<(), AuthError> {
    if caller_user_id == target_user_id {
        return Ok(());
    }
    if user_has_admin_permission(state, caller_user_id, caller_account_id).await? {
        return Ok(());
    }
    Err(AuthError::Forbidden)
}

pub async fn complete_mfa_login(
    state: &AppState,
    challenge_id: uuid::Uuid,
    totp_code: &str,
) -> Result<super::auth::TokenResponse, AuthError> {
    use crate::services::mfa::{verify_recovery_code, verify_totp};

    let (user_id, client_uuid) = state
        .repos
        .mfa()
        .complete_mfa_challenge(challenge_id)
        .await?
        .ok_or(AuthError::InvalidToken)?;

    if verify_totp(state, user_id, totp_code).await.is_err() {
        verify_recovery_code(state, user_id, totp_code).await?;
    }

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
