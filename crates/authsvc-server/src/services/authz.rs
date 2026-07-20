use authsvc_core::{AuthError, AuthzCheck, AuthzResult, ClientRepository, PolicyEvaluator, UserRepository};

use super::state::AppState;

pub async fn check_authorization(state: &AppState, req: AuthzCheck) -> Result<AuthzResult, AuthError> {
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
        .store
        .complete_mfa_challenge(challenge_id)
        .await?
        .ok_or(AuthError::InvalidToken)?;

    verify_totp(state, user_id, totp_code).await?;

    let user = UserRepository::find_by_id(&state.store, user_id)
        .await?
        .ok_or(AuthError::UserNotFound)?;

    let client_id: String = sqlx::query_scalar("SELECT client_id FROM oauth_clients WHERE id = $1")
        .bind(client_uuid)
        .fetch_one(state.store.pool())
        .await
        .map_err(|e| AuthError::Internal(e.to_string()))?;

    let client = ClientRepository::find_by_client_id(&state.store, &client_id)
        .await?
        .ok_or(AuthError::ClientNotFound)?;

    super::auth::complete_login(state, &user, &client).await
}
