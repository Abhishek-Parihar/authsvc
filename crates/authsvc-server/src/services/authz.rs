use authsvc_core::{AuthError, AuthzCheck, AuthzResult, PolicyEvaluator};

use super::state::AppState;

pub async fn check_authorization(state: &AppState, req: AuthzCheck) -> Result<AuthzResult, AuthError> {
    state.policy.check(&req).await
}

pub async fn complete_mfa_login(
    state: &AppState,
    challenge_id: uuid::Uuid,
    totp_code: &str,
) -> Result<super::auth::TokenResponse, AuthError> {
    use authsvc_core::UserRepository;
    use crate::services::mfa::verify_totp;
    use sqlx::Row;

    let (user_id, client_uuid) = state
        .store
        .complete_mfa_challenge(challenge_id)
        .await?
        .ok_or(AuthError::InvalidToken)?;

    verify_totp(state, user_id, totp_code).await?;

    let user = UserRepository::find_by_id(&state.store, user_id)
        .await?
        .ok_or(AuthError::UserNotFound)?;

    let row = sqlx::query(
        "SELECT id, tenant_id, client_id, client_secret_hash, name, grant_types, redirect_uris, scopes, is_confidential, created_at
         FROM oauth_clients WHERE id = $1",
    )
    .bind(client_uuid)
    .fetch_optional(state.store.pool())
    .await
    .map_err(|e| AuthError::Internal(e.to_string()))?
    .ok_or(AuthError::ClientNotFound)?;

    let client = authsvc_core::OAuthClient {
        id: row.get("id"),
        tenant_id: row.get("tenant_id"),
        client_id: row.get("client_id"),
        client_secret_hash: row.get("client_secret_hash"),
        name: row.get("name"),
        grant_types: row.get("grant_types"),
        redirect_uris: row.get("redirect_uris"),
        scopes: row.get("scopes"),
        is_confidential: row.get("is_confidential"),
        created_at: row.get("created_at"),
    };

    super::auth::issue_user_tokens(state, &user, &client).await
}
