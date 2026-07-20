use axum::{
    extract::{Path, State},
    Json,
};
use authsvc_core::AuthError;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::{
    handlers::{ApiError, AppResult, SharedState},
    services::admin,
};

#[derive(Debug, Deserialize)]
pub struct CreateAccountRequest {
    pub slug: String,
    pub name: String,
}

pub async fn create_account(
    State(state): State<SharedState>,
    Json(body): Json<CreateAccountRequest>,
) -> AppResult<impl axum::response::IntoResponse> {
    let account = admin::create_account(&state, &body.slug, &body.name).await?;
    Ok(Json(json!({"id": account.id, "slug": account.slug, "name": account.name})))
}

pub async fn get_account(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> AppResult<impl axum::response::IntoResponse> {
    let account = admin::get_account(&state, id).await.map_err(ApiError)?;
    Ok(Json(json!({"id": account.id, "slug": account.slug, "name": account.name})))
}

#[derive(Debug, Deserialize)]
pub struct CreateWebsiteRequest {
    pub account_id: String,
    pub slug: String,
    pub name: String,
    pub domain: Option<String>,
}

pub async fn create_website(
    State(state): State<SharedState>,
    Json(body): Json<CreateWebsiteRequest>,
) -> AppResult<impl axum::response::IntoResponse> {
    let account_id = Uuid::parse_str(&body.account_id)
        .map_err(|_| ApiError(AuthError::Validation("invalid account_id".into())))?;
    let website = admin::create_website(
        &state,
        account_id,
        &body.slug,
        &body.name,
        body.domain.as_deref(),
    )
    .await?;
    Ok(Json(website))
}

pub async fn list_clients(
    State(state): State<SharedState>,
) -> AppResult<impl axum::response::IntoResponse> {
    let clients = admin::list_default_clients(&state).await?;
    Ok(Json(json!({"clients": clients})))
}

pub async fn delete_client(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> AppResult<impl axum::response::IntoResponse> {
    admin::delete_client(&state, id).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
pub struct CreateRoleRequest {
    pub account_id: String,
    pub name: String,
    pub description: Option<String>,
}

pub async fn create_role(
    State(state): State<SharedState>,
    Json(body): Json<CreateRoleRequest>,
) -> AppResult<impl axum::response::IntoResponse> {
    let account_id = Uuid::parse_str(&body.account_id)
        .map_err(|_| ApiError(AuthError::Validation("invalid account_id".into())))?;
    let role = admin::create_role(
        &state,
        account_id,
        &body.name,
        body.description.as_deref(),
    )
    .await?;
    Ok(Json(json!({"id": role.id, "name": role.name})))
}

#[derive(Debug, Deserialize)]
pub struct CreatePermissionRequest {
    pub resource: String,
    pub action: String,
}

pub async fn create_permission(
    State(state): State<SharedState>,
    Json(body): Json<CreatePermissionRequest>,
) -> AppResult<impl axum::response::IntoResponse> {
    let account_id = admin::default_account_id(&state).await?;
    let perm = admin::create_permission(&state, account_id, &body.resource, &body.action).await?;
    Ok(Json(json!({"id": perm.id, "resource": perm.resource, "action": perm.action})))
}

#[derive(Debug, Deserialize)]
pub struct AssignRoleRequest {
    pub role_id: String,
}

pub async fn assign_user_role(
    State(state): State<SharedState>,
    Path(user_id): Path<Uuid>,
    Json(body): Json<AssignRoleRequest>,
) -> AppResult<impl axum::response::IntoResponse> {
    let role_id = Uuid::parse_str(&body.role_id)
        .map_err(|_| ApiError(AuthError::Validation("invalid role_id".into())))?;
    admin::assign_user_role(&state, user_id, role_id).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
pub struct CreateApiKeyRequest {
    pub account_id: String,
    pub name: String,
    pub scopes: Vec<String>,
}

pub async fn create_api_key_handler(
    State(state): State<SharedState>,
    Json(body): Json<CreateApiKeyRequest>,
) -> AppResult<impl axum::response::IntoResponse> {
    let account_id = Uuid::parse_str(&body.account_id)
        .map_err(|_| ApiError(AuthError::Validation("invalid account_id".into())))?;
    let (id, key) = admin::create_api_key(&state, account_id, &body.name, body.scopes).await?;
    Ok(Json(json!({"id": id, "api_key": key})))
}

pub async fn revoke_api_key_handler(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> AppResult<impl axum::response::IntoResponse> {
    admin::revoke_api_key(&state, id).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
pub struct CreateWebhookRequest {
    pub account_id: String,
    pub url: String,
    pub events: Vec<String>,
}

pub async fn create_webhook(
    State(state): State<SharedState>,
    Json(body): Json<CreateWebhookRequest>,
) -> AppResult<impl axum::response::IntoResponse> {
    let account_id = Uuid::parse_str(&body.account_id)
        .map_err(|_| ApiError(AuthError::Validation("invalid account_id".into())))?;
    let (id, secret) = admin::create_webhook(&state, account_id, &body.url, body.events).await?;
    Ok(Json(json!({"id": id, "secret": secret})))
}

pub async fn rotate_keys(
    State(state): State<SharedState>,
) -> AppResult<impl axum::response::IntoResponse> {
    let kid = admin::rotate_keys(&state).await?;
    Ok(Json(json!({"kid": kid, "rotated": true})))
}

#[derive(Debug, Deserialize)]
pub struct CreateCasbinRuleRequest {
    pub account_id: String,
    pub ptype: String,
    pub v0: Option<String>,
    pub v1: Option<String>,
    pub v2: Option<String>,
    pub v3: Option<String>,
    pub v4: Option<String>,
    pub v5: Option<String>,
}

pub async fn create_casbin_rule(
    State(state): State<SharedState>,
    Json(body): Json<CreateCasbinRuleRequest>,
) -> AppResult<impl axum::response::IntoResponse> {
    let account_id = Uuid::parse_str(&body.account_id)
        .map_err(|_| ApiError(AuthError::Validation("invalid account_id".into())))?;
    let id = admin::create_casbin_rule(
        &state,
        account_id,
        &body.ptype,
        body.v0.as_deref(),
        body.v1.as_deref(),
        body.v2.as_deref(),
        body.v3.as_deref(),
        body.v4.as_deref(),
        body.v5.as_deref(),
    )
    .await?;
    Ok(Json(json!({"id": id})))
}

pub async fn delete_casbin_rule(
    State(state): State<SharedState>,
    Path(id): Path<i32>,
) -> AppResult<impl axum::response::IntoResponse> {
    admin::delete_casbin_rule(&state, id).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

pub async fn list_casbin_rules(
    State(state): State<SharedState>,
    Path(account_id): Path<Uuid>,
) -> AppResult<impl axum::response::IntoResponse> {
    let rules = admin::list_casbin_rules(&state, account_id).await?;
    Ok(Json(json!({"rules": rules})))
}

pub async fn add_role_inheritance(
    State(state): State<SharedState>,
    Path((child_id, parent_id)): Path<(Uuid, Uuid)>,
) -> AppResult<impl axum::response::IntoResponse> {
    admin::add_role_inheritance(&state, child_id, parent_id).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

pub async fn remove_role_inheritance(
    State(state): State<SharedState>,
    Path((child_id, parent_id)): Path<(Uuid, Uuid)>,
) -> AppResult<impl axum::response::IntoResponse> {
    admin::remove_role_inheritance(&state, child_id, parent_id).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
pub struct CreateScimTokenRequest {
    pub name: String,
}

pub async fn create_scim_token_handler(
    State(state): State<SharedState>,
    Json(body): Json<CreateScimTokenRequest>,
) -> AppResult<impl axum::response::IntoResponse> {
    let account_id = admin::default_account_id(&state).await?;
    let (id, token) = crate::services::scim::create_scim_token(&state, account_id, &body.name).await?;
    Ok(Json(json!({"id": id, "token": token})))
}
