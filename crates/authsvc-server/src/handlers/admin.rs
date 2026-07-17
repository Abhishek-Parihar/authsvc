use axum::{extract::{Path, State}, Json};
use authsvc_core::{AuthError, TenantRepository};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::{
    handlers::{ApiError, AppResult, SharedState},
    services::api_keys::{create_api_key, revoke_api_key},
};

#[derive(Debug, Deserialize)]
pub struct CreateTenantRequest {
    pub slug: String,
    pub name: String,
}

pub async fn create_tenant(
    State(state): State<SharedState>,
    Json(body): Json<CreateTenantRequest>,
) -> AppResult<impl axum::response::IntoResponse> {
    let tenant = state.store.create_tenant(&body.slug, &body.name).await?;
    Ok(Json(json!({"id": tenant.id, "slug": tenant.slug, "name": tenant.name})))
}

pub async fn get_tenant(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> AppResult<impl axum::response::IntoResponse> {
    let tenant = TenantRepository::find_by_id(&state.store, id)
        .await?
        .ok_or_else(|| ApiError(AuthError::NotFound("tenant".into())))?;
    Ok(Json(json!({"id": tenant.id, "slug": tenant.slug, "name": tenant.name})))
}

pub async fn list_clients(
    State(state): State<SharedState>,
) -> AppResult<impl axum::response::IntoResponse> {
    let tenant = state
        .store
        .find_by_slug(&state.config.default_tenant_slug)
        .await?
        .ok_or_else(|| ApiError(AuthError::NotFound("tenant".into())))?;
    let clients = state.store.list_clients(tenant.id).await?;
    Ok(Json(json!({"clients": clients})))
}

pub async fn delete_client(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> AppResult<impl axum::response::IntoResponse> {
    state.store.delete_client(id).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
pub struct CreateRoleRequest {
    pub tenant_id: String,
    pub name: String,
    pub description: Option<String>,
}

pub async fn create_role(
    State(state): State<SharedState>,
    Json(body): Json<CreateRoleRequest>,
) -> AppResult<impl axum::response::IntoResponse> {
    let tenant_id = Uuid::parse_str(&body.tenant_id)
        .map_err(|_| ApiError(AuthError::Validation("invalid tenant_id".into())))?;
    let role = state
        .store
        .create_role(tenant_id, &body.name, body.description.as_deref())
        .await?;
    Ok(Json(json!({"id": role.id, "name": role.name})))
}

#[derive(Debug, Deserialize)]
pub struct CreatePermissionRequest {
    pub tenant_id: String,
    pub resource: String,
    pub action: String,
}

pub async fn create_permission(
    State(state): State<SharedState>,
    Json(body): Json<CreatePermissionRequest>,
) -> AppResult<impl axum::response::IntoResponse> {
    let tenant_id = Uuid::parse_str(&body.tenant_id)
        .map_err(|_| ApiError(AuthError::Validation("invalid tenant_id".into())))?;
    let perm = state
        .store
        .create_permission(tenant_id, &body.resource, &body.action)
        .await?;
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
    authsvc_core::RoleRepository::assign_role(&state.store, user_id, role_id).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
pub struct CreateApiKeyRequest {
    pub tenant_id: String,
    pub name: String,
    pub scopes: Vec<String>,
}

pub async fn create_api_key_handler(
    State(state): State<SharedState>,
    Json(body): Json<CreateApiKeyRequest>,
) -> AppResult<impl axum::response::IntoResponse> {
    let tenant_id = Uuid::parse_str(&body.tenant_id)
        .map_err(|_| ApiError(AuthError::Validation("invalid tenant_id".into())))?;
    let (id, key) = create_api_key(&state, tenant_id, &body.name, body.scopes).await?;
    Ok(Json(json!({"id": id, "api_key": key})))
}

pub async fn revoke_api_key_handler(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> AppResult<impl axum::response::IntoResponse> {
    revoke_api_key(&state, id).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
pub struct CreateWebhookRequest {
    pub tenant_id: String,
    pub url: String,
    pub events: Vec<String>,
}

pub async fn create_webhook(
    State(state): State<SharedState>,
    Json(body): Json<CreateWebhookRequest>,
) -> AppResult<impl axum::response::IntoResponse> {
    let tenant_id = Uuid::parse_str(&body.tenant_id)
        .map_err(|_| ApiError(AuthError::Validation("invalid tenant_id".into())))?;
    let secret = uuid::Uuid::new_v4().to_string();
    let id = state
        .store
        .create_webhook(tenant_id, &body.url, &secret, &body.events)
        .await?;
    Ok(Json(json!({"id": id, "secret": secret})))
}

pub async fn rotate_keys(
    State(state): State<SharedState>,
) -> AppResult<impl axum::response::IntoResponse> {
    let kid = crate::services::ops::rotate_keys(&state).await?;
    Ok(Json(json!({"kid": kid, "rotated": true})))
}

#[derive(Debug, Deserialize)]
pub struct CreateCasbinRuleRequest {
    pub tenant_id: String,
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
    let tenant_id = Uuid::parse_str(&body.tenant_id)
        .map_err(|_| ApiError(AuthError::Validation("invalid tenant_id".into())))?;
    let id = state
        .store
        .create_casbin_rule(
            tenant_id,
            &body.ptype,
            body.v0.as_deref(),
            body.v1.as_deref(),
            body.v2.as_deref(),
            body.v3.as_deref(),
            body.v4.as_deref(),
            body.v5.as_deref(),
        )
        .await?;
    state.policy.invalidate_casbin(tenant_id);
    Ok(Json(json!({"id": id})))
}

pub async fn delete_casbin_rule(
    State(state): State<SharedState>,
    Path(id): Path<i32>,
) -> AppResult<impl axum::response::IntoResponse> {
    state.store.delete_casbin_rule(id).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

pub async fn list_casbin_rules(
    State(state): State<SharedState>,
    Path(tenant_id): Path<Uuid>,
) -> AppResult<impl axum::response::IntoResponse> {
    let rules = state.store.list_casbin_rules(tenant_id).await?;
    Ok(Json(json!({"rules": rules})))
}

pub async fn add_role_inheritance(
    State(state): State<SharedState>,
    Path((child_id, parent_id)): Path<(Uuid, Uuid)>,
) -> AppResult<impl axum::response::IntoResponse> {
    state
        .store
        .add_role_inheritance(child_id, parent_id)
        .await?;
    state
        .audit(
            None,
            None,
            "roles.inherit",
            Some("role_hierarchy"),
            None,
            json!({"child_role_id": child_id, "parent_role_id": parent_id}),
        )
        .await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

pub async fn remove_role_inheritance(
    State(state): State<SharedState>,
    Path((child_id, parent_id)): Path<(Uuid, Uuid)>,
) -> AppResult<impl axum::response::IntoResponse> {
    state
        .store
        .remove_role_inheritance(child_id, parent_id)
        .await?;
    state
        .audit(
            None,
            None,
            "roles.uninherit",
            Some("role_hierarchy"),
            None,
            json!({"child_role_id": child_id, "parent_role_id": parent_id}),
        )
        .await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}
