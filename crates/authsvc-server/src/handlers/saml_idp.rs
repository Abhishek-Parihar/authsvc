use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse, Redirect, Response},
    Json,
};
use serde::Deserialize;
use serde_json::json;

use crate::{
    handlers::{ApiError, AppResult, SharedState},
    services::saml_idp,
};

#[derive(Debug, Deserialize)]
pub struct SamlIdpSsoQuery {
    #[serde(rename = "SAMLRequest")]
    pub saml_request: String,
    #[serde(rename = "RelayState")]
    pub relay_state: Option<String>,
}

pub async fn idp_metadata(State(state): State<SharedState>) -> AppResult<impl IntoResponse> {
    let xml = saml_idp::idp_metadata(&state).await?;
    Ok(([("content-type", "application/xml")], xml))
}

pub async fn idp_sso_get(
    State(state): State<SharedState>,
    Query(query): Query<SamlIdpSsoQuery>,
) -> AppResult<impl IntoResponse> {
    let pending_id = saml_idp::begin_sso(
        &state,
        &query.saml_request,
        query.relay_state.as_deref(),
    )
    .await?;
    Ok(Redirect::temporary(&format!(
        "{}/login?saml_authn_id={pending_id}",
        state.config.issuer
    )))
}

pub async fn idp_sso_post(
    State(state): State<SharedState>,
    axum::Form(form): axum::Form<SamlIdpSsoQuery>,
) -> AppResult<impl IntoResponse> {
    let pending_id = saml_idp::begin_sso(
        &state,
        &form.saml_request,
        form.relay_state.as_deref(),
    )
    .await?;
    Ok(Redirect::temporary(&format!(
        "{}/login?saml_authn_id={pending_id}",
        state.config.issuer
    )))
}

#[derive(Debug, Deserialize)]
pub struct SamlIdpLoginRequest {
    pub saml_authn_id: String,
    pub email: String,
    pub password: String,
}

pub async fn idp_login(
    State(state): State<SharedState>,
    Json(body): Json<SamlIdpLoginRequest>,
) -> AppResult<Response> {
    let pending_id = uuid::Uuid::parse_str(&body.saml_authn_id)
        .map_err(|_| ApiError(authsvc_core::AuthError::Validation("invalid saml_authn_id".into())))?;
    let html = saml_idp::complete_sso(
        &state,
        pending_id,
        &body.email,
        &body.password,
        None,
    )
    .await?;
    Ok(Html(html).into_response())
}

#[derive(Debug, Deserialize)]
pub struct CreateSamlSpRequest {
    pub name: String,
    pub entity_id: String,
    pub acs_url: String,
    pub slo_url: Option<String>,
    pub sp_cert_pem: Option<String>,
    #[serde(default)]
    pub want_authn_requests_signed: bool,
}

pub async fn create_saml_sp(
    State(state): State<SharedState>,
    Json(body): Json<CreateSamlSpRequest>,
) -> AppResult<impl IntoResponse> {
    let account_id = crate::services::admin::default_account_id(&state).await?;
    let sp = saml_idp::create_saml_sp(
        &state,
        account_id,
        &body.name,
        &body.entity_id,
        &body.acs_url,
        body.slo_url.as_deref(),
        body.sp_cert_pem.as_deref(),
        body.want_authn_requests_signed,
    )
    .await?;
    Ok(Json(json!({
        "id": sp.id,
        "name": sp.name,
        "entity_id": sp.entity_id,
        "acs_url": sp.acs_url,
        "slo_url": sp.slo_url,
        "want_authn_requests_signed": sp.want_authn_requests_signed,
    })))
}

pub async fn list_saml_sps(
    State(state): State<SharedState>,
) -> AppResult<impl IntoResponse> {
    let account_id = crate::services::admin::default_account_id(&state).await?;
    let sps = saml_idp::list_saml_sps(&state, account_id).await?;
    Ok(Json(json!({
        "service_providers": sps.iter().map(|sp| json!({
            "id": sp.id,
            "name": sp.name,
            "entity_id": sp.entity_id,
            "acs_url": sp.acs_url,
            "slo_url": sp.slo_url,
            "want_authn_requests_signed": sp.want_authn_requests_signed,
        })).collect::<Vec<_>>()
    })))
}

pub async fn delete_saml_sp(
    State(state): State<SharedState>,
    axum::extract::Path(id): axum::extract::Path<uuid::Uuid>,
) -> AppResult<impl IntoResponse> {
    let account_id = crate::services::admin::default_account_id(&state).await?;
    saml_idp::delete_saml_sp(&state, account_id, id).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
pub struct UserSearchQuery {
    pub email: String,
}

pub async fn search_users(
    State(state): State<SharedState>,
    Query(query): Query<UserSearchQuery>,
) -> AppResult<impl IntoResponse> {
    let users = saml_idp::search_users(&state, &query.email).await?;
    Ok(Json(json!({"users": users})))
}

#[derive(Debug, Deserialize)]
pub struct AuditEventsQuery {
    #[serde(default = "default_audit_limit")]
    pub limit: i64,
}

fn default_audit_limit() -> i64 {
    50
}

pub async fn list_audit_events(
    State(state): State<SharedState>,
    Query(query): Query<AuditEventsQuery>,
) -> AppResult<impl IntoResponse> {
    let account_id = crate::services::admin::default_account_id(&state).await?;
    let events = saml_idp::list_audit_events(&state, account_id, query.limit).await?;
    Ok(Json(json!({"events": events})))
}
