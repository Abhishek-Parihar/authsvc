use axum::{
    extract::{Query, State},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use authsvc_idp::IdentityProvider;
use uuid::Uuid;

use crate::{
    handlers::{AppResult, SharedState},
    services::{admin::default_account_id, federation},
};

#[derive(Debug, Deserialize)]
pub struct SamlCallbackQuery {
    pub SAMLResponse: String,
    pub RelayState: Option<String>,
    pub client_id: String,
}

pub async fn saml_metadata(State(state): State<SharedState>) -> AppResult<impl IntoResponse> {
    let account_id = default_account_id(&state).await?;
    let config = state
        .repos
        .idp_configs()
        .get(account_id, "saml")
        .await?
        .ok_or(authsvc_core::AuthError::NotFound("saml".into()))?;
    let provider = authsvc_idp::saml::SamlProvider::from_config(&config.2, &state.config.issuer)?;
    let acs = format!("{}/saml/acs", state.config.issuer);
    Ok((
        [("content-type", "application/xml")],
        provider.metadata_xml(&acs),
    ))
}

pub async fn saml_login(
    State(state): State<SharedState>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> AppResult<impl IntoResponse> {
    let account_id = default_account_id(&state).await?;
    let provider_name = params.get("provider").map(String::as_str).unwrap_or("saml");
    let (_, _, config) = state
        .repos
        .idp_configs()
        .get(account_id, provider_name)
        .await?
        .ok_or(authsvc_core::AuthError::NotFound(provider_name.into()))?;
    let provider = authsvc_idp::saml::SamlProvider::from_config(&config, &state.config.issuer)?;
    let state_param = Uuid::new_v4().to_string();
    state
        .repos
        .federation()
        .store_federation_state(
            &state_param,
            account_id,
            provider_name,
            chrono::Utc::now() + chrono::Duration::minutes(10),
        )
        .await?;
    let url = provider.authorization_url(&state_param, "")?;
    Ok(axum::response::Redirect::temporary(&url))
}

pub async fn saml_acs(
    State(state): State<SharedState>,
    axum::Form(form): axum::Form<SamlCallbackQuery>,
) -> AppResult<impl IntoResponse> {
    let state_param = form.RelayState.as_deref().unwrap_or("");
    let tokens = federation::federation_callback(
        &state,
        state_param,
        &form.SAMLResponse,
        &form.client_id,
    )
    .await?;
    Ok(Json(tokens))
}
