use axum::{
    extract::{Query, State},
    http::HeaderMap,
    response::IntoResponse,
    Json,
};
use authsvc_core::{
    AuthError, AuthzCheck, AuthzResult, ClientRepository, SessionStore, TenantRepository,
    UserRepository,
};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    handlers::{auth::extract_bearer_user, ApiError, AppResult, SharedState},
    services::authz::check_authorization,
};

pub async fn openid_configuration(
    State(state): State<SharedState>,
) -> AppResult<Json<Value>> {
    let issuer = state.jwt.issuer();
    Ok(Json(json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/oauth/authorize"),
        "token_endpoint": format!("{issuer}/oauth/token"),
        "jwks_uri": format!("{issuer}/.well-known/jwks.json"),
        "revocation_endpoint": format!("{issuer}/oauth/revoke"),
        "introspection_endpoint": format!("{issuer}/oauth/introspect"),
        "userinfo_endpoint": format!("{issuer}/oauth/userinfo"),
        "response_types_supported": ["code"],
        "grant_types_supported": [
            "authorization_code",
            "client_credentials",
            "password",
            "refresh_token"
        ],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_post",
            "client_secret_basic"
        ],
        "scopes_supported": ["openid", "profile", "email", "offline_access"],
        "code_challenge_methods_supported": ["S256"]
    })))
}

pub async fn jwks(State(state): State<SharedState>) -> AppResult<Json<Value>> {
    let jwks = state.jwt.jwks()?;
    Ok(Json(jwks))
}

#[derive(Debug, Deserialize)]
pub struct AuthzCheckRequest {
    pub subject_id: String,
    pub tenant_id: String,
    pub action: String,
    pub resource: String,
    pub context: Option<serde_json::Value>,
}

pub async fn check(
    State(state): State<SharedState>,
    Json(body): Json<AuthzCheckRequest>,
) -> AppResult<Json<AuthzResult>> {
    let req = AuthzCheck {
        subject_id: Uuid::parse_str(&body.subject_id)
            .map_err(|_| AuthError::Validation("invalid subject_id".into()))?,
        tenant_id: Uuid::parse_str(&body.tenant_id)
            .map_err(|_| AuthError::Validation("invalid tenant_id".into()))?,
        action: body.action,
        resource: body.resource,
        context: body.context,
    };
    let result = check_authorization(&state, req).await?;
    Ok(Json(result))
}

pub async fn userinfo(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    let claims = extract_bearer_user(&state, &headers).await?;
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| ApiError(AuthError::InvalidToken))?;
    let user = UserRepository::find_by_id(&state.store, user_id)
        .await?
        .ok_or_else(|| ApiError(AuthError::UserNotFound))?;
    Ok(Json(json!({
        "sub": user.id,
        "email": user.email,
        "email_verified": user.email_verified,
        "name": user.display_name,
        "tenant_id": user.tenant_id
    })))
}

#[derive(Debug, Deserialize)]
pub struct IntrospectRequest {
    pub token: String,
    #[serde(default)]
    pub token_type_hint: Option<String>,
}

pub async fn introspect(
    State(state): State<SharedState>,
    Json(body): Json<IntrospectRequest>,
) -> AppResult<Json<Value>> {
    let _ = body.token_type_hint;
    match state.jwt.validate_access_token(&body.token) {
        Ok(claims) => Ok(Json(json!({
            "active": true,
            "sub": claims.sub,
            "client_id": claims.client_id,
            "scope": claims.scope,
            "exp": claims.exp,
            "iat": claims.iat,
            "iss": claims.iss,
            "tenant_id": claims.tenant_id
        }))),
        Err(_) => Ok(Json(json!({ "active": false }))),
    }
}

#[derive(Debug, Deserialize)]
pub struct AuthorizeQuery {
    pub client_id: String,
    pub redirect_uri: String,
    pub response_type: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: String,
    pub code_challenge_method: Option<String>,
}

pub async fn authorize(
    State(state): State<SharedState>,
    Query(q): Query<AuthorizeQuery>,
) -> AppResult<impl axum::response::IntoResponse> {
    if q.response_type != "code" {
        return Err(ApiError(AuthError::Validation(
            "only response_type=code supported".into(),
        )));
    }
    if q.code_challenge_method.as_deref() != Some("S256") {
        return Err(ApiError(AuthError::Validation(
            "only S256 code challenge supported".into(),
        )));
    }

    let client = ClientRepository::find_by_client_id(&state.store, &q.client_id)
        .await?
        .ok_or_else(|| ApiError(AuthError::ClientNotFound))?;

    if !client.redirect_uris.is_empty()
        && !client.redirect_uris.contains(&q.redirect_uri)
    {
        return Err(ApiError(AuthError::Validation("invalid redirect_uri".into())));
    }

    let scopes: Vec<String> = q
        .scope
        .unwrap_or_else(|| "openid profile".into())
        .split_whitespace()
        .map(str::to_string)
        .collect();

    let login_state = Uuid::new_v4().to_string();
    state
        .store
        .store_login_state(
            &login_state,
            &q.client_id,
            &q.redirect_uri,
            &q.code_challenge,
            &scopes,
            chrono::Utc::now() + chrono::Duration::minutes(10),
        )
        .await?;

    Ok(Json(json!({
        "login_required": true,
        "login_state": login_state,
        "message": "POST credentials to /oauth/login with login_state"
    })))
}

#[derive(Debug, Deserialize)]
pub struct OAuthLoginRequest {
    pub login_state: String,
    pub email: String,
    pub password: String,
}

pub async fn oauth_login(
    State(state): State<SharedState>,
    Json(body): Json<OAuthLoginRequest>,
) -> AppResult<impl axum::response::IntoResponse> {
    let login = state
        .store
        .get_login_state(&body.login_state)
        .await?
        .ok_or_else(|| ApiError(AuthError::InvalidToken))?;

    let (client_id, redirect_uri, code_challenge, scopes) = login;
    let tenant = TenantRepository::find_by_slug(&state.store, &state.config.default_tenant_slug)
        .await?
        .ok_or_else(|| ApiError(AuthError::NotFound("tenant".into())))?;

    let user = state
        .store
        .find_by_email(tenant.id, &body.email.to_lowercase())
        .await?
        .ok_or_else(|| ApiError(AuthError::InvalidCredentials))?;

    let hash = user
        .password_hash
        .as_deref()
        .ok_or_else(|| ApiError(AuthError::InvalidCredentials))?;
    if !crate::crypto::password::verify_password(&body.password, hash)? {
        return Err(ApiError(AuthError::InvalidCredentials));
    }

    let session_id =
        crate::services::oidc_flow::store_browser_session(&state, user.id).await?;
    let redirect = crate::services::oidc_flow::create_authorization_redirect(
        &state,
        &client_id,
        &redirect_uri,
        &code_challenge,
        &scopes,
        user.id,
    )
    .await?;

    let mut response = Json(json!({
        "redirect": redirect,
        "session_id": session_id
    }))
    .into_response();

    let cookie = format!(
        "authsvc_session={session_id}; HttpOnly; Path=/; SameSite=Lax{}",
        if state.config.cookie_secure {
            "; Secure"
        } else {
            ""
        }
    );
    response.headers_mut().insert(
        axum::http::header::SET_COOKIE,
        cookie.parse().unwrap(),
    );
    Ok(response)
}

pub async fn logout(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> AppResult<impl axum::response::IntoResponse> {
    if let Some(cookie) = headers.get(axum::http::header::COOKIE).and_then(|v| v.to_str().ok()) {
        for part in cookie.split(';') {
            let part = part.trim();
            if let Some(sid) = part.strip_prefix("authsvc_session=") {
                if let Ok(id) = Uuid::parse_str(sid) {
                    SessionStore::delete(&state.sessions, id).await?;
                }
            }
        }
    }
    Ok(axum::http::StatusCode::NO_CONTENT)
}
