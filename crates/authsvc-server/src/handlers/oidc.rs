use axum::{extract::State, Json};
use serde_json::{json, Value};

use crate::handlers::{AppResult, SharedState};

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
        "response_types_supported": ["code", "token", "id_token"],
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
