use async_trait::async_trait;
use authsvc_core::AuthError;
use oauth2::{
    basic::BasicClient, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl,
    TokenResponse, TokenUrl,
};
use reqwest::header::{ACCEPT, AUTHORIZATION, USER_AGENT};

use crate::{FederatedUser, IdentityProvider};

pub struct GitHubProvider {
    client: BasicClient,
}

impl GitHubProvider {
    pub fn new(client_id: &str, client_secret: &str, redirect_uri: &str) -> Result<Self, AuthError> {
        let client = BasicClient::new(
            ClientId::new(client_id.to_string()),
            Some(ClientSecret::new(client_secret.to_string())),
            AuthUrl::new("https://github.com/login/oauth/authorize".into())
                .map_err(|e| AuthError::Internal(e.to_string()))?,
            Some(
                TokenUrl::new("https://github.com/login/oauth/access_token".into())
                    .map_err(|e| AuthError::Internal(e.to_string()))?,
            ),
        )
        .set_redirect_uri(
            RedirectUrl::new(redirect_uri.to_string())
                .map_err(|e| AuthError::Internal(e.to_string()))?,
        );
        Ok(Self { client })
    }
}

#[async_trait]
impl IdentityProvider for GitHubProvider {
    fn name(&self) -> &str {
        "github"
    }

    fn authorization_url(&self, state: &str, _redirect_uri: &str) -> Result<String, AuthError> {
        let (url, _) = self
            .client
            .authorize_url(|| CsrfToken::new(state.to_string()))
            .add_scope(oauth2::Scope::new("read:user user:email".into()))
            .url();
        Ok(url.to_string())
    }

    async fn exchange_code(
        &self,
        code: &str,
        _redirect_uri: &str,
    ) -> Result<FederatedUser, AuthError> {
        let token = self
            .client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .request_async(oauth2::reqwest::async_http_client)
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        let access = token.access_token().secret();
        let http = reqwest::Client::new();
        let user: serde_json::Value = http
            .get("https://api.github.com/user")
            .header(USER_AGENT, "authsvc")
            .header(ACCEPT, "application/vnd.github+json")
            .header(AUTHORIZATION, format!("Bearer {access}"))
            .send()
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?
            .json()
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        let emails: Vec<serde_json::Value> = http
            .get("https://api.github.com/user/emails")
            .header(USER_AGENT, "authsvc")
            .header(AUTHORIZATION, format!("Bearer {access}"))
            .send()
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?
            .json()
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        let primary = emails
            .iter()
            .find(|e| e["primary"].as_bool().unwrap_or(false))
            .and_then(|e| e["email"].as_str())
            .map(str::to_string);

        Ok(FederatedUser {
            provider: "github".into(),
            subject: user["id"].to_string(),
            email: primary,
            name: user["name"].as_str().or(user["login"].as_str()).map(str::to_string),
            email_verified: true,
        })
    }
}
