pub mod github;
pub mod google;
pub mod oidc;
pub mod registry;

use async_trait::async_trait;
use authsvc_core::AuthError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederatedUser {
    pub provider: String,
    pub subject: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub email_verified: bool,
}

#[async_trait]
pub trait IdentityProvider: Send + Sync {
    fn name(&self) -> &str;
    fn authorization_url(&self, state: &str, redirect_uri: &str) -> Result<String, AuthError>;
    async fn exchange_code(
        &self,
        code: &str,
        redirect_uri: &str,
    ) -> Result<FederatedUser, AuthError>;
}

pub use registry::ProviderRegistry;
