use async_trait::async_trait;
use uuid::Uuid;

use crate::{
    client::{CreateOAuthClient, OAuthClient},
    role::{AuthzCheck, AuthzResult, Permission, Role},
    tenant::Tenant,
    user::{CreateUser, User},
    AuthError,
};

#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn create(&self, user: &CreateUser, password_hash: &str) -> Result<User, AuthError>;
    async fn find_by_email(&self, tenant_id: Uuid, email: &str) -> Result<Option<User>, AuthError>;
    async fn find_by_id(&self, id: Uuid) -> Result<Option<User>, AuthError>;
}

#[async_trait]
pub trait ClientRepository: Send + Sync {
    async fn create(
        &self,
        input: &CreateOAuthClient,
        client_id: &str,
        client_secret_hash: Option<&str>,
    ) -> Result<(OAuthClient, Option<String>), AuthError>;
    async fn find_by_client_id(&self, client_id: &str) -> Result<Option<OAuthClient>, AuthError>;
}

#[async_trait]
pub trait TenantRepository: Send + Sync {
    async fn find_by_slug(&self, slug: &str) -> Result<Option<Tenant>, AuthError>;
    async fn find_by_id(&self, id: Uuid) -> Result<Option<Tenant>, AuthError>;
    async fn ensure_default(&self) -> Result<Tenant, AuthError>;
}

#[async_trait]
pub trait RoleRepository: Send + Sync {
    async fn list_user_permissions(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
    ) -> Result<Vec<Permission>, AuthError>;
    async fn assign_role(&self, user_id: Uuid, role_id: Uuid) -> Result<(), AuthError>;
    async fn list_roles(&self, tenant_id: Uuid) -> Result<Vec<Role>, AuthError>;
}

#[async_trait]
pub trait RefreshTokenRepository: Send + Sync {
    async fn store(
        &self,
        token_hash: &str,
        user_id: Option<Uuid>,
        client_id: Uuid,
        tenant_id: Uuid,
        family_id: Uuid,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), AuthError>;
    async fn consume(
        &self,
        token_hash: &str,
    ) -> Result<Option<RefreshTokenRecord>, AuthError>;
    async fn revoke_family(&self, family_id: Uuid) -> Result<(), AuthError>;
}

#[derive(Debug, Clone)]
pub struct RefreshTokenRecord {
    pub user_id: Option<Uuid>,
    pub client_id: Uuid,
    pub tenant_id: Uuid,
    pub family_id: Uuid,
    pub revoked: bool,
}

#[async_trait]
pub trait SessionStore: Send + Sync {
    async fn create(&self, session_id: Uuid, user_id: Uuid, ttl_secs: u64) -> Result<(), AuthError>;
    async fn get_user_id(&self, session_id: Uuid) -> Result<Option<Uuid>, AuthError>;
    async fn delete(&self, session_id: Uuid) -> Result<(), AuthError>;
}

#[async_trait]
pub trait PolicyEvaluator: Send + Sync {
    async fn check(&self, req: &AuthzCheck) -> Result<AuthzResult, AuthError>;
}
