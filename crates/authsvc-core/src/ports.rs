use async_trait::async_trait;
use uuid::Uuid;

use crate::{
    account::{Account, CreateAccount},
    client::{CreateOAuthClient, OAuthClient},
    membership::{AccountMember, WebsiteMember},
    role::{AuthzCheck, AuthzResult, Permission, Role},
    user::{CreateUser, User},
    website::{CreateWebsite, Website},
    AuthError,
};

#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn create(&self, user: &CreateUser, password_hash: &str) -> Result<User, AuthError>;
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, AuthError>;
    async fn find_by_id(&self, id: Uuid) -> Result<Option<User>, AuthError>;
}

#[async_trait]
pub trait AccountRepository: Send + Sync {
    async fn find_by_slug(&self, slug: &str) -> Result<Option<Account>, AuthError>;
    async fn find_by_id(&self, id: Uuid) -> Result<Option<Account>, AuthError>;
    async fn create(&self, input: &CreateAccount) -> Result<Account, AuthError>;
    async fn ensure_default(&self) -> Result<Account, AuthError>;
}

#[async_trait]
pub trait WebsiteRepository: Send + Sync {
    async fn find_by_slug(&self, account_id: Uuid, slug: &str) -> Result<Option<Website>, AuthError>;
    async fn find_by_id(&self, id: Uuid) -> Result<Option<Website>, AuthError>;
    async fn create(&self, input: &CreateWebsite) -> Result<Website, AuthError>;
    async fn find_by_client_id(&self, client_id: &str) -> Result<Option<(Website, OAuthClient)>, AuthError>;
}

#[async_trait]
pub trait MembershipRepository: Send + Sync {
    async fn add_account_member(
        &self,
        account_id: Uuid,
        user_id: Uuid,
        role_id: Option<Uuid>,
    ) -> Result<AccountMember, AuthError>;
    async fn list_user_accounts(&self, user_id: Uuid) -> Result<Vec<AccountMember>, AuthError>;
    async fn get_account_member(
        &self,
        account_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<AccountMember>, AuthError>;
    async fn add_website_member(
        &self,
        website_id: Uuid,
        user_id: Uuid,
        role_id: Option<Uuid>,
    ) -> Result<WebsiteMember, AuthError>;
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
pub trait RoleRepository: Send + Sync {
    async fn list_user_permissions(
        &self,
        user_id: Uuid,
        account_id: Uuid,
        website_id: Option<Uuid>,
    ) -> Result<Vec<Permission>, AuthError>;
    async fn assign_role(&self, user_id: Uuid, role_id: Uuid) -> Result<(), AuthError>;
    async fn list_roles(&self, account_id: Uuid) -> Result<Vec<Role>, AuthError>;
}

#[async_trait]
pub trait RefreshTokenRepository: Send + Sync {
    async fn store(
        &self,
        token_hash: &str,
        user_id: Option<Uuid>,
        client_id: Uuid,
        account_id: Uuid,
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
    pub account_id: Uuid,
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

#[async_trait]
pub trait NotificationSender: Send + Sync {
    async fn send_email(&self, to: &str, subject: &str, body: &str) -> Result<(), AuthError>;
    async fn send_sms(&self, to: &str, body: &str) -> Result<(), AuthError>;
}

#[derive(Debug, Clone)]
pub struct WebAuthnCredential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub sign_count: i64,
    pub name: Option<String>,
}

#[async_trait]
pub trait WebAuthnRepository: Send + Sync {
    async fn store_credential(
        &self,
        user_id: Uuid,
        credential_id: &[u8],
        public_key: &[u8],
        name: Option<&str>,
    ) -> Result<Uuid, AuthError>;
    async fn list_credentials(&self, user_id: Uuid) -> Result<Vec<WebAuthnCredential>, AuthError>;
    async fn update_sign_count(&self, id: Uuid, sign_count: i64) -> Result<(), AuthError>;
    async fn find_user_by_email(&self, email: &str) -> Result<Option<User>, AuthError>;
}

/// Resolved auth context when issuing tokens.
#[derive(Debug, Clone)]
pub struct TokenContext {
    pub account_id: Uuid,
    pub website_id: Uuid,
}
