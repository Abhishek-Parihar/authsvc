use std::sync::Arc;

use async_trait::async_trait;
use authsvc_core::{AuthError, Permission};
use authsvc_policy::rbac::PermissionLoader;
use uuid::Uuid;

use super::{PostgresStore, RedisSessionStore};

/// Redis-backed permission cache in front of Postgres.
pub struct CachedPermissionLoader {
    postgres: Arc<PostgresStore>,
    sessions: RedisSessionStore,
}

impl CachedPermissionLoader {
    pub fn new(postgres: Arc<PostgresStore>, sessions: RedisSessionStore) -> Self {
        Self { postgres, sessions }
    }
}

#[async_trait]
impl PermissionLoader for CachedPermissionLoader {
    async fn list_user_permissions(
        &self,
        user_id: Uuid,
        account_id: Uuid,
        website_id: Option<Uuid>,
    ) -> Result<Vec<Permission>, AuthError> {
        let key = format!("cache:perms:{user_id}:{account_id}:{website_id:?}");
        if let Some(perms) = self
            .sessions
            .get_json::<Vec<Permission>>(&key)
            .await?
        {
            return Ok(perms);
        }
        let perms = self
            .postgres
            .list_user_permissions(user_id, account_id, website_id)
            .await?;
        self.sessions.set_json(&key, &perms, 60).await?;
        Ok(perms)
    }
}
