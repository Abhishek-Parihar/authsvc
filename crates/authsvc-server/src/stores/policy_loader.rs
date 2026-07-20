use async_trait::async_trait;
use authsvc_core::{AuthError, Permission};
use authsvc_policy::rbac::PermissionLoader;
use uuid::Uuid;

use super::PostgresStore;

#[async_trait]
impl PermissionLoader for PostgresStore {
    async fn list_user_permissions(
        &self,
        user_id: Uuid,
        account_id: Uuid,
        website_id: Option<Uuid>,
    ) -> Result<Vec<Permission>, AuthError> {
        self.list_user_permissions(user_id, account_id, website_id).await
    }
}
