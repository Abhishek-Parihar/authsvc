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
        tenant_id: Uuid,
    ) -> Result<Vec<Permission>, AuthError> {
        self.list_user_permissions(user_id, tenant_id).await
    }
}
