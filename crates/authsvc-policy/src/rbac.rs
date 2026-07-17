use async_trait::async_trait;
use authsvc_core::{AuthError, AuthzCheck, AuthzResult, Permission, PolicyEvaluator};
use std::sync::Arc;
use uuid::Uuid;

#[async_trait]
pub trait PermissionLoader: Send + Sync {
    async fn list_user_permissions(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
    ) -> Result<Vec<Permission>, AuthError>;
}

pub struct RbacEvaluator {
    loader: Arc<dyn PermissionLoader>,
}

impl RbacEvaluator {
    pub fn new(loader: Arc<dyn PermissionLoader>) -> Self {
        Self { loader }
    }
}

#[async_trait]
impl PolicyEvaluator for RbacEvaluator {
    async fn check(&self, req: &AuthzCheck) -> Result<AuthzResult, AuthError> {
        let permissions = self
            .loader
            .list_user_permissions(req.subject_id, req.tenant_id)
            .await?;

        let allowed = permissions.iter().any(|p| {
            p.action == req.action
                && (p.resource == req.resource
                    || p.resource == "*"
                    || req.resource.starts_with(&format!("{}/", p.resource)))
        });

        Ok(AuthzResult {
            allowed,
            reason: if allowed {
                None
            } else {
                Some("no matching permission".into())
            },
        })
    }
}
