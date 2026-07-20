use async_trait::async_trait;
use authsvc_core::{AuthError, AuthzCheck, AuthzResult, Permission, PolicyEvaluator};
use std::sync::Arc;
use uuid::Uuid;

#[async_trait]
pub trait PermissionLoader: Send + Sync {
    async fn list_user_permissions(
        &self,
        user_id: Uuid,
        account_id: Uuid,
        website_id: Option<Uuid>,
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
            .list_user_permissions(req.subject_id, req.account_id, req.website_id)
            .await?;

        let allowed = permissions.iter().any(|p| {
            let action_match = p.action == "*" || p.action == req.action;
            let resource_match = p.resource == "*"
                || p.resource == req.resource
                || req.resource.starts_with(&format!("{}/", p.resource));
            action_match && resource_match
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

#[cfg(test)]
mod tests {
    use super::*;
    use authsvc_core::{AuthzCheck, PolicyEvaluator};
    use std::sync::Arc;
    use uuid::Uuid;

    struct StubLoader;

    #[async_trait::async_trait]
    impl PermissionLoader for StubLoader {
        async fn list_user_permissions(
            &self,
            _user_id: Uuid,
            _account_id: Uuid,
            _website_id: Option<Uuid>,
        ) -> Result<Vec<Permission>, AuthError> {
            Ok(vec![Permission {
                id: Uuid::new_v4(),
                resource: "orders".into(),
                action: "read".into(),
                description: None,
            }])
        }
    }

    #[tokio::test]
    async fn rbac_allows_matching_permission() {
        let evaluator = RbacEvaluator::new(Arc::new(StubLoader));
        let account_id = Uuid::new_v4();
        let result = evaluator
            .check(&AuthzCheck {
                subject_id: Uuid::new_v4(),
                account_id,
                website_id: None,
                resource: "orders".into(),
                action: "read".into(),
                context: None,
            })
            .await
            .expect("check");
        assert!(result.allowed);
    }

    #[tokio::test]
    async fn rbac_denies_missing_permission() {
        let evaluator = RbacEvaluator::new(Arc::new(StubLoader));
        let result = evaluator
            .check(&AuthzCheck {
                subject_id: Uuid::new_v4(),
                account_id: Uuid::new_v4(),
                website_id: None,
                resource: "orders".into(),
                action: "delete".into(),
                context: None,
            })
            .await
            .expect("check");
        assert!(!result.allowed);
    }
}
