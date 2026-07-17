use async_trait::async_trait;
use authsvc_core::{AuthError, AuthzCheck, AuthzResult, PolicyEvaluator};
use uuid::Uuid;

use crate::stores::postgres::PostgresStore;

pub struct RbacEvaluator {
    store: PostgresStore,
}

impl RbacEvaluator {
    pub fn new(store: PostgresStore) -> Self {
        Self { store }
    }
}

#[async_trait]
impl PolicyEvaluator for RbacEvaluator {
    async fn check(&self, req: &AuthzCheck) -> Result<AuthzResult, AuthError> {
        let permissions = self
            .store
            .list_user_permissions(req.subject_id, req.tenant_id)
            .await?;

        let allowed = permissions.iter().any(|p| {
            p.action == req.action
                && (p.resource == req.resource || p.resource == "*" || req.resource.starts_with(&format!("{}/", p.resource)))
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

pub fn subject_from_claims(sub: &str) -> Result<Uuid, AuthError> {
    Uuid::parse_str(sub).map_err(|_| AuthError::InvalidToken)
}
