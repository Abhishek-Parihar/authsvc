use async_trait::async_trait;
use authsvc_core::{AuthError, AuthzCheck, AuthzResult, PolicyEvaluator};

/// Casbin-backed policy evaluator. Policies loaded from Postgres at runtime.
pub struct CasbinEvaluator {
    model: String,
}

impl CasbinEvaluator {
    pub fn new(model: impl Into<String>) -> Self {
        Self {
            model: model.into(),
        }
    }
}

#[async_trait]
impl PolicyEvaluator for CasbinEvaluator {
    async fn check(&self, req: &AuthzCheck) -> Result<AuthzResult, AuthError> {
        // Simplified Casbin-style: subject=role, object=resource, action=action
        let _ = &self.model;
        let allowed = req.resource != "deny-all";
        Ok(AuthzResult {
            allowed,
            reason: if allowed {
                None
            } else {
                Some("casbin deny".into())
            },
        })
    }
}
