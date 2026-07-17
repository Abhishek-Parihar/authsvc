use authsvc_core::{AuthError, AuthzCheck, AuthzResult, PolicyEvaluator};
use uuid::Uuid;

use crate::{
    policy::rbac::RbacEvaluator,
    services::auth::AppState,
};

pub async fn check_authorization(
    state: &AppState,
    req: AuthzCheck,
) -> Result<AuthzResult, AuthError> {
    let evaluator = RbacEvaluator::new(state.store.clone());
    evaluator.check(&req).await
}

pub fn parse_subject(subject: &str) -> Result<Uuid, AuthError> {
    Uuid::parse_str(subject).map_err(|_| AuthError::Validation("invalid subject_id".into()))
}
