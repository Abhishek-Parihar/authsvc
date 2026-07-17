pub mod casbin;
pub mod openfga;
pub mod rbac;

use async_trait::async_trait;
use authsvc_core::{AuthError, AuthzCheck, AuthzResult, PolicyEvaluator};

pub enum PolicyBackend {
    Rbac,
    Casbin,
    OpenFga,
}

impl PolicyBackend {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "casbin" => Self::Casbin,
            "openfga" => Self::OpenFga,
            _ => Self::Rbac,
        }
    }
}

pub struct CompositeEvaluator {
    inner: Box<dyn PolicyEvaluator>,
}

impl CompositeEvaluator {
    pub fn new(
        backend: PolicyBackend,
        rbac: rbac::RbacEvaluator,
        casbin: casbin::CasbinEvaluator,
        openfga: openfga::OpenFgaEvaluator,
    ) -> Self {
        let inner: Box<dyn PolicyEvaluator> = match backend {
            PolicyBackend::Casbin => Box::new(casbin),
            PolicyBackend::OpenFga => Box::new(openfga),
            PolicyBackend::Rbac => Box::new(rbac),
        };
        Self { inner }
    }
}

#[async_trait]
impl PolicyEvaluator for CompositeEvaluator {
    async fn check(&self, req: &AuthzCheck) -> Result<AuthzResult, AuthError> {
        self.inner.check(req).await
    }
}
