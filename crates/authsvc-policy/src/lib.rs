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
    pub fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "casbin" => Self::Casbin,
            "openfga" => Self::OpenFga,
            _ => Self::Rbac,
        }
    }
}

pub struct CompositeEvaluator {
    inner: Box<dyn PolicyEvaluator>,
    casbin: Option<std::sync::Arc<casbin::CasbinEvaluator>>,
}

impl CompositeEvaluator {
    pub fn new(
        backend: PolicyBackend,
        rbac: rbac::RbacEvaluator,
        casbin: casbin::CasbinEvaluator,
        openfga: openfga::OpenFgaEvaluator,
    ) -> Self {
        let casbin_arc = std::sync::Arc::new(casbin);
        let inner: Box<dyn PolicyEvaluator> = match backend {
            PolicyBackend::Casbin => Box::new(casbin::CasbinEvalWrapper(casbin_arc.clone())),
            PolicyBackend::OpenFga => Box::new(openfga),
            PolicyBackend::Rbac => Box::new(rbac),
        };
        Self {
            inner,
            casbin: Some(casbin_arc),
        }
    }

    pub fn invalidate_casbin(&self, tenant_id: uuid::Uuid) {
        if let Some(c) = &self.casbin {
            c.invalidate_tenant(tenant_id);
        }
    }
}

#[async_trait]
impl PolicyEvaluator for CompositeEvaluator {
    async fn check(&self, req: &AuthzCheck) -> Result<AuthzResult, AuthError> {
        self.inner.check(req).await
    }
}
