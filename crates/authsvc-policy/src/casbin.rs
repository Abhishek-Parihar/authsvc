use async_trait::async_trait;
use authsvc_core::{AuthError, AuthzCheck, AuthzResult, PolicyEvaluator};
use casbin::{CoreApi, DefaultModel, Enforcer, MemoryAdapter, MgmtApi};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use uuid::Uuid;

const MODEL: &str = r#"
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && (p.obj == "*" || r.obj == p.obj) && (p.act == "*" || r.act == p.act)
"#;

#[derive(Debug, Clone)]
pub struct CasbinRuleRow {
    pub ptype: String,
    pub v0: Option<String>,
    pub v1: Option<String>,
    pub v2: Option<String>,
    pub v3: Option<String>,
    pub v4: Option<String>,
    pub v5: Option<String>,
}

#[async_trait]
pub trait CasbinPolicyLoader: Send + Sync {
    async fn list_rules(&self, account_id: Uuid) -> Result<Vec<CasbinRuleRow>, AuthError>;
}

struct CachedRules {
    rules: Vec<CasbinRuleRow>,
    loaded_at: Instant,
}

pub struct CasbinEvaluator {
    loader: Arc<dyn CasbinPolicyLoader>,
    cache: RwLock<HashMap<Uuid, CachedRules>>,
    cache_ttl: Duration,
}

impl CasbinEvaluator {
    pub fn new(loader: Arc<dyn CasbinPolicyLoader>) -> Self {
        Self {
            loader,
            cache: RwLock::new(HashMap::new()),
            cache_ttl: Duration::from_secs(60),
        }
    }

    pub fn invalidate_account(&self, account_id: Uuid) {
        if let Ok(mut cache) = self.cache.write() {
            cache.remove(&account_id);
        }
    }

    async fn rules_for(&self, account_id: Uuid) -> Result<Vec<CasbinRuleRow>, AuthError> {
        if let Ok(cache) = self.cache.read() {
            if let Some(entry) = cache.get(&account_id) {
                if entry.loaded_at.elapsed() < self.cache_ttl {
                    return Ok(entry.rules.clone());
                }
            }
        }

        let rules = self.loader.list_rules(account_id).await?;
        if let Ok(mut cache) = self.cache.write() {
            cache.insert(
                account_id,
                CachedRules {
                    rules: rules.clone(),
                    loaded_at: Instant::now(),
                },
            );
        }
        Ok(rules)
    }

    async fn enforcer_for(&self, account_id: Uuid) -> Result<Enforcer, AuthError> {
        let rules = self.rules_for(account_id).await?;
        let model = DefaultModel::from_str(MODEL)
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        let adapter = MemoryAdapter::default();
        let mut enforcer = Enforcer::new(model, adapter)
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        for rule in rules {
            let mut params = Vec::new();
            for v in [rule.v0, rule.v1, rule.v2, rule.v3, rule.v4, rule.v5]
                .into_iter()
                .flatten()
            {
                params.push(v);
            }
            if !params.is_empty() {
                let _ = enforcer.add_named_policy(&rule.ptype, params).await;
            }
        }

        Ok(enforcer)
    }
}

pub struct CasbinEvalWrapper(pub Arc<CasbinEvaluator>);

#[async_trait]
impl PolicyEvaluator for CasbinEvalWrapper {
    async fn check(&self, req: &AuthzCheck) -> Result<AuthzResult, AuthError> {
        self.0.check(req).await
    }
}

#[async_trait]
impl PolicyEvaluator for CasbinEvaluator {
    async fn check(&self, req: &AuthzCheck) -> Result<AuthzResult, AuthError> {
        let enforcer = self.enforcer_for(req.account_id).await?;
        let sub = format!("user:{}", req.subject_id);
        let allowed = enforcer
            .enforce((sub.as_str(), req.resource.as_str(), req.action.as_str()))
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        Ok(AuthzResult {
            allowed,
            reason: if allowed {
                None
            } else {
                Some("casbin denied".into())
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    struct StubLoader {
        rules: Vec<CasbinRuleRow>,
    }

    #[async_trait]
    impl CasbinPolicyLoader for StubLoader {
        async fn list_rules(&self, _account_id: Uuid) -> Result<Vec<CasbinRuleRow>, AuthError> {
            Ok(self.rules.clone())
        }
    }

    #[tokio::test]
    async fn casbin_allows_matching_policy() {
        let account_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let evaluator = CasbinEvaluator::new(Arc::new(StubLoader {
            rules: vec![CasbinRuleRow {
                ptype: "p".into(),
                v0: Some(format!("user:{user_id}")),
                v1: Some("orders".into()),
                v2: Some("read".into()),
                v3: None,
                v4: None,
                v5: None,
            }],
        }));

        let result = evaluator
            .check(&AuthzCheck {
                subject_id: user_id,
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
    async fn casbin_denies_when_no_policy() {
        let evaluator = CasbinEvaluator::new(Arc::new(StubLoader { rules: vec![] }));
        let result = evaluator
            .check(&AuthzCheck {
                subject_id: Uuid::new_v4(),
                account_id: Uuid::new_v4(),
                website_id: None,
                resource: "deny-all".into(),
                action: "read".into(),
                context: None,
            })
            .await
            .expect("check");
        assert!(!result.allowed);
    }
}
