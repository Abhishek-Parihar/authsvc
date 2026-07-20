use async_trait::async_trait;
use authsvc_core::{AuthError, AuthzCheck, AuthzResult, PolicyEvaluator};

pub struct OpenFgaEvaluator {
    client: reqwest::Client,
    base_url: String,
    store_id: String,
}

impl OpenFgaEvaluator {
    pub fn new(base_url: impl Into<String>, store_id: impl Into<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: base_url.into(),
            store_id: store_id.into(),
        }
    }
}

#[async_trait]
impl PolicyEvaluator for OpenFgaEvaluator {
    async fn check(&self, req: &AuthzCheck) -> Result<AuthzResult, AuthError> {
        let url = format!(
            "{}/stores/{}/check",
            self.base_url.trim_end_matches('/'),
            self.store_id
        );
        let body = serde_json::json!({
            "tuple_key": {
                "user": format!("user:{}", req.subject_id),
                "relation": req.action,
                "object": format!(
                    "{}:{}",
                    req.resource,
                    req.website_id
                        .map(|id| id.to_string())
                        .unwrap_or_else(|| req.account_id.to_string())
                )
            }
        });

        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        if !resp.status().is_success() {
            return Ok(AuthzResult {
                allowed: false,
                reason: Some("openfga check failed".into()),
            });
        }

        let val: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        let allowed = val["allowed"].as_bool().unwrap_or(false);
        Ok(AuthzResult {
            allowed,
            reason: if allowed {
                None
            } else {
                Some("openfga denied".into())
            },
        })
    }
}
