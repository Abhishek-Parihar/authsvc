use async_trait::async_trait;
use authsvc_core::AuthError;
use authsvc_policy::casbin::{CasbinPolicyLoader, CasbinRuleRow};
use uuid::Uuid;

use super::PostgresStore;

#[async_trait]
impl CasbinPolicyLoader for PostgresStore {
    async fn list_rules(&self, account_id: Uuid) -> Result<Vec<CasbinRuleRow>, AuthError> {
        let rows = self.list_casbin_rules(account_id).await?;
        Ok(rows
            .into_iter()
            .map(|(_, ptype, v0, v1, v2, v3, v4, v5)| CasbinRuleRow {
                ptype,
                v0,
                v1,
                v2,
                v3,
                v4,
                v5,
            })
            .collect())
    }
}
