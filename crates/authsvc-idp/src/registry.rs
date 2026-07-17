use std::collections::HashMap;
use std::sync::Arc;

use authsvc_core::AuthError;

use crate::IdentityProvider;

pub struct ProviderRegistry {
    providers: HashMap<String, Arc<dyn IdentityProvider>>,
}

impl ProviderRegistry {
    pub fn new() -> Self {
        Self {
            providers: HashMap::new(),
        }
    }

    pub fn register(&mut self, provider: Arc<dyn IdentityProvider>) {
        self.providers.insert(provider.name().to_string(), provider);
    }

    pub fn get(&self, name: &str) -> Result<Arc<dyn IdentityProvider>, AuthError> {
        self.providers
            .get(name)
            .cloned()
            .ok_or_else(|| AuthError::NotFound(format!("provider {name}")))
    }
}

impl Default for ProviderRegistry {
    fn default() -> Self {
        Self::new()
    }
}
