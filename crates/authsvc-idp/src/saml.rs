use async_trait::async_trait;
use authsvc_core::AuthError;
use base64::Engine;
use serde_json::Value;

use crate::{FederatedUser, IdentityProvider};

/// Minimal SAML 2.0 SP for enterprise IdP integration.
pub struct SamlProvider {
    name: String,
    idp_sso_url: String,
    sp_entity_id: String,
}

impl SamlProvider {
    pub fn from_config(config: &Value, issuer: &str) -> Result<Self, AuthError> {
        Ok(Self {
            name: config["provider"]
                .as_str()
                .unwrap_or("saml")
                .to_string(),
            idp_sso_url: config["idp_sso_url"]
                .as_str()
                .ok_or_else(|| AuthError::Validation("idp_sso_url required".into()))?
                .to_string(),
            sp_entity_id: config["sp_entity_id"]
                .as_str()
                .unwrap_or(issuer)
                .to_string(),
        })
    }

    pub fn metadata_xml(&self, acs_url: &str) -> String {
        format!(
            r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{entity}">
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{acs}" index="0"/>
  </SPSSODescriptor>
</EntityDescriptor>"#,
            entity = self.sp_entity_id,
            acs = acs_url
        )
    }

    pub fn login_redirect_url(&self, relay_state: &str) -> String {
        let encoded_state: String =
            url::form_urlencoded::byte_serialize(relay_state.as_bytes()).collect();
        format!(
            "{}?SAMLRequest=AuthnRequest&RelayState={encoded_state}",
            self.idp_sso_url
        )
    }

    pub fn parse_response(&self, saml_response_b64: &str) -> Result<FederatedUser, AuthError> {
        let xml = base64::engine::general_purpose::STANDARD
            .decode(saml_response_b64)
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        let text = String::from_utf8_lossy(&xml);
        let subject = extract_xml_value(&text, "NameID").unwrap_or_default();
        let email = extract_xml_value(&text, "AttributeValue").or_else(|| {
            if subject.contains('@') {
                Some(subject.clone())
            } else {
                None
            }
        });
        Ok(FederatedUser {
            provider: self.name.clone(),
            subject,
            email,
            name: None,
            email_verified: true,
        })
    }
}

fn extract_xml_value(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}");
    let start = xml.find(&open)?;
    let after = &xml[start..];
    let content_start = after.find('>')? + 1;
    let rest = &after[content_start..];
    let end = rest.find('<')?;
    let value = rest[..end].trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

#[async_trait]
impl IdentityProvider for SamlProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn authorization_url(&self, state: &str, _redirect_uri: &str) -> Result<String, AuthError> {
        Ok(self.login_redirect_url(state))
    }

    async fn exchange_code(
        &self,
        code: &str,
        _redirect_uri: &str,
    ) -> Result<FederatedUser, AuthError> {
        self.parse_response(code)
    }
}
