use async_trait::async_trait;
use authsvc_core::AuthError;
use base64::Engine;
use serde_json::Value;

use crate::{
    saml_authn_request::{self, SamlAuthnRequestBuilder},
    saml_signature::{sign_saml_xml, verify_saml_xml_signature},
    FederatedUser, IdentityProvider,
};

#[cfg(feature = "encryption")]
use crate::saml_encryption::decrypt_encrypted_assertions;

/// SAML 2.0 Service Provider.
pub struct SamlProvider {
    name: String,
    idp_sso_url: String,
    idp_slo_url: Option<String>,
    sp_entity_id: String,
    issuer: String,
    idp_cert_pem: Option<String>,
    sp_private_key_pem: Option<String>,
    require_signature: bool,
    allow_unsolicited: bool,
}

impl SamlProvider {
    pub fn from_config(config: &Value, issuer: &str) -> Result<Self, AuthError> {
        let idp_cert_pem = config
            .get("idp_cert_pem")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        Ok(Self {
            name: config["provider"]
                .as_str()
                .unwrap_or("saml")
                .to_string(),
            idp_sso_url: config["idp_sso_url"]
                .as_str()
                .ok_or_else(|| AuthError::Validation("idp_sso_url required".into()))?
                .to_string(),
            idp_slo_url: config
                .get("idp_slo_url")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            sp_entity_id: config["sp_entity_id"]
                .as_str()
                .unwrap_or(issuer)
                .to_string(),
            issuer: issuer.to_string(),
            require_signature: config
                .get("require_signature")
                .and_then(|v| v.as_bool())
                .unwrap_or(idp_cert_pem.is_some()),
            idp_cert_pem,
            sp_private_key_pem: config
                .get("sp_private_key_pem")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            allow_unsolicited: config
                .get("unsolicited")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
        })
    }

    pub fn acs_url(&self) -> String {
        format!("{}/saml/acs", self.issuer.trim_end_matches('/'))
    }

    pub fn slo_url(&self) -> String {
        format!("{}/saml/slo", self.issuer.trim_end_matches('/'))
    }

    pub fn metadata_xml(&self, acs_url: &str) -> String {
        let slo = self.slo_url();
        let slo_service = if self.idp_slo_url.is_some() {
            format!(
                r#"    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{slo}"/>
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{slo}"/>
"#
            )
        } else {
            String::new()
        };
        format!(
            r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{entity}">
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
{slo_service}    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{acs}" index="0"/>
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{acs}" index="1"/>
  </SPSSODescriptor>
</EntityDescriptor>"#,
            entity = self.sp_entity_id,
            acs = acs_url,
            slo_service = slo_service,
        )
    }

    /// Returns `(redirect_url, request_id)`.
    pub fn login_redirect_url(&self, relay_state: &str) -> Result<(String, String), AuthError> {
        SamlAuthnRequestBuilder::new(&self.sp_entity_id, self.acs_url(), &self.idp_sso_url)
            .sp_private_key_pem(self.sp_private_key_pem.clone())
            .build_redirect_url(relay_state)
    }

    pub fn parse_response(
        &self,
        saml_response_b64: &str,
        in_response_to: Option<&str>,
    ) -> Result<FederatedUser, AuthError> {
        let xml = base64::engine::general_purpose::STANDARD
            .decode(saml_response_b64)
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        let mut text = String::from_utf8_lossy(&xml).into_owned();

        if let Some(sp_key) = &self.sp_private_key_pem {
            #[cfg(feature = "encryption")]
            {
                if text.contains("EncryptedAssertion") || text.contains("xenc:EncryptedData") {
                    text = decrypt_encrypted_assertions(&text, sp_key)?;
                }
            }
            #[cfg(not(feature = "encryption"))]
            if text.contains("EncryptedAssertion") {
                return Err(AuthError::Validation(
                    "encrypted assertions require authsvc-idp encryption feature".into(),
                ));
            }
        }

        validate_saml_response(&text, self, in_response_to)?;

        let subject = extract_xml_value(&text, "NameID").unwrap_or_default();
        let email = extract_named_attribute(&text, "mail")
            .or_else(|| extract_named_attribute(&text, "email"))
            .or_else(|| {
                extract_xml_value(&text, "AttributeValue").filter(|v| v.contains('@'))
            })
            .or_else(|| {
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
            name: extract_named_attribute(&text, "displayName")
                .or_else(|| extract_named_attribute(&text, "cn"))
                .or_else(|| extract_xml_value(&text, "Attribute")),
            email_verified: true,
        })
    }

    pub fn build_logout_request(&self, name_id: &str, session_index: Option<&str>) -> Result<(String, String), AuthError> {
        let request_id = saml_authn_request::generate_saml_id();
        let issue_instant = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
        let destination = self
            .idp_slo_url
            .as_deref()
            .unwrap_or(&self.idp_sso_url);
        let session_index_xml = session_index
            .map(|idx| format!(r#"  <samlp:SessionIndex>{idx}</samlp:SessionIndex>"#))
            .unwrap_or_default();
        let mut xml = format!(
            r#"<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{request_id}" Version="2.0" IssueInstant="{issue_instant}" Destination="{destination}">
  <saml:Issuer>{issuer}</saml:Issuer>
  <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{name_id}</saml:NameID>
{session_index_xml}
</samlp:LogoutRequest>"#,
            request_id = request_id,
            issue_instant = issue_instant,
            destination = destination,
            issuer = self.sp_entity_id,
            name_id = name_id,
            session_index_xml = session_index_xml,
        );
        if let Some(key_pem) = &self.sp_private_key_pem {
            xml = sign_saml_xml(&xml, key_pem, &request_id)?;
        }
        Ok((xml, request_id))
    }

    pub fn logout_redirect_url(
        &self,
        name_id: &str,
        session_index: Option<&str>,
        relay_state: &str,
    ) -> Result<String, AuthError> {
        let destination = self
            .idp_slo_url
            .as_deref()
            .ok_or_else(|| AuthError::Validation("idp_slo_url required for SP-initiated logout".into()))?;
        let (xml, _) = self.build_logout_request(name_id, session_index)?;
        let encoded_request = saml_authn_request::deflate_base64_url_encode(xml.as_bytes())?;
        let encoded_state: String =
            url::form_urlencoded::byte_serialize(relay_state.as_bytes()).collect();
        Ok(format!(
            "{destination}?SAMLRequest={encoded_request}&RelayState={encoded_state}"
        ))
    }

    pub fn parse_logout_request(&self, saml_request_b64: &str) -> Result<String, AuthError> {
        let xml = decode_saml_message(saml_request_b64)?;
        if !xml.contains("LogoutRequest") {
            return Err(AuthError::Validation("expected LogoutRequest".into()));
        }
        if let Some(cert_pem) = &self.idp_cert_pem {
            verify_saml_xml_signature(&xml, cert_pem)?;
        }
        extract_xml_value(&xml, "NameID")
            .ok_or_else(|| AuthError::Validation("LogoutRequest missing NameID".into()))
    }

    pub fn build_logout_response(&self, in_response_to: &str, status: &str) -> Result<String, AuthError> {
        let response_id = saml_authn_request::generate_saml_id();
        let issue_instant = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
        let mut xml = format!(
            r#"<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{response_id}" Version="2.0" IssueInstant="{issue_instant}" Destination="{destination}" InResponseTo="{in_response_to}">
  <saml:Issuer>{issuer}</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="{status}"/>
  </samlp:Status>
</samlp:LogoutResponse>"#,
            response_id = response_id,
            issue_instant = issue_instant,
            destination = self.idp_slo_url.as_deref().unwrap_or(&self.idp_sso_url),
            in_response_to = in_response_to,
            issuer = self.sp_entity_id,
            status = status,
        );
        if let Some(key_pem) = &self.sp_private_key_pem {
            xml = sign_saml_xml(&xml, key_pem, &response_id)?;
        }
        Ok(xml)
    }

    pub fn parse_logout_response(&self, saml_response_b64: &str) -> Result<(), AuthError> {
        let xml = decode_saml_message(saml_response_b64)?;
        if !xml.contains("LogoutResponse") {
            return Err(AuthError::Validation("expected LogoutResponse".into()));
        }
        if let Some(cert_pem) = &self.idp_cert_pem {
            verify_saml_xml_signature(&xml, cert_pem)?;
        }
        if !xml.contains("Success") && !xml.contains("samlp:Success") {
            return Err(AuthError::Validation("SAML logout status not Success".into()));
        }
        Ok(())
    }
}

pub fn encode_relay_state(federation_state: &str, request_id: &str) -> String {
    format!("{federation_state}|{request_id}")
}

pub fn split_relay_state(relay_state: &str) -> (&str, Option<&str>) {
    relay_state
        .split_once('|')
        .map(|(state, request_id)| (state, Some(request_id)))
        .unwrap_or((relay_state, None))
}

fn decode_saml_message(encoded: &str) -> Result<String, AuthError> {
    saml_authn_request::decode_redirect_saml_message(encoded)
}

fn validate_saml_response(
    xml: &str,
    provider: &SamlProvider,
    in_response_to: Option<&str>,
) -> Result<(), AuthError> {
    if !xml.contains("Success") && !xml.contains("samlp:Success") {
        return Err(AuthError::Validation("SAML response status not Success".into()));
    }

    let response_in_response_to = extract_attribute(xml, "InResponseTo");
    match (response_in_response_to.as_deref(), in_response_to) {
        (Some(actual), Some(expected)) if actual != expected => {
            return Err(AuthError::Validation(format!(
                "SAML InResponseTo mismatch: expected {expected}, got {actual}"
            )));
        }
        (None, Some(_)) if !provider.allow_unsolicited => {
            return Err(AuthError::Validation(
                "SAML response missing InResponseTo; enable unsolicited for IdP-initiated SSO"
                    .into(),
            ));
        }
        _ => {}
    }

    if xml.contains("NotOnOrAfter") {
        if let Some(expiry) = extract_attribute(xml, "NotOnOrAfter") {
            if let Ok(ts) = chrono::DateTime::parse_from_rfc3339(&expiry) {
                if ts < chrono::Utc::now() {
                    return Err(AuthError::Validation("SAML assertion expired".into()));
                }
            }
        }
    }

    let has_signature = xml.contains("Signature") || xml.contains("ds:Signature");
    if provider.require_signature && !has_signature {
        return Err(AuthError::Validation(
            "SAML response missing signature; set idp_cert_pem in config".into(),
        ));
    }

    if let Some(cert_pem) = &provider.idp_cert_pem {
        if !has_signature {
            return Err(AuthError::Validation("SAML signature required".into()));
        }
        verify_saml_xml_signature(xml, cert_pem)?;
    } else if provider.require_signature {
        return Err(AuthError::Validation(
            "idp_cert_pem required when require_signature is enabled".into(),
        ));
    }

    Ok(())
}

fn extract_xml_value(xml: &str, tag: &str) -> Option<String> {
    let patterns = [format!("<{tag}"), format!("<saml:{tag}"), format!("<samlp:{tag}")];
    let start = patterns
        .iter()
        .filter_map(|open| xml.find(open))
        .min()?;
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

fn extract_named_attribute(xml: &str, name: &str) -> Option<String> {
    let pattern = format!("Name=\"{name}\"");
    let attr_pos = xml.find(&pattern)?;
    let section = &xml[attr_pos..];
    extract_xml_value(section, "AttributeValue")
}

fn extract_attribute(xml: &str, attr: &str) -> Option<String> {
    let pattern = format!("{attr}=\"");
    let start = xml.find(&pattern)? + pattern.len();
    let rest = &xml[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

#[async_trait]
impl IdentityProvider for SamlProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn authorization_url(&self, state: &str, _redirect_uri: &str) -> Result<String, AuthError> {
        let builder = SamlAuthnRequestBuilder::new(
            &self.sp_entity_id,
            self.acs_url(),
            &self.idp_sso_url,
        )
        .sp_private_key_pem(self.sp_private_key_pem.clone());
        let (xml, request_id) = builder.build()?;
        let relay = encode_relay_state(state, &request_id);
        let encoded_request = saml_authn_request::deflate_base64_url_encode(xml.as_bytes())?;
        let encoded_state: String =
            url::form_urlencoded::byte_serialize(relay.as_bytes()).collect();
        Ok(format!(
            "{}?SAMLRequest={encoded_request}&RelayState={encoded_state}",
            self.idp_sso_url
        ))
    }

    async fn exchange_code(
        &self,
        code: &str,
        _redirect_uri: &str,
    ) -> Result<FederatedUser, AuthError> {
        self.parse_response(code, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SIGNED_RESPONSE: &str =
        include_str!("../tests/fixtures/saml/response_signed_by_idp_ecdsa.xml");
    const IDP_PUBLIC_KEY_PEM: &str =
        include_str!("../tests/fixtures/keys/ec/saml-idp-ecdsa-pubkey.pem");

    #[test]
    fn rejects_missing_signature_when_cert_configured() {
        let provider = SamlProvider::from_config(
            &json!({
                "idp_sso_url": "https://idp.example/sso",
                "idp_cert_pem": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
            }),
            "https://sp.example",
        )
        .unwrap();
        let xml = base64::engine::general_purpose::STANDARD.encode(
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject></saml:Assertion>
</samlp:Response>"#,
        );
        assert!(provider.parse_response(&xml, None).is_err());
    }

    #[test]
    fn accepts_signed_fixture_with_unsolicited() {
        let provider = SamlProvider::from_config(
            &json!({
                "idp_sso_url": "https://idp.example/sso",
                "idp_cert_pem": IDP_PUBLIC_KEY_PEM,
                "unsolicited": true
            }),
            "https://sp.example",
        )
        .unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode(SIGNED_RESPONSE);
        let user = provider.parse_response(&encoded, None).expect("parse");
        assert_eq!(user.email.as_deref(), Some("test@example.com"));
    }

    #[test]
    fn metadata_includes_slo_when_configured() {
        let provider = SamlProvider::from_config(
            &json!({
                "idp_sso_url": "https://idp.example/sso",
                "idp_slo_url": "https://idp.example/slo"
            }),
            "https://sp.example",
        )
        .unwrap();
        let metadata = provider.metadata_xml("https://sp.example/saml/acs");
        assert!(metadata.contains("SingleLogoutService"));
    }
}
