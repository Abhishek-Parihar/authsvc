use authsvc_core::AuthError;
use base64::Engine;
use chrono::Utc;
use flate2::write::DeflateEncoder;
use flate2::Compression;
use std::io::Write;
use uuid::Uuid;

use crate::saml_signature::sign_saml_xml;

const SAML_PROTOCOL_NS: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
const SAML_ASSERTION_NS: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
const HTTP_POST_BINDING: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
const NAMEID_EMAIL: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

/// Builds SAML 2.0 AuthnRequest documents for HTTP-Redirect binding.
pub struct SamlAuthnRequestBuilder {
    sp_entity_id: String,
    acs_url: String,
    idp_sso_url: String,
    name_id_format: String,
    sp_private_key_pem: Option<String>,
}

impl SamlAuthnRequestBuilder {
    pub fn new(sp_entity_id: impl Into<String>, acs_url: impl Into<String>, idp_sso_url: impl Into<String>) -> Self {
        Self {
            sp_entity_id: sp_entity_id.into(),
            acs_url: acs_url.into(),
            idp_sso_url: idp_sso_url.into(),
            name_id_format: NAMEID_EMAIL.to_string(),
            sp_private_key_pem: None,
        }
    }

    pub fn name_id_format(mut self, format: impl Into<String>) -> Self {
        self.name_id_format = format.into();
        self
    }

    pub fn sp_private_key_pem(mut self, key: Option<String>) -> Self {
        self.sp_private_key_pem = key;
        self
    }

    /// Returns `(request_xml, request_id)`.
    pub fn build(&self) -> Result<(String, String), AuthError> {
        let request_id = generate_saml_id();
        let issue_instant = Utc::now().format("%Y-%m-%dT%H:%M:%SZ");

        let mut xml = format!(
            r#"<samlp:AuthnRequest xmlns:samlp="{SAML_PROTOCOL_NS}" xmlns:saml="{SAML_ASSERTION_NS}" ID="{request_id}" Version="2.0" IssueInstant="{issue_instant}" Destination="{destination}" AssertionConsumerServiceURL="{acs}" ProtocolBinding="{HTTP_POST_BINDING}">
  <saml:Issuer>{issuer}</saml:Issuer>
  <samlp:NameIDPolicy Format="{name_id_format}" AllowCreate="true"/>
</samlp:AuthnRequest>"#,
            request_id = xml_escape(&request_id),
            issue_instant = issue_instant,
            destination = xml_escape(&self.idp_sso_url),
            acs = xml_escape(&self.acs_url),
            issuer = xml_escape(&self.sp_entity_id),
            name_id_format = xml_escape(&self.name_id_format),
        );

        if let Some(key_pem) = &self.sp_private_key_pem {
            xml = sign_saml_xml(&xml, key_pem, &request_id)?;
        }

        Ok((xml, request_id))
    }

    /// Returns `(redirect_url, request_id)` with DEFLATE+base64 SAMLRequest per HTTP-Redirect binding.
    pub fn build_redirect_url(&self, relay_state: &str) -> Result<(String, String), AuthError> {
        let (xml, request_id) = self.build()?;
        let encoded_request = deflate_base64_url_encode(xml.as_bytes())?;
        let encoded_state: String =
            url::form_urlencoded::byte_serialize(relay_state.as_bytes()).collect();
        let url = format!(
            "{}?SAMLRequest={encoded_request}&RelayState={encoded_state}",
            self.idp_sso_url
        );
        Ok((url, request_id))
    }
}

pub fn generate_saml_id() -> String {
    format!("_{}", Uuid::new_v4().simple())
}

/// SAML HTTP-Redirect uses raw DEFLATE (no zlib wrapper) then base64.
pub fn deflate_base64_url_encode(input: &[u8]) -> Result<String, AuthError> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(input)
        .map_err(|e| AuthError::Internal(e.to_string()))?;
    let deflated = encoder
        .finish()
        .map_err(|e| AuthError::Internal(e.to_string()))?;
    let b64 = base64::engine::general_purpose::STANDARD.encode(deflated);
    Ok(url::form_urlencoded::byte_serialize(b64.as_bytes()).collect())
}

/// Inflate raw DEFLATE bytes (SAML HTTP-Redirect binding).
pub fn inflate_raw_deflate(input: &[u8]) -> Result<Vec<u8>, AuthError> {
    use flate2::read::DeflateDecoder;
    use std::io::Read;
    let mut decoder = DeflateDecoder::new(input);
    let mut output = Vec::new();
    decoder
        .read_to_end(&mut output)
        .map_err(|e| AuthError::Internal(format!("SAML inflate failed: {e}")))?;
    Ok(output)
}

pub fn decode_redirect_saml_message(encoded: &str) -> Result<String, AuthError> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| AuthError::Validation(format!("invalid SAML message encoding: {e}")))?;
    let xml_bytes = inflate_raw_deflate(&decoded).unwrap_or(decoded);
    String::from_utf8(xml_bytes)
        .map_err(|e| AuthError::Validation(format!("invalid SAML XML: {e}")))
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authn_request_contains_required_elements() {
        let builder = SamlAuthnRequestBuilder::new(
            "https://sp.example",
            "https://sp.example/saml/acs",
            "https://idp.example/sso",
        );
        let (xml, request_id) = builder.build().unwrap();
        assert!(xml.contains(&format!("ID=\"{request_id}\"")));
        assert!(xml.contains("IssueInstant="));
        assert!(xml.contains("AssertionConsumerServiceURL=\"https://sp.example/saml/acs\""));
        assert!(xml.contains("NameIDPolicy"));
        assert!(xml.contains(NAMEID_EMAIL));
    }

    #[test]
    fn redirect_url_uses_deflated_saml_request() {
        let builder = SamlAuthnRequestBuilder::new(
            "https://sp.example",
            "https://sp.example/saml/acs",
            "https://idp.example/sso",
        );
        let (url, _) = builder.build_redirect_url("state-123").unwrap();
        assert!(url.starts_with("https://idp.example/sso?SAMLRequest="));
        assert!(url.contains("RelayState=state-123"));
        assert!(!url.contains("SAMLRequest=AuthnRequest"));
    }
}
