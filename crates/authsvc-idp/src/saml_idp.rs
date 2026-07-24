use authsvc_core::AuthError;
use base64::Engine;
use chrono::{Duration, Utc};

use crate::saml_authn_request::{decode_redirect_saml_message, generate_saml_id};
use crate::saml_signature::{sign_saml_xml, verify_saml_xml_signature};

const SAML_PROTOCOL_NS: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
const SAML_ASSERTION_NS: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
const NAMEID_EMAIL: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

#[derive(Debug, Clone)]
pub struct ParsedAuthnRequest {
    pub id: String,
    pub issuer: String,
    pub acs_url: String,
}

pub fn decode_saml_request_param(encoded: &str) -> Result<String, AuthError> {
    decode_redirect_saml_message(encoded)
}

pub fn parse_authn_request(xml: &str) -> Result<ParsedAuthnRequest, AuthError> {
    if !xml.contains("AuthnRequest") {
        return Err(AuthError::Validation("expected AuthnRequest".into()));
    }
    let id = extract_xml_attr(xml, "ID")
        .ok_or_else(|| AuthError::Validation("AuthnRequest missing ID".into()))?;
    let issuer = extract_xml_value(xml, "Issuer")
        .ok_or_else(|| AuthError::Validation("AuthnRequest missing Issuer".into()))?;
    let acs_url = extract_xml_attr(xml, "AssertionConsumerServiceURL")
        .ok_or_else(|| AuthError::Validation("AuthnRequest missing ACS URL".into()))?;
    Ok(ParsedAuthnRequest {
        id,
        issuer,
        acs_url,
    })
}

pub fn verify_authn_request_signature(xml: &str, sp_cert_pem: &str) -> Result<(), AuthError> {
    verify_saml_xml_signature(xml, sp_cert_pem)
}

pub fn build_authn_response(
    idp_entity_id: &str,
    sp_entity_id: &str,
    acs_url: &str,
    in_response_to: &str,
    name_id: &str,
    email: &str,
    display_name: Option<&str>,
    idp_private_key_pem: &str,
) -> Result<String, AuthError> {
    let response_id = generate_saml_id();
    let assertion_id = generate_saml_id();
    let now = Utc::now();
    let issue_instant = now.format("%Y-%m-%dT%H:%M:%SZ");
    let not_on_or_after = (now + Duration::minutes(5)).format("%Y-%m-%dT%H:%M:%SZ");
    let not_before = (now - Duration::minutes(1)).format("%Y-%m-%dT%H:%M:%SZ");
    let name = display_name.unwrap_or(email);

    let mut xml = format!(
        r#"<samlp:Response xmlns:samlp="{SAML_PROTOCOL_NS}" xmlns:saml="{SAML_ASSERTION_NS}" ID="{response_id}" Version="2.0" IssueInstant="{issue_instant}" Destination="{acs_url}" InResponseTo="{in_response_to}">
  <saml:Issuer>{idp_entity_id}</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion ID="{assertion_id}" Version="2.0" IssueInstant="{issue_instant}">
    <saml:Issuer>{idp_entity_id}</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="{NAMEID_EMAIL}">{name_id}</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="{not_on_or_after}" Recipient="{acs_url}" InResponseTo="{in_response_to}"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="{not_before}" NotOnOrAfter="{not_on_or_after}">
      <saml:AudienceRestriction>
        <saml:Audience>{sp_entity_id}</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AttributeStatement>
      <saml:Attribute Name="email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue>{email}</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="displayName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue>{name}</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>"#,
        response_id = xml_escape(&response_id),
        issue_instant = issue_instant,
        acs_url = xml_escape(acs_url),
        in_response_to = xml_escape(in_response_to),
        idp_entity_id = xml_escape(idp_entity_id),
        assertion_id = xml_escape(&assertion_id),
        name_id = xml_escape(name_id),
        not_on_or_after = not_on_or_after,
        not_before = not_before,
        sp_entity_id = xml_escape(sp_entity_id),
        email = xml_escape(email),
        name = xml_escape(name),
    );

    xml = sign_saml_xml(&xml, idp_private_key_pem, &response_id)?;
    Ok(xml)
}

pub fn encode_response_for_post(response_xml: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(response_xml.as_bytes())
}

pub fn post_binding_html(acs_url: &str, saml_response_b64: &str, relay_state: Option<&str>) -> String {
    let relay_input = relay_state
        .map(|rs| format!(r#"<input type="hidden" name="RelayState" value="{}"/>"#, xml_escape(rs)))
        .unwrap_or_default();
    format!(
        r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Redirecting…</title></head>
<body onload="document.forms[0].submit()">
<p>Redirecting to your application…</p>
<form method="post" action="{acs_url}">
<input type="hidden" name="SAMLResponse" value="{saml_response_b64}"/>
{relay_input}
<noscript><button type="submit">Continue</button></noscript>
</form></body></html>"#,
        acs_url = xml_escape(acs_url),
        saml_response_b64 = xml_escape(saml_response_b64),
        relay_input = relay_input,
    )
}

pub fn idp_metadata_xml(
    entity_id: &str,
    sso_url: &str,
    slo_url: &str,
    cert_pem: &str,
) -> String {
    let cert_body = cert_pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    format!(
        r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{entity_id}">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data><ds:X509Certificate>{cert_body}</ds:X509Certificate></ds:X509Data>
      </ds:KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{sso_url}"/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{sso_url}"/>
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{slo_url}"/>
    <NameIDFormat>{NAMEID_EMAIL}</NameIDFormat>
  </IDPSSODescriptor>
</EntityDescriptor>"#,
        entity_id = xml_escape(entity_id),
        cert_body = cert_body,
        sso_url = xml_escape(sso_url),
        slo_url = xml_escape(slo_url),
    )
}

fn extract_xml_attr(xml: &str, attr: &str) -> Option<String> {
    let pattern = format!("{attr}=\"");
    let start = xml.find(&pattern)? + pattern.len();
    let rest = &xml[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn extract_xml_value(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<saml:{tag}>");
    let close = format!("</saml:{tag}>");
    if let Some(start) = xml.find(&open) {
        let rest = &xml[start + open.len()..];
        if let Some(end) = rest.find(&close) {
            return Some(rest[..end].to_string());
        }
    }
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    if let Some(start) = xml.find(&open) {
        let rest = &xml[start + open.len()..];
        if let Some(end) = rest.find(&close) {
            return Some(rest[..end].to_string());
        }
    }
    None
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
    use rsa::pkcs8::{EncodePrivateKey, LineEnding};
    use rsa::RsaPrivateKey;

    #[test]
    fn parses_authn_request() {
        let xml = r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_req1" Version="2.0" IssueInstant="2020-01-01T00:00:00Z" AssertionConsumerServiceURL="https://sp.example/acs">
  <saml:Issuer>https://sp.example</saml:Issuer>
</samlp:AuthnRequest>"#;
        let parsed = parse_authn_request(xml).unwrap();
        assert_eq!(parsed.id, "_req1");
        assert_eq!(parsed.issuer, "https://sp.example");
        assert_eq!(parsed.acs_url, "https://sp.example/acs");
    }

    #[test]
    fn builds_signed_response() {
        let mut rng = rand::thread_rng();
        let private = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let private_pem = private.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
        let response = build_authn_response(
            "https://idp.example",
            "https://sp.example",
            "https://sp.example/acs",
            "_req1",
            "user@example.com",
            "user@example.com",
            Some("Test User"),
            &private_pem,
        )
        .unwrap();
        assert!(response.contains("samlp:Response"));
        assert!(response.contains("ds:Signature"));
        assert!(response.contains("user@example.com"));
    }
}
