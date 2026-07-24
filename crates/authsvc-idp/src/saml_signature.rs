use authsvc_core::AuthError;
use base64::Engine;
use x509_parser::prelude::FromDer;
use xml_sec::c14n::{C14nAlgorithm, C14nMode};
use xml_sec::xmldsig::{ReferenceBuilder, SignatureBuilder};
use xml_sec::xmldsig::sign::{RsaSigningKey, SignContext};
use xml_sec::xmldsig::verify::{verify_signature_with_pem_key, DsigStatus};
use xml_sec::xmldsig::{DigestAlgorithm, SignatureAlgorithm, Transform};

/// Verify the XML digital signature on a SAML response using the IdP certificate or public key.
pub fn verify_saml_xml_signature(xml: &str, idp_cert_pem: &str) -> Result<(), AuthError> {
    let public_key_pem = public_key_pem_from_cert(idp_cert_pem)?;
    let result = verify_signature_with_pem_key(xml, &public_key_pem, false)
        .map_err(|e| AuthError::Validation(format!("SAML signature parse error: {e}")))?;

    match result.status {
        DsigStatus::Valid => Ok(()),
        other => Err(AuthError::Validation(format!(
            "SAML XML signature verification failed: {other:?}"
        ))),
    }
}

/// Sign a SAML XML document (AuthnRequest, LogoutRequest) with the SP private key.
pub fn sign_saml_xml(xml: &str, sp_private_key_pem: &str, element_id: &str) -> Result<String, AuthError> {
    let signing_key = RsaSigningKey::from_pkcs8_pem(sp_private_key_pem)
        .map_err(|e| AuthError::Validation(format!("invalid SP signing key: {e}")))?;
    let c14n = C14nAlgorithm::new(C14nMode::Exclusive1_0, false);
    let builder = SignatureBuilder::new(c14n.clone(), SignatureAlgorithm::RsaSha256)
        .ns_prefix("ds")
        .add_reference(
            ReferenceBuilder::new(DigestAlgorithm::Sha256)
                .uri(format!("#{element_id}"))
                .transform(Transform::Enveloped)
                .transform(Transform::C14n(c14n)),
        )
        .key_info(true);
    SignContext::new(&signing_key)
        .sign_with_builder(xml, &builder)
        .map_err(|e| AuthError::Validation(format!("SAML signing failed: {e}")))
}

pub fn public_key_pem_from_cert(cert_or_key_pem: &str) -> Result<String, AuthError> {
    let trimmed = cert_or_key_pem.trim();
    if trimmed.contains("BEGIN PUBLIC KEY") {
        return Ok(trimmed.to_string());
    }

    let (_, pem) = x509_parser::pem::parse_x509_pem(trimmed.as_bytes())
        .map_err(|e| AuthError::Validation(format!("invalid IdP certificate PEM: {e}")))?;
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(&pem.contents)
        .map_err(|e| AuthError::Validation(format!("invalid IdP certificate DER: {e}")))?;

    let spki_der = cert.tbs_certificate.subject_pki.raw;
    let b64 = base64::engine::general_purpose::STANDARD.encode(spki_der);
    let wrapped = b64
        .as_bytes()
        .chunks(64)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n");

    Ok(format!(
        "-----BEGIN PUBLIC KEY-----\n{wrapped}\n-----END PUBLIC KEY-----"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
    use rsa::RsaPrivateKey;

    const SIGNED_RESPONSE: &str =
        include_str!("../tests/fixtures/saml/response_signed_by_idp_ecdsa.xml");
    const IDP_PUBLIC_KEY_PEM: &str =
        include_str!("../tests/fixtures/keys/ec/saml-idp-ecdsa-pubkey.pem");

    #[test]
    fn verifies_signed_saml_response_fixture() {
        verify_saml_xml_signature(SIGNED_RESPONSE, IDP_PUBLIC_KEY_PEM).expect("valid signature");
    }

    #[test]
    fn signs_authn_request_with_sp_key() {
        let mut rng = rand::thread_rng();
        let private = RsaPrivateKey::new(&mut rng, 2048).expect("rsa key");
        let private_pem = private
            .to_pkcs8_pem(LineEnding::LF)
            .expect("pem")
            .to_string();
        let request_id = "_test-request-id";
        let xml = format!(
            r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{request_id}" Version="2.0" IssueInstant="2020-01-01T00:00:00Z" Destination="https://idp.example/sso" AssertionConsumerServiceURL="https://sp.example/acs" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
  <saml:Issuer>https://sp.example</saml:Issuer>
</samlp:AuthnRequest>"#
        );
        let signed = sign_saml_xml(&xml, &private_pem, request_id).expect("sign");
        assert!(signed.contains("ds:Signature"));
        let public_pem = private
            .to_public_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("pub pem")
            .to_string();
        verify_saml_xml_signature(&signed, &public_pem).expect("self-verify");
    }
}
