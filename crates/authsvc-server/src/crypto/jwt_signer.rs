use authsvc_core::AuthError;
use base64::engine::Engine;
use jsonwebtoken::{Algorithm, Header};
use serde::Serialize;

#[derive(Clone)]
pub enum JwtSigningBackend {
    Local {
        private_pem: String,
    },
    HttpKms {
        url: String,
        key_id: Option<String>,
    },
}

impl JwtSigningBackend {
    pub fn local(private_pem: String) -> Self {
        Self::Local { private_pem }
    }

    pub fn http_kms(url: String, key_id: Option<String>) -> Self {
        Self::HttpKms { url, key_id }
    }

    pub fn sign_rs256(&self, signing_input: &[u8]) -> Result<Vec<u8>, AuthError> {
        match self {
            Self::Local { private_pem } => sign_local_rs256(private_pem, signing_input),
            Self::HttpKms { url, key_id } => sign_kms_rs256(url, key_id.as_deref(), signing_input),
        }
    }
}

fn sign_local_rs256(private_pem: &str, signing_input: &[u8]) -> Result<Vec<u8>, AuthError> {
    use rsa::pkcs1v15::SigningKey;
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::signature::{SignatureEncoding, Signer};
    use rsa::RsaPrivateKey;
    use sha2::Sha256;

    let private = RsaPrivateKey::from_pkcs8_pem(private_pem)
        .map_err(|e| AuthError::Internal(e.to_string()))?;
    let signing_key = SigningKey::<Sha256>::new(private);
    Ok(signing_key.sign(signing_input).to_bytes().to_vec())
}

fn sign_kms_rs256(url: &str, key_id: Option<&str>, signing_input: &[u8]) -> Result<Vec<u8>, AuthError> {
    let client = crate::http_client::outbound_blocking_client();
    let resp = client
        .post(format!("{url}/sign"))
        .json(&serde_json::json!({
            "message": base64::engine::general_purpose::STANDARD.encode(signing_input),
            "key_id": key_id,
            "algorithm": "RSASSA_PKCS1_V1_5_SHA_256"
        }))
        .send()
        .map_err(|e| AuthError::Internal(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(AuthError::Internal(format!(
            "JWT KMS sign failed: {}",
            resp.status()
        )));
    }
    let body: serde_json::Value = resp
        .json()
        .map_err(|e| AuthError::Internal(e.to_string()))?;
    let b64 = body["signature"]
        .as_str()
        .ok_or_else(|| AuthError::Internal("invalid JWT KMS sign response".into()))?;
    base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| AuthError::Internal(e.to_string()))
}

pub fn base64url_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

pub fn encode_rs256_jwt<T: Serialize>(
    backend: &JwtSigningBackend,
    kid: &str,
    claims: &T,
) -> Result<String, AuthError> {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());
    header.typ = Some("JWT".into());

    let header_b64 = base64url_encode(
        &serde_json::to_vec(&header).map_err(|e| AuthError::Internal(e.to_string()))?,
    );
    let payload_b64 = base64url_encode(
        &serde_json::to_vec(claims).map_err(|e| AuthError::Internal(e.to_string()))?,
    );
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = backend.sign_rs256(signing_input.as_bytes())?;
    Ok(format!(
        "{signing_input}.{}",
        base64url_encode(&signature)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::jwt::generate_rsa_keypair;

    #[test]
    fn local_backend_signs_jwt() {
        let (priv_pem, _) = generate_rsa_keypair().unwrap();
        let backend = JwtSigningBackend::local(priv_pem);
        let token = encode_rs256_jwt(
            &backend,
            "test-kid",
            &serde_json::json!({"sub": "user-1", "iss": "http://localhost"}),
        )
        .unwrap();
        assert_eq!(token.matches('.').count(), 2);
    }
}
