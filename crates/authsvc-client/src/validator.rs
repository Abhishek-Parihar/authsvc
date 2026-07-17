use std::sync::Arc;
use std::time::Duration;

use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};
use rsa::pkcs8::EncodePublicKey;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("invalid token")]
    InvalidToken,
    #[error("http error: {0}")]
    Http(String),
    #[error("jwks error: {0}")]
    Jwks(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: String,
    pub iss: String,
    pub exp: usize,
    pub iat: usize,
    pub tenant_id: String,
    pub scope: Option<String>,
    pub client_id: Option<String>,
}

#[derive(Clone)]
pub struct JwksValidator {
    issuer: String,
    jwks_uri: String,
    client: reqwest::Client,
    keys: Arc<RwLock<Vec<DecodingKey>>>,
}

impl JwksValidator {
    pub fn new(issuer: impl Into<String>, jwks_uri: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            jwks_uri: jwks_uri.into(),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("reqwest client"),
            keys: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub async fn refresh_keys(&self) -> Result<(), ClientError> {
        let resp = self
            .client
            .get(&self.jwks_uri)
            .send()
            .await
            .map_err(|e| ClientError::Http(e.to_string()))?
            .error_for_status()
            .map_err(|e| ClientError::Http(e.to_string()))?;

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| ClientError::Jwks(e.to_string()))?;

        let keys = body["keys"]
            .as_array()
            .ok_or_else(|| ClientError::Jwks("missing keys".into()))?;

        let mut decoded = Vec::new();
        for key in keys {
            let n = key["n"].as_str().ok_or_else(|| ClientError::Jwks("missing n".into()))?;
            let e = key["e"].as_str().ok_or_else(|| ClientError::Jwks("missing e".into()))?;
            let pem = rsa_components_to_pem(n, e)?;
            let dk = DecodingKey::from_rsa_pem(pem.as_bytes())
                .map_err(|err| ClientError::Jwks(err.to_string()))?;
            decoded.push(dk);
        }

        *self.keys.write().await = decoded;
        Ok(())
    }

    pub async fn validate(&self, token: &str) -> Result<TokenClaims, ClientError> {
        if self.keys.read().await.is_empty() {
            self.refresh_keys().await?;
        }

        let header = decode_header(token).map_err(|_| ClientError::InvalidToken)?;
        let alg = header.alg;

        let keys = self.keys.read().await.clone();
        let mut validation = Validation::new(alg);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&["authsvc"]);

        for key in keys {
            if let Ok(data) = decode::<TokenClaims>(token, &key, &validation) {
                return Ok(data.claims);
            }
        }

        // keys may have rotated
        self.refresh_keys().await?;
        let keys = self.keys.read().await.clone();
        for key in keys {
            if let Ok(data) = decode::<TokenClaims>(token, &key, &validation) {
                return Ok(data.claims);
            }
        }

        Err(ClientError::InvalidToken)
    }
}

fn rsa_components_to_pem(n: &str, e: &str) -> Result<String, ClientError> {
    use base64::Engine;
    let n_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(n)
        .map_err(|err| ClientError::Jwks(err.to_string()))?;
    let e_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(e)
        .map_err(|err| ClientError::Jwks(err.to_string()))?;

    // Build minimal RSA public key PEM via rsa crate
    use rsa::BigUint;
    let public =
        rsa::RsaPublicKey::new(BigUint::from_bytes_be(&n_bytes), BigUint::from_bytes_be(&e_bytes))
            .map_err(|err| ClientError::Jwks(err.to_string()))?;
    public
        .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
        .map(|s| s.to_string())
        .map_err(|err| ClientError::Jwks(err.to_string()))
}

/// Axum middleware extractor helper — validates Bearer token via JWKS.
pub async fn bearer_claims(
    validator: &JwksValidator,
    authorization: Option<&str>,
) -> Result<TokenClaims, ClientError> {
    let header = authorization.ok_or(ClientError::InvalidToken)?;
    let token = header
        .strip_prefix("Bearer ")
        .ok_or(ClientError::InvalidToken)?;
    validator.validate(token).await
}
