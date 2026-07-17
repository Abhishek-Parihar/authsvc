use std::sync::Arc;

use authsvc_core::AuthError;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use rsa::RsaPrivateKey;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub sub: String,
    pub iss: String,
    pub aud: Vec<String>,
    pub exp: usize,
    pub iat: usize,
    pub jti: String,
    pub tenant_id: String,
    pub client_id: Option<String>,
    pub scope: String,
    pub token_type: String,
}

#[derive(Clone)]
pub struct JwtSigner {
    encoding: EncodingKey,
    decoding: DecodingKey,
    kid: String,
    issuer: String,
    access_ttl_secs: u64,
    public_pem: String,
}

impl JwtSigner {
    pub fn new(
        issuer: &str,
        access_ttl_secs: u64,
        private_pem: Option<String>,
        public_pem: Option<String>,
    ) -> Result<Self, AuthError> {
        let (private_key, public_key_pem) = match (private_pem, public_pem) {
            (Some(priv_pem), Some(pub_pem)) => (priv_pem, pub_pem),
            _ => {
                let mut rng = rand::thread_rng();
                let private = RsaPrivateKey::new(&mut rng, 2048)
                    .map_err(|e| AuthError::Internal(e.to_string()))?;
                let public = rsa::RsaPublicKey::from(&private);
                let priv_pem = private
                    .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
                    .map_err(|e| AuthError::Internal(e.to_string()))?
                    .to_string();
                let pub_pem = public
                    .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
                    .map_err(|e| AuthError::Internal(e.to_string()))?
                    .to_string();
                tracing::warn!("generated ephemeral RSA key pair; set JWT_*_KEY_PEM for production");
                (priv_pem, pub_pem)
            }
        };

        let encoding = EncodingKey::from_rsa_pem(private_key.as_bytes())
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        let decoding = DecodingKey::from_rsa_pem(public_key_pem.as_bytes())
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        Ok(Self {
            encoding,
            decoding,
            kid: "authsvc-key-1".into(),
            issuer: issuer.to_string(),
            access_ttl_secs,
            public_pem: public_key_pem,
        })
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    pub fn public_pem(&self) -> &str {
        &self.public_pem
    }

    pub fn issue_access_token(
        &self,
        subject: Uuid,
        tenant_id: Uuid,
        client_id: Option<&str>,
        scopes: &[String],
    ) -> Result<(String, AccessTokenClaims), AuthError> {
        let now = chrono::Utc::now().timestamp() as usize;
        let claims = AccessTokenClaims {
            sub: subject.to_string(),
            iss: self.issuer.clone(),
            aud: vec!["authsvc".into()],
            exp: now + self.access_ttl_secs as usize,
            iat: now,
            jti: Uuid::new_v4().to_string(),
            tenant_id: tenant_id.to_string(),
            client_id: client_id.map(str::to_string),
            scope: scopes.join(" "),
            token_type: "Bearer".into(),
        };

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.kid.clone());

        let token = encode(&header, &claims, &self.encoding)
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok((token, claims))
    }

    pub fn validate_access_token(&self, token: &str) -> Result<AccessTokenClaims, AuthError> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&["authsvc"]);

        decode::<AccessTokenClaims>(token, &self.decoding, &validation)
            .map(|data| data.claims)
            .map_err(|_| AuthError::InvalidToken)
    }

    pub fn jwks(&self) -> Result<serde_json::Value, AuthError> {
        use rsa::traits::PublicKeyParts;
        let public = rsa::RsaPublicKey::from_public_key_pem(&self.public_pem)
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        let n = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            public.n().to_bytes_be(),
        );
        let e = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            public.e().to_bytes_be(),
        );

        Ok(serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": self.kid,
                "n": n,
                "e": e
            }]
        }))
    }
}

pub type SharedJwtSigner = Arc<JwtSigner>;
