use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use authsvc_core::{AuthError, DataKeyStore, SigningKeyStore, User};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use rsa::pkcs8::{DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use rsa::RsaPrivateKey;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::jwt_signer::{encode_rs256_jwt, JwtSigningBackend};
use super::signing_keys::{decrypt_private_pem, encrypt_private_pem, ensure_signing_key};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub sub: String,
    pub iss: String,
    pub aud: Vec<String>,
    pub exp: usize,
    pub iat: usize,
    pub jti: String,
    pub account_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub website_id: Option<String>,
    pub client_id: Option<String>,
    pub scope: String,
    pub token_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permissions: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub sub: String,
    pub iss: String,
    pub aud: Vec<String>,
    pub exp: usize,
    pub iat: usize,
    pub email: Option<String>,
    pub email_verified: bool,
    pub name: Option<String>,
    pub account_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub website_id: Option<String>,
}

struct VerifyKey {
    decoding: DecodingKey,
    public_pem: String,
}

struct KeySet {
    active_kid: String,
    active_signer: JwtSigningBackend,
    verify_keys: HashMap<String, VerifyKey>,
}

#[derive(Clone)]
pub struct JwtKeyStore {
    inner: Arc<RwLock<KeySet>>,
    issuer: String,
    access_ttl_secs: u64,
    grace_secs: u64,
    env_private_pem: Option<String>,
    jwt_kms_http_url: Option<String>,
    jwt_kms_key_id: Option<String>,
}

impl JwtKeyStore {
    pub async fn load(
        store: &dyn SigningKeyStore,
        data_keys: &Arc<dyn DataKeyStore>,
        issuer: &str,
        access_ttl_secs: u64,
        grace_secs: u64,
        env_private_pem: Option<String>,
        env_public_pem: Option<String>,
        jwt_kms_http_url: Option<String>,
        jwt_kms_key_id: Option<String>,
        allow_ephemeral: bool,
    ) -> Result<Self, AuthError> {
        ensure_signing_key(
            store,
            data_keys,
            env_private_pem.clone(),
            env_public_pem,
            allow_ephemeral,
        )
        .await?;
        let key_set = build_key_set(
            store,
            data_keys,
            grace_secs,
            env_private_pem.as_deref(),
            jwt_kms_http_url.as_deref(),
            jwt_kms_key_id.as_deref(),
        )
        .await?;
        Ok(Self {
            inner: Arc::new(RwLock::new(key_set)),
            issuer: issuer.to_string(),
            access_ttl_secs,
            grace_secs,
            env_private_pem,
            jwt_kms_http_url,
            jwt_kms_key_id,
        })
    }

    pub async fn reload(
        &self,
        store: &dyn SigningKeyStore,
        data_keys: &Arc<dyn DataKeyStore>,
    ) -> Result<(), AuthError> {
        let key_set = build_key_set(
            store,
            data_keys,
            self.grace_secs,
            self.env_private_pem.as_deref(),
            self.jwt_kms_http_url.as_deref(),
            self.jwt_kms_key_id.as_deref(),
        )
        .await?;
        *self
            .inner
            .write()
            .map_err(|e| AuthError::Internal(e.to_string()))? = key_set;
        Ok(())
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn kid(&self) -> String {
        self.inner
            .read()
            .map(|ks| ks.active_kid.clone())
            .unwrap_or_else(|_| "unknown".into())
    }

    pub fn access_ttl_secs(&self) -> u64 {
        self.access_ttl_secs
    }

    pub fn issue_access_token(
        &self,
        subject: Uuid,
        account_id: Uuid,
        website_id: Option<Uuid>,
        client_id: Option<&str>,
        scopes: &[String],
        permissions: Option<&[String]>,
    ) -> Result<(String, AccessTokenClaims), AuthError> {
        let key_set = self
            .inner
            .read()
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        let now = chrono::Utc::now().timestamp() as usize;
        let claims = AccessTokenClaims {
            sub: subject.to_string(),
            iss: self.issuer.clone(),
            aud: vec!["authsvc".into()],
            exp: now + self.access_ttl_secs as usize,
            iat: now,
            jti: Uuid::new_v4().to_string(),
            account_id: account_id.to_string(),
            website_id: website_id.map(|id| id.to_string()),
            client_id: client_id.map(str::to_string),
            scope: scopes.join(" "),
            token_type: "Bearer".into(),
            permissions: permissions.map(|p| p.to_vec()),
        };

        let token = encode_rs256_jwt(&key_set.active_signer, &key_set.active_kid, &claims)?;
        Ok((token, claims))
    }

    pub fn issue_id_token(
        &self,
        user: &User,
        account_id: Uuid,
        website_id: Option<Uuid>,
    ) -> Result<String, AuthError> {
        let key_set = self
            .inner
            .read()
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        let now = chrono::Utc::now().timestamp() as usize;
        let claims = IdTokenClaims {
            sub: user.id.to_string(),
            iss: self.issuer.clone(),
            aud: vec!["authsvc".into()],
            exp: now + self.access_ttl_secs as usize,
            iat: now,
            email: Some(user.email.clone()),
            email_verified: user.email_verified,
            name: user.display_name.clone(),
            account_id: account_id.to_string(),
            website_id: website_id.map(|id| id.to_string()),
        };
        encode_rs256_jwt(&key_set.active_signer, &key_set.active_kid, &claims)
    }

    pub fn validate_access_token(&self, token: &str) -> Result<AccessTokenClaims, AuthError> {
        let header = decode_header(token).map_err(|_| AuthError::InvalidToken)?;
        let kid = header.kid.ok_or(AuthError::InvalidToken)?;
        let key_set = self
            .inner
            .read()
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        let verify_key = key_set
            .verify_keys
            .get(&kid)
            .ok_or(AuthError::InvalidToken)?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&["authsvc"]);

        decode::<AccessTokenClaims>(token, &verify_key.decoding, &validation)
            .map(|data| data.claims)
            .map_err(|_| AuthError::InvalidToken)
    }

    pub fn validate_id_token(&self, token: &str) -> Result<IdTokenClaims, AuthError> {
        let header = decode_header(token).map_err(|_| AuthError::InvalidToken)?;
        let kid = header.kid.ok_or(AuthError::InvalidToken)?;
        let key_set = self
            .inner
            .read()
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        let verify_key = key_set
            .verify_keys
            .get(&kid)
            .ok_or(AuthError::InvalidToken)?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&["authsvc"]);

        decode::<IdTokenClaims>(token, &verify_key.decoding, &validation)
            .map(|data| data.claims)
            .map_err(|_| AuthError::InvalidToken)
    }

    pub fn jwks(&self) -> Result<serde_json::Value, AuthError> {
        use rsa::traits::PublicKeyParts;

        let key_set = self
            .inner
            .read()
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        let mut keys = Vec::new();
        for (kid, material) in &key_set.verify_keys {
            let public = rsa::RsaPublicKey::from_public_key_pem(&material.public_pem)
                .map_err(|e| AuthError::Internal(e.to_string()))?;
            let n = base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                public.n().to_bytes_be(),
            );
            let e = base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                public.e().to_bytes_be(),
            );
            keys.push(serde_json::json!({
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": kid,
                "n": n,
                "e": e
            }));
        }

        Ok(serde_json::json!({ "keys": keys }))
    }
}

pub type SharedJwtKeyStore = Arc<JwtKeyStore>;

async fn build_key_set(
    store: &dyn SigningKeyStore,
    data_keys: &Arc<dyn DataKeyStore>,
    grace_secs: u64,
    env_private_pem: Option<&str>,
    jwt_kms_http_url: Option<&str>,
    jwt_kms_key_id: Option<&str>,
) -> Result<KeySet, AuthError> {
    let active = store
        .get_active_signing_key()
        .await?
        .ok_or_else(|| AuthError::Internal("no active signing key".into()))?;

    let (active_kid, active_public_pem, encrypted_private) = active;

    if let Some(ref enc) = encrypted_private {
        if enc.starts_with("-----BEGIN") {
            let enc_new = encrypt_private_pem(data_keys, enc).await?;
            store
                .store_signing_key(&active_kid, &active_public_pem, Some(&enc_new))
                .await?;
        }
    }

    let active_signer = if let Some(url) = jwt_kms_http_url {
        JwtSigningBackend::http_kms(url.to_string(), jwt_kms_key_id.map(str::to_string))
    } else {
        let private_pem = if let Some(env_pem) = env_private_pem {
            env_pem.to_string()
        } else {
            let enc = encrypted_private.ok_or_else(|| {
                AuthError::Internal(
                    "JWT_PRIVATE_KEY_PEM, JWT_KMS_HTTP_URL, or encrypted signing key required"
                        .into(),
                )
            })?;
            decrypt_private_pem(data_keys, &enc).await?
        };
        JwtSigningBackend::local(private_pem)
    };

    let jwks_rows = store.list_signing_keys_for_jwks(grace_secs).await?;
    let mut verify_keys = HashMap::new();
    for (kid, public_pem) in jwks_rows {
        let decoding = DecodingKey::from_rsa_pem(public_pem.as_bytes())
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        verify_keys.insert(
            kid,
            VerifyKey {
                decoding,
                public_pem,
            },
        );
    }

    if !verify_keys.contains_key(&active_kid) {
        return Err(AuthError::Internal(
            "active signing key missing from JWKS key set".into(),
        ));
    }

    Ok(KeySet {
        active_kid,
        active_signer,
        verify_keys,
    })
}

pub fn generate_rsa_keypair() -> Result<(String, String), AuthError> {
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
    Ok((priv_pem, pub_pem))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jwt_issue_and_validate_by_kid() {
        let (priv_pem, pub_pem) = generate_rsa_keypair().unwrap();

        let decoding = DecodingKey::from_rsa_pem(pub_pem.as_bytes()).unwrap();
        let kid = "test-kid".to_string();

        let key_set = KeySet {
            active_kid: kid.clone(),
            active_signer: JwtSigningBackend::local(priv_pem),
            verify_keys: HashMap::from([(
                kid.clone(),
                VerifyKey {
                    decoding,
                    public_pem: pub_pem,
                },
            )]),
        };

        let store = JwtKeyStore {
            inner: Arc::new(RwLock::new(key_set)),
            issuer: "http://localhost".into(),
            access_ttl_secs: 900,
            grace_secs: 86400,
            env_private_pem: None,
            jwt_kms_http_url: None,
            jwt_kms_key_id: None,
        };

        let (token, _) = store
            .issue_access_token(
                Uuid::new_v4(),
                Uuid::new_v4(),
                None,
                Some("cli_test"),
                &["openid".into()],
                None,
            )
            .unwrap();
        let claims = store.validate_access_token(&token).unwrap();
        assert_eq!(claims.client_id.as_deref(), Some("cli_test"));
        assert_eq!(store.kid(), kid);
    }
}
