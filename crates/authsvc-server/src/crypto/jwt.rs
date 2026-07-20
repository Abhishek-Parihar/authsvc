use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use authsvc_core::{AuthError, SigningKeyStore, User};
use jsonwebtoken::{
    decode, decode_header, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use rsa::pkcs8::{DecodePublicKey, EncodePrivateKey, EncodePublicKey};
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
    pub account_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub website_id: Option<String>,
    pub client_id: Option<String>,
    pub scope: String,
    pub token_type: String,
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
    active_encoding: EncodingKey,
    verify_keys: HashMap<String, VerifyKey>,
}

#[derive(Clone)]
pub struct JwtKeyStore {
    inner: Arc<RwLock<KeySet>>,
    issuer: String,
    access_ttl_secs: u64,
    grace_secs: u64,
}

impl JwtKeyStore {
    pub async fn load_from_db(
        store: &dyn SigningKeyStore,
        issuer: &str,
        access_ttl_secs: u64,
        grace_secs: u64,
        env_private_pem: Option<String>,
        env_public_pem: Option<String>,
    ) -> Result<Self, AuthError> {
        ensure_signing_key_in_db(store, env_private_pem, env_public_pem).await?;
        let key_set = build_key_set(store, grace_secs).await?;
        Ok(Self {
            inner: Arc::new(RwLock::new(key_set)),
            issuer: issuer.to_string(),
            access_ttl_secs,
            grace_secs,
        })
    }

    pub async fn reload(&self, store: &dyn SigningKeyStore) -> Result<(), AuthError> {
        let key_set = build_key_set(store, self.grace_secs).await?;
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
        };

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(key_set.active_kid.clone());

        let token = encode(&header, &claims, &key_set.active_encoding)
            .map_err(|e| AuthError::Internal(e.to_string()))?;
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
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(key_set.active_kid.clone());
        encode(&header, &claims, &key_set.active_encoding)
            .map_err(|e| AuthError::Internal(e.to_string()))
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

async fn ensure_signing_key_in_db(
    store: &dyn SigningKeyStore,
    env_private_pem: Option<String>,
    env_public_pem: Option<String>,
) -> Result<(), AuthError> {
    if store.get_active_signing_key().await?.is_some() {
        return Ok(());
    }

    let (kid, private_pem, public_pem) = match (env_private_pem, env_public_pem) {
        (Some(priv_pem), Some(pub_pem)) => ("authsvc-key-1".to_string(), priv_pem, pub_pem),
        _ => {
            tracing::warn!("generating ephemeral RSA key pair; set JWT_*_KEY_PEM for production");
            let (priv_pem, pub_pem) = generate_rsa_keypair()?;
            (
                "authsvc-key-1".to_string(),
                priv_pem,
                pub_pem,
            )
        }
    };

    store
        .store_signing_key(&kid, &private_pem, &public_pem)
        .await
}

async fn build_key_set(store: &dyn SigningKeyStore, grace_secs: u64) -> Result<KeySet, AuthError> {
    let active = store
        .get_active_signing_key()
        .await?
        .ok_or_else(|| AuthError::Internal("no active signing key".into()))?;

    let (active_kid, active_private_pem, _active_public_pem) = active;
    let active_encoding = EncodingKey::from_rsa_pem(active_private_pem.as_bytes())
        .map_err(|e| AuthError::Internal(e.to_string()))?;

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
        active_encoding,
        verify_keys,
    })
}

fn generate_rsa_keypair() -> Result<(String, String), AuthError> {
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

        let encoding = EncodingKey::from_rsa_pem(priv_pem.as_bytes()).unwrap();
        let decoding = DecodingKey::from_rsa_pem(pub_pem.as_bytes()).unwrap();
        let kid = "test-kid".to_string();

        let key_set = KeySet {
            active_kid: kid.clone(),
            active_encoding: encoding,
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
        };

        let (token, _) = store
            .issue_access_token(
                Uuid::new_v4(),
                Uuid::new_v4(),
                None,
                Some("cli_test"),
                &["openid".into()],
            )
            .unwrap();
        let claims = store.validate_access_token(&token).unwrap();
        assert_eq!(claims.client_id.as_deref(), Some("cli_test"));
        assert_eq!(store.kid(), kid);
    }
}
