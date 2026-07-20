use authsvc_core::AuthError;
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::*;

use super::{auth::TokenResponse, state::AppState};

const CHALLENGE_TTL_SECS: u64 = 300;

#[derive(Serialize, Deserialize)]
struct RegisterChallenge {
    state: PasskeyRegistration,
    user_id: Uuid,
    name: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct LoginChallenge {
    state: PasskeyAuthentication,
    user_id: Uuid,
    client_id: String,
}

pub struct WebAuthnService {
    webauthn: Webauthn,
    rp_origin: String,
}

impl WebAuthnService {
    pub fn new(rp_id: &str, origin: &str) -> Result<Self, AuthError> {
        let url = Url::parse(origin).map_err(|e| AuthError::Internal(e.to_string()))?;
        let builder =
            WebauthnBuilder::new(rp_id, &url).map_err(|e| AuthError::Internal(e.to_string()))?;
        let webauthn = builder
            .rp_name("authsvc")
            .build()
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(Self {
            webauthn,
            rp_origin: origin.to_string(),
        })
    }

    pub fn origin(&self) -> &str {
        &self.rp_origin
    }

    pub async fn begin_registration(
        &self,
        state: &AppState,
        user_id: Uuid,
        name: Option<String>,
    ) -> Result<(Uuid, CreationChallengeResponse), AuthError> {
        let user = state
            .repos
            .users()
            .find_by_id(user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        let existing = state.repos.webauthn().list_credentials(user_id).await?;
        let exclude: Vec<CredentialID> = existing
            .iter()
            .map(|c| CredentialID::from(c.credential_id.clone()))
            .collect();

        let (ccr, reg_state) = self
            .webauthn
            .start_passkey_registration(user.id, &user.email, &user.email, Some(exclude))
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        let challenge_id = Uuid::new_v4();
        state
            .sessions
            .set_json(
                &format!("webauthn:reg:{challenge_id}"),
                &RegisterChallenge {
                    state: reg_state,
                    user_id,
                    name,
                },
                CHALLENGE_TTL_SECS,
            )
            .await?;

        Ok((challenge_id, ccr))
    }

    pub async fn finish_registration(
        &self,
        state: &AppState,
        challenge_id: Uuid,
        reg: RegisterPublicKeyCredential,
    ) -> Result<Uuid, AuthError> {
        let key = format!("webauthn:reg:{challenge_id}");
        let stored: RegisterChallenge = state
            .sessions
            .get_json(&key)
            .await?
            .ok_or(AuthError::InvalidToken)?;
        state.sessions.delete_key(&key).await?;

        let passkey = self
            .webauthn
            .finish_passkey_registration(&reg, &stored.state)
            .map_err(|e| AuthError::Validation(e.to_string()))?;

        let cred_id = passkey.cred_id().as_ref().to_vec();
        let public_key =
            serde_json::to_vec(&passkey).map_err(|e| AuthError::Internal(e.to_string()))?;

        let id = state
            .repos
            .webauthn()
            .store_credential(
                stored.user_id,
                &cred_id,
                &public_key,
                stored.name.as_deref(),
            )
            .await?;

        state
            .audit(
                None,
                Some(&stored.user_id.to_string()),
                "webauthn.enrolled",
                Some("webauthn_credentials"),
                None,
                serde_json::json!({"credential_id": id}),
            )
            .await?;

        Ok(id)
    }

    pub async fn begin_login(
        &self,
        state: &AppState,
        email: &str,
        client_id: &str,
    ) -> Result<(Uuid, RequestChallengeResponse), AuthError> {
        state
            .repos
            .clients()
            .find_by_client_id(client_id)
            .await?
            .ok_or(AuthError::ClientNotFound)?;

        let user = state
            .repos
            .users()
            .find_by_email(&email.to_lowercase())
            .await?
            .ok_or(AuthError::UserNotFound)?;

        let creds = state.repos.webauthn().list_credentials(user.id).await?;
        if creds.is_empty() {
            return Err(AuthError::Validation("no passkeys registered".into()));
        }

        let passkeys = creds
            .iter()
            .filter_map(|c| serde_json::from_slice::<Passkey>(&c.public_key).ok())
            .collect::<Vec<_>>();

        if passkeys.is_empty() {
            return Err(AuthError::Internal("failed to load passkeys".into()));
        }

        let (rcr, auth_state) = self
            .webauthn
            .start_passkey_authentication(&passkeys)
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        let challenge_id = Uuid::new_v4();
        state
            .sessions
            .set_json(
                &format!("webauthn:auth:{challenge_id}"),
                &LoginChallenge {
                    state: auth_state,
                    user_id: user.id,
                    client_id: client_id.to_string(),
                },
                CHALLENGE_TTL_SECS,
            )
            .await?;

        Ok((challenge_id, rcr))
    }

    pub async fn finish_login(
        &self,
        state: &AppState,
        challenge_id: Uuid,
        auth: PublicKeyCredential,
    ) -> Result<TokenResponse, AuthError> {
        let key = format!("webauthn:auth:{challenge_id}");
        let stored: LoginChallenge = state
            .sessions
            .get_json(&key)
            .await?
            .ok_or(AuthError::InvalidToken)?;
        state.sessions.delete_key(&key).await?;

        let auth_result = self
            .webauthn
            .finish_passkey_authentication(&auth, &stored.state)
            .map_err(|_e| AuthError::InvalidCredentials)?;

        let creds = state
            .repos
            .webauthn()
            .list_credentials(stored.user_id)
            .await?;
        if let Some(record) = creds.iter().find(|c| {
            c.credential_id
                .as_slice()
                .eq(auth_result.cred_id().as_ref())
        }) {
            state
                .repos
                .webauthn()
                .update_sign_count(record.id, auth_result.counter() as i64)
                .await?;
        }

        let user = state
            .repos
            .users()
            .find_by_id(stored.user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;
        let client = state
            .repos
            .clients()
            .find_by_client_id(&stored.client_id)
            .await?
            .ok_or(AuthError::ClientNotFound)?;

        state
            .audit(
                None,
                Some(&user.id.to_string()),
                "login.success",
                Some("webauthn"),
                None,
                serde_json::json!({"method": "webauthn"}),
            )
            .await?;

        super::auth::complete_login(state, &user, &client).await
    }
}

pub fn rp_id_from_issuer(issuer: &str) -> String {
    Url::parse(issuer)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_else(|| "localhost".to_string())
}
