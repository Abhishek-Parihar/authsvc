use authsvc_core::{client::OAuthClient, AuthError};

/// Validate that `redirect_uri` is allowed for the OAuth client.
pub fn validate_redirect_uri(
    client: &OAuthClient,
    redirect_uri: &str,
    require_registered: bool,
) -> Result<(), AuthError> {
    if client.redirect_uris.is_empty() {
        if require_registered {
            return Err(AuthError::Validation(
                "client has no registered redirect_uris".into(),
            ));
        }
        return Ok(());
    }
    if !client.redirect_uris.contains(&redirect_uri.to_string()) {
        return Err(AuthError::Validation("invalid redirect_uri".into()));
    }
    Ok(())
}

/// OAuth clients using authorization_code must register at least one redirect URI in production.
pub fn validate_client_redirect_uris(
    redirect_uris: &[String],
    grant_types: &[String],
    require_registered: bool,
) -> Result<(), AuthError> {
    let needs_redirect = grant_types.iter().any(|g| g == "authorization_code");
    if require_registered && needs_redirect && redirect_uris.is_empty() {
        return Err(AuthError::Validation(
            "redirect_uris required for authorization_code clients".into(),
        ));
    }
    Ok(())
}
