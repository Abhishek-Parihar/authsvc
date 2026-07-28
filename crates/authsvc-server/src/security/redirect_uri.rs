use authsvc_core::{client::OAuthClient, AuthError};

use super::host::is_blocked_host;

/// Validate redirect URI structure and production safety rules.
pub fn validate_redirect_uri_format(uri: &str, production: bool) -> Result<(), AuthError> {
    let parsed = url::Url::parse(uri)
        .map_err(|_| AuthError::Validation("redirect_uri must be a valid absolute URL".into()))?;

    if parsed.fragment().is_some() {
        return Err(AuthError::Validation(
            "redirect_uri must not contain a fragment".into(),
        ));
    }

    if parsed.username() != "" || parsed.password().is_some() {
        return Err(AuthError::Validation(
            "redirect_uri must not contain userinfo".into(),
        ));
    }

    let scheme = parsed.scheme();
    match scheme {
        "http" | "https" => {
            if production && scheme == "http" {
                return Err(AuthError::Validation(
                    "redirect_uri must use https in production".into(),
                ));
            }
            let host = parsed.host_str().ok_or_else(|| {
                AuthError::Validation("redirect_uri must include a host".into())
            })?;
            if production && is_blocked_host(host) {
                return Err(AuthError::Validation(
                    "redirect_uri must not target localhost or private addresses in production".into(),
                ));
            }
        }
        "javascript" | "data" | "file" | "vbscript" => {
            return Err(AuthError::Validation(
                "redirect_uri scheme is not allowed".into(),
            ));
        }
        _ => {
            // Custom URI schemes (e.g. mobile deep links) are allowed.
        }
    }

    Ok(())
}

/// Validate that `redirect_uri` is allowed for the OAuth client.
pub fn validate_redirect_uri(
    client: &OAuthClient,
    redirect_uri: &str,
    require_registered: bool,
) -> Result<(), AuthError> {
    validate_redirect_uri_format(redirect_uri, require_registered)?;

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
    for uri in redirect_uris {
        validate_redirect_uri_format(uri, require_registered)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_localhost_in_production() {
        assert!(validate_redirect_uri_format("http://localhost/cb", true).is_err());
        assert!(validate_redirect_uri_format("https://127.0.0.1/cb", true).is_err());
    }

    #[test]
    fn allows_localhost_in_dev() {
        assert!(validate_redirect_uri_format("http://localhost/cb", false).is_ok());
    }

    #[test]
    fn requires_https_in_production() {
        assert!(validate_redirect_uri_format("http://app.example.com/cb", true).is_err());
        assert!(validate_redirect_uri_format("https://app.example.com/cb", true).is_ok());
    }

    #[test]
    fn allows_custom_scheme() {
        assert!(validate_redirect_uri_format("myapp://callback", true).is_ok());
    }

    #[test]
    fn blocks_javascript_scheme() {
        assert!(validate_redirect_uri_format("javascript:alert(1)", false).is_err());
    }
}
