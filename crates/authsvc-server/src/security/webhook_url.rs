use authsvc_core::AuthError;

use super::host::{is_blocked_host, validate_resolved_host};

/// Reject webhook targets that could reach internal infrastructure (SSRF mitigation).
pub fn validate_webhook_url(url: &str, require_https: bool) -> Result<(), AuthError> {
    let parsed = url::Url::parse(url).map_err(|_| {
        AuthError::Validation("webhook url must be a valid absolute URL".into())
    })?;

    let scheme = parsed.scheme();
    if require_https {
        if scheme != "https" {
            return Err(AuthError::Validation(
                "webhook url must use https in production".into(),
            ));
        }
    } else if scheme != "http" && scheme != "https" {
        return Err(AuthError::Validation(
            "webhook url must use http or https".into(),
        ));
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| AuthError::Validation("webhook url must include a host".into()))?;

    if is_blocked_host(host) {
        return Err(AuthError::Validation(
            "webhook url must not target private or local addresses".into(),
        ));
    }

    let port = parsed.port_or_known_default().unwrap_or(if scheme == "https" {
        443
    } else {
        80
    });
    validate_resolved_host(host, port)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_localhost() {
        assert!(validate_webhook_url("http://localhost/hook", false).is_err());
        assert!(validate_webhook_url("https://127.0.0.1/hook", true).is_err());
    }

    #[test]
    fn allows_public_https() {
        assert!(validate_webhook_url("https://example.com/hook", true).is_ok());
    }

    #[test]
    fn requires_https_in_production_mode() {
        assert!(validate_webhook_url("http://example.com/hook", true).is_err());
    }
}
