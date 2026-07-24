use authsvc_core::AuthError;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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

    Ok(())
}

fn is_blocked_host(host: &str) -> bool {
    let lower = host.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "localhost"
            | "localhost.localdomain"
            | "metadata.google.internal"
            | "metadata"
    ) {
        return true;
    }
    if lower.ends_with(".local") || lower.ends_with(".internal") {
        return true;
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return is_blocked_ip(ip);
    }
    false
}

fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.octets()[0] == 0
                || v4 == Ipv4Addr::new(169, 254, 169, 254)
                || v4 == Ipv4Addr::new(100, 64, 0, 0) // shared CGNAT range start heuristic
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.segments()[0] & 0xffc0 == 0xfe80 // link-local
                || v6 == Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xa9fe, 0xa9fe)
        }
    }
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
