use authsvc_core::AuthError;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

pub fn is_blocked_host(host: &str) -> bool {
    let lower = host.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "localhost" | "localhost.localdomain" | "metadata.google.internal" | "metadata"
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

pub fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.octets()[0] == 0
                || v4 == Ipv4Addr::new(169, 254, 169, 254)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.segments()[0] & 0xffc0 == 0xfe80
                || v6 == Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xa9fe, 0xa9fe)
        }
    }
}

/// Resolve hostname and reject if any address is private/local (DNS rebinding mitigation).
pub fn validate_resolved_host(host: &str, port: u16) -> Result<(), AuthError> {
    if host.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    let addrs: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|_| AuthError::Validation("host could not be resolved".into()))?
        .collect();
    if addrs.is_empty() {
        return Err(AuthError::Validation("host could not be resolved".into()));
    }
    for addr in addrs {
        if is_blocked_ip(addr.ip()) {
            return Err(AuthError::Validation(
                "host must not resolve to private or local addresses".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_loopback_ip() {
        assert!(is_blocked_ip("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn allows_public_ip() {
        assert!(!is_blocked_ip("8.8.8.8".parse().unwrap()));
    }
}
