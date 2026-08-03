/// Constant-time string comparison to mitigate timing side-channels.
pub fn secure_compare(a: &str, b: &str) -> bool {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    if a_bytes.len() != b_bytes.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a_bytes.iter().zip(b_bytes.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Compare `Authorization: Bearer <token>` header value against an expected secret.
pub fn bearer_matches(auth_header: &str, expected: &str) -> bool {
    let Some(token) = auth_header.strip_prefix("Bearer ") else {
        return false;
    };
    secure_compare(token.trim(), expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_compare_matches_and_rejects() {
        assert!(secure_compare("secret", "secret"));
        assert!(!secure_compare("secret", "secrex"));
        assert!(!secure_compare("short", "longer"));
    }

    #[test]
    fn bearer_matches_header() {
        assert!(bearer_matches("Bearer my-token", "my-token"));
        assert!(!bearer_matches("Bearer wrong", "my-token"));
        assert!(!bearer_matches("Basic abc", "abc"));
    }
}
