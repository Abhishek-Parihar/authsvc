use std::time::Duration;

/// Shared outbound HTTP client with connect + request timeouts (SSRF / slowloris mitigation).
pub fn outbound_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()
        .expect("outbound reqwest client")
}

pub fn outbound_blocking_client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()
        .expect("outbound blocking reqwest client")
}
