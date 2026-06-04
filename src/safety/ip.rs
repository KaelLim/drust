use axum::http::HeaderMap;
use std::net::{IpAddr, SocketAddr};

/// Returns the verified client IP behind a known proxy chain.
/// Spec S3: take the **second-from-the-right** entry of `X-Forwarded-For`.
/// The rightmost is the most-recent hop (.221 nginx, trusted).
/// The second-from-right is the IP that .221 received the request from — the verified client.
/// Anything to the left of that may have been forged by the client.
///
/// Falls back to `socket_addr.ip()` if XFF is missing, has only one entry, or any
/// of the relevant entries are malformed.
pub fn client_ip(headers: &HeaderMap, socket_addr: SocketAddr) -> IpAddr {
    let fallback = socket_addr.ip();
    let raw = match headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        Some(s) => s,
        None => return fallback,
    };
    let parts: Vec<&str> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if parts.len() < 2 {
        return fallback;
    }
    let candidate = parts[parts.len() - 2];
    candidate.parse::<IpAddr>().unwrap_or(fallback)
}
