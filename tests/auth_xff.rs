use axum::http::HeaderMap;
use drust::safety::ip::client_ip;
use std::net::{IpAddr, SocketAddr};

fn h(xff: Option<&str>) -> HeaderMap {
    let mut m = HeaderMap::new();
    if let Some(v) = xff {
        m.insert("x-forwarded-for", v.parse().unwrap());
    }
    m
}
fn fallback() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

#[test]
fn missing_xff_falls_back_to_socket() {
    assert_eq!(
        client_ip(&h(None), fallback()),
        "127.0.0.1".parse::<IpAddr>().unwrap()
    );
}

#[test]
fn single_entry_xff_returns_socket() {
    // Only one entry means we don't have a verified hop chain.
    assert_eq!(
        client_ip(&h(Some("203.0.113.10")), fallback()),
        "127.0.0.1".parse::<IpAddr>().unwrap()
    );
}

#[test]
fn double_entry_xff_returns_second_from_right() {
    // <client>, <.221>  → we pick "<client>" only because it's directly to the left of our trusted hop.
    let ip = client_ip(&h(Some("203.0.113.10, 192.0.2.221")), fallback());
    assert_eq!(ip, "203.0.113.10".parse::<IpAddr>().unwrap());
}

#[test]
fn spoofed_xff_does_not_bypass() {
    // Attacker prepends their own faked IP; we must still pick the trusted "second-from-right".
    let ip = client_ip(&h(Some("1.1.1.1, 203.0.113.10, 192.0.2.221")), fallback());
    assert_eq!(ip, "203.0.113.10".parse::<IpAddr>().unwrap());
}

#[test]
fn ipv6_works() {
    let ip = client_ip(&h(Some("2001:db8::1, 192.0.2.221")), fallback());
    assert_eq!(ip, "2001:db8::1".parse::<IpAddr>().unwrap());
}

#[test]
fn malformed_entries_fall_back_to_socket() {
    let ip = client_ip(&h(Some("not-an-ip, 192.0.2.221")), fallback());
    assert_eq!(ip, "127.0.0.1".parse::<IpAddr>().unwrap());
}
