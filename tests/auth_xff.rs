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

#[test]
fn double_prepend_forge_still_picks_second_from_right() {
    // Attacker prepends TWO forged entries (depth 4). Right-indexing must still
    // pick parts[len-2] == the real client, proving extra LEFT entries never
    // shift the key (the `>=`, not `==`, length rule).
    let ip = client_ip(
        &h(Some("9.9.9.9, 8.8.8.8, 203.0.113.10, 192.0.2.221")),
        fallback(),
    );
    assert_eq!(ip, "203.0.113.10".parse::<IpAddr>().unwrap());
}

#[test]
fn unparseable_candidate_falls_back_to_socket_never_raw() {
    // parts[len-2] is at the trusted client position but is not an IpAddr.
    // Must fall back to the socket peer — NEVER return the raw string,
    // NEVER let junk become the key. (warn! fires; observed manually.)
    let ip = client_ip(&h(Some("not-an-ip, 192.0.2.221")), fallback());
    assert_eq!(ip, "127.0.0.1".parse::<IpAddr>().unwrap());
}

#[test]
fn lone_client_entry_never_becomes_key() {
    // A single client-supplied entry (len 1 < 2) must fall back to the socket
    // peer and must NOT become the rate-limit key. Security restatement of
    // single_entry_xff_returns_socket: the returned IP is the socket, not 9.9.9.9.
    let ip = client_ip(&h(Some("9.9.9.9")), fallback());
    assert_eq!(ip, "127.0.0.1".parse::<IpAddr>().unwrap());
    assert_ne!(ip, "9.9.9.9".parse::<IpAddr>().unwrap());
}
