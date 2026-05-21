//! v1.19.2 regression — webhook URL validation rejects private-IP hosts
//! and disables redirect following.

use drust::tenant::webhook_routes::check_url;

#[test]
fn https_public_passes() {
    // Use a hostname guaranteed to resolve to a public IP. example.com
    // is documented (RFC 2606) and IANA-assigned to a public IP. A test
    // machine without network connectivity will fail this test
    // deterministically — appropriate (the validator requires DNS).
    let res = check_url("https://example.com/hook");
    assert!(res.is_ok(), "expected example.com to pass, got {res:?}");
}

#[test]
fn http_localhost_carveout_still_works() {
    assert!(check_url("http://localhost:8080/hook").is_ok());
    assert!(check_url("http://127.0.0.1:8080/hook").is_ok());
    assert!(check_url("http://[::1]:8080/hook").is_ok());
}

#[test]
fn https_to_rfc1918_ip_rejected() {
    let (code, _) = check_url("https://10.0.0.1/hook").unwrap_err();
    assert_eq!(code, "INVALID_URL");
    let (code, _) = check_url("https://192.168.1.1/hook").unwrap_err();
    assert_eq!(code, "INVALID_URL");
    let (code, _) = check_url("https://172.16.0.1/hook").unwrap_err();
    assert_eq!(code, "INVALID_URL");
}

#[test]
fn https_to_link_local_rejected() {
    let (code, _) = check_url("https://169.254.169.254/").unwrap_err();
    assert_eq!(code, "INVALID_URL");
}

#[test]
fn http_non_loopback_rejected() {
    let (code, _) = check_url("http://example.com/").unwrap_err();
    assert_eq!(code, "INVALID_URL");
}

#[test]
fn unparseable_url_rejected() {
    let (code, _) = check_url("not a url at all").unwrap_err();
    assert_eq!(code, "INVALID_URL");
}
