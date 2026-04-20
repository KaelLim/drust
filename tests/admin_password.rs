use drust::auth::admin::{hash_password, verify_password};

#[test]
fn round_trip_success() {
    let hash = hash_password("hunter2").unwrap();
    assert!(hash.starts_with("$argon2id$"));
    assert!(verify_password(&hash, "hunter2").unwrap());
}

#[test]
fn wrong_password_rejected() {
    let hash = hash_password("hunter2").unwrap();
    assert!(!verify_password(&hash, "wrong").unwrap());
}

#[test]
fn malformed_hash_returns_error() {
    assert!(verify_password("not-a-hash", "anything").is_err());
}
