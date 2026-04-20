use drust::auth::bearer::{generate_token, hash_token, token_hint, verify_token_hash};

#[test]
fn generate_format() {
    let t = generate_token();
    assert!(t.starts_with("drust_"));
    assert_eq!(t.len(), "drust_".len() + 43); // 32 bytes base64url unpadded = 43
}

#[test]
fn hash_is_hex_sha256() {
    let t = "drust_abcdef";
    let h = hash_token(t);
    assert_eq!(h.len(), 64);
    assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn verify_matches() {
    let t = generate_token();
    let h = hash_token(&t);
    assert!(verify_token_hash(&t, &h));
    assert!(!verify_token_hash("drust_wrong", &h));
}

#[test]
fn token_hint_masks_correctly() {
    assert_eq!(token_hint("drust_abcdef0123456789"), "drust_abcdef…");
    // Minimum-length token still masks cleanly
    assert!(token_hint("drust_xx").ends_with("…"));
}
