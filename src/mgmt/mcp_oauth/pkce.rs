//! PKCE (RFC 7636), S256 only: the authorize-side challenge shape check and
//! the token-side verifier check. `plain` is refused at authorize, and
//! `verify_s256` has no `plain` branch, so even a stored `plain` challenge
//! could never be redeemed with `verifier == challenge`.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// RFC 7636 §4.1: 43..=128 chars of [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~".
/// Byte length on purpose: every allowed char is one ASCII byte, so a multi-byte
/// char can never pass and `len()` never over-counts an allowed string.
pub fn verifier_well_formed(v: &str) -> bool {
    (43..=128).contains(&v.len())
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

/// RFC 7636 §4.6, S256 only: BASE64URL(SHA256(ASCII(verifier))) == challenge,
/// compared in constant time. The length check first is public information
/// (an S256 challenge is always 43 chars); `ct_eq` covers the content.
/// Callers MUST run `verifier_well_formed` first — this fn does not, so the RFC
/// vector test can feed it directly.
pub fn verify_s256(verifier: &str, challenge: &str) -> bool {
    let computed = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let (a, b) = (computed.as_bytes(), challenge.as_bytes());
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

/// S256 challenge = base64url_nopad(SHA-256(verifier)) — always exactly 43
/// chars of `[A-Za-z0-9-_]`. Non-canonical trailing bits are NOT rejected
/// here: such a challenge can never equal a computed one, so the code would
/// simply be unredeemable.
pub fn challenge_well_formed(c: &str) -> bool {
    c.len() == 43
        && c.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc7636_appendix_b_challenge_is_well_formed() {
        assert!(challenge_well_formed(
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        ));
    }

    #[test]
    fn issue_pkce_challenge_is_well_formed() {
        for _ in 0..100 {
            let (_verifier, challenge) = crate::oauth::state::issue_pkce();
            assert!(challenge_well_formed(&challenge), "{challenge}");
        }
    }

    #[test]
    fn rejects_wrong_length_and_alphabet() {
        let base = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert_eq!(base.len(), 43);
        assert!(!challenge_well_formed(&base[..42]));
        assert!(!challenge_well_formed(&format!("{base}A")));
        assert!(!challenge_well_formed(""));
        for bad in ['+', '/', '=', ' '] {
            let s = format!("{}{bad}", &base[..42]);
            assert_eq!(s.len(), 43);
            assert!(!challenge_well_formed(&s), "{s:?}");
        }
        // 43 bytes, but one multi-byte character (41 ASCII + "é").
        let mb = format!("{}é", &base[..41]);
        assert_eq!(mb.len(), 43);
        assert!(!challenge_well_formed(&mb));
    }

    // ─── verifier_well_formed / verify_s256 ──────────────────────────────────

    /// RFC 7636 appendix B, copied from the RFC text.
    const RFC_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const RFC_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    /// A different character of the verifier alphabet at the same position.
    fn other_legal(c: u8) -> u8 {
        if c == b'a' { b'b' } else { b'a' }
    }

    #[test]
    fn rfc7636_appendix_b_vector_verifies() {
        assert!(verifier_well_formed(RFC_VERIFIER));
        assert!(verify_s256(RFC_VERIFIER, RFC_CHALLENGE));
    }

    #[test]
    fn issue_pkce_pairs_verify() {
        for _ in 0..32 {
            let (v, c) = crate::oauth::state::issue_pkce();
            assert!(verifier_well_formed(&v), "{v}");
            assert!(verify_s256(&v, &c), "{v}");
        }
    }

    #[test]
    fn a_single_flipped_char_fails() {
        for i in 0..RFC_VERIFIER.len() {
            let mut b = RFC_VERIFIER.as_bytes().to_vec();
            b[i] = other_legal(b[i]);
            let v = String::from_utf8(b).unwrap();
            assert!(verifier_well_formed(&v), "{v}");
            assert!(!verify_s256(&v, RFC_CHALLENGE), "verifier position {i}");
        }
        for i in 0..RFC_CHALLENGE.len() {
            let mut b = RFC_CHALLENGE.as_bytes().to_vec();
            b[i] = other_legal(b[i]);
            let c = String::from_utf8(b).unwrap();
            assert!(!verify_s256(RFC_VERIFIER, &c), "challenge position {i}");
        }
    }

    #[test]
    fn a_challenge_of_the_wrong_length_fails_without_panicking() {
        for c in [
            String::new(),
            RFC_CHALLENGE[..42].to_string(),
            format!("{RFC_CHALLENGE}A"),
            format!("{RFC_CHALLENGE}-tail"),
        ] {
            assert!(!verify_s256(RFC_VERIFIER, &c), "{c:?}");
        }
    }

    #[test]
    fn plain_style_equality_never_verifies() {
        assert!(!verify_s256(RFC_VERIFIER, RFC_VERIFIER));
        for _ in 0..10 {
            // 43 chars of base64url: a well-formed verifier AND a well-formed
            // challenge shape, so only the S256 transform can tell them apart.
            let v = crate::mgmt::mcp_oauth::tokens::new_token(
                crate::mgmt::mcp_oauth::tokens::TokenKind::Code,
            );
            assert!(verifier_well_formed(&v));
            assert!(challenge_well_formed(&v));
            assert!(!verify_s256(&v, &v), "{v}");
        }
    }

    #[test]
    fn verifier_length_bounds() {
        assert!(!verifier_well_formed(""));
        assert!(!verifier_well_formed(&"a".repeat(42)));
        assert!(verifier_well_formed(&"a".repeat(43)));
        assert!(verifier_well_formed(&"a".repeat(128)));
        assert!(!verifier_well_formed(&"a".repeat(129)));
    }

    #[test]
    fn verifier_charset() {
        for bad in ['+', '/', '=', ' ', '%', '\0'] {
            let s = format!("{}{bad}", "a".repeat(42));
            assert_eq!(s.len(), 43);
            assert!(!verifier_well_formed(&s), "{s:?}");
        }
        // 43 bytes, one of them part of a 2-byte "é".
        let mb = format!("{}é", "a".repeat(41));
        assert_eq!(mb.len(), 43);
        assert!(!verifier_well_formed(&mb));
        let ok = format!("-._~{}", "aZ9".repeat(13));
        assert_eq!(ok.len(), 43);
        assert!(verifier_well_formed(&ok));
    }

    /// Structural pin: a behaviour test cannot see a timing difference, so a
    /// `==` here would stay green. Convention and defence in depth, not a
    /// load-bearing rule — the challenge is not a secret (it travels in the
    /// authorize URL).
    #[test]
    fn verify_s256_compares_in_constant_time() {
        use crate::tenant::rooms::srcpin::{code_only, prod_fn_body};
        let stripped = code_only(include_str!("pkce.rs"));
        let body = prod_fn_body(&stripped, "pub fn verify_s256(");
        assert!(body.contains("ct_eq("), "verify_s256 must use ct_eq");
        for forbidden in ["== challenge", "challenge ==", ".eq("] {
            assert!(
                !body.contains(forbidden),
                "verify_s256 must not compare with `{forbidden}`"
            );
        }
    }
}
