//! PKCE S256-only verifier per RFC 7636.

use base64::Engine;
use sha2::{Digest, Sha256};

/// Verify that `base64url(SHA-256(verifier)) == challenge`. Strict — only S256.
pub fn verify_s256(verifier: &str, challenge: &str) -> bool {
    let mut h = Sha256::new();
    h.update(verifier.as_bytes());
    let computed = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(h.finalize());
    use subtle::ConstantTimeEq;
    computed.as_bytes().ct_eq(challenge.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc7636_appendix_b_example() {
        let v = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let c = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(verify_s256(v, c));
    }

    #[test]
    fn rejects_wrong_verifier() {
        assert!(!verify_s256(
            "wrong",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        ));
    }
}
