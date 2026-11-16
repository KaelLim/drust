//! PKCE (RFC 7636). MA0-5 ships only the authorize-side shape check;
//! `verifier_well_formed` and `verify_s256` arrive with the code exchange
//! (MA0-7).

/// S256 challenge = base64url_nopad(SHA-256(verifier)) — always exactly 43
/// chars of `[A-Za-z0-9-_]`. Non-canonical trailing bits are NOT rejected
/// here: such a challenge can never equal a computed one, so the code would
/// simply be unredeemable (MA0-7).
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
}
