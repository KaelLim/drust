//! CSRF state token + cookie helpers for the OAuth start/callback flow.
//! Used by /admin/oauth/*/start to set a short-TTL cookie that the
//! matching /callback validates against the `state` query param.

use axum_extra::extract::cookie::{Cookie, SameSite};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub const STATE_COOKIE: &str = "drust_oauth_state";
const STATE_BYTES: usize = 32;
pub const STATE_TTL_SECS: i64 = 300;

const PKCE_VERIFIER_BYTES: usize = 48; // 48 bytes → 64 char base64url
pub const PKCE_COOKIE: &str = "drust_oauth_pkce";

/// Generate a URL-safe random state token (32 bytes → 43 chars base64url).
pub fn issue_state() -> String {
    let mut b = [0u8; STATE_BYTES];
    rand::thread_rng().fill_bytes(&mut b);
    URL_SAFE_NO_PAD.encode(b)
}

/// Constant-time comparison; returns false on any length mismatch or
/// empty input.
pub fn verify_state(cookie: &str, query: &str) -> bool {
    if cookie.is_empty() || query.is_empty() {
        return false;
    }
    let a = cookie.as_bytes();
    let b = query.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Build a state cookie with the standard attributes. `secure` should
/// be derived from the request's `X-Forwarded-Proto` header.
pub fn state_cookie(state: &str, secure: bool) -> Cookie<'static> {
    Cookie::build((STATE_COOKIE, state.to_string()))
        .path("/admin")
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(secure)
        .max_age(cookie::time::Duration::seconds(STATE_TTL_SECS))
        .build()
}

pub fn clear_state_cookie() -> Cookie<'static> {
    Cookie::build((STATE_COOKIE, String::new()))
        .path("/admin")
        .max_age(cookie::time::Duration::ZERO)
        .build()
}

/// Generate (verifier, challenge) per RFC 7636 S256 method.
pub fn issue_pkce() -> (String, String) {
    let mut raw = [0u8; PKCE_VERIFIER_BYTES];
    rand::thread_rng().fill_bytes(&mut raw);
    let verifier = URL_SAFE_NO_PAD.encode(raw);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

pub fn pkce_cookie(verifier: &str, secure: bool) -> Cookie<'static> {
    Cookie::build((PKCE_COOKIE, verifier.to_string()))
        .path("/admin")
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(secure)
        .max_age(cookie::time::Duration::seconds(STATE_TTL_SECS))
        .build()
}

pub fn clear_pkce_cookie() -> Cookie<'static> {
    Cookie::build((PKCE_COOKIE, String::new()))
        .path("/admin")
        .max_age(cookie::time::Duration::ZERO)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_state_returns_url_safe_token() {
        let s = issue_state();
        assert!(s.len() >= 32, "too short: {} bytes", s.len());
        // base64url alphabet
        for b in s.bytes() {
            assert!(
                b.is_ascii_alphanumeric() || b == b'-' || b == b'_',
                "non-url-safe byte: {b:#x}"
            );
        }
    }

    #[test]
    fn verify_state_matches_self() {
        let s = issue_state();
        assert!(verify_state(&s, &s));
    }

    #[test]
    fn verify_state_rejects_mismatch() {
        let s1 = issue_state();
        let s2 = issue_state();
        assert!(!verify_state(&s1, &s2));
    }

    #[test]
    fn verify_state_rejects_empty() {
        assert!(!verify_state("", ""));
        assert!(!verify_state("x", ""));
    }

    #[test]
    fn pkce_pair_verifier_length_in_range() {
        let (v, _c) = issue_pkce();
        // RFC 7636: verifier is 43-128 chars from [A-Z][a-z][0-9]-._~
        assert!(v.len() >= 43 && v.len() <= 128, "verifier len: {}", v.len());
        for b in v.bytes() {
            assert!(
                b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'),
                "non-RFC byte: {b:#x}"
            );
        }
    }

    #[test]
    fn pkce_pair_challenge_is_s256_of_verifier() {
        use sha2::{Digest, Sha256};
        let (v, c) = issue_pkce();
        let want = URL_SAFE_NO_PAD.encode(Sha256::digest(v.as_bytes()));
        assert_eq!(c, want);
    }
}
