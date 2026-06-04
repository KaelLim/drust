//! CSRF state token + cookie helpers for the OAuth start/callback flow.
//! Used by /admin/oauth/*/start to set a short-TTL cookie that the
//! matching /callback validates against the `state` query param.
//!
//! For per-tenant OAuth where the frontend's `redirect_uri` must also
//! round-trip through the provider, see [`TenantOauthStateToken`].

use axum_extra::extract::cookie::{Cookie, SameSite};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

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
        .path("/drust/admin")
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(secure)
        .max_age(cookie::time::Duration::seconds(STATE_TTL_SECS))
        .build()
}

pub fn clear_state_cookie() -> Cookie<'static> {
    Cookie::build((STATE_COOKIE, String::new()))
        .path("/drust/admin")
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
        .path("/drust/admin")
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(secure)
        .max_age(cookie::time::Duration::seconds(STATE_TTL_SECS))
        .build()
}

pub fn clear_pkce_cookie() -> Cookie<'static> {
    Cookie::build((PKCE_COOKIE, String::new()))
        .path("/drust/admin")
        .max_age(cookie::time::Duration::ZERO)
        .build()
}

// ---------- Per-tenant OAuth: HMAC-bound state token ----------

/// Errors returned by [`TenantOauthStateToken::decode`].
#[derive(Debug, PartialEq, Eq)]
pub enum TenantOauthStateError {
    /// Base64url decode failed.
    BadEncoding,
    /// Payload shorter than the fixed-prefix overhead.
    TooShort,
    /// Declared `redirect_uri` length doesn't match the buffer size.
    LengthMismatch,
    /// HMAC didn't verify under the provided secret.
    HmacMismatch,
    /// `redirect_uri` bytes are not valid UTF-8.
    InvalidUtf8,
}

/// State token used by the per-tenant OAuth flow. Embeds the frontend's
/// `redirect_uri` directly in the `state` query param via an HMAC-SHA256
/// envelope so the value round-trips through the provider untouched
/// without a SEPARATE cookie.
///
/// The old design stored `redirect_uri` in a `drust_t_oauth_redirect_uri`
/// cookie; two parallel OAuth starts in different tabs (each for a
/// different allowlisted frontend) raced the cookie write — the later one
/// clobbered the earlier, and the first callback then redirected to the
/// wrong frontend. Embedding the URI in `state` makes each tab carry its
/// own copy through the provider round-trip.
///
/// Wire format (base64url-encoded):
///
/// ```text
/// [16 B nonce] [2 B u16 BE len] [N B redirect_uri utf8] [32 B HMAC-SHA256]
/// ```
///
/// The HMAC is computed over `nonce || len_be || redirect_uri`. The
/// callback re-checks the recovered `redirect_uri` against the per-tenant
/// allowlist (TOCTOU-safe) AFTER HMAC verify — defense in depth.
#[derive(Debug)]
pub struct TenantOauthStateToken {
    pub nonce: [u8; 16],
    pub redirect_uri: String,
}

impl TenantOauthStateToken {
    /// Generate a fresh nonce and pair it with the supplied redirect_uri.
    pub fn new(redirect_uri: impl Into<String>) -> Self {
        let mut nonce = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut nonce);
        Self {
            nonce,
            redirect_uri: redirect_uri.into(),
        }
    }

    /// Encode + HMAC + base64url. Panics if `redirect_uri.len()` exceeds
    /// `u16::MAX` (65 535 bytes — far above any sane URI; an OAuth flow
    /// with a 64 KB redirect_uri is misconfigured well before encryption).
    pub fn encode(&self, secret: &[u8]) -> String {
        let uri_bytes = self.redirect_uri.as_bytes();
        let len_u16 = u16::try_from(uri_bytes.len())
            .expect("redirect_uri len must fit in u16 (≤65535 bytes)");
        let mut payload = Vec::with_capacity(16 + 2 + uri_bytes.len() + 32);
        payload.extend_from_slice(&self.nonce);
        payload.extend_from_slice(&len_u16.to_be_bytes());
        payload.extend_from_slice(uri_bytes);
        let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
        mac.update(&payload);
        payload.extend_from_slice(&mac.finalize().into_bytes());
        URL_SAFE_NO_PAD.encode(&payload)
    }

    /// Decode + HMAC-verify. Returns the recovered nonce + redirect_uri on
    /// success. The HMAC check is constant-time.
    pub fn decode(s: &str, secret: &[u8]) -> Result<Self, TenantOauthStateError> {
        let raw = URL_SAFE_NO_PAD
            .decode(s.as_bytes())
            .map_err(|_| TenantOauthStateError::BadEncoding)?;
        // 16 nonce + 2 len + 32 HMAC = 50 B floor (even with 0-byte URI).
        if raw.len() < 16 + 2 + 32 {
            return Err(TenantOauthStateError::TooShort);
        }
        let nonce: [u8; 16] = raw[..16].try_into().expect("slice len 16");
        let len = u16::from_be_bytes(raw[16..18].try_into().expect("slice len 2")) as usize;
        let total = 16 + 2 + len + 32;
        if raw.len() != total {
            return Err(TenantOauthStateError::LengthMismatch);
        }
        let uri_bytes = &raw[18..18 + len];
        let mac_received = &raw[18 + len..18 + len + 32];
        let signed_region = &raw[..18 + len];
        let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
        mac.update(signed_region);
        let mac_expected = mac.finalize().into_bytes();
        // Constant-time comparison — never short-circuit on byte mismatch.
        if mac_received.ct_eq(mac_expected.as_slice()).unwrap_u8() != 1 {
            return Err(TenantOauthStateError::HmacMismatch);
        }
        let redirect_uri = std::str::from_utf8(uri_bytes)
            .map_err(|_| TenantOauthStateError::InvalidUtf8)?
            .to_string();
        Ok(Self {
            nonce,
            redirect_uri,
        })
    }
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

    /// Path attribute must match the browser-facing URL prefix that Caddy
    /// adds (`/drust/*` via `handle_path`). If this drifts back to `/admin`,
    /// browsers stop sending the cookie on `/drust/admin/oauth/...` callback
    /// requests and every login fails with `oauth_state_mismatch`.
    /// Integration tests in `tests/admin_oauth.rs` bypass Caddy and won't
    /// catch this — this unit test is the regression guard.
    #[test]
    fn cookie_paths_match_caddy_prefix() {
        for cookie in [
            state_cookie("s", true),
            pkce_cookie("v", true),
            clear_state_cookie(),
            clear_pkce_cookie(),
        ] {
            assert_eq!(
                cookie.path(),
                Some("/drust/admin"),
                "cookie {} has wrong Path",
                cookie.name()
            );
        }
    }

    // ---------- TenantOauthStateToken ----------

    const TEST_SECRET: &[u8] = b"unit-test-secret-32-bytes-foo!!!";

    #[test]
    fn tenant_state_round_trip_decodes_to_input() {
        let original = TenantOauthStateToken::new("https://app.example.com/auth/callback");
        let encoded = original.encode(TEST_SECRET);
        let decoded =
            TenantOauthStateToken::decode(&encoded, TEST_SECRET).expect("round-trip must succeed");
        assert_eq!(decoded.nonce, original.nonce);
        assert_eq!(decoded.redirect_uri, original.redirect_uri);
    }

    #[test]
    fn tenant_state_encoded_is_url_safe() {
        let tok = TenantOauthStateToken::new("https://app.example.com/cb");
        let encoded = tok.encode(TEST_SECRET);
        for b in encoded.bytes() {
            assert!(
                b.is_ascii_alphanumeric() || b == b'-' || b == b'_',
                "non-url-safe byte in encoded state: {b:#x}"
            );
        }
    }

    #[test]
    fn tenant_state_tampered_redirect_uri_rejected() {
        // Take a legit state, decode raw bytes, mutate the URI region,
        // re-encode, then attempt decode. HMAC was computed over the
        // ORIGINAL URI so verification must fail.
        let tok = TenantOauthStateToken::new("https://app.example.com/cb");
        let encoded = tok.encode(TEST_SECRET);
        let mut raw = URL_SAFE_NO_PAD.decode(encoded.as_bytes()).unwrap();
        // URI starts at byte 18; flip the first byte of the URI.
        raw[18] ^= 0x01;
        let tampered = URL_SAFE_NO_PAD.encode(&raw);
        let err = TenantOauthStateToken::decode(&tampered, TEST_SECRET).unwrap_err();
        assert_eq!(err, TenantOauthStateError::HmacMismatch);
    }

    #[test]
    fn tenant_state_tampered_hmac_rejected() {
        // Flip a bit in the HMAC region (last 32 bytes). Decode must reject.
        let tok = TenantOauthStateToken::new("https://app.example.com/cb");
        let encoded = tok.encode(TEST_SECRET);
        let mut raw = URL_SAFE_NO_PAD.decode(encoded.as_bytes()).unwrap();
        let last = raw.len() - 1;
        let original = raw[last];
        raw[last] ^= 0x01;
        // Sanity: we actually flipped something.
        assert_ne!(raw[last], original);
        let tampered = URL_SAFE_NO_PAD.encode(&raw);
        let err = TenantOauthStateToken::decode(&tampered, TEST_SECRET).unwrap_err();
        assert_eq!(err, TenantOauthStateError::HmacMismatch);
    }

    #[test]
    fn tenant_state_truncated_rejected() {
        let tok = TenantOauthStateToken::new("https://app.example.com/cb");
        let encoded = tok.encode(TEST_SECRET);
        let raw = URL_SAFE_NO_PAD.decode(encoded.as_bytes()).unwrap();
        // Drop the trailing 8 bytes — corrupts HMAC region size.
        let truncated_raw = &raw[..raw.len() - 8];
        let truncated = URL_SAFE_NO_PAD.encode(truncated_raw);
        let err = TenantOauthStateToken::decode(&truncated, TEST_SECRET).unwrap_err();
        // Could be LengthMismatch (declared len > actual) or HmacMismatch
        // depending on alignment; both signal rejection. Empty-URI happens
        // to make this LengthMismatch; with our non-empty URI it is also
        // LengthMismatch because `total = 18 + len + 32` exceeds raw.len().
        assert_eq!(err, TenantOauthStateError::LengthMismatch);
    }

    #[test]
    fn tenant_state_floor_too_short_rejected() {
        // Anything below 50 bytes (16 nonce + 2 len + 32 HMAC) is structurally
        // impossible. Send 10 bytes of garbage.
        let raw = vec![0u8; 10];
        let s = URL_SAFE_NO_PAD.encode(&raw);
        let err = TenantOauthStateToken::decode(&s, TEST_SECRET).unwrap_err();
        assert_eq!(err, TenantOauthStateError::TooShort);
    }

    #[test]
    fn tenant_state_wrong_secret_rejected() {
        let tok = TenantOauthStateToken::new("https://app.example.com/cb");
        let encoded = tok.encode(TEST_SECRET);
        let err = TenantOauthStateToken::decode(&encoded, b"different-secret-32-bytes-bar!!!")
            .unwrap_err();
        assert_eq!(err, TenantOauthStateError::HmacMismatch);
    }

    #[test]
    fn tenant_state_bad_base64_rejected() {
        // `!` is not in URL_SAFE alphabet.
        let err = TenantOauthStateToken::decode("invalid!!!base64", TEST_SECRET).unwrap_err();
        assert_eq!(err, TenantOauthStateError::BadEncoding);
    }

    #[test]
    fn tenant_state_two_fresh_tokens_have_different_nonces() {
        let a = TenantOauthStateToken::new("https://app.example.com/cb");
        let b = TenantOauthStateToken::new("https://app.example.com/cb");
        assert_ne!(a.nonce, b.nonce, "rand should produce distinct nonces");
        // … and produce distinct encoded states.
        assert_ne!(a.encode(TEST_SECRET), b.encode(TEST_SECRET));
    }
}
