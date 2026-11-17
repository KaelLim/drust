//! Resume envelope and resume cookie: the signed authorize request that the
//! consent page and a resumed login carry.
//!
//! `GET /oauth/authorize` seals the validated request into an HMAC envelope
//! and sends it both as the consent page's `req` query value and as the
//! `drust_mcp_oauth_resume` cookie. Wire format:
//!
//! ```text
//! version   1 byte  = 0x01
//! exp       8 bytes = unix seconds, big-endian (issued_at + 600)
//! nonce    16 bytes = random
//! fields    fixed order: client_id, redirect_uri, state, code_challenge, resource
//!           each = present (1 byte, 0|1) [+ len (u16 BE) + UTF-8 bytes when present]
//! mac      32 bytes = HMAC-SHA256(envelope_key, b"drust-mcp-env-v1\0" || every byte above)
//! wire     = base64url, no padding
//! ```
//!
//! The key is per process (`McpOauthConfig::envelope_key`), so a restart
//! invalidates every in-flight consent; the user re-runs the client's login.
//! No `expect` / `unwrap` on any path outside the tests.
//!
//! The resume cookie is `SameSite=Lax` and must never become `Strict`: it has
//! to survive the cross-site top-level return from Google/GitHub login, which
//! a `Strict` cookie does not ride, so the consent flow would break after
//! sign-in (the session cookie is Lax for the same reason).
//!
//! The resume cookie selects which request resumes after login, and consent
//! requires it to equal the `req` it shows or approves. It is NOT the CSRF
//! defence: anyone who can steer a browser into the consent page with a given
//! `req` can first steer it through authorize. Forged approvals are stopped by
//! the consent CSRF token, which must never be dropped on the strength of this
//! cookie.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::mgmt::mcp_oauth::config::McpOauthConfig;

type HmacSha256 = Hmac<Sha256>;

const VERSION: u8 = 0x01;
const TTL_SECS: u64 = 600;
const MAC_DOMAIN: &[u8] = b"drust-mcp-env-v1\0";
const NONCE_LEN: usize = 16;
const MAC_LEN: usize = 32;
pub const MAX_CLIENT_ID: usize = 256;
/// == `redirect::MAX_REDIRECT_URI_BYTES`.
pub const MAX_REDIRECT_URI: usize = 64;
const _: () = assert!(
    MAX_REDIRECT_URI == crate::mgmt::mcp_oauth::redirect::MAX_REDIRECT_URI_BYTES,
    "the envelope's redirect_uri limit is redirect_uri_allowed's limit"
);
pub const MAX_STATE: usize = 512;
pub const CHALLENGE_LEN: usize = 43;
pub const MAX_RESOURCE: usize = 512;
/// Checked BEFORE base64 decoding.
const MAX_WIRE: usize = 4096;
pub const RESUME_COOKIE: &str = "drust_mcp_oauth_resume";
pub const RESUME_MAX_AGE_SECS: u64 = 600;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthzRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub state: Option<String>,
    pub code_challenge: String,
    pub resource: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum EnvelopeError {
    Malformed,
    BadMac,
    /// Carries the MAC-verified request, so its redirect is trustworthy.
    Expired {
        req: AuthzRequest,
    },
}

/// `Malformed` on any over-limit field (authorize checks the same limits
/// first, so this is a second line, never a panic).
pub fn seal(
    cfg: &McpOauthConfig,
    req: &AuthzRequest,
    now_unix: u64,
) -> Result<String, EnvelopeError> {
    if req.code_challenge.len() != CHALLENGE_LEN {
        return Err(EnvelopeError::Malformed);
    }
    let exp = now_unix
        .checked_add(TTL_SECS)
        .ok_or(EnvelopeError::Malformed)?;
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    let mut buf = Vec::with_capacity(1024);
    buf.push(VERSION);
    buf.extend_from_slice(&exp.to_be_bytes());
    buf.extend_from_slice(&nonce);
    put_field(&mut buf, Some(&req.client_id), MAX_CLIENT_ID)?;
    put_field(&mut buf, Some(&req.redirect_uri), MAX_REDIRECT_URI)?;
    put_field(&mut buf, req.state.as_deref(), MAX_STATE)?;
    put_field(&mut buf, Some(&req.code_challenge), CHALLENGE_LEN)?;
    put_field(&mut buf, req.resource.as_deref(), MAX_RESOURCE)?;
    let tag = mac(cfg, &buf)?;
    buf.extend_from_slice(&tag);
    Ok(URL_SAFE_NO_PAD.encode(buf))
}

/// Structure -> MAC (constant time) -> expiry, in that order: a tampered and
/// expired envelope is `BadMac`.
pub fn open(
    cfg: &McpOauthConfig,
    wire: &str,
    now_unix: u64,
) -> Result<AuthzRequest, EnvelopeError> {
    use EnvelopeError::Malformed;
    if wire.len() > MAX_WIRE {
        return Err(Malformed);
    }
    // base64 0.22's URL_SAFE_NO_PAD also refuses padding and non-canonical
    // trailing bits, so one envelope has exactly one wire spelling.
    let raw = URL_SAFE_NO_PAD.decode(wire).map_err(|_| Malformed)?;
    let mut r = Reader { rest: &raw };
    match r.take(1)? {
        [VERSION] => {}
        _ => return Err(Malformed),
    }
    let exp = u64::from_be_bytes(r.take(8)?.try_into().map_err(|_| Malformed)?);
    r.take(NONCE_LEN)?;
    let client_id = r.field(MAX_CLIENT_ID)?.ok_or(Malformed)?;
    let redirect_uri = r.field(MAX_REDIRECT_URI)?.ok_or(Malformed)?;
    let state = r.field(MAX_STATE)?;
    let code_challenge = r.field(CHALLENGE_LEN)?.ok_or(Malformed)?;
    let resource = r.field(MAX_RESOURCE)?;
    if r.rest.len() != MAC_LEN {
        return Err(Malformed); // truncated, or a trailing tail
    }
    let body_len = raw.len().checked_sub(MAC_LEN).ok_or(Malformed)?;
    let (body, tag) = raw.split_at(body_len);
    let expected = mac(cfg, body)?;
    if !bool::from(expected.as_slice().ct_eq(tag)) {
        return Err(EnvelopeError::BadMac);
    }
    // MAC-valid means we wrote it, so these are our own UTF-8 and lengths;
    // a failure is still an answer, never a panic.
    let text = |b: &[u8]| String::from_utf8(b.to_vec()).map_err(|_| Malformed);
    let req = AuthzRequest {
        client_id: text(client_id)?,
        redirect_uri: text(redirect_uri)?,
        state: state.map(text).transpose()?,
        code_challenge: text(code_challenge)?,
        resource: resource.map(text).transpose()?,
    };
    if req.code_challenge.len() != CHALLENGE_LEN {
        return Err(Malformed);
    }
    if now_unix >= exp {
        return Err(EnvelopeError::Expired { req });
    }
    Ok(req)
}

fn put_field(buf: &mut Vec<u8>, v: Option<&str>, max: usize) -> Result<(), EnvelopeError> {
    match v {
        None => buf.push(0),
        Some(s) => {
            if s.len() > max {
                return Err(EnvelopeError::Malformed);
            }
            let n = u16::try_from(s.len()).map_err(|_| EnvelopeError::Malformed)?;
            buf.push(1);
            buf.extend_from_slice(&n.to_be_bytes());
            buf.extend_from_slice(s.as_bytes());
        }
    }
    Ok(())
}

fn mac(cfg: &McpOauthConfig, body: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
    let mut m =
        HmacSha256::new_from_slice(cfg.envelope_key()).map_err(|_| EnvelopeError::Malformed)?;
    m.update(MAC_DOMAIN);
    m.update(body);
    Ok(m.finalize().into_bytes().to_vec())
}

/// Bounded cursor: every read is length-checked first.
struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], EnvelopeError> {
        if self.rest.len() < n {
            return Err(EnvelopeError::Malformed);
        }
        let (head, tail) = self.rest.split_at(n);
        self.rest = tail;
        Ok(head)
    }

    /// present byte 0 => None; 1 => u16 BE length (<= `max`) + bytes.
    fn field(&mut self, max: usize) -> Result<Option<&'a [u8]>, EnvelopeError> {
        match self.take(1)? {
            [0] => Ok(None),
            [1] => {
                let n = match self.take(2)? {
                    [hi, lo] => usize::from(u16::from_be_bytes([*hi, *lo])),
                    _ => return Err(EnvelopeError::Malformed),
                };
                if n > max {
                    return Err(EnvelopeError::Malformed);
                }
                self.take(n).map(Some)
            }
            _ => Err(EnvelopeError::Malformed),
        }
    }
}

/// `Set-Cookie` value carrying the whole envelope (base64url is all RFC 6265
/// cookie-octets). Same attribute shape as
/// `auth::middleware::build_session_cookie`. `SameSite=Lax` is required, see
/// the module doc; never `Strict`. No `__Host-` prefix: it needs `Path=/`,
/// which the `/drust` mount cannot use.
pub fn resume_cookie(wire: &str) -> String {
    cookie_line(wire, RESUME_MAX_AGE_SECS)
}

/// Same name, Path and attributes, empty value, `Max-Age=0`.
pub fn clear_resume_cookie() -> String {
    cookie_line("", 0)
}

fn cookie_line(value: &str, max_age: u64) -> String {
    let cpath = crate::base_path::cookie_path("");
    let base =
        format!("{RESUME_COOKIE}={value}; Path={cpath}; HttpOnly; SameSite=Lax; Max-Age={max_age}");
    if std::env::var("DRUST_DEV_NO_SECURE_COOKIES").is_ok() {
        base
    } else {
        format!("{base}; Secure")
    }
}

/// Every `Cookie` header (HTTP/2 may split them); the first exact-name match
/// wins.
pub fn read_resume_cookie(headers: &axum::http::HeaderMap) -> Option<String> {
    for hv in headers.get_all(axum::http::header::COOKIE) {
        let Ok(raw) = hv.to_str() else { continue };
        for part in raw.split(';') {
            if let Some((k, v)) = part.trim().split_once('=')
                && k == RESUME_COOKIE
            {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// `None` when the system clock reads before the epoch. Seal side
/// (authorize): `None` -> 303 `server_error`. Open side (consent, login
/// resume): pass
/// `now_unix().unwrap_or(u64::MAX)`, so every MAC-valid envelope opens as
/// `Expired { req }` — fail closed, redirect still trustworthy. Never map a
/// clock failure to 0: `open(.., 0)` would treat every envelope as unexpired.
pub fn now_unix() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

/// Where a successful admin login goes next.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResumeDecision {
    /// No in-flight MCP authorization: the usual landing page.
    None,
    /// A resume cookie that opens: go to this fixed consent path.
    Resume(String),
    /// A resume cookie that no longer opens: usual landing page, and clear it.
    ClearStale,
}

/// `login_submit` (303) and `oauth_callback` (302) ask this after the session
/// is created. Pass `now_unix().unwrap_or(u64::MAX)`: a clock failure makes
/// every cookie `ClearStale`. The client and redirect are NOT re-validated
/// here; that is the consent page's job, which therefore clears the cookie on
/// `ClientChanged` itself.
pub fn resume_target(
    cfg: &McpOauthConfig,
    headers: &axum::http::HeaderMap,
    now_unix: u64,
) -> ResumeDecision {
    // MUST stay the first statement: disabled == byte-identical login, never
    // reads the cookie (pinned by a source test).
    if !cfg.enabled() {
        return ResumeDecision::None;
    }
    let Some(wire) = read_resume_cookie(headers) else {
        return ResumeDecision::None;
    };
    // Empty = already cleared; do not answer it with Max-Age=0 on every login.
    if wire.is_empty() {
        return ResumeDecision::None;
    }
    match open(cfg, &wire, now_unix) {
        // A fixed string, never a URL taken from the cookie: no open redirect.
        Ok(_) => ResumeDecision::Resume(crate::base_path::base("/oauth/consent")),
        Err(_) => ResumeDecision::ClearStale,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue, header};

    const T: u64 = 1_800_000_000;
    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    fn cfg() -> McpOauthConfig {
        McpOauthConfig::for_tests("https://drust.test")
    }

    fn full() -> AuthzRequest {
        AuthzRequest {
            client_id: "https://claude.ai/oauth/claude-code-client-metadata".into(),
            redirect_uri: "http://localhost:54321/callback".into(),
            state: Some("st-é &=".into()),
            code_challenge: CHALLENGE.into(),
            resource: Some("https://drust.test/drust/mcp".into()),
        }
    }

    fn minimal() -> AuthzRequest {
        AuthzRequest {
            state: None,
            resource: None,
            ..full()
        }
    }

    fn sealed(req: &AuthzRequest) -> String {
        match seal(&cfg(), req, T) {
            Ok(w) => w,
            Err(e) => panic!("seal refused {req:?}: {e:?}"),
        }
    }

    fn decode(wire: &str) -> Vec<u8> {
        URL_SAFE_NO_PAD.decode(wire).unwrap()
    }

    fn encode(raw: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(raw)
    }

    /// Byte offsets of exp, nonce, every field's CONTENT bytes and the MAC
    /// (not version, present or length bytes) of an envelope of `req`.
    fn payload_offsets(req: &AuthzRequest, total: usize) -> Vec<usize> {
        let mut out: Vec<usize> = (1..1 + 8 + NONCE_LEN).collect();
        let mut pos = 1 + 8 + NONCE_LEN;
        for f in [
            Some(req.client_id.as_str()),
            Some(req.redirect_uri.as_str()),
            req.state.as_deref(),
            Some(req.code_challenge.as_str()),
            req.resource.as_deref(),
        ] {
            match f {
                None => pos += 1,
                Some(s) => {
                    pos += 3;
                    out.extend(pos..pos + s.len());
                    pos += s.len();
                }
            }
        }
        assert_eq!(
            pos + MAC_LEN,
            total,
            "offset walk disagrees with the format"
        );
        out.extend(pos..total);
        out
    }

    #[test]
    fn round_trip() {
        for req in [full(), minimal()] {
            let w = sealed(&req);
            assert_eq!(open(&cfg(), &w, T), Ok(req.clone()));
            assert_eq!(open(&cfg(), &w, T + 599), Ok(req));
        }
    }

    #[test]
    fn expired_after_600s_carries_request() {
        let req = full();
        let w = sealed(&req);
        assert_eq!(
            open(&cfg(), &w, T + 600),
            Err(EnvelopeError::Expired { req: req.clone() })
        );
        assert_eq!(
            open(&cfg(), &w, T + 10_000),
            Err(EnvelopeError::Expired { req })
        );
    }

    #[test]
    fn bad_mac_wins_over_expired() {
        let mut raw = decode(&sealed(&full()));
        raw[1 + 8] ^= 0x01; // first nonce byte
        assert_eq!(
            open(&cfg(), &encode(&raw), T + 601),
            Err(EnvelopeError::BadMac)
        );
    }

    #[test]
    fn flipped_payload_byte_is_bad_mac() {
        for req in [full(), minimal()] {
            let raw = decode(&sealed(&req));
            let offsets = payload_offsets(&req, raw.len());
            assert!(offsets.len() > 1 + 8 + NONCE_LEN + MAC_LEN);
            for i in offsets {
                let mut m = raw.clone();
                m[i] ^= 0x01;
                assert_eq!(
                    open(&cfg(), &encode(&m), T),
                    Err(EnvelopeError::BadMac),
                    "byte {i}"
                );
            }
        }
    }

    #[test]
    fn every_flipped_byte_is_rejected() {
        for req in [full(), minimal()] {
            let raw = decode(&sealed(&req));
            assert!(!raw.is_empty());
            for i in 0..raw.len() {
                for bit in [0x01u8, 0x80] {
                    let mut m = raw.clone();
                    m[i] ^= bit;
                    let got = open(&cfg(), &encode(&m), T);
                    assert!(got.is_err(), "byte {i} bit {bit:#x}: {got:?}");
                }
            }
        }
    }

    #[test]
    fn malformed_inputs() {
        let good = decode(&sealed(&full()));
        let mut version2 = good.clone();
        version2[0] = 0x02;
        let mut present2 = good.clone();
        present2[1 + 8 + NONCE_LEN] = 2; // client_id's present byte
        let mut cid_257 = good.clone();
        let at = 1 + 8 + NONCE_LEN + 1;
        cid_257[at..at + 2].copy_from_slice(&257u16.to_be_bytes());
        let mut trailing = good.clone();
        trailing.push(0);
        let cases: Vec<(&str, String)> = vec![
            ("empty", String::new()),
            ("not base64", "!".into()),
            ("truncated by 1", encode(&good[..good.len() - 1])),
            ("1 trailing byte", encode(&trailing)),
            ("version 0x02", encode(&version2)),
            ("present byte 2", encode(&present2)),
            ("client_id len 257", encode(&cid_257)),
            ("over 4096 chars", "A".repeat(MAX_WIRE + 1)),
        ];
        for (what, wire) in cases {
            assert_eq!(
                open(&cfg(), &wire, T),
                Err(EnvelopeError::Malformed),
                "{what}"
            );
        }
    }

    #[test]
    fn seal_rejects_over_limit_fields() {
        let over: Vec<(&str, AuthzRequest)> = vec![
            (
                "client_id 257",
                AuthzRequest {
                    client_id: "c".repeat(257),
                    ..full()
                },
            ),
            (
                "redirect_uri 65",
                AuthzRequest {
                    redirect_uri: "r".repeat(65),
                    ..full()
                },
            ),
            (
                "state 513",
                AuthzRequest {
                    state: Some("s".repeat(513)),
                    ..full()
                },
            ),
            (
                "challenge 42",
                AuthzRequest {
                    code_challenge: "c".repeat(42),
                    ..full()
                },
            ),
            (
                "challenge 44",
                AuthzRequest {
                    code_challenge: "c".repeat(44),
                    ..full()
                },
            ),
            (
                "resource 513",
                AuthzRequest {
                    resource: Some("x".repeat(513)),
                    ..full()
                },
            ),
        ];
        for (what, req) in over {
            assert_eq!(
                seal(&cfg(), &req, T),
                Err(EnvelopeError::Malformed),
                "{what}"
            );
        }
        let largest = AuthzRequest {
            client_id: "c".repeat(MAX_CLIENT_ID),
            redirect_uri: "r".repeat(MAX_REDIRECT_URI),
            state: Some("s".repeat(MAX_STATE)),
            code_challenge: "c".repeat(CHALLENGE_LEN),
            resource: Some("x".repeat(MAX_RESOURCE)),
        };
        let w = sealed(&largest);
        assert!(w.len() < 2_100, "largest envelope is {} chars", w.len());
        assert_eq!(open(&cfg(), &w, T), Ok(largest));
        // exp overflow is refused, not wrapped.
        assert_eq!(
            seal(&cfg(), &full(), u64::MAX - 599),
            Err(EnvelopeError::Malformed)
        );
    }

    #[test]
    fn different_key_is_bad_mac() {
        let other = McpOauthConfig::from_parts(
            &crate::mgmt::mcp_oauth::config::McpOauthEnv {
                mode: Some("on"),
                public_url: Some("https://drust.test"),
                ..Default::default()
            },
            crate::base_path::base_path(),
            [9; 32],
            [8; 32],
        );
        assert!(other.enabled());
        let w = sealed(&full());
        assert_eq!(open(&other, &w, T), Err(EnvelopeError::BadMac));
    }

    #[test]
    fn resume_cookie_attributes() {
        // Lib tests never call base_path::set (default "/drust") and never set
        // DRUST_DEV_NO_SECURE_COOKIES (only the standalone admin_theme target does).
        let c = resume_cookie("abc");
        assert_eq!(
            c,
            "drust_mcp_oauth_resume=abc; Path=/drust; HttpOnly; SameSite=Lax; Max-Age=600; Secure"
        );
        assert!(!c.contains("SameSite=Strict"));
        assert_eq!(
            clear_resume_cookie(),
            "drust_mcp_oauth_resume=; Path=/drust; HttpOnly; SameSite=Lax; Max-Age=0; Secure"
        );
    }

    #[test]
    fn now_unix_reads_the_clock() {
        let n = now_unix();
        assert!(n.is_some());
        assert!(n.unwrap_or(0) > 1_767_225_600, "{n:?}"); // 2026-01-01
    }

    #[test]
    fn open_at_u64_max_is_expired_not_ok() {
        let req = full();
        let w = sealed(&req);
        assert_eq!(
            open(&cfg(), &w, u64::MAX),
            Err(EnvelopeError::Expired { req })
        );
        let mut raw = decode(&w);
        let last = raw.len() - 1;
        raw[last] ^= 0x01; // inside the MAC
        assert_eq!(
            open(&cfg(), &encode(&raw), u64::MAX),
            Err(EnvelopeError::BadMac)
        );
    }

    fn headers(values: &[&str]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for v in values {
            h.append(header::COOKIE, HeaderValue::from_str(v).unwrap());
        }
        h
    }

    #[test]
    fn read_resume_cookie_cases() {
        let r = |v: &[&str]| read_resume_cookie(&headers(v));
        assert_eq!(r(&["drust_mcp_oauth_resume=w1"]), Some("w1".into()));
        assert_eq!(
            r(&["a=1; drust_mcp_oauth_resume=w2; b=2"]),
            Some("w2".into())
        );
        assert_eq!(r(&["a=1", "drust_mcp_oauth_resume=w3"]), Some("w3".into()));
        assert_eq!(
            r(&["a=1;   drust_mcp_oauth_resume=w4  ;b=2"]),
            Some("w4".into())
        );
        assert_eq!(
            r(&["drust_mcp_oauth_resume=first; drust_mcp_oauth_resume=second"]),
            Some("first".into())
        );
        assert_eq!(r(&["drust_mcp_oauth_resume2=x"]), None);
        assert_eq!(r(&["xdrust_mcp_oauth_resume=x"]), None);
        assert_eq!(r(&["a=1; b=2"]), None);
        assert_eq!(r(&[]), None);
    }

    fn resume(c: &McpOauthConfig, cookie: &[&str], now: u64) -> ResumeDecision {
        resume_target(c, &headers(cookie), now)
    }

    #[test]
    fn disabled_config_never_resumes() {
        let w = sealed(&full());
        let line = format!("{RESUME_COOKIE}={w}");
        assert_eq!(
            resume(&McpOauthConfig::disabled(), &[&line], T),
            ResumeDecision::None
        );
        assert_eq!(
            resume(
                &McpOauthConfig::disabled(),
                &[&format!("{RESUME_COOKIE}=junk")],
                T
            ),
            ResumeDecision::None
        );
    }

    #[test]
    fn no_cookie_or_empty_cookie_is_none() {
        assert_eq!(resume(&cfg(), &[], T), ResumeDecision::None);
        assert_eq!(resume(&cfg(), &["a=1"], T), ResumeDecision::None);
        assert_eq!(
            resume(&cfg(), &[&format!("{RESUME_COOKIE}=")], T),
            ResumeDecision::None
        );
    }

    #[test]
    fn valid_cookie_resumes_to_the_fixed_consent_path() {
        // Lib tests run with the default "/drust" base.
        for req in [
            full(),
            AuthzRequest {
                redirect_uri: "http://127.0.0.1:1/elsewhere".into(),
                ..minimal()
            },
        ] {
            let line = format!("{RESUME_COOKIE}={}", sealed(&req));
            assert_eq!(
                resume(&cfg(), &[&line], T + 10),
                ResumeDecision::Resume("/drust/oauth/consent".into())
            );
        }
    }

    #[test]
    fn expired_bad_mac_and_garbage_clear_stale() {
        let w = sealed(&full());
        let expired = format!("{RESUME_COOKIE}={w}");
        assert_eq!(
            resume(&cfg(), &[&expired], T + 700),
            ResumeDecision::ClearStale
        );
        let mut raw = decode(&w);
        raw[12] ^= 0x01; // inside the nonce
        let bad_mac = format!("{RESUME_COOKIE}={}", encode(&raw));
        assert_eq!(resume(&cfg(), &[&bad_mac], T), ResumeDecision::ClearStale);
        let garbage = format!("{RESUME_COOKIE}=!!");
        assert_eq!(resume(&cfg(), &[&garbage], T), ResumeDecision::ClearStale);
    }

    #[test]
    fn first_same_name_cookie_wins() {
        let w = sealed(&full());
        let line = format!("{RESUME_COOKIE}={w}; {RESUME_COOKIE}=junk");
        assert_eq!(
            resume(&cfg(), &[&line], T),
            ResumeDecision::Resume("/drust/oauth/consent".into())
        );
        let line = format!("{RESUME_COOKIE}=junk; {RESUME_COOKIE}={w}");
        assert_eq!(resume(&cfg(), &[&line], T), ResumeDecision::ClearStale);
    }

    /// Structural guarantee that a disabled host never reads the cookie (a
    /// behavioural test cannot tell "read but ignored" from "not read").
    #[test]
    fn resume_target_checks_enabled_before_reading_the_cookie() {
        let prod = include_str!("envelope.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        let start = prod.find("pub fn resume_target").unwrap();
        let body = &prod[start..];
        let body = &body[..body.find("\n}\n").unwrap()];
        let enabled = body.find("cfg.enabled()").unwrap();
        let read = body.find("read_resume_cookie(").unwrap();
        assert!(enabled < read);
        let first_stmt = body[body.find('{').unwrap() + 1..]
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty() && !l.starts_with("//"))
            .unwrap();
        assert_eq!(first_stmt, "if !cfg.enabled() {");
    }

    #[test]
    fn now_unix_failure_value_fails_closed() {
        let real_now = now_unix().unwrap();
        let req = full();
        let w = seal(&cfg(), &req, real_now).unwrap();
        assert!(matches!(
            open(&cfg(), &w, u64::MAX),
            Err(EnvelopeError::Expired { .. })
        ));
        assert_eq!(seal(&cfg(), &req, u64::MAX), Err(EnvelopeError::Malformed));
        let line = format!("{RESUME_COOKIE}={w}");
        assert_eq!(
            resume(&cfg(), &[&line], u64::MAX),
            ResumeDecision::ClearStale
        );
    }
}
