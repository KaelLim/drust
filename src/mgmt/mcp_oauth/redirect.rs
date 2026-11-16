//! `redirect_uri` validation for `GET /oauth/authorize` (MA0-PLAN §3.8.2).
//!
//! This file is the review surface of MA0-5. It deliberately never calls
//! `url::Url::parse` outside its tests: WHATWG parsing lower-cases hosts,
//! resolves dot-segments, rewrites numeric IPv4 and drops an explicit default
//! port, so a parse-then-compare check would accept spellings that are not the
//! pinned string — and the token endpoint later compares the same raw bytes
//! against the code row. Only prefix and byte comparisons happen here.

use crate::mgmt::mcp_oauth::clients::KnownClient;

/// The longest legal value, `http://127.0.0.1:65535/callback`, is 31 bytes.
/// Also the envelope's `redirect_uri` limit (`envelope::MAX_REDIRECT_URI`).
pub const MAX_REDIRECT_URI_BYTES: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedirectTarget {
    /// The validated input, byte for byte — never a re-serialised form. The
    /// consent approval stores it in `codes.redirect_uri` (MA0-6), and the
    /// token endpoint compares the client's resent string against it.
    pub raw: String,
    /// `"localhost"` or `"127.0.0.1"` (becomes `grants.redirect_host`).
    pub host: &'static str,
    /// `None` = no `:port` in the input.
    pub port: Option<u16>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RedirectReject {
    TooLong,
    NotLoopbackForm,
    PortOutOfRange,
    NotPinned,
}

/// Validate the RAW parameter value: form-urlencoded-decoded exactly once by
/// `params::parse_pairs`, never decoded again and never re-parsed by the url
/// crate.
///
/// Accepted language, exactly:
///   "http://" HOST [ ":" PORT ] PATH
///   HOST = "localhost" | "127.0.0.1"   (literal, case-sensitive, followed by ':' or '/')
///   PORT = 1–5 ASCII digits, no leading '0', value 1..=65535
///   PATH = every remaining byte; "http://" HOST PATH must equal one of client.redirect_uris
/// and the whole input is at most MAX_REDIRECT_URI_BYTES bytes.
///
/// An explicit `:80` is accepted and kept verbatim in `raw` (OAuth 2.1 lets a
/// loopback redirect use any port); do not normalise it away.
pub fn redirect_uri_allowed(
    client: &KnownClient,
    raw: &str,
) -> Result<RedirectTarget, RedirectReject> {
    if raw.len() > MAX_REDIRECT_URI_BYTES {
        return Err(RedirectReject::TooLong);
    }
    let rest = raw
        .strip_prefix("http://")
        .ok_or(RedirectReject::NotLoopbackForm)?;
    let (host, after_host): (&'static str, &str) = if let Some(r) = rest.strip_prefix("localhost") {
        ("localhost", r)
    } else if let Some(r) = rest.strip_prefix("127.0.0.1") {
        ("127.0.0.1", r)
    } else {
        return Err(RedirectReject::NotLoopbackForm);
    };
    // Host boundary: "localhost.evil", "127.0.0.10", "127.0.0.1@x",
    // "localhost\\…" all stop here.
    let (port, path) = match after_host.as_bytes().first() {
        Some(b'/') => (None, after_host),
        Some(b':') => {
            let digits_and_path = &after_host[1..];
            let end = digits_and_path
                .find('/')
                .ok_or(RedirectReject::NotLoopbackForm)?;
            let digits = &digits_and_path[..end];
            // is_ascii_digit, never char::is_numeric: ":١" (Arabic-Indic) is not a port.
            if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
                return Err(RedirectReject::NotLoopbackForm); // ":", ":+1", ":1a"
            }
            if digits.len() > 5 || digits.starts_with('0') {
                return Err(RedirectReject::PortOutOfRange); // ":0", ":080", ":123456"
            }
            let p: u32 = digits.parse().map_err(|_| RedirectReject::PortOutOfRange)?;
            let p = u16::try_from(p).map_err(|_| RedirectReject::PortOutOfRange)?; // ":65536"
            (Some(p), &digits_and_path[end..])
        }
        _ => return Err(RedirectReject::NotLoopbackForm), // no path, '.', '@', '0', '\\', …
    };
    // `p == 0` is impossible here (leading-zero rule), so the range is exactly 1..=65535.
    let pinned_form_len = "http://".len() + host.len() + path.len();
    let matches_pin = client.redirect_uris.iter().any(|u| {
        u.len() == pinned_form_len
            && u.strip_prefix("http://")
                .and_then(|r| r.strip_prefix(host))
                .is_some_and(|r| r == path)
    });
    if !matches_pin {
        // "/callback/", "/./callback", "/%63allback", "?x", "#f", "/Callback"
        return Err(RedirectReject::NotPinned);
    }
    Ok(RedirectTarget {
        raw: raw.to_owned(),
        host,
        port,
    })
}

/// Append form-urlencoded pairs. `raw` is always a validated
/// `RedirectTarget.raw` (no '?', no '#'); the '&' branch exists only so a
/// future caller cannot produce a second '?'.
pub fn append_query(raw: &str, pairs: &[(&str, &str)]) -> String {
    let mut ser = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in pairs {
        ser.append_pair(k, v);
    }
    let q = ser.finish();
    let sep = if raw.contains('?') { '&' } else { '?' };
    format!("{raw}{sep}{q}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mgmt::mcp_oauth::clients::find_client;

    const CC: &str = "https://claude.ai/oauth/claude-code-client-metadata";

    fn cc() -> &'static KnownClient {
        find_client(CC).expect("Claude Code is pinned")
    }

    fn ok(
        raw: &str,
        host: &'static str,
        port: Option<u16>,
    ) -> Result<RedirectTarget, RedirectReject> {
        Ok(RedirectTarget {
            raw: raw.to_string(),
            host,
            port,
        })
    }

    #[test]
    fn pinned_redirects_pass_their_own_validator() {
        let c = cc();
        // CIMD: the client_id IS the metadata document's URL.
        assert_eq!(c.client_id, c.source_url);
        assert!(!c.redirect_uris.is_empty());
        for u in c.redirect_uris {
            let t = redirect_uri_allowed(c, u);
            assert!(t.is_ok(), "{u}: {t:?}");
            let t = t.unwrap();
            assert_eq!(t.raw, *u);
            assert_eq!(t.port, None, "{u}");
        }
    }

    #[test]
    fn accepts_pinned_loopback_forms() {
        let c = cc();
        assert_eq!(
            redirect_uri_allowed(c, "http://localhost:1/callback"),
            ok("http://localhost:1/callback", "localhost", Some(1))
        );
        assert_eq!(
            redirect_uri_allowed(c, "http://127.0.0.1:65535/callback"),
            ok("http://127.0.0.1:65535/callback", "127.0.0.1", Some(65535))
        );
        assert_eq!(
            redirect_uri_allowed(c, "http://localhost/callback"),
            ok("http://localhost/callback", "localhost", None)
        );
        assert_eq!(
            redirect_uri_allowed(c, "http://127.0.0.1/callback"),
            ok("http://127.0.0.1/callback", "127.0.0.1", None)
        );
        assert_eq!(
            redirect_uri_allowed(c, "http://localhost:54321/callback"),
            ok("http://localhost:54321/callback", "localhost", Some(54321))
        );
    }

    #[test]
    fn explicit_port_80_is_kept_verbatim() {
        let c = cc();
        for (raw, host) in [
            ("http://localhost:80/callback", "localhost"),
            ("http://127.0.0.1:80/callback", "127.0.0.1"),
        ] {
            assert_eq!(redirect_uri_allowed(c, raw), ok(raw, host, Some(80)));
        }
    }

    #[test]
    fn every_port_1_to_65535_is_accepted() {
        let c = cc();
        for host in ["localhost", "127.0.0.1"] {
            for p in 1..=u16::MAX {
                let raw = format!("http://{host}:{p}/callback");
                match redirect_uri_allowed(c, &raw) {
                    Ok(t) => {
                        assert_eq!(t.port, Some(p), "{raw}");
                        assert_eq!(t.host, host, "{raw}");
                        assert_eq!(t.raw, raw);
                    }
                    Err(e) => panic!("{raw}: {e:?}"),
                }
            }
        }
    }

    /// Every row asserts the SPECIFIC variant.
    const REJECTED: &[(&str, RedirectReject)] = {
        use RedirectReject::*;
        &[
            ("https://localhost:1/callback", NotLoopbackForm),
            ("HTTP://localhost:1/callback", NotLoopbackForm),
            ("http:/localhost/callback", NotLoopbackForm),
            (" http://localhost:1/callback", NotLoopbackForm),
            ("", NotLoopbackForm),
            ("http://localhost.evil.com/callback", NotLoopbackForm),
            ("http://127.0.0.1.evil.com/callback", NotLoopbackForm),
            ("http://localhostx/callback", NotLoopbackForm),
            ("http://127.0.0.10:1/callback", NotLoopbackForm),
            ("http://127.0.0.1@evil.com/callback", NotLoopbackForm),
            ("http://user@localhost:1/callback", NotLoopbackForm),
            ("http://localhost\\@evil.com/callback", NotLoopbackForm),
            ("http://localhost%2F@evil/callback", NotLoopbackForm),
            ("http://[::1]:1/callback", NotLoopbackForm),
            ("http://LOCALHOST:1/callback", NotLoopbackForm),
            ("http://2130706433:1/callback", NotLoopbackForm),
            ("http://127.1:1/callback", NotLoopbackForm),
            ("http://0x7f.0.0.1:1/callback", NotLoopbackForm),
            ("http://localhost", NotLoopbackForm),
            ("http://localhost:1", NotLoopbackForm),
            ("http://localhost:/callback", NotLoopbackForm),
            ("http://localhost:1a/callback", NotLoopbackForm),
            ("http://localhost:+1/callback", NotLoopbackForm),
            ("http://localhost:\u{0661}/callback", NotLoopbackForm),
            ("http://localhost:0/callback", PortOutOfRange),
            ("http://localhost:080/callback", PortOutOfRange),
            ("http://localhost:00001/callback", PortOutOfRange),
            ("http://localhost:65536/callback", PortOutOfRange),
            ("http://localhost:123456/callback", PortOutOfRange),
            ("http://localhost:1/callback/", NotPinned),
            ("http://localhost:1/./callback", NotPinned),
            ("http://localhost:1/%63allback", NotPinned),
            ("http://localhost:1//callback", NotPinned),
            ("http://localhost:1/Callback", NotPinned),
            ("http://localhost:1/callback?x=1", NotPinned),
            ("http://localhost:1/callback#f", NotPinned),
            ("http://localhost:1/callback ", NotPinned),
            ("http://localhost:1/callback\n", NotPinned),
        ]
    };

    #[test]
    fn rejects_with_reason() {
        let c = cc();
        for (raw, want) in REJECTED {
            assert_eq!(redirect_uri_allowed(c, raw), Err(*want), "{raw:?}");
        }
        // 65 bytes -> TooLong, before any other check.
        let long = format!("http://localhost:1/{}", "a".repeat(46));
        assert_eq!(long.len(), 65);
        assert_eq!(redirect_uri_allowed(c, &long), Err(RedirectReject::TooLong));
        // Exactly 64 bytes but otherwise illegal: NOT TooLong (boundary).
        let at_limit = format!("http://localhost:1/{}", "a".repeat(45));
        assert_eq!(at_limit.len(), 64);
        assert_eq!(
            redirect_uri_allowed(c, &at_limit),
            Err(RedirectReject::NotPinned)
        );
        // A 65-byte value that would otherwise be NotLoopbackForm is TooLong.
        let long_https = format!("https://x/{}", "a".repeat(55));
        assert_eq!(long_https.len(), 65);
        assert_eq!(
            redirect_uri_allowed(c, &long_https),
            Err(RedirectReject::TooLong)
        );
    }

    #[test]
    fn accepted_strings_parse_to_the_same_target() {
        let c = cc();
        let mut samples: Vec<String> = [
            "http://localhost:1/callback",
            "http://127.0.0.1:65535/callback",
            "http://localhost/callback",
            "http://127.0.0.1/callback",
            "http://localhost:54321/callback",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        for host in ["localhost", "127.0.0.1"] {
            for p in [1u16, 80, 443, 8080, 65535] {
                samples.push(format!("http://{host}:{p}/callback"));
            }
        }
        let accepted: Vec<(String, RedirectTarget)> = samples
            .iter()
            .filter_map(|s| redirect_uri_allowed(c, s).ok().map(|t| (s.clone(), t)))
            .collect();
        // Anti-vacuous: every sample must be accepted.
        assert_eq!(accepted.len(), samples.len());
        for (s, t) in accepted {
            let u = url::Url::parse(&s).unwrap();
            assert_eq!(u.scheme(), "http", "{s}");
            assert_eq!(u.username(), "", "{s}");
            assert_eq!(u.password(), None, "{s}");
            assert_eq!(u.host_str(), Some(t.host), "{s}");
            assert_eq!(u.port_or_known_default(), Some(t.port.unwrap_or(80)), "{s}");
            assert_eq!(u.path(), "/callback", "{s}");
            assert_eq!(u.query(), None, "{s}");
            assert_eq!(u.fragment(), None, "{s}");
            assert_eq!(t.raw, s);
            if t.port == Some(80) {
                // WHATWG drops the default port; the target is the same and
                // `raw` keeps the input verbatim.
                assert_eq!(u.as_str(), s.replacen(":80/", "/", 1), "{s}");
            } else {
                assert_eq!(u.as_str(), s, "{s}");
            }
        }
    }

    #[test]
    fn whatwg_would_normalize_but_we_reject() {
        let c = cc();
        for s in [
            "http://LOCALHOST:1/callback",
            "http://localhost:1/./callback",
            "http://2130706433:1/callback",
        ] {
            let u = url::Url::parse(s).unwrap();
            assert!(
                matches!(u.host_str(), Some("localhost") | Some("127.0.0.1")),
                "{s} -> {:?}",
                u.host_str()
            );
            assert_eq!(u.path(), "/callback", "{s}");
            assert!(redirect_uri_allowed(c, s).is_err(), "{s}");
        }
    }

    #[test]
    fn append_query_form_encodes_and_orders() {
        assert_eq!(
            append_query(
                "http://localhost:1/callback",
                &[
                    ("code", "a b"),
                    ("state", "x&y=z"),
                    ("iss", "https://drust.test/drust")
                ]
            ),
            "http://localhost:1/callback?code=a+b&state=x%26y%3Dz&iss=https%3A%2F%2Fdrust.test%2Fdrust"
        );
        assert_eq!(
            append_query("http://localhost:1/callback", &[]),
            "http://localhost:1/callback?"
        );
    }
}
