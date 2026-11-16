//! Per-tenant egress allowlist (v1.49).
//!
//! Pure enforcement helper shared by the webhook third gate and the
//! `http-fetch` edge-function host import. An origin-level, deny-all-default
//! allowlist stored as tagged `{system, uri}` JSON on the `tenants` row
//! (`egress_allowlist_json`). This module is the single source of truth for
//! parsing that JSON, normalizing origins, and the `check_egress` decision —
//! it holds NO I/O and NO network. Fail-closed everywhere: unknown system,
//! bad JSON, bad origin shape, or empty list all deny.

use rusqlite::Connection;
use serde::{Deserialize, Serialize};

/// Which outbound subsystem an allowlist entry grants. Serialized as its
/// lowercase string tag (`"webhook"` / `"function"`).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EgressSystem {
    Webhook,
    Function,
}

impl EgressSystem {
    /// The string tag stored in JSON / echoed to config surfaces.
    pub fn as_str(&self) -> &'static str {
        match self {
            EgressSystem::Webhook => "webhook",
            EgressSystem::Function => "function",
        }
    }

    /// Parse a string tag; unknown tags return `None` (fail-closed).
    pub fn parse(s: &str) -> Option<EgressSystem> {
        match s {
            "webhook" => Some(EgressSystem::Webhook),
            "function" => Some(EgressSystem::Function),
            _ => None,
        }
    }
}

/// One allowlist entry: an outbound subsystem paired with an allowed origin.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EgressEntry {
    pub system: EgressSystem,
    pub uri: String,
}

/// Normalize a URL to its origin (`scheme://host[:port]`): require an
/// `http`/`https` scheme and a non-empty host, lowercase the host, drop the
/// default port (80 for http, 443 for https), and strip any path / query /
/// fragment / trailing slash. Anything that is not a well-formed http(s)
/// origin is rejected with an `Err` describing why.
///
/// An IPv6 literal is written in brackets (`https://[2001:db8::1]:8443`). It is
/// parsed with `std::net::Ipv6Addr` and re-emitted in that type's canonical
/// text (RFC 5952 compression, lowercase hex; an IPv4-mapped address prints in
/// mixed notation, `[::ffff:127.0.0.1]`), so two spellings of the same address
/// normalise to one string — the only equalities this adds. Zone ids, IPv4
/// inside brackets and anything after `]` other than `:<port>` are refused.
/// Outside brackets, a host containing `:`, `[` or `]` is refused: it is never a
/// valid reg-name or IPv4, so it could never match anything the dial parser
/// produces. DNS names and IPv4 hosts are compared as text, as before — no
/// alternate-IPv4 equivalence (`127.1` vs `127.0.0.1`) is introduced.
pub fn normalize_origin(raw: &str) -> Result<String, String> {
    let raw = raw.trim();
    let (scheme, rest) = raw
        .split_once("://")
        .ok_or_else(|| format!("missing scheme separator in {raw:?}"))?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(format!("unsupported scheme {scheme:?}"));
    }
    // Authority is everything up to the first path/query/fragment delimiter.
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.is_empty() {
        return Err("empty host".into());
    }
    // Origins never carry userinfo — reject to avoid host-spoofing shapes.
    if authority.contains('@') {
        return Err(format!("userinfo not allowed in {authority:?}"));
    }
    let (host_canon, port): (String, Option<u16>) = if let Some(after) = authority.strip_prefix('[')
    {
        // RFC 3986 IP-literal. Parsed with std so the stored form is canonical.
        let (literal, tail) = after
            .split_once(']')
            .ok_or_else(|| format!("unterminated IPv6 literal in {authority:?}"))?;
        let addr: std::net::Ipv6Addr = literal
            .parse()
            .map_err(|_| format!("invalid IPv6 literal in {authority:?}"))?;
        let port = match tail {
            "" => None,
            t => Some(parse_port(
                t.strip_prefix(':')
                    .ok_or_else(|| format!("invalid authority {authority:?}"))?,
                authority,
            )?),
        };
        (format!("[{addr}]"), port)
    } else {
        // Split an optional numeric port off the end. A colon followed by
        // anything non-numeric (or an empty port) is a malformed authority.
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => (h, Some(parse_port(p, authority)?)),
            None => (authority, None),
        };
        if host.is_empty() {
            return Err("empty host".into());
        }
        // A bare ':' / '[' / ']' left in the host is never a valid reg-name
        // or IPv4 (`http://::1`, `https://a:b:443`, `https://ex]ample.com`).
        if host.contains([':', '[', ']']) {
            return Err(format!("invalid authority {authority:?}"));
        }
        (host.to_ascii_lowercase(), port)
    };
    let mut origin = format!("{scheme}://{host_canon}");
    if let Some(p) = port {
        let is_default = (scheme == "http" && p == 80) || (scheme == "https" && p == 443);
        if !is_default {
            origin.push(':');
            origin.push_str(&p.to_string());
        }
    }
    Ok(origin)
}

/// The port rule `normalize_origin` applies: non-empty, ASCII digits only,
/// fits a `u16`.
fn parse_port(p: &str, authority: &str) -> Result<u16, String> {
    if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("invalid authority {authority:?}"));
    }
    p.parse::<u16>()
        .map_err(|_| format!("invalid port in {authority:?}"))
}

/// True iff `origin`'s host is an IP LITERAL in a private/loopback/link-local/
/// CGNAT/ULA/documentation range. `origin` is expected to be a `normalize_origin`
/// output (`scheme://host[:port]`).
///
/// The `PinnedPublicResolver` DiD gate only filters *resolved DNS names* — hyper's
/// connector short-circuits DNS for a host that is already an IP literal and dials
/// it directly, never polling the custom resolver. So an IP-literal origin
/// (`http://169.254.169.254`, `http://127.0.0.1`) silently bypasses the private-IP
/// block unless it is checked explicitly.
///
/// CRITICAL: this check MUST use the SAME parser reqwest dials with. `reqwest::Url`
/// is the `url` crate's WHATWG parser, which CANONICALIZES alternate IPv4 encodings
/// — `http://2130706433` / `http://0x7f000001` / `http://127.1` → `127.0.0.1`,
/// `http://2851995374` → `169.254.169.254`, `http://0` → `0.0.0.0`. A naive
/// substring + `std::net::IpAddr` parse (which REJECTS those encodings) would let an
/// allowlisted `http://2851995374` dial cloud metadata — the classic
/// parser-differential SSRF (codex full-scan F2; the same lesson as the v1.49 egress
/// review). By deriving the host through the dial's own parser and re-reading its
/// canonicalized `host_str`, this gate sees exactly what reqwest will dial. DNS-name
/// hosts return `false` and stay covered by `PinnedPublicResolver`.
pub fn origin_host_is_private_ip(origin: &str) -> bool {
    let url = match reqwest::Url::parse(origin) {
        Ok(u) => u,
        Err(_) => return false,
    };
    let Some(host) = url.host_str() else {
        return false;
    };
    // `url` brackets IPv6 (`[::1]`); std's `IpAddr` parser wants it unbracketed.
    // For canonicalized IPv4 (`127.0.0.1`) and DNS names it is returned verbatim.
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => crate::tenant::webhook_resolver::is_private_ip(ip),
        Err(_) => false,
    }
}

/// Parse the stored allowlist JSON leniently: bad JSON yields an empty list,
/// and any individual entry with a missing/invalid `system` or `uri` is
/// skipped. Loud validation is the config-time gate; here we fail closed.
pub fn parse_allowlist(json: &str) -> Vec<EgressEntry> {
    let values: Vec<serde_json::Value> = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    values
        .into_iter()
        .filter_map(|v| {
            let system = EgressSystem::parse(v.get("system")?.as_str()?)?;
            let uri = v.get("uri")?.as_str()?.to_string();
            Some(EgressEntry { system, uri })
        })
        .collect()
}

/// True iff `allowlist_json` contains an entry whose `system` matches and
/// whose normalized origin is exactly equal to the normalized `origin`. The
/// incoming `origin` and every stored `uri` are normalized before comparison,
/// so casing / default-port / trailing-slash differences never break a match.
/// An un-normalizable `origin` denies.
pub fn check_egress(allowlist_json: &str, system: EgressSystem, origin: &str) -> bool {
    let target = match normalize_origin(origin) {
        Ok(o) => o,
        Err(_) => return false,
    };
    parse_allowlist(allowlist_json).into_iter().any(|entry| {
        entry.system == system
            && normalize_origin(&entry.uri)
                .map(|o| o == target)
                .unwrap_or(false)
    })
}

/// Read a tenant's stored egress allowlist JSON from `meta.sqlite`. Returns the
/// deny-all `'[]'` when the row or the column is absent, or on ANY read error —
/// fail-CLOSED, since an empty allowlist denies every outbound path. The
/// `Result` is retained for signature symmetry with the rest of the read path
/// but this helper never surfaces an `Err`; every failure collapses to deny-all.
///
/// Config and boot surfaces keep using this one: it reads the row whatever its
/// `deleted_at`, which is what the one-time `backfill_egress_allowlist` pass
/// needs (it iterates `SELECT id FROM tenants`, soft-deleted rows included, and
/// merges the stored list forward — a liveness filter there would silently
/// blank a soft-deleted tenant's allowlist). Anything deciding whether traffic
/// may LEAVE the host wants [`try_read_live_egress_allowlist`] instead.
pub fn read_egress_allowlist(meta: &Connection, tenant_id: &str) -> rusqlite::Result<String> {
    let stored = meta
        .query_row(
            "SELECT COALESCE(egress_allowlist_json, '[]') FROM tenants WHERE id = ?1",
            [tenant_id],
            |row| row.get::<_, String>(0),
        )
        .unwrap_or_else(|_| "[]".to_string());
    Ok(stored)
}

/// Three-way allowlist read for the LIVE egress gates, i.e. every caller that
/// must tell a real denial apart from a meta it could not read at all.
///
/// * `Ok(Some(json))` — the tenant is live; this is its allowlist.
/// * `Ok(None)` — **authoritative deny**: no such tenant, or it is
///   soft-deleted. `deleted_at IS NULL` is load-bearing, not decoration: a
///   soft-delete leaves the `tenants` row in place with `egress_allowlist_json`
///   untouched, so a reader without the predicate keeps authorizing outbound
///   traffic for a tenant an admin has already deleted. `dispatch_many` refuses
///   to START a fan-out for a non-live tenant (`get_if_live`); this keeps the
///   per-attempt gate agreeing with it for a delete that lands mid-flight.
/// * `Err(e)` — meta could not be queried. **Not** a denial. A caller with
///   retries left must fail closed for that attempt without concluding the
///   origin was revoked; collapsing the two makes a transient hiccup
///   indistinguishable from a revocation.
pub fn try_read_live_egress_allowlist(
    meta: &Connection,
    tenant_id: &str,
) -> rusqlite::Result<Option<String>> {
    match meta.query_row(
        "SELECT COALESCE(egress_allowlist_json, '[]') FROM tenants \
          WHERE id = ?1 AND deleted_at IS NULL",
        [tenant_id],
        |row| row.get::<_, String>(0),
    ) {
        Ok(json) => Ok(Some(json)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_host_private_ip_flags_literals_and_ignores_dns() {
        // private / loopback / link-local / CGNAT IP literals → true
        for o in [
            "http://10.0.0.1",
            "http://127.0.0.1",
            "http://127.0.0.1:8080",
            "http://169.254.169.254",
            "http://192.168.1.1",
            "http://172.16.0.1",
            "http://100.64.0.1",
            "http://[::1]",
            "https://[fd00::1]",
            "https://[fe80::1]",
            "https://[::ffff:127.0.0.1]",
            "https://[::ffff:10.0.0.1]",
            // alternate IPv4 encodings the `url` crate canonicalizes to a private
            // IP but std::net::IpAddr::parse REJECTS — the parser-differential the
            // fix must close (F2 BROKEN → fixed).
            "http://2130706433", // = 127.0.0.1
            "http://0x7f000001", // = 127.0.0.1
            "http://127.1",      // = 127.0.0.1
            "http://2852039166", // = 169.254.169.254
            "http://0",          // = 0.0.0.0
        ] {
            assert!(
                origin_host_is_private_ip(o),
                "should flag private literal {o}"
            );
        }
        // public IP literals + DNS names → false (the resolver covers DNS names)
        for o in [
            "http://8.8.8.8",
            "https://93.184.216.34",
            "https://example.com",
            "https://api.github.com:443",
            "https://[2606:4700:4700::1111]",
        ] {
            assert!(!origin_host_is_private_ip(o), "should NOT flag {o}");
        }
        // The normalised form of each private IPv6 literal is still flagged.
        for raw in [
            "http://[::1]",
            "https://[FD00::1]:8443",
            "https://[::FFFF:7F00:1]",
        ] {
            let o = normalize_origin(raw).unwrap();
            assert!(origin_host_is_private_ip(&o), "should flag normalised {o}");
        }
    }

    #[test]
    fn normalize_accepts_bracketed_ipv6_without_port() {
        assert_eq!(
            normalize_origin("https://[2606:4700:4700::1111]").unwrap(),
            "https://[2606:4700:4700::1111]"
        );
        assert_eq!(
            normalize_origin("http://[2001:4860:4860::8888]/x?y").unwrap(),
            "http://[2001:4860:4860::8888]"
        );
    }

    #[test]
    fn normalize_ipv6_drops_default_port_keeps_others() {
        let a = "2606:4700:4700::1111";
        assert_eq!(
            normalize_origin(&format!("https://[{a}]:443")).unwrap(),
            format!("https://[{a}]")
        );
        assert_eq!(
            normalize_origin(&format!("http://[{a}]:80")).unwrap(),
            format!("http://[{a}]")
        );
        assert_eq!(
            normalize_origin(&format!("https://[{a}]:8443")).unwrap(),
            format!("https://[{a}]:8443")
        );
        assert_eq!(
            normalize_origin(&format!("https://[{a}]:0443")).unwrap(),
            format!("https://[{a}]")
        );
        // A non-default port on the other scheme is kept.
        assert_eq!(
            normalize_origin(&format!("http://[{a}]:443")).unwrap(),
            format!("http://[{a}]:443")
        );
    }

    #[test]
    fn normalize_ipv6_canonicalizes_spelling() {
        for spelling in [
            "https://[2606:4700:4700:0:0:0:0:1111]",
            "https://[2606:4700:4700:0000:0000:0000:0000:1111]",
            "https://[2606:4700:4700::1111]",
            "HTTPS://[2606:4700:4700::1111]:443/",
        ] {
            assert_eq!(
                normalize_origin(spelling).unwrap(),
                "https://[2606:4700:4700::1111]",
                "{spelling}"
            );
        }
        assert_eq!(
            normalize_origin("https://[2001:DB8::ABCD]:8443").unwrap(),
            "https://[2001:db8::abcd]:8443"
        );
        assert_eq!(
            normalize_origin("https://[::FFFF:7F00:1]").unwrap(),
            "https://[::ffff:127.0.0.1]"
        );
    }

    #[test]
    fn normalize_rejects_malformed_ipv6_and_stray_colons() {
        for bad in [
            "https://[fe80::1%25eth0]",
            "https://[fe80::1%eth0]",
            "https://[1.2.3.4]",
            "https://[]",
            "https://[::1",
            "https://[::1]x",
            "https://[::1]:",
            "https://[::1]]",
            "https://[::1]:99999",
            "https://[zz::1]",
            "http://::1",
            "https://a:b:443",
            "https://ex]ample.com",
            "https://ex[ample.com",
            "https://a.com:",
            "https://:443",
        ] {
            assert!(normalize_origin(bad).is_err(), "{bad} should be rejected");
        }
    }

    /// The hand-written normaliser must never be LOOSER than the URL parser
    /// that dials: for every IPv6 origin it accepts, `reqwest::Url` accepts
    /// both the input and the normalised form, they name the same address
    /// (compared as `Ipv6Addr`, not as text), and the effective port agrees.
    #[test]
    fn normalize_ipv6_never_looser_than_the_dial_parser() {
        fn dial_target(u: &str) -> (std::net::Ipv6Addr, Option<u16>) {
            let url = reqwest::Url::parse(u).unwrap_or_else(|e| panic!("{u}: {e}"));
            let host = url.host_str().expect("host");
            let inner = host
                .strip_prefix('[')
                .and_then(|h| h.strip_suffix(']'))
                .unwrap_or_else(|| panic!("{u}: host {host} is not a bracketed literal"));
            (inner.parse().unwrap(), url.port_or_known_default())
        }
        for input in [
            "https://[2606:4700:4700::1111]",
            "https://[2606:4700:4700:0:0:0:0:1111]:443",
            "http://[2001:4860:4860::8888]:8080/x",
            "https://[2001:DB8::ABCD]:8443",
            "https://[::FFFF:7F00:1]",
            "https://[::ffff:127.0.0.1]",
            "https://[64:ff9b::808:808]:8443",
            "https://[::1]",
            "http://[fe80::1]:0443",
        ] {
            let normalized = normalize_origin(input).unwrap();
            assert_eq!(
                dial_target(input),
                dial_target(&normalized),
                "{input} -> {normalized} names a different socket"
            );
            // Idempotent on its own output — what http_fetch's re-derive relies on.
            assert_eq!(normalize_origin(&normalized).unwrap(), normalized);
        }
    }

    #[test]
    fn check_egress_matches_ipv6_across_default_port_and_spelling() {
        let list = r#"[{"system":"webhook","uri":"https://[2606:4700:4700::1111]:443"}]"#;
        for ok in [
            "https://[2606:4700:4700::1111]/h",
            "https://[2606:4700:4700::1111]",
            "https://[2606:4700:4700:0:0:0:0:1111]/h",
        ] {
            assert!(check_egress(list, EgressSystem::Webhook, ok), "{ok}");
        }
        for no in [
            "https://[2606:4700:4700::1111]:8443/h",
            "http://[2606:4700:4700::1111]/h",
            "https://[2606:4700:4700::1112]/h",
        ] {
            assert!(!check_egress(list, EgressSystem::Webhook, no), "{no}");
        }
        assert!(!check_egress(
            list,
            EgressSystem::Function,
            "https://[2606:4700:4700::1111]"
        ));
    }

    #[test]
    fn normalize_strips_path_and_lowercases_and_drops_default_port() {
        assert_eq!(
            normalize_origin("https://GitLab.com/path?q=1").unwrap(),
            "https://gitlab.com"
        );
        assert_eq!(
            normalize_origin("https://a.com:443/").unwrap(),
            "https://a.com"
        );
        assert_eq!(normalize_origin("http://a.com:80").unwrap(), "http://a.com");
        assert_eq!(
            normalize_origin("https://a.com:8443").unwrap(),
            "https://a.com:8443"
        );
    }

    #[test]
    fn normalize_rejects_non_origin() {
        for bad in [
            "",
            "a.com",
            "ftp://a.com",
            "https://",
            "javascript:alert(1)",
        ] {
            assert!(normalize_origin(bad).is_err(), "{bad} should be rejected");
        }
    }

    #[test]
    fn check_exact_origin_only_no_subdomain_no_scheme_confusion() {
        let list = r#"[{"system":"webhook","uri":"https://gitlab.com"}]"#;
        assert!(check_egress(
            list,
            EgressSystem::Webhook,
            "https://gitlab.com"
        ));
        assert!(!check_egress(
            list,
            EgressSystem::Webhook,
            "https://evil.gitlab.com"
        ));
        assert!(!check_egress(
            list,
            EgressSystem::Webhook,
            "http://gitlab.com"
        ));
        assert!(!check_egress(
            list,
            EgressSystem::Webhook,
            "https://gitlab.com:8443"
        ));
    }

    #[test]
    fn check_dispatches_on_system() {
        let list = r#"[{"system":"webhook","uri":"https://a.com"}]"#;
        assert!(check_egress(list, EgressSystem::Webhook, "https://a.com"));
        assert!(
            !check_egress(list, EgressSystem::Function, "https://a.com"),
            "webhook entry must not grant function"
        );
    }

    #[test]
    fn empty_or_garbage_is_deny() {
        assert!(!check_egress("[]", EgressSystem::Webhook, "https://a.com"));
        assert!(!check_egress(
            "not json",
            EgressSystem::Function,
            "https://a.com"
        ));
        assert!(!check_egress(
            r#"[{"system":"bogus","uri":"https://a.com"}]"#,
            EgressSystem::Webhook,
            "https://a.com"
        ));
    }
}
