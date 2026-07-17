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
    // Split an optional numeric port off the end. A colon followed by
    // anything non-numeric (or an empty port) is a malformed authority.
    let (host, port): (&str, Option<u16>) = match authority.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => {
            let pn = p
                .parse::<u16>()
                .map_err(|_| format!("invalid port in {authority:?}"))?;
            (h, Some(pn))
        }
        Some(_) => return Err(format!("invalid authority {authority:?}")),
        None => (authority, None),
    };
    if host.is_empty() {
        return Err("empty host".into());
    }
    let host_lc = host.to_ascii_lowercase();
    let mut origin = format!("{scheme}://{host_lc}");
    if let Some(p) = port {
        let is_default = (scheme == "http" && p == 80) || (scheme == "https" && p == 443);
        if !is_default {
            origin.push(':');
            origin.push_str(&p.to_string());
        }
    }
    Ok(origin)
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
            // alternate IPv4 encodings the `url` crate canonicalizes to a private
            // IP but std::net::IpAddr::parse REJECTS — the parser-differential the
            // fix must close (F2 BROKEN → fixed).
            "http://2130706433",  // = 127.0.0.1
            "http://0x7f000001",  // = 127.0.0.1
            "http://127.1",       // = 127.0.0.1
            "http://2852039166",  // = 169.254.169.254
            "http://0",           // = 0.0.0.0
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
        ] {
            assert!(!origin_host_is_private_ip(o), "should NOT flag {o}");
        }
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
