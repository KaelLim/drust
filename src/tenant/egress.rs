//! Per-tenant egress allowlist (v1.49).
//!
//! Pure enforcement helper shared by the webhook third gate and the
//! `http-fetch` edge-function host import. An origin-level, deny-all-default
//! allowlist stored as tagged `{system, uri}` JSON on the `tenants` row
//! (`egress_allowlist_json`). This module is the single source of truth for
//! parsing that JSON, normalizing origins, and the `check_egress` decision —
//! it holds NO I/O and NO network. Fail-closed everywhere: unknown system,
//! bad JSON, bad origin shape, or empty list all deny.

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

#[cfg(test)]
mod tests {
    use super::*;

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
