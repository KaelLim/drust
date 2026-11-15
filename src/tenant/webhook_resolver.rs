//! Per-dispatch DNS resolver. See spec
//! docs/superpowers/specs/2026-05-22-drust-v121-design.md §1.
//!
//! Two pieces:
//!   - `is_private_ip` — pure predicate over `IpAddr` for ranges drust will
//!     never deliver webhooks to (RFC1918, loopback, link-local, wildcard,
//!     IPv6 ULA). Same body that lived in `webhook_routes.rs` pre-v1.21.
//!   - `PinnedPublicResolver` — `reqwest::dns::Resolve` impl that wraps the
//!     stdlib synchronous DNS lookup and filters every private IP out of
//!     the result. Reused per attempt so a rebinding mid-flight cannot
//!     win a race against the resolver cache.
//!
//! `resolve_public` is the standalone helper used by
//! `WebhookDispatcher::deliver_for_test` to short-circuit a delivery whose
//! host has gone fully private/unresolvable between registration and dispatch.

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

/// True if `ip` is in any range we forbid for outbound webhook targets:
/// RFC1918 private (10/8, 172.16/12, 192.168/16), loopback (127/8, ::1),
/// link-local (169.254/16, fe80::/10), wildcard (0.0.0.0/8), IPv6 ULA
/// (fc00::/7), RFC 6598 CGNAT (100.64.0.0/10), IPv6 unspecified (::/128),
/// RFC 3849 documentation (2001:db8::/32), and every IPv6 spelling of a
/// private IPv4 — IPv4-mapped (::ffff:0:0/96), IPv4-compatible (::/96),
/// NAT64 (64:ff9b::/96) and 6to4 (2002::/16) when the embedded IPv4 is
/// itself private — plus the whole NAT64 local-use prefix 64:ff9b:1::/48,
/// whose embedding is operator-chosen. (Teredo, 2001::/32, is not decoded:
/// its embedding is obfuscated.) Returned for
/// any IP that should never receive a webhook from an internet-facing drust
/// instance.
///
/// `localhost`/`127.0.0.1`/`::1` are deliberately included. The `check_url`
/// carve-out for `http://localhost` runs BEFORE this check (see
/// `webhook_routes::check_url`) so dev-mode webhooks pointing at the same
/// host still work — but only when `webhook_loopback_allowed` permits it
/// (debug build, or `DRUST_WEBHOOK_ALLOW_LOOPBACK` set). In a prod release
/// build with the env unset, that carve-out is skipped and this predicate is
/// the one that rejects loopback (DEPLOY-1).
pub(crate) fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // 10/8
            if octets[0] == 10 {
                return true;
            }
            // 172.16/12
            if octets[0] == 172 && (octets[1] & 0xf0) == 16 {
                return true;
            }
            // 192.168/16
            if octets[0] == 192 && octets[1] == 168 {
                return true;
            }
            // 127/8 loopback
            if octets[0] == 127 {
                return true;
            }
            // 169.254/16 link-local
            if octets[0] == 169 && octets[1] == 254 {
                return true;
            }
            // 0/8 wildcard
            if octets[0] == 0 {
                return true;
            }
            // v1.32 A3: RFC 6598 CGNAT 100.64.0.0/10 — first 10 bits = 0110 0100 01
            // i.e. octets[0]==100 and octets[1] in [64..127]
            if octets[0] == 100 && (octets[1] & 0xc0) == 0x40 {
                return true;
            }
            false
        }
        IpAddr::V6(v6) => {
            // ::1 loopback
            if v6.is_loopback() {
                return true;
            }
            // v1.32 A3: ::/128 — unspecified address
            if v6.is_unspecified() {
                return true;
            }
            let segs = v6.segments();
            // fc00::/7 ULA  — first 7 bits = 1111110
            if (segs[0] & 0xfe00) == 0xfc00 {
                return true;
            }
            // fe80::/10 link-local — first 10 bits = 1111111010
            if (segs[0] & 0xffc0) == 0xfe80 {
                return true;
            }
            // v1.32 A3: 2001:db8::/32 — RFC 3849 documentation prefix
            if segs[0] == 0x2001 && segs[1] == 0x0db8 {
                return true;
            }
            // ::ffff:a.b.c.d — IPv4-mapped IPv6; re-check the V4 part.
            // v1.32 A3: this also catches ::ffff:0:0/96 wildcard when the
            // mapped address itself is private (e.g. ::ffff:10.x.x.x).
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_private_ip(IpAddr::V4(v4));
            }
            // The other IPv6 spellings that carry an IPv4 address. On a
            // network that routes these prefixes to IPv4 (a NAT64 gateway, a
            // 6to4 relay), dialling one reaches the embedded IPv4, so it is
            // judged by the V4 arm's own rules. A public embedded IPv4 still
            // passes. A new transition prefix belongs here, not at a call site.
            let embedded = |hi: u16, lo: u16| {
                std::net::Ipv4Addr::new((hi >> 8) as u8, hi as u8, (lo >> 8) as u8, lo as u8)
            };
            // ::a.b.c.d — IPv4-compatible (::/96; `::` and `::1` are caught above).
            if segs[0..6] == [0; 6] {
                return is_private_ip(IpAddr::V4(embedded(segs[6], segs[7])));
            }
            // 64:ff9b::/96 — NAT64 well-known prefix (RFC 6052).
            if segs[0] == 0x0064 && segs[1] == 0xff9b && segs[2..6] == [0; 4] {
                return is_private_ip(IpAddr::V4(embedded(segs[6], segs[7])));
            }
            // 64:ff9b:1::/48 — NAT64 local-use prefix (RFC 8215). The operator
            // chooses where the IPv4 sits inside it, so it cannot be extracted:
            // the whole prefix is treated as private.
            if segs[0] == 0x0064 && segs[1] == 0xff9b && segs[2] == 0x0001 {
                return true;
            }
            // 2002::/16 — 6to4 (RFC 3056); the IPv4 is segments 1-2.
            if segs[0] == 0x2002 {
                return is_private_ip(IpAddr::V4(embedded(segs[1], segs[2])));
            }
            false
        }
    }
}

/// Resolve `host:port` and return only non-private SocketAddrs. Error if
/// resolution fails OR every IP is private/loopback/link-local.
///
/// `host` may be a bracketed IPv6 literal (`[2606:4700:4700::1111]`, the form
/// `Url::host_str` returns): the brackets are stripped so the literal is
/// parsed without DNS and judged by `is_private_ip`. hyper never asks a
/// resolver about an IP literal, so for a literal webhook target this
/// wrap-first resolve is the only private-IP gate at dispatch.
pub(crate) async fn resolve_public(host: String, port: u16) -> Result<Vec<SocketAddr>, String> {
    let host = match host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        Some(inner) => inner.to_owned(),
        None => host,
    };
    let resolved = tokio::task::spawn_blocking(move || {
        (host.as_str(), port)
            .to_socket_addrs()
            .map(|it| it.collect::<Vec<_>>())
    })
    .await
    .map_err(|e| format!("dns join error: {e}"))?
    .map_err(|e| format!("dns lookup failed: {e}"))?;
    let public: Vec<_> = resolved
        .into_iter()
        .filter(|sa| !is_private_ip(sa.ip()))
        .collect();
    if public.is_empty() {
        return Err("host resolves only to private/loopback/link-local IPs".into());
    }
    Ok(public)
}

/// reqwest DNS resolver that pins every dial to a public IP — any
/// resolved address that lands in a private/loopback/link-local range is
/// dropped before reqwest sees it. Constructed fresh per delivery attempt
/// in `WebhookDispatcher::deliver_for_test`.
#[derive(Debug, Clone, Copy)]
pub struct PinnedPublicResolver;

impl Resolve for PinnedPublicResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let addrs = resolve_public(host, 0)
                .await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

/// Sized newtype around `Arc<dyn Resolve + Send + Sync>` so the trait
/// object can be passed to `reqwest::ClientBuilder::dns_resolver`, whose
/// signature requires `Arc<R>` where `R: Resolve + 'static + Sized`. The
/// inner `Arc` is cloned per delegated call — cheap pointer bump only.
pub(crate) struct ResolverHandle(pub Arc<dyn Resolve + Send + Sync>);

impl Resolve for ResolverHandle {
    fn resolve(&self, name: Name) -> Resolving {
        self.0.resolve(name)
    }
}

// Bring `Arc` into the file for `ResolverHandle`. (`std::sync::Arc` —
// kept after the impl so the unused-import lints stay quiet if this file
// is ever stripped down.)
use std::sync::Arc;

/// Whether the `http://localhost` (and `127.0.0.1` / `::1`) dev carve-out
/// in the webhook SSRF defense is permitted. The loopback bypass is a
/// development convenience ONLY — in a production release build it would
/// let a tenant register a webhook to the host loopback and SSRF internal
/// services that `PinnedPublicResolver` / `is_private_ip` otherwise block.
///
/// Pure so the prod-blocking branch is unit-testable even though the test
/// suite always runs in debug (`cfg!(debug_assertions) == true`): callers
/// pass `is_debug = cfg!(debug_assertions)` and
/// `env_set = std::env::var("DRUST_WEBHOOK_ALLOW_LOOPBACK").is_ok()`.
/// Fail-closed: allowed ONLY when one of those opt-ins is present.
pub(crate) fn webhook_loopback_allowed(is_debug: bool, env_set: bool) -> bool {
    is_debug || env_set
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// A bracketed public IPv6 literal (what `Url::host_str` hands the
    /// dispatcher) resolves to itself, with no DNS lookup.
    #[tokio::test]
    async fn resolve_public_accepts_bracketed_public_ipv6_literal() {
        let addrs = resolve_public("[2606:4700:4700::1111]".into(), 443)
            .await
            .unwrap();
        assert_eq!(
            addrs,
            vec![SocketAddr::new(ip("2606:4700:4700::1111"), 443)]
        );
    }

    /// A bracketed private literal is refused for being private, not for
    /// failing a DNS lookup of the bracketed string.
    #[tokio::test]
    async fn resolve_public_rejects_bracketed_private_ipv6_literal() {
        for host in ["[::1]", "[fd00::1]", "[fe80::1]", "[::ffff:10.0.0.1]"] {
            let err = resolve_public(host.into(), 443).await.unwrap_err();
            assert_eq!(
                err, "host resolves only to private/loopback/link-local IPs",
                "{host}"
            );
        }
    }

    /// Every IPv6 spelling of a private IPv4 is private; the same spellings
    /// of a public IPv4 are not.
    #[test]
    fn is_private_ip_flags_embedded_private_ipv4() {
        for private in [
            "::a00:1",            // IPv4-compatible 10.0.0.1
            "::7f00:1",           // IPv4-compatible 127.0.0.1
            "64:ff9b::a9fe:a9fe", // NAT64 169.254.169.254
            "64:ff9b::c0a8:101",  // NAT64 192.168.1.1
            "64:ff9b:1::1",       // NAT64 local-use, private outright
            "64:ff9b:1:abcd::1",  // anywhere inside the /48
            "2002:c0a8:101::1",   // 6to4 192.168.1.1
            "2002:7f00:1::",      // 6to4 127.0.0.1
            "2002:a9fe:a9fe::1",  // 6to4 169.254.169.254
        ] {
            assert!(is_private_ip(ip(private)), "{private} must be private");
        }
        for public in [
            "64:ff9b::808:808",     // NAT64 8.8.8.8
            "2002:808:808::1",      // 6to4 8.8.8.8
            "::808:808",            // IPv4-compatible 8.8.8.8
            "2606:4700:4700::1111", // ordinary global unicast
            "64:ff9b:2::1",         // outside both NAT64 prefixes
        ] {
            assert!(!is_private_ip(ip(public)), "{public} must stay public");
        }
    }

    #[test]
    fn rejects_rfc1918() {
        assert!(is_private_ip(ip("10.0.0.1")));
        assert!(is_private_ip(ip("172.16.5.10")));
        assert!(is_private_ip(ip("172.31.255.255")));
        assert!(is_private_ip(ip("192.168.1.1")));
    }

    #[test]
    fn rejects_loopback_and_link_local() {
        assert!(is_private_ip(ip("127.0.0.1")));
        assert!(is_private_ip(ip("169.254.169.254")));
        assert!(is_private_ip(ip("0.0.0.0")));
        assert!(is_private_ip(ip("::1")));
        assert!(is_private_ip(ip("fe80::1")));
        assert!(is_private_ip(ip("fc00::1")));
    }

    #[test]
    fn accepts_public_ips() {
        assert!(!is_private_ip(ip("8.8.8.8")));
        assert!(!is_private_ip(ip("203.0.113.5")));
        assert!(!is_private_ip(ip("2001:4860:4860::8888")));
    }

    // DEPLOY-1 — full truth table for the loopback opt-in gate. Pure fn,
    // so the prod-blocking case (false, false) => false is exercised even
    // though the suite runs in debug. Written before the helper exists
    // (RED: references an undefined fn => compile error), green after.
    #[test]
    fn webhook_loopback_allowed_truth_table() {
        // (is_debug, env_set)
        assert!(!webhook_loopback_allowed(false, false)); // prod, no opt-in => BLOCKED
        assert!(webhook_loopback_allowed(true, false)); // debug build => allowed
        assert!(webhook_loopback_allowed(false, true)); // prod + env opt-in => allowed
        assert!(webhook_loopback_allowed(true, true)); // both => allowed
    }

    #[test]
    fn ipv4_mapped_ipv6_rechecks() {
        // ::ffff:127.0.0.1 → loopback when unmapped
        assert!(is_private_ip(ip("::ffff:127.0.0.1")));
        // ::ffff:8.8.8.8 → public when unmapped
        assert!(!is_private_ip(ip("::ffff:8.8.8.8")));
    }

    // v1.32 A3 — new range tests (written before the fix to prove they fail)

    #[test]
    fn rejects_cgnat_range() {
        // RFC 6598 CGNAT 100.64.0.0/10
        assert!(is_private_ip(ip("100.64.0.5")));
        assert!(is_private_ip(ip("100.127.255.254")));
        // Just outside the /10 range — must NOT be flagged
        assert!(!is_private_ip(ip("100.128.0.0")));
        assert!(!is_private_ip(ip("100.63.255.255")));
    }

    #[test]
    fn rejects_ipv6_special_ranges() {
        // ::/128 — IPv6 unspecified
        assert!(is_private_ip(ip("::")));
        // 2001:db8::/32 — RFC 3849 documentation prefix
        assert!(is_private_ip(ip("2001:db8::1")));
        // IPv4-mapped private: recurse into IPv4 check
        assert!(is_private_ip(ip("::ffff:10.0.0.1")));
        assert!(is_private_ip(ip("::ffff:192.168.1.1")));
        // IPv4-mapped public: must NOT be flagged
        assert!(!is_private_ip(ip("::ffff:8.8.8.8")));
    }
}
