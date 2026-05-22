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
/// link-local (169.254/16, fe80::/10), wildcard (0.0.0.0/8), or IPv6 ULA
/// (fc00::/7). Returned for any IP that should never receive a webhook
/// from an internet-facing drust instance.
///
/// `localhost`/`127.0.0.1`/`::1` are deliberately included — the existing
/// `check_url` carve-out for `http://localhost` already runs BEFORE this
/// check (see `webhook_routes::check_url`), so dev-mode webhooks pointing
/// at the same host still work.
pub(crate) fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // 10/8
            if octets[0] == 10 { return true; }
            // 172.16/12
            if octets[0] == 172 && (octets[1] & 0xf0) == 16 { return true; }
            // 192.168/16
            if octets[0] == 192 && octets[1] == 168 { return true; }
            // 127/8 loopback
            if octets[0] == 127 { return true; }
            // 169.254/16 link-local
            if octets[0] == 169 && octets[1] == 254 { return true; }
            // 0/8 wildcard
            if octets[0] == 0 { return true; }
            false
        }
        IpAddr::V6(v6) => {
            // ::1 loopback
            if v6.is_loopback() { return true; }
            let segs = v6.segments();
            // fc00::/7 ULA  — first 7 bits = 1111110
            if (segs[0] & 0xfe00) == 0xfc00 { return true; }
            // fe80::/10 link-local — first 10 bits = 1111111010
            if (segs[0] & 0xffc0) == 0xfe80 { return true; }
            // ::ffff:a.b.c.d — IPv4-mapped IPv6; re-check the V4 part.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_private_ip(IpAddr::V4(v4));
            }
            false
        }
    }
}

/// Resolve `host:port` and return only non-private SocketAddrs. Error if
/// resolution fails OR every IP is private/loopback/link-local.
pub(crate) async fn resolve_public(
    host: String,
    port: u16,
) -> Result<Vec<SocketAddr>, String> {
    let resolved = tokio::task::spawn_blocking(move || {
        (host.as_str(), port).to_socket_addrs().map(|it| it.collect::<Vec<_>>())
    })
    .await
    .map_err(|e| format!("dns join error: {e}"))?
    .map_err(|e| format!("dns lookup failed: {e}"))?;
    let public: Vec<_> = resolved.into_iter().filter(|sa| !is_private_ip(sa.ip())).collect();
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

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr { s.parse().unwrap() }

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

    #[test]
    fn ipv4_mapped_ipv6_rechecks() {
        // ::ffff:127.0.0.1 → loopback when unmapped
        assert!(is_private_ip(ip("::ffff:127.0.0.1")));
        // ::ffff:8.8.8.8 → public when unmapped
        assert!(!is_private_ip(ip("::ffff:8.8.8.8")));
    }
}
