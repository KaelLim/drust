//! Client-IP derivation for the per-IP rate limiters.
//!
//! `DRUST_TRUSTED_PROXIES` (`N`, default [`DEFAULT_TRUSTED_PROXIES`], range
//! `0..=`[`MAX_TRUSTED_PROXIES`], an out-of-range value refuses to boot) is the
//! number of reverse proxies in front of drust that each APPEND one entry to
//! `X-Forwarded-For`. The client is `parts[len - N]` — the Express
//! `trust proxy = N` convention: count the proxies.
//!
//! Per deployment target:
//!   - **bare-metal** `browser → .221 nginx → :8793 Caddy → drust`: `N = 2`
//!     (the default). nginx's `$proxy_add_x_forwarded_for` appends its PEER
//!     (the real browser), then the local Caddy block appends ITS peer (.221's
//!     LAN IP) as the rightmost entry, so the client is the second-from-right.
//!     Load-bearing: depends on the documented nginx XFF invariant in
//!     services.md ("XFF client-IP invariant"). Adding/removing a proxy hop
//!     REQUIRES setting `DRUST_TRUSTED_PROXIES` in that host's `.env`.
//!   - **Docker Compose**: `N = 1` (`docker-compose.yml`) — the bundled Caddy
//!     rebuilds the header from its TCP peer.
//!   - **the image alone** (`docker run -p`, no proxy): `N = 0` (Dockerfile) —
//!     the header is ignored and the key is the TCP peer.
//!
//! Entries to the LEFT of the client position are client-forgeable and are
//! ignored by right-indexing — a client prepending `9.9.9.9, …` cannot shift
//! the picked index, for any `N`.
//!
//! Every fallback is the immediate TCP peer ([`peer_addr`], read from the
//! `ConnectInfo` the server is built with), never a client-supplied value.
//! A short chain or an unparseable entry at the client position emits a
//! THROTTLED warning (at most one per [`WARN_WINDOW_SECS`] per process, with
//! the header's length and a count of what it suppressed) and never carries
//! the header's value at any log level.

use axum::http::HeaderMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

/// Binary default for `DRUST_TRUSTED_PROXIES`: the bare-metal nginx → Caddy
/// chain. Identical to the pre-knob hardcoded `parts[len - 2]`.
pub const DEFAULT_TRUSTED_PROXIES: u8 = 2;
/// Upper bound accepted by `Config::from_env`; a larger value refuses to boot.
pub const MAX_TRUSTED_PROXIES: u8 = 8;
/// At most one fallback warning per this many seconds, per process.
pub const WARN_WINDOW_SECS: u64 = 300;

static TRUSTED_PROXIES: OnceLock<u8> = OnceLock::new();

/// Set the process-global proxy count once at startup (first write wins, the
/// `base_path::set` pattern). Only `main` may call this — a source pin keeps
/// it that way, so no library or handler code can move the key under the
/// suite, which runs on the default.
pub fn set_trusted_proxies(n: u8) {
    let _ = TRUSTED_PROXIES.set(n);
}

/// The configured proxy count, or [`DEFAULT_TRUSTED_PROXIES`] when unset.
pub fn trusted_proxies() -> u8 {
    TRUSTED_PROXIES
        .get()
        .copied()
        .unwrap_or(DEFAULT_TRUSTED_PROXIES)
}

/// Returns the client IP: `client_ip_with(headers, peer, trusted_proxies())`.
pub fn client_ip(headers: &HeaderMap, peer: SocketAddr) -> IpAddr {
    client_ip_with(headers, peer, trusted_proxies())
}

/// Pure derivation; all logic lives here so unit tests never touch the global.
///
/// - `n == 0`: the TCP peer; `X-Forwarded-For` is never read.
/// - header absent or not visible ASCII: the peer, no warning.
/// - fewer than `n` entries: the peer, throttled warning (`reason="short"`).
/// - `parts[len - n]` not an `IpAddr`: the peer, throttled warning
///   (`reason="unparseable"`).
/// - otherwise `parts[len - n]` as parsed (not canonicalised, so the
///   bare-metal keys stay byte-identical).
///
/// The peer is canonicalised (`::ffff:a.b.c.d` → `a.b.c.d`) so a dual-stack
/// bind does not split one client across two keys.
pub fn client_ip_with(headers: &HeaderMap, peer: SocketAddr, n: u8) -> IpAddr {
    let fallback = peer.ip().to_canonical();
    if n == 0 {
        return fallback;
    }
    let raw = match headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        Some(s) => s,
        None => return fallback,
    };
    let parts: Vec<&str> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    let n = usize::from(n);

    // `<`, not `!=`: a legitimate client behind its own proxy produces extra
    // LEFT entries, which right-indexing tolerates — they must NOT trigger a
    // fallback, or every such client is herded onto the peer's bucket.
    if parts.len() < n {
        warn_throttled(FallbackReason::Short, parts.len());
        return fallback;
    }

    match parts[parts.len() - n].parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => {
            // Right position but unparseable: never return the raw string,
            // never log it either.
            warn_throttled(FallbackReason::Unparseable, parts.len());
            fallback
        }
    }
}

#[derive(Clone, Copy)]
enum FallbackReason {
    Short,
    Unparseable,
}

/// Last emit time in seconds since process start, offset by 1 so `0` means
/// "never emitted" (the first event after boot always emits).
static LAST_WARN_SECS: AtomicU64 = AtomicU64::new(0);
/// Fallbacks swallowed since the last emitted warning.
static SUPPRESSED: AtomicU64 = AtomicU64::new(0);
static PROCESS_START: OnceLock<std::time::Instant> = OnceLock::new();

/// Monotonic seconds since the first call, plus 1 (never 0).
fn monotonic_secs() -> u64 {
    PROCESS_START
        .get_or_init(std::time::Instant::now)
        .elapsed()
        .as_secs()
        .saturating_add(1)
}

/// True when a warning may be emitted now: never emitted before, or the last
/// one is at least `window` seconds old.
fn throttle_decide(now_secs: u64, last_secs: u64, window: u64) -> bool {
    last_secs == 0 || now_secs >= last_secs.saturating_add(window)
}

/// One shared slot for both reasons. No header content in any field.
fn warn_throttled(reason: FallbackReason, xff_len: usize) {
    let now = monotonic_secs();
    let last = LAST_WARN_SECS.load(Ordering::Relaxed);
    let emit = throttle_decide(now, last, WARN_WINDOW_SECS)
        && LAST_WARN_SECS
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok();
    if !emit {
        SUPPRESSED.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let suppressed = SUPPRESSED.swap(0, Ordering::Relaxed);
    let trusted_proxies = trusted_proxies();
    match reason {
        FallbackReason::Short => tracing::warn!(
            reason = "short",
            xff_len,
            trusted_proxies,
            suppressed,
            "client_ip: X-Forwarded-For too short for DRUST_TRUSTED_PROXIES, falling back to the TCP peer"
        ),
        FallbackReason::Unparseable => tracing::warn!(
            reason = "unparseable",
            xff_len,
            trusted_proxies,
            suppressed,
            "client_ip: X-Forwarded-For entry at DRUST_TRUSTED_PROXIES is not an IP address, falling back to the TCP peer"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(xff: Option<&str>) -> HeaderMap {
        let mut m = HeaderMap::new();
        if let Some(v) = xff {
            m.insert("x-forwarded-for", v.parse().unwrap());
        }
        m
    }
    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }
    fn loopback_peer() -> SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }
    /// A non-loopback documentation address, so "returned the peer" is a
    /// meaningful assertion rather than a coincidence with the old literal.
    fn doc_peer() -> SocketAddr {
        "192.0.2.50:41000".parse().unwrap()
    }

    #[test]
    fn n2_matches_legacy_constant() {
        // Every input of tests/auth_xff.rs, with the result the hardcoded
        // `parts[len - 1 - 1]` gave. Pins bare-metal byte-identity.
        let cases: &[(Option<&str>, &str)] = &[
            (None, "127.0.0.1"),
            (Some("203.0.113.10"), "127.0.0.1"),
            (Some("203.0.113.10, 192.0.2.221"), "203.0.113.10"),
            (Some("1.1.1.1, 203.0.113.10, 192.0.2.221"), "203.0.113.10"),
            (
                Some("9.9.9.9, 8.8.8.8, 203.0.113.10, 192.0.2.221"),
                "203.0.113.10",
            ),
            (Some("2001:db8::1, 192.0.2.221"), "2001:db8::1"),
            (Some("not-an-ip, 192.0.2.221"), "127.0.0.1"),
            (Some("9.9.9.9"), "127.0.0.1"),
        ];
        for (xff, want) in cases {
            assert_eq!(
                client_ip_with(&h(*xff), loopback_peer(), 2),
                ip(want),
                "xff={xff:?}"
            );
        }
    }

    #[test]
    fn n1_takes_rightmost_entry() {
        assert_eq!(
            client_ip_with(&h(Some("203.0.113.10")), doc_peer(), 1),
            ip("203.0.113.10")
        );
    }

    #[test]
    fn n1_left_prepended_entries_cannot_shift_key() {
        assert_eq!(
            client_ip_with(&h(Some("9.9.9.9, 8.8.8.8, 203.0.113.10")), doc_peer(), 1),
            ip("203.0.113.10")
        );
    }

    #[test]
    fn n0_ignores_xff_entirely() {
        for xff in ["203.0.113.10", "9.9.9.9, 203.0.113.10, 198.51.100.1"] {
            assert_eq!(
                client_ip_with(&h(Some(xff)), doc_peer(), 0),
                ip("192.0.2.50"),
                "xff={xff}"
            );
        }
    }

    #[test]
    fn absent_or_non_ascii_header_returns_peer_for_every_n() {
        let mut non_ascii = HeaderMap::new();
        non_ascii.insert(
            "x-forwarded-for",
            axum::http::HeaderValue::from_bytes(b"203.0.113.10, \xff").unwrap(),
        );
        for n in [0u8, 1, 2, MAX_TRUSTED_PROXIES] {
            assert_eq!(client_ip_with(&h(None), doc_peer(), n), ip("192.0.2.50"));
            assert_eq!(
                client_ip_with(&non_ascii, doc_peer(), n),
                ip("192.0.2.50"),
                "n={n}"
            );
        }
    }

    #[test]
    fn short_chain_returns_peer() {
        assert_eq!(
            client_ip_with(&h(Some("203.0.113.10, 198.51.100.1")), doc_peer(), 3),
            ip("192.0.2.50")
        );
    }

    #[test]
    fn unparseable_candidate_returns_peer_never_raw() {
        assert_eq!(
            client_ip_with(&h(Some("203.0.113.10, not-an-ip")), doc_peer(), 1),
            ip("192.0.2.50")
        );
    }

    #[test]
    fn ipv4_mapped_peer_is_canonicalised() {
        let peer: SocketAddr = "[::ffff:192.0.2.7]:1".parse().unwrap();
        assert_eq!(client_ip_with(&h(None), peer, 0), ip("192.0.2.7"));
    }

    #[test]
    fn throttle_decide_once_per_window() {
        // Never emitted: always emit.
        assert!(throttle_decide(5, 0, 300));
        // Inside the window: suppressed.
        assert!(!throttle_decide(10, 10, 300));
        assert!(!throttle_decide(309, 10, 300));
        // At and after the window: emit.
        assert!(throttle_decide(310, 10, 300));
        assert!(throttle_decide(1_000, 10, 300));
    }
}
