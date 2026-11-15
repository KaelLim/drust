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
/// - the chain is every `X-Forwarded-For` field line, concatenated in order
///   (a single-line header — every shipped proxy — is unchanged by this).
/// - header absent, or any line not visible ASCII: the peer, no warning.
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
    // EVERY field line, in order: HTTP lets a list header arrive as several
    // lines (RFC 9110 §5.3, equivalent to one comma-joined value), and some
    // appending proxies (HAProxy `option forwardfor`) add their entry as a NEW
    // line. `get` would return only the first — the line the client sent —
    // and the right-indexing below would then pick a client-chosen value.
    let mut parts: Vec<&str> = Vec::new();
    let mut any = false;
    for line in headers.get_all("x-forwarded-for") {
        let Ok(s) = line.to_str() else {
            return fallback;
        };
        any = true;
        parts.extend(s.split(',').map(str::trim).filter(|s| !s.is_empty()));
    }
    if !any {
        return fallback;
    }
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

/// The immediate TCP peer: the `ConnectInfo<SocketAddr>` the server attaches
/// (`main` serves with `into_make_service_with_connect_info`), else
/// `127.0.0.1:0` — `Router::oneshot` in tests, or any server built without
/// connect-info. On bare-metal every request comes from the host Caddy over
/// loopback, so the real peer equals that literal.
pub fn peer_addr(ext: &axum::http::Extensions) -> SocketAddr {
    ext.get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0)
        .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 0)))
}

/// Infallible extractor for the per-IP rate limiters:
/// `client_ip(&parts.headers, peer_addr(&parts.extensions))`. Every handler
/// that keys on the caller's address takes this rather than deriving it by
/// hand — a source pin below enumerates the consumers.
#[derive(Debug, Clone, Copy)]
pub struct ClientIp(pub IpAddr);

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for ClientIp {
    type Rejection = std::convert::Infallible;
    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(ClientIp(client_ip(
            &parts.headers,
            peer_addr(&parts.extensions),
        )))
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

    /// Two field lines, client-sent first, proxy-appended second (HAProxy
    /// `option forwardfor` shape). The chain is their concatenation, so the
    /// client's own line cannot be what right-indexing lands on.
    fn two_lines(first: &[u8], second: &[u8]) -> HeaderMap {
        let mut m = HeaderMap::new();
        m.append(
            "x-forwarded-for",
            axum::http::HeaderValue::from_bytes(first).unwrap(),
        );
        m.append(
            "x-forwarded-for",
            axum::http::HeaderValue::from_bytes(second).unwrap(),
        );
        m
    }

    #[test]
    fn multiple_field_lines_are_one_chain() {
        let m = two_lines(b"198.51.100.7", b"203.0.113.10");
        assert_eq!(client_ip_with(&m, doc_peer(), 1), ip("203.0.113.10"));
        assert_eq!(client_ip_with(&m, doc_peer(), 2), ip("198.51.100.7"));
        // A comma list in the client's line still cannot move the n=1 key.
        let m = two_lines(b"9.9.9.9, 8.8.8.8", b"203.0.113.10");
        assert_eq!(client_ip_with(&m, doc_peer(), 1), ip("203.0.113.10"));
        assert_eq!(client_ip_with(&m, doc_peer(), 2), ip("8.8.8.8"));
        // Short across both lines: the peer.
        let m = two_lines(b"198.51.100.7", b"203.0.113.10");
        assert_eq!(client_ip_with(&m, doc_peer(), 3), ip("192.0.2.50"));
    }

    #[test]
    fn any_non_ascii_field_line_returns_peer() {
        for m in [
            two_lines(b"\xff", b"203.0.113.10"),
            two_lines(b"198.51.100.7", b"203.0.113.10, \xff"),
        ] {
            for n in [1u8, 2] {
                assert_eq!(client_ip_with(&m, doc_peer(), n), ip("192.0.2.50"), "n={n}");
            }
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
    fn peer_addr_without_connect_info_is_loopback() {
        let ext = axum::http::Extensions::new();
        assert_eq!(peer_addr(&ext), loopback_peer());
    }

    #[test]
    fn peer_addr_reads_connect_info() {
        let mut ext = axum::http::Extensions::new();
        ext.insert(axum::extract::ConnectInfo(doc_peer()));
        assert_eq!(peer_addr(&ext), doc_peer());
    }

    /// Byte index one past the `)` that closes the `(` at `open`, or the end of
    /// the input when unbalanced (the caller then sees the whole tail, which
    /// still has to contain the needle — fail-closed in practice).
    fn balanced_args(code: &str, open: usize) -> &str {
        let b = code.as_bytes();
        let mut depth = 0usize;
        for (k, &c) in b.iter().enumerate().skip(open) {
            match c {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        return &code[open + 1..k];
                    }
                }
                _ => {}
            }
        }
        &code[open + 1..]
    }

    fn is_ident(c: u8) -> bool {
        c.is_ascii_alphanumeric() || c == b'_'
    }

    /// Start offsets of `needle` in `code` not preceded by an identifier byte.
    fn call_sites(code: &str, needle: &str) -> Vec<usize> {
        code.match_indices(needle)
            .map(|(i, _)| i)
            .filter(|&i| i == 0 || !is_ident(code.as_bytes()[i - 1]))
            .collect()
    }

    /// The per-IP limiters are enforced by ENUMERATION: eleven consumers, each
    /// of which used to hand a literal `127.0.0.1:0` to `client_ip` as its
    /// "socket peer". This pins the list so a regressed site — or a twelfth
    /// consumer — fails the suite instead of silently keying every caller on
    /// loopback (or on a client-chosen header position).
    ///
    /// Scans the WHOLE file through `code_only` (comments blanked, so a
    /// commented-out call can neither satisfy nor hide a needle), not
    /// `production_half`, which cuts at the first `#[cfg(test)]` and would
    /// fail open on files that carry one near the top.
    ///
    /// Also, for every file under `src/` but this one: no `client_ip_with(`
    /// call (it takes the peer as a bare argument, so it would escape the
    /// count table), and no string literal naming a client-address header
    /// (`x-forwarded-for`, `x-real-ip`, `forwarded`) — a hand-rolled read.
    /// `set_trusted_proxies(` is pinned to `main.rs` across `src/` AND `tests/`,
    /// since a harness member calling it would re-key every XFF test in its
    /// binary.
    ///
    /// This file is skipped, so `ClientIp` / `peer_addr` going back to a
    /// literal loopback is caught by the behavioural tests instead:
    /// `auth_login::login_without_xff_records_the_connect_info_peer_as_ip_at_login`
    /// and `admin_login_rate_limit::admin_login_rate_limit_keys_on_connect_info_peer_without_xff`.
    #[test]
    fn every_client_ip_consumer_keys_on_the_real_peer() {
        use crate::tenant::rooms::srcpin::{code_only, collect_rs_files};
        use std::path::Path;

        // (file, `client_ip(` calls, `ClientIp(` extractor patterns)
        const CONSUMERS: &[(&str, usize, usize)] = &[
            ("functions/invoke_gate.rs", 1, 0),
            ("tenant/file_caps.rs", 1, 0),
            ("tenant/auth_routes.rs", 0, 3),
            ("tenant/oauth_routes.rs", 0, 2),
            ("mgmt/oauth_login.rs", 0, 1),
            ("mgmt/cli_device.rs", 0, 2),
            ("mgmt/routes.rs", 0, 1),
        ];
        const THIS_FILE: &str = "safety/ip.rs";
        // The spellings of a loopback "peer" a consumer could hand in instead of
        // `peer_addr(…)`. None of them appears anywhere else in src/ today.
        const LOOPBACK_LITERALS: &[&str] = &[
            "[127, 0, 0, 1], 0",
            "127.0.0.1:0",
            "Ipv4Addr::LOCALHOST",
            "Ipv4Addr::new(127,",
        ];
        const HEADER_LITERALS: &[&str] = &["\"x-forwarded-for\"", "\"x-real-ip\"", "\"forwarded\""];

        let root = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src"));
        let mut files = Vec::new();
        collect_rs_files(root, &mut files);
        files.sort();
        assert!(
            files.len() > 100,
            "the tree walk found only {} .rs file(s) under {} — every assertion below \
             would pass vacuously",
            files.len(),
            root.display(),
        );

        let mut offenders: Vec<String> = Vec::new();
        let mut seen = [false; CONSUMERS.len()];
        for path in &files {
            let rel = path
                .strip_prefix(root)
                .expect("collect_rs_files only yields paths under root")
                .to_string_lossy()
                .replace('\\', "/");
            if rel == THIS_FILE {
                continue;
            }
            let raw = std::fs::read_to_string(path)
                .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
            let code = code_only(&raw);

            let calls = call_sites(&code, "client_ip(");
            for &at in &calls {
                let args = balanced_args(&code, at + "client_ip".len());
                if !args.contains("peer_addr(") {
                    offenders.push(format!(
                        "{rel}: `client_ip(` called without `peer_addr(` in its arguments \
                         (args: `{}`) — the fallback must be the real TCP peer",
                        args.split_whitespace().collect::<Vec<_>>().join(" ")
                    ));
                }
            }
            let extractors = call_sites(&code, "ClientIp(").len();

            if code.contains("client_ip") || code.contains("ClientIp") {
                for lit in LOOPBACK_LITERALS.iter().filter(|l| code.contains(*l)) {
                    offenders.push(format!(
                        "{rel}: names client_ip/ClientIp and still builds the literal \
                         `{lit}` peer — use `ClientIp` or `peer_addr`"
                    ));
                }
            }
            if rel != "main.rs" && !call_sites(&code, "set_trusted_proxies(").is_empty() {
                offenders.push(format!(
                    "{rel}: calls `set_trusted_proxies` — only main may set the global"
                ));
            }
            if !call_sites(&code, "client_ip_with(").is_empty() {
                offenders.push(format!(
                    "{rel}: calls `client_ip_with` — take `ClientIp`, or call \
                     `client_ip(…, peer_addr(…))`"
                ));
            }
            let lower = code.to_ascii_lowercase();
            for needle in HEADER_LITERALS {
                if lower.contains(needle) {
                    offenders.push(format!(
                        "{rel}: names the header literal {needle} — derive the client \
                         through `safety::ip::ClientIp`, never a hand-rolled header read"
                    ));
                }
            }

            match CONSUMERS.iter().position(|(f, _, _)| *f == rel) {
                Some(k) => {
                    seen[k] = true;
                    let (_, want_calls, want_ext) = CONSUMERS[k];
                    if calls.len() != want_calls || extractors != want_ext {
                        offenders.push(format!(
                            "{rel}: {} `client_ip(` call(s) and {extractors} `ClientIp(` \
                             extractor(s), pinned {want_calls} and {want_ext}",
                            calls.len()
                        ));
                    }
                }
                None if !calls.is_empty() || extractors != 0 => offenders.push(format!(
                    "{rel}: {} `client_ip(` call(s) and {extractors} `ClientIp(` extractor(s) \
                     outside the pinned consumer table",
                    calls.len()
                )),
                None => {}
            }
        }
        for (k, (f, _, _)) in CONSUMERS.iter().enumerate() {
            if !seen[k] {
                offenders.push(format!("{f}: pinned consumer file not found under src/"));
            }
        }

        // `set_trusted_proxies` from an integration test: every harness member
        // shares its binary's global with the XFF tests.
        let tests_root = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tests"));
        let mut test_files = Vec::new();
        collect_rs_files(tests_root, &mut test_files);
        test_files.sort();
        assert!(
            test_files.len() > 100,
            "the tree walk found only {} .rs file(s) under {} — the tests/ half of the \
             `set_trusted_proxies` pin would pass vacuously",
            test_files.len(),
            tests_root.display(),
        );
        for path in &test_files {
            let raw = std::fs::read_to_string(path)
                .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
            if !call_sites(&code_only(&raw), "set_trusted_proxies(").is_empty() {
                offenders.push(format!(
                    "tests/{}: calls `set_trusted_proxies` — only main may set the global",
                    path.strip_prefix(tests_root)
                        .unwrap_or(path)
                        .to_string_lossy()
                        .replace('\\', "/")
                ));
            }
        }
        assert!(
            offenders.is_empty(),
            "client-IP consumer pin failed — a new client-IP consumer? add it to this \
             table and to the proxy-hops design §4:\n  {}",
            offenders.join("\n  ")
        );
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
