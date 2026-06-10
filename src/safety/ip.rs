use axum::http::HeaderMap;
use std::net::{IpAddr, SocketAddr};

/// Trusted proxy entries appended to X-Forwarded-For to the RIGHT of the real
/// client by the chain `browser → .221 nginx → :8793 Caddy → drust`.
/// EXACTLY ONE entry sits right of the client value: the local Caddy block
/// appends its peer (.221's LAN IP) as the rightmost entry. The .221 nginx hop
/// does NOT add a separate trailing entry — `$proxy_add_x_forwarded_for` makes
/// nginx append its PEER (the real browser), so the client value IS nginx's
/// appended entry, immediately left of Caddy's. Hence the client is the
/// second-from-right: parts[len - 1 - TRUSTED_TRAILING_HOPS] == parts[len - 2].
/// Load-bearing: depends on the documented nginx XFF invariant in services.md
/// ("XFF client-IP invariant"). Adding/removing a proxy hop REQUIRES bumping
/// this constant in the same commit.
const TRUSTED_TRAILING_HOPS: usize = 1;

/// Returns the verified client IP behind the known proxy chain
/// `browser → .221 nginx → :8793 Caddy → drust`.
///
/// The real client is `parts[len - 1 - TRUSTED_TRAILING_HOPS]` == the
/// second-from-right entry of `X-Forwarded-For`: the rightmost entry is the
/// local Caddy hop's peer (.221's LAN IP), and the entry immediately left of it
/// is the browser peer that `.221` nginx appended via
/// `$proxy_add_x_forwarded_for`. Entries to the LEFT of the client position are
/// client-forgeable and are correctly ignored by right-indexing — a client
/// prepending `9.9.9.9, …` cannot shift the picked index.
///
/// Falls back to `socket_addr.ip()` (the immediate TCP peer) in two cases, both
/// loud via `tracing::warn!` so topology drift surfaces instead of silently
/// herding clients onto a shared bucket or leaking a client-chosen value as the
/// key:
///   - chain too SHORT (`len < TRUSTED_TRAILING_HOPS + 1` == `len < 2`): genuine
///     topology breakage or a direct/non-proxied connection;
///   - candidate at the client position is not a parseable `IpAddr`.
///
/// When `X-Forwarded-For` is absent entirely, returns the socket peer with no
/// warn (the expected non-proxied case). A client-supplied or junk value can
/// NEVER become the returned key.
pub fn client_ip(headers: &HeaderMap, socket_addr: SocketAddr) -> IpAddr {
    let fallback = socket_addr.ip();
    let raw = match headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        Some(s) => s,
        None => return fallback,
    };
    let parts: Vec<&str> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();

    // Need at least the client entry + the trusted trailing hop(s). `>=`, not
    // `==`: a legitimate client behind its own proxy produces extra LEFT
    // entries (len > 2), which right-indexing tolerates — they must NOT trigger
    // a fallback, or every such real client gets herded onto the shared
    // socket-peer bucket (the limiter-DoS this finding fixes).
    if parts.len() < TRUSTED_TRAILING_HOPS + 1 {
        tracing::warn!(
            xff_len = parts.len(),
            raw_xff = %raw,
            "client_ip: X-Forwarded-For too short for trusted proxy chain, falling back to socket peer"
        );
        return fallback;
    }

    let candidate = parts[parts.len() - 1 - TRUSTED_TRAILING_HOPS];
    match candidate.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => {
            // Right position but unparseable: never return the raw string,
            // never silently swallow it onto the shared bucket.
            tracing::warn!(
                raw_xff = %raw,
                candidate = %candidate,
                "client_ip: X-Forwarded-For client-position entry unparseable, falling back to socket peer"
            );
            fallback
        }
    }
}
