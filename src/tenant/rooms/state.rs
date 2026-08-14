//! v1.31 rooms config: env-driven knobs threaded through `TenantStack`.
//!
//! - `DRUST_BROADCAST_PUBLISH_QPS`         — per-tenant token bucket (default 100)
//! - `DRUST_BROADCAST_PAYLOAD_MAX_BYTES`   — per-message cap (default 65536)
//! - `DRUST_BROADCAST_ROOM_SUBSCRIBER_MAX` — WS subscribe gate (default 1000)
//! - `DRUST_BROADCAST_CLIENT_ROOM_MAX`     — WS per-conn rooms cap (default 100)
//! - `DRUST_BROADCAST_SWEEPER_INTERVAL_SECS` — empty-channel GC (default 300; 0 disables)
//! - `DRUST_BROADCAST_KEEPALIVE_SECS`       — WS keepalive tick (default 30,
//!   **clamped into `1..=300`**). Unlike the sweeper knob above it, this one is
//!   not purely a chattiness preference: the keepalive branch is one of the two
//!   #955 epoch checkpoints, so **for an IDLE socket this value IS the
//!   revocation latency** — the time a token-revoked / evicted holder's socket
//!   can still sit open after `evict_tenant`. Both ends are therefore clamped
//!   at the source:
//!   - 0 means 1, never "disabled" (a disabled tick would strand an evicted
//!     idle socket forever, and `tokio::time::interval` panics on a zero period);
//!   - anything above 300 means 300, because tokio does NOT reject an absurd
//!     period — `interval.rs` computes the next deadline with
//!     `checked_add(period).unwrap_or_else(Instant::far_future)`, so a huge
//!     value silently becomes "never ticks again", i.e. exactly the
//!     documented-impossible disabled state, reached through the knob that
//!     documents it as impossible. The realistic case is worse than the exotic
//!     one: `3600` (a plausible "reduce WS chatter" setting) would stretch idle
//!     revocation from 30 s to an hour with nothing surfacing the change.
//!
//!   Because that clamp overrules a deliberate setting, `from_env` **says so**:
//!   a clamped value, or a value that is set but unparseable, emits a
//!   `tracing::warn!` naming the raw value and what is actually running
//!   ([`KeepaliveNotice`]). Silence on a knob that IS a security bound is the
//!   `x-drust-boot-degraded` failure shape — a best-effort override that
//!   quietly did not take. The other knobs in this list stay on the silent
//!   parse-or-default path on purpose; none of them bounds a revocation.

use super::policy::PublishBucket;
use std::sync::Arc;

/// #955 — floor for [`RoomsConfig::keepalive_secs`]. 0 must mean "as fast as
/// allowed", never "keepalive disabled"; see the module doc.
pub const KEEPALIVE_MIN_SECS: u64 = 1;

/// #955 — ceiling for [`RoomsConfig::keepalive_secs`]. This is a **security
/// bound, not a chattiness preference**: it is the worst-case revocation
/// latency of an evicted idle WS socket. Raising it here raises that latency
/// for every deployment.
pub const KEEPALIVE_MAX_SECS: u64 = 300;

/// #955 — the env var backing [`RoomsConfig::keepalive_secs`]. Named once
/// so the resolver, the log line and the tests cannot drift apart.
pub const KEEPALIVE_VAR: &str = "DRUST_BROADCAST_KEEPALIVE_SECS";

/// #955 — the single place the keepalive bounds are applied. Pure and
/// env-free so it can be tested without touching process-global state
/// (the env tests below cover the variable name / default / garbage path).
pub fn clamp_keepalive_secs(raw: u64) -> u64 {
    raw.clamp(KEEPALIVE_MIN_SECS, KEEPALIVE_MAX_SECS)
}

/// #955 (quality review round 3) — what [`resolve_keepalive_secs`] had to
/// do to the operator's raw value, returned instead of logged so the
/// decision stays a pure function (`from_env` is the only thing that logs).
///
/// The motivation is that BOTH ways of not honouring this knob were
/// invisible: the clamp silently turned a deliberate `3600` into `300` and
/// a deliberate `0` (meaning "off") into a 1 Hz Ping on every open socket,
/// and `env_or`'s parse-or-default made a typo indistinguishable from an
/// unset variable. This knob is the one in `RoomsConfig` whose value is a
/// **security bound** — the revocation latency of an evicted IDLE WS socket
/// — so a silently-ignored override is the same failure shape that
/// `x-drust-boot-degraded` exists for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeepaliveNotice {
    /// Unset, empty (how compose/systemd spell "unset"), or a value inside
    /// `KEEPALIVE_MIN_SECS..=KEEPALIVE_MAX_SECS` that was honoured verbatim.
    Silent,
    /// Parsed, but outside the bounds — `applied` is what the process runs.
    Clamped { raw: u64, applied: u64 },
    /// Set to something that is not a `u64` — folded to the default, which
    /// is byte-identical to the unset outcome, so only a log can tell them
    /// apart.
    Unparseable { raw: String, applied: u64 },
}

impl KeepaliveNotice {
    /// Emit the operator-facing line. Deliberately `warn` and not `info`:
    /// the deployment is running a revocation latency its config does not
    /// state.
    pub fn warn(&self) {
        match self {
            Self::Silent => {}
            Self::Clamped { raw, applied } => tracing::warn!(
                var = KEEPALIVE_VAR,
                requested = raw,
                applied = applied,
                min = KEEPALIVE_MIN_SECS,
                max = KEEPALIVE_MAX_SECS,
                "{KEEPALIVE_VAR}={raw} is outside {KEEPALIVE_MIN_SECS}..={KEEPALIVE_MAX_SECS} \
                 and was clamped to {applied}s — this knob is the revocation latency of an \
                 evicted IDLE WS socket, not a chattiness preference",
            ),
            Self::Unparseable { raw, applied } => tracing::warn!(
                var = KEEPALIVE_VAR,
                requested = %raw,
                applied = applied,
                "{KEEPALIVE_VAR}={raw:?} is not a whole number of seconds; falling back to \
                 {applied}s (the default). Set a value in \
                 {KEEPALIVE_MIN_SECS}..={KEEPALIVE_MAX_SECS}",
            ),
        }
    }
}

/// #955 — resolve the keepalive knob from an already-read raw value.
/// Returns the seconds the process will use **and** what had to be done to
/// get there, so the caller can tell the operator. Pure: no env, no log.
///
/// Parsing is deliberately unchanged from `env_or` (no trimming, so `" 5 "`
/// still falls back to the default) — the fix here is visibility, not new
/// leniency. An empty/whitespace-only value is treated as *unset* for
/// NOTICE purposes only; it already resolved to the default, and warning
/// about it would fire on every boot of a compose deployment that passes an
/// unset variable through.
pub fn resolve_keepalive_secs(raw: Option<String>) -> (u64, KeepaliveNotice) {
    const DEFAULT: u64 = 30;
    match raw {
        None => (DEFAULT, KeepaliveNotice::Silent),
        Some(s) if s.trim().is_empty() => (DEFAULT, KeepaliveNotice::Silent),
        Some(s) => match s.parse::<u64>() {
            Ok(n) => {
                let applied = clamp_keepalive_secs(n);
                if applied == n {
                    (applied, KeepaliveNotice::Silent)
                } else {
                    (applied, KeepaliveNotice::Clamped { raw: n, applied })
                }
            }
            Err(_) => (
                DEFAULT,
                KeepaliveNotice::Unparseable {
                    raw: s,
                    applied: DEFAULT,
                },
            ),
        },
    }
}

#[derive(Clone, Debug)]
pub struct RoomsConfig {
    pub publish_qps: i64,
    pub payload_max_bytes: usize,
    pub room_subscriber_max: usize,
    pub client_room_max: usize,
    pub sweeper_interval_secs: u64,
    /// #955 — WS keepalive Ping period, and the same number is the upper
    /// bound on how long an IDLE socket survives a tenant eviction: the
    /// keepalive branch is one of the two epoch checkpoints.
    /// **`from_env` guarantees `1..=300`** ([`clamp_keepalive_secs`]) —
    /// the floor because a disabled tick would strand evicted idle
    /// sockets forever, the ceiling because this knob doubles as a
    /// revocation-latency bound. Other constructors (test literals) can
    /// still hand out any `u64`, which is why the consumer keeps a
    /// `.max(1)`; see `ws::keepalive_interval`.
    pub keepalive_secs: u64,
}

impl RoomsConfig {
    pub fn from_env() -> Self {
        // Parse-or-default. Named for what it does: it validates NOTHING
        // (the old name `pos` implied a positivity check that was never
        // there), so any knob with a forbidden value must clamp at its
        // own call site.
        fn env_or<T: std::str::FromStr>(name: &str, default: T) -> T {
            std::env::var(name)
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(default)
        }
        // #955 — the keepalive knob deliberately does NOT go through
        // `env_or`. It clamps BOTH ends at the SOURCE, so the FIELD (not
        // one lucky reader) carries the guarantee — the ceiling is not
        // tidiness: this value is the revocation latency of an evicted idle
        // socket, and tokio turns an absurd period into "never ticks again"
        // rather than rejecting it (see the module doc). And because that
        // clamp can overrule a deliberate operator setting, the resolver
        // hands back WHAT it had to do and we say so out loud; `env_or`
        // folds both a clamp and a typo into silence.
        let (keepalive_secs, keepalive_notice) =
            resolve_keepalive_secs(std::env::var(KEEPALIVE_VAR).ok());
        keepalive_notice.warn();

        Self {
            publish_qps: env_or("DRUST_BROADCAST_PUBLISH_QPS", 100i64),
            payload_max_bytes: env_or("DRUST_BROADCAST_PAYLOAD_MAX_BYTES", 65_536usize),
            room_subscriber_max: env_or("DRUST_BROADCAST_ROOM_SUBSCRIBER_MAX", 1_000usize),
            client_room_max: env_or("DRUST_BROADCAST_CLIENT_ROOM_MAX", 100usize),
            sweeper_interval_secs: env_or("DRUST_BROADCAST_SWEEPER_INTERVAL_SECS", 300u64),
            keepalive_secs,
        }
    }

    /// Permissive defaults for tests — no rate-limit / payload cap surprises.
    #[cfg(any(test, debug_assertions))]
    pub fn test_defaults() -> Self {
        Self {
            publish_qps: 10_000,
            payload_max_bytes: 1_048_576,
            room_subscriber_max: 10_000,
            client_room_max: 1_000,
            sweeper_interval_secs: 0,
            // MUST stay 30: a 1 s tick would make every existing WS
            // test's recv loop eat extra Ping frames. The idle-close
            // test overrides this field itself.
            keepalive_secs: 30,
        }
    }

    /// Materialize a `PublishBucket` matching this config's QPS.
    pub fn bucket(&self) -> Arc<PublishBucket> {
        Arc::new(PublishBucket::new(self.publish_qps))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Set (or unset) the keepalive env var, read it back through
    /// `from_env`, then RESTORE whatever the process started with — an
    /// operator who runs the suite with this exported must not have it
    /// clobbered for the rest of the binary.
    ///
    /// Callers MUST carry `#[serial_test::serial]`. `cargo test --lib`
    /// builds ONE binary running every test in parallel, and it contains
    /// two other env-mutating domains (`crate::config::tests`,
    /// `crate::oauth::config::tests`). A module-private `Mutex` would
    /// serialise these tests against each other and against nothing else,
    /// which is no mutual exclusion at all; the default `#[serial]` key is
    /// the only mechanism here that spans modules, and all three domains
    /// now use it.
    fn keepalive_from_env(value: Option<&str>) -> u64 {
        let prev = std::env::var(KEEPALIVE_VAR).ok();
        // SAFETY: `set_var`/`remove_var` are unsound while any other thread
        // may be inside `getenv`. The real precondition is therefore "no
        // concurrent environment access", not "nobody else reads THIS
        // variable". `#[serial_test::serial]` on every caller excludes every
        // other env-mutating test in this binary, and the window below holds
        // no `.await` and calls nothing but `from_env`, keeping it as narrow
        // as a process-global mutation can be.
        unsafe {
            match value {
                Some(v) => std::env::set_var(KEEPALIVE_VAR, v),
                None => std::env::remove_var(KEEPALIVE_VAR),
            }
        }
        let secs = RoomsConfig::from_env().keepalive_secs;
        unsafe {
            match prev {
                Some(v) => std::env::set_var(KEEPALIVE_VAR, v),
                None => std::env::remove_var(KEEPALIVE_VAR),
            }
        }
        secs
    }

    /// #955 — pure bounds check, no process-global state, so it runs in
    /// parallel with everything and pins the clamp itself.
    ///
    /// What the LOWER clamp does and does not buy, stated honestly: 0 and 1
    /// both yield a 1 s tick, so clamping at the source does NOT avoid the
    /// 1 Hz Ping flood an operator asked for by typing 0 — it only decides
    /// WHERE the 1 comes from. The benefit is that the FIELD, not one lucky
    /// consumer, is guaranteed ≥ 1: no present or future reader of
    /// `RoomsConfig` can observe 0, and no `from_env` config can panic
    /// `tokio::time::interval`. Operators must read 0 as "1 s", never "off";
    /// the module doc says so beside the sweeper knob, where "0 disables" IS
    /// literal.
    ///
    /// The UPPER clamp is the load-bearing one: the keepalive tick is one of
    /// the two epoch checkpoints, so this number is the revocation latency of
    /// an evicted IDLE socket. tokio does not reject a huge period (it folds
    /// into `Instant::far_future` and never fires again), so without a
    /// ceiling the "keepalive cannot be disabled" promise is reachable-false
    /// through the knob itself.
    #[test]
    fn clamp_keepalive_secs_bounds_both_ends() {
        assert_eq!(clamp_keepalive_secs(0), 1, "0 means 1 s, never disabled");
        assert_eq!(clamp_keepalive_secs(1), 1);
        assert_eq!(clamp_keepalive_secs(30), 30, "default must pass through");
        assert_eq!(clamp_keepalive_secs(300), 300, "ceiling is inclusive");
        assert_eq!(
            clamp_keepalive_secs(3_600),
            300,
            "a plausible 'reduce WS chatter' value must not silently stretch \
             idle-socket revocation latency to an hour",
        );
        assert_eq!(
            clamp_keepalive_secs(u64::MAX),
            300,
            "tokio folds an absurd period into far_future (never ticks again) \
             instead of rejecting it — that is the disabled state the module \
             doc promises is unreachable",
        );
    }

    /// #955 (quality review round 3) — an operator who SETS this knob and
    /// does not get what they asked for must be told. Two silent folds
    /// existed: the clamp (`3600` → `300`, or `0` → `1`, i.e. a 1 Hz Ping
    /// to every open socket for someone who meant "off") and `env_or`'s
    /// parse failure (a typo is indistinguishable from unset). This knob is
    /// the one in this struct whose value is a SECURITY bound — the
    /// revocation latency of an evicted IDLE socket — so silence here is
    /// the `x-drust-boot-degraded` failure shape: a best-effort override
    /// that quietly did not take.
    ///
    /// The decision is returned as a value rather than logged inside the
    /// resolver, so this test needs no tracing subscriber and no
    /// process-global env; `from_env` is the only thing that logs.
    #[test]
    fn keepalive_notice_names_every_silent_override() {
        // Unset, and values that are honored verbatim: nothing to say.
        assert_eq!(resolve_keepalive_secs(None), (30, KeepaliveNotice::Silent));
        assert_eq!(
            resolve_keepalive_secs(Some("30".into())),
            (30, KeepaliveNotice::Silent)
        );
        assert_eq!(
            resolve_keepalive_secs(Some("5".into())),
            (5, KeepaliveNotice::Silent)
        );
        assert_eq!(
            resolve_keepalive_secs(Some("300".into())),
            (300, KeepaliveNotice::Silent),
            "the ceiling itself is honored, not clamped"
        );
        // Clamped in BOTH directions — the operator asked for something the
        // security bound refuses, and the refusal must be visible.
        assert_eq!(
            resolve_keepalive_secs(Some("3600".into())),
            (
                300,
                KeepaliveNotice::Clamped {
                    raw: 3600,
                    applied: 300
                }
            ),
            "a plausible 'reduce WS chatter' value must warn, not silently apply 300"
        );
        assert_eq!(
            resolve_keepalive_secs(Some("0".into())),
            (1, KeepaliveNotice::Clamped { raw: 0, applied: 1 }),
            "0 means 1 s, never 'disabled' — an operator who meant 'off' gets a 1 Hz Ping \
             and must be told"
        );
        // Set but unparseable: same resolved value as unset, so ONLY a log
        // line can distinguish a typo from an absent variable.
        assert_eq!(
            resolve_keepalive_secs(Some("banana".into())),
            (
                30,
                KeepaliveNotice::Unparseable {
                    raw: "banana".into(),
                    applied: 30
                }
            )
        );
        assert_eq!(
            resolve_keepalive_secs(Some("-1".into())),
            (
                30,
                KeepaliveNotice::Unparseable {
                    raw: "-1".into(),
                    applied: 30
                }
            ),
            "a negative value must fall back to the default AND warn, never wrap to 0"
        );
        assert_eq!(
            resolve_keepalive_secs(Some(" 5 ".into())),
            (
                30,
                KeepaliveNotice::Unparseable {
                    raw: " 5 ".into(),
                    applied: 30
                }
            ),
            "padded values are NOT parsed (unchanged behaviour) — but the operator who \
             wrote 5 and got 30 now hears about it"
        );
        // An EMPTY value is how compose/systemd spell "unset"; resolving it
        // to the default is not an override, so it must stay quiet.
        assert_eq!(
            resolve_keepalive_secs(Some("".into())),
            (30, KeepaliveNotice::Silent)
        );
        assert_eq!(
            resolve_keepalive_secs(Some("   ".into())),
            (30, KeepaliveNotice::Silent)
        );
    }

    /// #955 — env wiring: the variable name, the default, and the fact that
    /// `from_env` routes through the clamp in both directions.
    #[test]
    #[serial_test::serial] // mutates process-global DRUST_BROADCAST_* env vars
    fn keepalive_from_env_is_clamped_both_ends() {
        assert_eq!(keepalive_from_env(Some("0")), 1);
        assert_eq!(keepalive_from_env(Some("100000")), 300);
    }

    /// The clamp must not eat the default or a legitimate override, and
    /// an unparseable value must fall back to the default, never to 0.
    #[test]
    #[serial_test::serial] // mutates process-global DRUST_BROADCAST_* env vars
    fn keepalive_default_override_and_garbage() {
        assert_eq!(keepalive_from_env(None), 30);
        assert_eq!(keepalive_from_env(Some("5")), 5);
        assert_eq!(keepalive_from_env(Some("banana")), 30);
    }
}
