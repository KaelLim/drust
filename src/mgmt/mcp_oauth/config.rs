//! `McpOauthConfig`: whether the MCP OAuth authorization server is on, the public
//! origin it names itself by, and its four lifetime knobs.
//!
//! Read once at boot from `DRUST_MCP`, `DRUST_PUBLIC_URL` and the four
//! `DRUST_MCP_OAUTH_*` variables. An unusable value never aborts boot: it leaves
//! MCP off and says why in the boot log (`main.rs` picks the level). The raw
//! `DRUST_PUBLIC_URL` is never logged — it may carry userinfo — and is normalized
//! here for MCP only; the global `public_url` the admin/tenant OAuth providers
//! use is not rewritten.

use rand::RngCore;
use url::{Host, Url};

pub const MODE_VAR: &str = "DRUST_MCP";
pub const PUBLIC_URL_VAR: &str = "DRUST_PUBLIC_URL";
pub const ACCESS_TTL_VAR: &str = "DRUST_MCP_OAUTH_ACCESS_TTL_SECS";
pub const REFRESH_GRACE_VAR: &str = "DRUST_MCP_OAUTH_REFRESH_GRACE_SECS";
pub const IDLE_DAYS_VAR: &str = "DRUST_MCP_OAUTH_IDLE_DAYS";
pub const MAX_DAYS_VAR: &str = "DRUST_MCP_OAUTH_MAX_DAYS";

// (var, default, min, max) — the max of IDLE is applied again against max_days.
const ACCESS_TTL: Knob = Knob {
    var: ACCESS_TTL_VAR,
    default: 3600,
    min: 900,
    max: 86_400,
};
const GRACE: Knob = Knob {
    var: REFRESH_GRACE_VAR,
    default: 60,
    min: 0,
    max: 300,
};
const IDLE: Knob = Knob {
    var: IDLE_DAYS_VAR,
    default: 30,
    min: 1,
    max: 365,
};
const MAX: Knob = Knob {
    var: MAX_DAYS_VAR,
    default: 90,
    min: 1,
    max: 365,
};

struct Knob {
    var: &'static str,
    default: u32,
    min: u32,
    max: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum McpMode {
    Auto,
    On,
    Off,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DisabledReason {
    ModeOff,
    /// `auto` (or unset) without an https DRUST_PUBLIC_URL on a non-loopback host.
    AutoNeedsHttpsPublicUrl,
    /// `auto` (or unset) while DRUST_BASE_PATH is set: the root discovery
    /// paths need proxy routes first, so a path-mounted host must opt in with `on`.
    AutoPathMounted,
    /// Unknown `DRUST_MCP` value (at most 32 chars of it) -> off + error log.
    InvalidMode(String),
    PublicUrlMissing,
    /// Unparsable, non-http(s), userinfo, path, query, fragment or no host.
    PublicUrlInvalid(&'static str),
    /// `http://` on a non-loopback host.
    InsecureHttp,
    /// `DRUST_BASE_PATH` outside `[A-Za-z0-9._~/-]`, or with an empty, `.` or
    /// `..` segment.
    BasePathInvalid,
}

/// The six raw inputs, so `from_parts` is a pure function of them.
#[derive(Default)]
pub struct McpOauthEnv<'a> {
    pub mode: Option<&'a str>,               // DRUST_MCP
    pub public_url: Option<&'a str>, // DRUST_PUBLIC_URL (raw; global public_url is NOT rewritten)
    pub access_ttl_secs: Option<&'a str>, // DRUST_MCP_OAUTH_ACCESS_TTL_SECS   default 3600, clamp 900..=86400
    pub refresh_grace_secs: Option<&'a str>, // DRUST_MCP_OAUTH_REFRESH_GRACE_SECS default 60, clamp 0..=300
    pub idle_days: Option<&'a str>, // DRUST_MCP_OAUTH_IDLE_DAYS          default 30, clamp 1..=max_days
    pub max_days: Option<&'a str>,  // DRUST_MCP_OAUTH_MAX_DAYS           default 90, clamp 1..=365
}

/// NOT Debug / Clone / PartialEq: it holds two per-process HMAC keys. Shared as
/// `Arc<McpOauthConfig>` in `MgmtState`.
pub struct McpOauthConfig {
    mode: McpMode,
    disabled: Option<DisabledReason>,
    origin: String, // normalized "scheme://host[:port]": lowercase, default port dropped, no trailing '/'
    loopback_http: bool,
    access_ttl_secs: u32,
    refresh_grace_secs: u32,
    idle_days: u32,
    max_days: u32,
    envelope_key: [u8; 32], // per process (thread_rng); restart invalidates in-flight consents
    csrf_key: [u8; 32],     // per process; separate key from envelope_key
    notices: Vec<String>,   // clamp / fallback notices for the boot log
}

impl McpOauthConfig {
    /// The two HMAC keys are per process and never persisted (so they never reach a
    /// backup). A restart therefore invalidates every in-flight consent / resume
    /// envelope (<= 10 min of work); the user re-runs the client's login. Deliberate.
    pub fn from_env() -> Self {
        let get = |k: &str| std::env::var(k).ok(); // non-UTF-8 == unset
        let (mode, url, a, g, i, m) = (
            get(MODE_VAR),
            get(PUBLIC_URL_VAR),
            get(ACCESS_TTL_VAR),
            get(REFRESH_GRACE_VAR),
            get(IDLE_DAYS_VAR),
            get(MAX_DAYS_VAR),
        );
        let env = McpOauthEnv {
            mode: mode.as_deref(),
            public_url: url.as_deref(),
            access_ttl_secs: a.as_deref(),
            refresh_grace_secs: g.as_deref(),
            idle_days: i.as_deref(),
            max_days: m.as_deref(),
        };
        Self::from_parts(
            &env,
            crate::base_path::base_path(),
            random_key(),
            random_key(),
        )
    }

    /// Pure. `base_path` decides whether `auto` may enable (it may not when
    /// non-empty) and is validated for characters under `on`;
    /// issuer()/resource_url()/endpoint_url()/is_our_resource() still read the
    /// process-global base path at call time.
    pub fn from_parts(
        env: &McpOauthEnv<'_>,
        base_path: &str,
        envelope_key: [u8; 32],
        csrf_key: [u8; 32],
    ) -> Self {
        // Knob notices are independent of the mode: an operator who set a knob
        // while MCP is off still learns it was not taken as written.
        let mut notices = Vec::new();
        let access_ttl_secs = resolve_knob(env.access_ttl_secs, &ACCESS_TTL, &mut notices);
        let refresh_grace_secs = resolve_knob(env.refresh_grace_secs, &GRACE, &mut notices);
        let mut idle_days = resolve_knob(env.idle_days, &IDLE, &mut notices);
        let max_days = resolve_knob(env.max_days, &MAX, &mut notices);
        if idle_days > max_days {
            notices.push(format!(
                "{IDLE_DAYS_VAR}={idle_days} exceeds {MAX_DAYS_VAR}={max_days}; using {max_days}"
            ));
            idle_days = max_days;
        }

        // Check order: mode -> public URL -> base path. `off` and an invalid
        // mode never look at the URL, so their reason is not masked by a URL problem.
        // A disabled config keeps an empty origin: nothing may build a URL from it.
        let off = |mode, reason| (mode, Some(reason), String::new(), false);
        let (mode, disabled, origin, loopback_http) = match parse_mode(env.mode) {
            Err(v) => off(McpMode::Off, DisabledReason::InvalidMode(v)),
            Ok(McpMode::Off) => off(McpMode::Off, DisabledReason::ModeOff),
            Ok(McpMode::Auto) => match normalize_public_url(env.public_url) {
                // `auto` enables only on an https origin on a non-loopback host
                Ok((origin, false)) if !origin_is_loopback(&origin) => {
                    if base_path.is_empty() {
                        (McpMode::Auto, None, origin, false)
                    } else {
                        off(McpMode::Auto, DisabledReason::AutoPathMounted)
                    }
                }
                _ => off(McpMode::Auto, DisabledReason::AutoNeedsHttpsPublicUrl),
            },
            Ok(McpMode::On) => match normalize_public_url(env.public_url) {
                Err(reason) => off(McpMode::On, reason),
                Ok(_) if !base_path_ok(base_path) => {
                    off(McpMode::On, DisabledReason::BasePathInvalid)
                }
                Ok((origin, loopback)) => (McpMode::On, None, origin, loopback),
            },
        };
        Self {
            mode,
            disabled,
            origin,
            loopback_http,
            access_ttl_secs,
            refresh_grace_secs,
            idle_days,
            max_days,
            envelope_key,
            csrf_key,
            notices,
        }
    }

    /// `MgmtState::test_default`: mode Off, reason ModeOff. The keys are random
    /// too, so a route mounted by mistake fails closed (no verification ever
    /// succeeds) instead of signing with a publicly known key.
    pub fn disabled() -> Self {
        Self {
            mode: McpMode::Off,
            disabled: Some(DisabledReason::ModeOff),
            origin: String::new(),
            loopback_http: false,
            access_ttl_secs: ACCESS_TTL.default,
            refresh_grace_secs: GRACE.default,
            idle_days: IDLE.default,
            max_days: MAX.default,
            envelope_key: random_key(),
            csrf_key: random_key(),
            notices: Vec::new(),
        }
    }

    #[cfg(any(test, debug_assertions))]
    pub fn for_tests(public_url: &str) -> Self {
        let env = McpOauthEnv {
            mode: Some("on"),
            public_url: Some(public_url),
            ..Default::default()
        };
        let c = Self::from_parts(
            &env,
            crate::base_path::base_path(),
            *b"drust-test-mcp-envelope-key-32b!",
            *b"drust-test-mcp-csrf-key-32bytes!",
        );
        assert!(
            c.enabled(),
            "McpOauthConfig::for_tests({public_url:?}) did not enable: {:?}",
            c.disabled_reason()
        );
        c
    }

    /// Sets the four knobs verbatim — no clamp — so a test can use a 1-second
    /// access lifetime.
    #[cfg(any(test, debug_assertions))]
    pub fn with_ttls_for_tests(
        mut self,
        access_ttl_secs: u32,
        refresh_grace_secs: u32,
        idle_days: u32,
        max_days: u32,
    ) -> Self {
        self.access_ttl_secs = access_ttl_secs;
        self.refresh_grace_secs = refresh_grace_secs;
        self.idle_days = idle_days;
        self.max_days = max_days;
        self
    }

    pub fn enabled(&self) -> bool {
        self.disabled.is_none()
    }

    /// `InvalidMode` reads as `Off`.
    pub fn mode(&self) -> McpMode {
        self.mode
    }

    pub fn disabled_reason(&self) -> Option<&DisabledReason> {
        self.disabled.as_ref()
    }

    /// Origin + the process-global base path; no trailing '/'. Meaningless while
    /// disabled — callers check `enabled()` first.
    pub fn issuer(&self) -> String {
        format!("{}{}", self.origin, crate::base_path::base_path())
    }

    /// Origin + `base(rest)`, e.g. `endpoint_url("/oauth/token")`.
    pub fn endpoint_url(&self, rest: &str) -> String {
        format!("{}{}", self.origin, crate::base_path::base(rest))
    }

    pub fn resource_url(&self) -> String {
        self.endpoint_url("/mcp")
    }

    /// True only for this server's own `/mcp` resource: scheme and host compared
    /// case-insensitively, the port compared as a number with the scheme default
    /// filled in, the path compared byte for byte. No userinfo, query or fragment.
    pub fn is_our_resource(&self, s: &str) -> bool {
        if !self.enabled() || s.contains('#') || s.contains('?') {
            return false;
        }
        let (Some((scheme, rest)), Some((our_scheme, our_auth))) =
            (s.split_once("://"), self.origin.split_once("://"))
        else {
            return false;
        };
        if !scheme.eq_ignore_ascii_case(our_scheme) {
            return false;
        }
        let (authority, path) = match rest.find('/') {
            Some(i) => rest.split_at(i),
            None => (rest, ""),
        };
        if authority.contains('@') {
            return false;
        }
        let auth = authority.to_ascii_lowercase();
        let default_port: u16 = if our_scheme == "https" { 443 } else { 80 };
        // `origin` comes from Url::origin().ascii_serialization(), so splitting it
        // always succeeds; if it ever did not, this fails closed.
        let (Some((host, port)), Some((our_host, our_port))) =
            (split_authority(&auth), split_authority(our_auth))
        else {
            return false;
        };
        host == our_host
            && port.unwrap_or(default_port) == our_port.unwrap_or(default_port)
            && path == crate::base_path::base("/mcp")
    }

    /// The host of `DRUST_PUBLIC_URL`: lowercase, no port, an IPv6 literal
    /// without its brackets. `None` while disabled.
    pub fn public_host(&self) -> Option<&str> {
        if !self.enabled() {
            return None;
        }
        let (_, authority) = self.origin.split_once("://")?;
        let (host, _) = split_authority(authority)?;
        let host = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host);
        (!host.is_empty()).then_some(host)
    }

    /// The hosts a request to the resource server may name: `localhost`,
    /// `127.0.0.1`, `::1`, in that order, then `public_host()` unless it is one
    /// of those three. One list for the Host check in front of the resource
    /// server and for rmcp's own guard. Never empty: an empty list disables
    /// rmcp's Host guard entirely.
    pub fn allowed_hosts(&self) -> Vec<String> {
        let mut hosts: Vec<String> = ["localhost", "127.0.0.1", "::1"]
            .into_iter()
            .map(String::from)
            .collect();
        if let Some(h) = self.public_host()
            && !hosts.iter().any(|l| l == h)
        {
            hosts.push(h.to_string());
        }
        hosts
    }

    /// The protected-resource metadata URL for `/mcp`, under the base path.
    /// Meaningless while disabled — callers check `enabled()` first.
    pub fn prm_url(&self) -> String {
        self.endpoint_url("/.well-known/oauth-protected-resource/mcp")
    }

    /// The normalized public origin (scheme://host[:port], no trailing '/'); None while disabled.
    pub fn public_origin(&self) -> Option<&str> {
        self.enabled().then_some(self.origin.as_str())
    }

    /// Whether a browser `Origin` header may reach the resource server: this
    /// server's own origin (scheme and host case-insensitive, the default port
    /// optional) or a loopback origin (`localhost`, `127.0.0.1`, `::1`) on any
    /// port. `false` while disabled, for `null`, and for anything that is not a
    /// bare http(s) origin.
    ///
    /// Asked only when a request carries Origin; a request without one never
    /// reaches it (MCP clients send none). Loopback origins are accepted on any
    /// port only because /mcp reads no cookie or other ambient credential; if it
    /// ever does, drop the loopback arm.
    pub fn origin_allowed(&self, origin: &str) -> bool {
        if !self.enabled() {
            return false;
        }
        let Ok(u) = Url::parse(origin) else {
            return false;
        };
        if !matches!(u.scheme(), "http" | "https")
            || !u.username().is_empty()
            || u.password().is_some()
            || u.path() != "/"
            || u.query().is_some()
            || u.fragment().is_some()
        {
            return false;
        }
        if u.origin().ascii_serialization() == self.origin {
            return true;
        }
        match u.host() {
            Some(Host::Domain(d)) => d == "localhost",
            Some(Host::Ipv4(a)) => a == std::net::Ipv4Addr::LOCALHOST,
            Some(Host::Ipv6(a)) => a == std::net::Ipv6Addr::LOCALHOST,
            None => false,
        }
    }

    pub fn access_ttl_secs(&self) -> u32 {
        self.access_ttl_secs
    }

    pub fn refresh_grace_secs(&self) -> u32 {
        self.refresh_grace_secs
    }

    pub fn idle_days(&self) -> u32 {
        self.idle_days
    }

    pub fn max_days(&self) -> u32 {
        self.max_days
    }

    /// Reading a key while disabled means a route is mounted that should not be.
    pub fn envelope_key(&self) -> &[u8; 32] {
        debug_assert!(
            self.enabled(),
            "McpOauthConfig::envelope_key() read while MCP OAuth is disabled"
        );
        &self.envelope_key
    }

    /// Reading a key while disabled means a route is mounted that should not be.
    pub fn csrf_key(&self) -> &[u8; 32] {
        debug_assert!(
            self.enabled(),
            "McpOauthConfig::csrf_key() read while MCP OAuth is disabled"
        );
        &self.csrf_key
    }

    /// `[0]` is the status line; `[1..]` the loopback-http warning (if any) and
    /// then the knob notices. No line ever contains the raw `DRUST_PUBLIC_URL`.
    /// The level is `main.rs`'s call, from `disabled_reason()`.
    pub fn boot_log_lines(&self) -> Vec<String> {
        let status = match &self.disabled {
            None => format!(
                "MCP OAuth AS enabled (DRUST_MCP={}): issuer={} resource={} access_ttl={}s \
                 refresh_grace={}s idle={}d max={}d allowed_hosts=[{}]",
                mode_name(self.mode),
                self.issuer(),
                self.resource_url(),
                self.access_ttl_secs,
                self.refresh_grace_secs,
                self.idle_days,
                self.max_days,
                self.allowed_hosts().join(",")
            ),
            Some(DisabledReason::ModeOff) => "MCP OAuth AS disabled: DRUST_MCP=off".to_string(),
            Some(DisabledReason::AutoNeedsHttpsPublicUrl) => {
                "MCP OAuth AS disabled: DRUST_MCP=auto \
                 (the default) enables it only when DRUST_PUBLIC_URL is an https:// origin on a \
                 non-loopback host; set it, or set DRUST_MCP=on"
                    .to_string()
            }
            Some(DisabledReason::AutoPathMounted) => "MCP OAuth AS disabled: DRUST_MCP=auto \
                 (the default) does not enable it while DRUST_BASE_PATH is set; forward the root \
                 discovery paths in the proxy, then set DRUST_MCP=on"
                .to_string(),
            Some(DisabledReason::InvalidMode(v)) => format!(
                "MCP OAuth AS disabled: DRUST_MCP={v:?} is not one of auto|on|off; treated as off"
            ),
            Some(DisabledReason::PublicUrlMissing) => "MCP OAuth AS disabled: DRUST_MCP=on but \
                 DRUST_PUBLIC_URL is empty; set it to the public https origin"
                .to_string(),
            Some(DisabledReason::PublicUrlInvalid(why)) => format!(
                "MCP OAuth AS disabled: DRUST_PUBLIC_URL must be a bare origin \
                 scheme://host[:port] (problem: {why}); its value is not logged"
            ),
            Some(DisabledReason::InsecureHttp) => "MCP OAuth AS disabled: DRUST_PUBLIC_URL uses \
                 http:// on a non-loopback host; use https://"
                .to_string(),
            Some(DisabledReason::BasePathInvalid) => "MCP OAuth AS disabled: DRUST_BASE_PATH must \
                 use only [A-Za-z0-9._~/-] and have no empty, '.' or '..' segment"
                .to_string(),
        };
        let mut lines = vec![status];
        if self.loopback_http {
            lines.push(
                "DRUST_PUBLIC_URL is loopback http:// — not RFC 8414 / RFC 9207 conformant; \
                 development only"
                    .to_string(),
            );
        }
        lines.extend(self.notices.iter().cloned());
        lines
    }
}

fn random_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut k);
    k
}

fn mode_name(m: McpMode) -> &'static str {
    match m {
        McpMode::Auto => "auto",
        McpMode::On => "on",
        McpMode::Off => "off",
    }
}

fn parse_mode(raw: Option<&str>) -> Result<McpMode, String> {
    let t = raw.map(str::trim).unwrap_or("");
    if t.is_empty() {
        return Ok(McpMode::Auto); // unset / "" = auto
    }
    match t.to_ascii_lowercase().as_str() {
        "auto" => Ok(McpMode::Auto),
        "on" => Ok(McpMode::On),
        "off" => Ok(McpMode::Off),
        _ => Err(truncate_for_log(t, 32)), // echoed (quoted) in the boot log
    }
}

/// Ok((origin, insecure_http)); insecure http is accepted only on a loopback
/// host. Never returns or logs the raw input: it may carry userinfo.
fn normalize_public_url(raw: Option<&str>) -> Result<(String, bool), DisabledReason> {
    let t = raw.map(str::trim).unwrap_or("");
    if t.is_empty() {
        return Err(DisabledReason::PublicUrlMissing);
    }
    let u = Url::parse(t).map_err(|_| DisabledReason::PublicUrlInvalid("unparsable"))?;
    let https = match u.scheme() {
        "https" => true,
        "http" => false,
        _ => return Err(DisabledReason::PublicUrlInvalid("scheme")),
    };
    if !u.username().is_empty() || u.password().is_some() {
        return Err(DisabledReason::PublicUrlInvalid("userinfo"));
    }
    if u.path() != "/" {
        return Err(DisabledReason::PublicUrlInvalid("path"));
    }
    if u.query().is_some() {
        return Err(DisabledReason::PublicUrlInvalid("query"));
    }
    if u.fragment().is_some() {
        return Err(DisabledReason::PublicUrlInvalid("fragment"));
    }
    let loopback = match host_is_loopback(&u) {
        Some(b) => b,
        None => return Err(DisabledReason::PublicUrlInvalid("host")),
    };
    if !https && !loopback {
        return Err(DisabledReason::InsecureHttp);
    }
    Ok((u.origin().ascii_serialization(), !https))
}

/// `None` when the URL has no host; otherwise whether that host is a
/// loopback name or address.
fn host_is_loopback(u: &Url) -> Option<bool> {
    match u.host() {
        Some(Host::Domain(d)) => Some(d == "localhost"),
        Some(Host::Ipv4(a)) => Some(a == std::net::Ipv4Addr::LOCALHOST),
        Some(Host::Ipv6(a)) => Some(a == std::net::Ipv6Addr::LOCALHOST),
        None => None,
    }
}

/// Whether a normalized origin names a loopback host, for the `auto` decision
/// only. Broader than [`host_is_loopback`]: any address in 127.0.0.0/8, `::1`,
/// an IPv4-mapped loopback (`::ffff:127.x.x.x`), `localhost` and any name under
/// `.localhost`, each also with one trailing dot. An origin that does not parse
/// or has no host counts as loopback, so `auto` fails closed and stays off.
fn origin_is_loopback(origin: &str) -> bool {
    let Some(u) = Url::parse(origin).ok() else {
        return true;
    };
    match u.host() {
        Some(Host::Domain(d)) => {
            let d = d.strip_suffix('.').unwrap_or(d).to_ascii_lowercase();
            d == "localhost" || d.ends_with(".localhost")
        }
        Some(Host::Ipv4(a)) => a.is_loopback(),
        Some(Host::Ipv6(a)) => {
            a.is_loopback() || a.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
        None => true,
    }
}

/// `bp` is the NORMALIZED base (`base_path::normalize`: "" or "/seg[/seg…]", no
/// trailing '/'). Characters [A-Za-z0-9._~/-] only, and no empty, "." or ".." segment:
/// the issuer is compared verbatim by clients, and a dot segment is one a client-side
/// URL normalizer may rewrite.
fn base_path_ok(bp: &str) -> bool {
    bp.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"._~/-".contains(&b))
        && (bp.is_empty()
            || bp.strip_prefix('/').is_some_and(|r| {
                r.split('/')
                    .all(|seg| !seg.is_empty() && seg != "." && seg != "..")
            }))
}

/// At most `n` CHARS, never a byte slice: `&s[..n]` panics on a UTF-8 boundary, and
/// this runs while main.rs builds the config, so a byte slice would turn a typo in
/// DRUST_MCP into a boot failure. The caller prints the result with `{:?}`, which
/// escapes control characters (no forged log lines).
fn truncate_for_log(s: &str, n: usize) -> String {
    match s.char_indices().nth(n) {
        Some((i, _)) => format!("{}…", &s[..i]), // `i` is a char boundary by construction
        None => s.to_string(),
    }
}

/// Unset or blank -> default, silent. Not a whole number -> default + notice.
/// Out of range -> clamp + notice. Parsed as u64 so a value above u32::MAX (but within
/// u64) clamps to the max; a value beyond u64 fails to parse and reads as "not a
/// number" (default + notice).
fn resolve_knob(raw: Option<&str>, k: &Knob, notices: &mut Vec<String>) -> u32 {
    let t = raw.map(str::trim).unwrap_or("");
    if t.is_empty() {
        return k.default;
    }
    match t.parse::<u64>() {
        Err(_) => {
            notices.push(format!(
                "{}={:?} is not a whole number; using the default {}",
                k.var,
                truncate_for_log(t, 32),
                k.default
            ));
            k.default
        }
        Ok(v) if v < u64::from(k.min) || v > u64::from(k.max) => {
            let clamped = if v < u64::from(k.min) { k.min } else { k.max };
            notices.push(format!(
                "{}={v} is outside {}..={}; clamped to {clamped}",
                k.var, k.min, k.max
            ));
            clamped
        }
        // In range, so it fits in u32 (k.max is a u32).
        Ok(v) => u32::try_from(v).unwrap_or(k.max),
    }
}

/// Lowercased authority -> (host, explicit port). IPv6 literals keep their brackets and
/// their inner ':' do not count. None = not a form we accept: empty host, a second ':'
/// outside brackets, or a port that is empty, non-decimal, zero-padded, 0 or > 65535.
fn split_authority(a: &str) -> Option<(&str, Option<u16>)> {
    let (host, port) = if a.starts_with('[') {
        let end = a.find(']')?;
        let (h, rest) = a.split_at(end + 1);
        if rest.is_empty() {
            (h, None)
        } else {
            (h, Some(rest.strip_prefix(':')?))
        }
    } else {
        match a.rsplit_once(':') {
            None => (a, None),
            Some((h, p)) => (h, Some(p)),
        }
    };
    if host.is_empty() || (!host.starts_with('[') && host.contains(':')) {
        return None;
    }
    let port = match port {
        None => None,
        Some(p) => {
            if p.is_empty()
                || !p.bytes().all(|b| b.is_ascii_digit())
                || (p.len() > 1 && p.starts_with('0'))
            {
                return None;
            }
            match p.parse::<u16>() {
                Ok(0) | Err(_) => return None,
                Ok(n) => Some(n),
            }
        }
    };
    Some((host, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENV_KEY: [u8; 32] = *b"drust-test-mcp-envelope-key-32b!";
    const CSRF_KEY: [u8; 32] = *b"drust-test-mcp-csrf-key-32bytes!";

    /// `from_parts` with the default lib-test base path and two fixed keys.
    fn fixed(env: &McpOauthEnv<'_>) -> McpOauthConfig {
        McpOauthConfig::from_parts(env, "/drust", ENV_KEY, CSRF_KEY)
    }

    fn with_mode(mode: Option<&str>) -> McpOauthConfig {
        fixed(&McpOauthEnv {
            mode,
            public_url: Some("https://drust.test"),
            ..Default::default()
        })
    }

    fn with_url(url: Option<&str>) -> McpOauthConfig {
        fixed(&McpOauthEnv {
            mode: Some("on"),
            public_url: url,
            ..Default::default()
        })
    }

    fn with_base(bp: &str) -> McpOauthConfig {
        McpOauthConfig::from_parts(
            &McpOauthEnv {
                mode: Some("on"),
                public_url: Some("https://drust.test"),
                ..Default::default()
            },
            bp,
            ENV_KEY,
            CSRF_KEY,
        )
    }

    // ---- mode ----

    #[test]
    fn mode_unset_or_auto_is_auto() {
        for raw in [
            None,
            Some(""),
            Some("  "),
            Some("auto"),
            Some("AUTO"),
            Some(" Auto "),
        ] {
            // `with_mode` passes an https URL and the "/drust" base path, so
            // the URL qualifies and the base path keeps `auto` off.
            let c = with_mode(raw);
            assert_eq!(c.mode(), McpMode::Auto, "{raw:?}");
            assert_eq!(
                c.disabled_reason(),
                Some(&DisabledReason::AutoPathMounted),
                "{raw:?}"
            );
            assert!(!c.enabled(), "{raw:?}");
        }
    }

    fn auto_with(url: Option<&str>, base: &str) -> McpOauthConfig {
        McpOauthConfig::from_parts(
            &McpOauthEnv {
                mode: Some("auto"),
                public_url: url,
                ..Default::default()
            },
            base,
            ENV_KEY,
            CSRF_KEY,
        )
    }

    #[test]
    fn auto_enables_with_an_https_public_url_and_no_base_path() {
        for raw in [None, Some(""), Some("auto"), Some(" AUTO ")] {
            let c = McpOauthConfig::from_parts(
                &McpOauthEnv {
                    mode: raw,
                    public_url: Some("https://drust.test"),
                    ..Default::default()
                },
                "",
                ENV_KEY,
                CSRF_KEY,
            );
            assert_eq!(c.mode(), McpMode::Auto, "{raw:?}");
            assert!(c.enabled(), "{raw:?}");
            assert_eq!(c.disabled_reason(), None);
        }
    }

    #[test]
    fn auto_needs_an_https_public_url_on_a_public_host() {
        for url in [
            None,
            Some(""),
            Some("not a url"),
            Some("http://drust.test"),
            Some("http://127.0.0.1:47826"),
            Some("http://localhost"),
            // https on a loopback host is a development setup, not a public one
            Some("https://localhost"),
            Some("https://127.0.0.1:47826"),
            Some("https://[::1]"),
            // every other loopback spelling, each also with one trailing dot
            Some("https://127.0.0.2"),
            Some("https://127.255.255.254:8443"),
            Some("https://127.1"),
            Some("https://127.0.0.1."),
            Some("https://127.9.8.7."),
            Some("https://[::ffff:127.0.0.1]"),
            Some("https://[::ffff:127.3.2.1]"),
            Some("https://localhost."),
            Some("https://LOCALHOST"),
            Some("https://drust.localhost"),
            Some("https://a.b.localhost."),
            Some("https://localhost:47826"),
        ] {
            let c = auto_with(url, "");
            assert!(!c.enabled(), "{url:?}");
            assert_eq!(
                c.disabled_reason(),
                Some(&DisabledReason::AutoNeedsHttpsPublicUrl),
                "{url:?}"
            );
        }
    }

    #[test]
    fn on_still_accepts_an_https_loopback_origin() {
        let c = McpOauthConfig::from_parts(
            &McpOauthEnv {
                mode: Some("on"),
                public_url: Some("https://localhost"),
                ..Default::default()
            },
            "",
            ENV_KEY,
            CSRF_KEY,
        );
        assert!(
            c.enabled(),
            "explicit on is the operator's choice and stays unchanged"
        );
    }

    #[test]
    fn auto_never_enables_under_a_base_path() {
        for base in ["/drust", "/x"] {
            let c = auto_with(Some("https://drust.test"), base);
            assert!(!c.enabled(), "{base}");
            assert_eq!(
                c.disabled_reason(),
                Some(&DisabledReason::AutoPathMounted),
                "{base}"
            );
        }
        // the URL is judged first: a bad URL under a base path names the URL
        assert_eq!(
            auto_with(None, "/drust").disabled_reason(),
            Some(&DisabledReason::AutoNeedsHttpsPublicUrl)
        );
    }

    #[test]
    fn boot_log_names_the_mode_that_enabled_it() {
        let c = auto_with(Some("https://drust.test"), "");
        assert!(
            c.boot_log_lines()[0].starts_with("MCP OAuth AS enabled (DRUST_MCP=auto): "),
            "{:?}",
            c.boot_log_lines()
        );
        let p = auto_with(Some("https://drust.test"), "/drust");
        assert!(
            p.boot_log_lines()[0].starts_with("MCP OAuth AS disabled: DRUST_MCP=auto"),
            "{:?}",
            p.boot_log_lines()
        );
        let n = auto_with(None, "");
        assert!(
            n.boot_log_lines()[0].starts_with("MCP OAuth AS disabled: DRUST_MCP=auto"),
            "{:?}",
            n.boot_log_lines()
        );
        // the raw DRUST_PUBLIC_URL never reaches a disabled boot line
        let leaky = auto_with(Some("https://u:p@drust.test"), "");
        for line in leaky.boot_log_lines() {
            assert!(
                !line.contains("u:p") && !line.contains("drust.test"),
                "{line}"
            );
        }
    }

    #[test]
    fn mode_off() {
        for raw in ["off", "OFF"] {
            let c = with_mode(Some(raw));
            assert_eq!(c.mode(), McpMode::Off, "{raw}");
            assert_eq!(c.disabled_reason(), Some(&DisabledReason::ModeOff), "{raw}");
        }
    }

    #[test]
    fn mode_on_with_a_valid_url_enables() {
        for raw in ["on", " ON "] {
            let c = with_mode(Some(raw));
            assert_eq!(c.mode(), McpMode::On, "{raw}");
            assert!(c.enabled(), "{raw}: {:?}", c.disabled_reason());
        }
    }

    #[test]
    fn mode_invalid_reads_as_off() {
        for raw in ["yes", "1", "true"] {
            let c = with_mode(Some(raw));
            assert_eq!(c.mode(), McpMode::Off, "{raw}");
            assert_eq!(
                c.disabled_reason(),
                Some(&DisabledReason::InvalidMode(raw.to_string()))
            );
        }
    }

    #[test]
    fn mode_invalid_multibyte_is_truncated_by_chars_without_panicking() {
        for raw in ["開啟".repeat(20), "😀".repeat(33)] {
            let c = with_mode(Some(&raw));
            assert_eq!(c.mode(), McpMode::Off);
            let want: String = raw.chars().take(32).collect::<String>() + "…";
            assert_eq!(
                c.disabled_reason(),
                Some(&DisabledReason::InvalidMode(want))
            );
        }
    }

    #[test]
    fn mode_invalid_control_chars_cannot_forge_a_log_line() {
        let c = with_mode(Some("on\nINFO forged"));
        assert!(matches!(
            c.disabled_reason(),
            Some(DisabledReason::InvalidMode(_))
        ));
        let line = &c.boot_log_lines()[0];
        assert!(!line.contains('\n'), "raw newline in {line:?}");
        assert!(line.contains("\\n"), "escaped newline expected in {line:?}");
    }

    #[test]
    fn mode_off_is_decided_before_the_url_is_looked_at() {
        let off = fixed(&McpOauthEnv {
            mode: Some("off"),
            public_url: Some("ftp://x"),
            ..Default::default()
        });
        assert_eq!(off.disabled_reason(), Some(&DisabledReason::ModeOff));
        let auto = fixed(&McpOauthEnv {
            mode: Some("auto"),
            public_url: Some("not a url"),
            ..Default::default()
        });
        assert_eq!(
            auto.disabled_reason(),
            Some(&DisabledReason::AutoNeedsHttpsPublicUrl)
        );
    }

    // ---- DRUST_PUBLIC_URL ----

    #[test]
    fn public_url_is_normalized_to_a_bare_origin() {
        for raw in [
            "https://drust.test",
            "https://drust.test/",
            "https://DRUST.Test",
            "https://drust.test:443",
            " https://drust.test ",
        ] {
            let c = with_url(Some(raw));
            assert!(c.enabled(), "{raw:?}: {:?}", c.disabled_reason());
            assert_eq!(c.issuer(), "https://drust.test/drust", "{raw:?}");
        }
        assert_eq!(
            with_url(Some("https://drust.test:8443")).issuer(),
            "https://drust.test:8443/drust"
        );
    }

    #[test]
    fn public_url_rejections() {
        use DisabledReason::*;
        let cases: [(Option<&str>, DisabledReason); 13] = [
            (None, PublicUrlMissing),
            (Some(""), PublicUrlMissing),
            (Some("not a url"), PublicUrlInvalid("unparsable")),
            (Some("ftp://drust.test"), PublicUrlInvalid("scheme")),
            (
                Some("https://u:secret@drust.test"),
                PublicUrlInvalid("userinfo"),
            ),
            (Some("https://drust.test/drust"), PublicUrlInvalid("path")),
            (Some("https://drust.test?x=1"), PublicUrlInvalid("query")),
            (Some("https://drust.test/?"), PublicUrlInvalid("query")),
            (Some("https://drust.test/#f"), PublicUrlInvalid("fragment")),
            (Some("http://drust.test"), InsecureHttp),
            (Some("http://127.0.0.2"), InsecureHttp),
            (Some("https://ZQX@drust.test"), PublicUrlInvalid("userinfo")),
            (Some("http://drust.test:80"), InsecureHttp),
        ];
        for (raw, want) in cases {
            let c = with_url(raw);
            assert!(!c.enabled(), "{raw:?}");
            assert_eq!(c.mode(), McpMode::On, "{raw:?}");
            assert_eq!(c.disabled_reason(), Some(&want), "{raw:?}");
        }
    }

    #[test]
    fn loopback_http_enables_with_a_development_warning() {
        for raw in [
            "http://127.0.0.1:47826",
            "http://localhost:8080",
            "http://[::1]:8080",
        ] {
            let c = with_url(Some(raw));
            assert!(c.enabled(), "{raw}: {:?}", c.disabled_reason());
            assert!(c.loopback_http, "{raw}");
            let lines = c.boot_log_lines();
            assert!(
                lines[1..]
                    .iter()
                    .any(|l| l.contains("loopback http://") && l.contains("development only")),
                "{raw}: {lines:?}"
            );
        }
        assert!(!with_url(Some("https://drust.test")).loopback_http);
    }

    // ---- base path ----

    #[test]
    fn base_path_characters_and_segments() {
        for bad in ["/dr ust", "/dr%75st", "/drust/../x", "/a//b", "/./x", "/.."] {
            assert_eq!(
                with_base(bad).disabled_reason(),
                Some(&DisabledReason::BasePathInvalid),
                "{bad:?}"
            );
        }
        for good in ["", "/drust", "/a.b~c_d-e/f", "/a..b"] {
            let c = with_base(good);
            assert!(c.enabled(), "{good:?}: {:?}", c.disabled_reason());
        }
    }

    // ---- knobs ----

    #[test]
    fn knob_defaults_and_no_notice() {
        let c = with_url(Some("https://drust.test"));
        assert_eq!(
            (
                c.access_ttl_secs(),
                c.refresh_grace_secs(),
                c.idle_days(),
                c.max_days()
            ),
            (3600, 60, 30, 90)
        );
        assert_eq!(c.boot_log_lines().len(), 1, "{:?}", c.boot_log_lines());
    }

    fn knobs(a: Option<&str>, g: Option<&str>, i: Option<&str>, m: Option<&str>) -> McpOauthConfig {
        fixed(&McpOauthEnv {
            mode: Some("on"),
            public_url: Some("https://drust.test"),
            access_ttl_secs: a,
            refresh_grace_secs: g,
            idle_days: i,
            max_days: m,
        })
    }

    fn notices(c: &McpOauthConfig) -> Vec<String> {
        c.boot_log_lines()[1..].to_vec()
    }

    #[test]
    fn knob_not_a_number_falls_back_to_default_with_notice() {
        for raw in ["abc", "-5", "1.5"] {
            let c = knobs(Some(raw), Some(raw), Some(raw), Some(raw));
            assert_eq!(
                (
                    c.access_ttl_secs(),
                    c.refresh_grace_secs(),
                    c.idle_days(),
                    c.max_days()
                ),
                (3600, 60, 30, 90),
                "{raw}"
            );
            let n = notices(&c);
            for var in [
                ACCESS_TTL_VAR,
                REFRESH_GRACE_VAR,
                IDLE_DAYS_VAR,
                MAX_DAYS_VAR,
            ] {
                assert!(n.iter().any(|l| l.contains(var)), "{raw}: {var} in {n:?}");
            }
        }
    }

    #[test]
    fn knob_out_of_range_clamps_with_notice() {
        let one = |a: Option<&str>, g: Option<&str>, i: Option<&str>, m: Option<&str>| {
            let c = knobs(a, g, i, m);
            let n = notices(&c);
            (c, n)
        };
        let (c, n) = one(Some("60"), None, None, None);
        assert_eq!(c.access_ttl_secs(), 900);
        assert!(n.iter().any(|l| l.contains(ACCESS_TTL_VAR)), "{n:?}");
        let (c, n) = one(Some("100000"), None, None, None);
        assert_eq!(c.access_ttl_secs(), 86_400);
        assert_eq!(n.len(), 1, "{n:?}");
        // Beyond u64: fails to parse, so it is "not a number" -> default + notice.
        let (c, n) = one(Some("99999999999999999999"), None, None, None);
        assert_eq!(c.access_ttl_secs(), 3600);
        assert!(n.iter().any(|l| l.contains(ACCESS_TTL_VAR)), "{n:?}");
        let (c, n) = one(Some("1800"), None, None, None);
        assert_eq!(c.access_ttl_secs(), 1800);
        assert!(n.is_empty(), "{n:?}");

        let (c, n) = one(None, Some("0"), None, None);
        assert_eq!(c.refresh_grace_secs(), 0);
        assert!(n.is_empty(), "{n:?}");
        let (c, n) = one(None, Some("301"), None, None);
        assert_eq!(c.refresh_grace_secs(), 300);
        assert!(n.iter().any(|l| l.contains(REFRESH_GRACE_VAR)), "{n:?}");

        let (c, n) = one(None, None, None, Some("0"));
        assert_eq!(c.max_days(), 1);
        assert!(n.iter().any(|l| l.contains(MAX_DAYS_VAR)), "{n:?}");
        let (c, _) = one(None, None, None, Some("400"));
        assert_eq!(c.max_days(), 365);
        let (c, n) = one(None, None, Some("0"), None);
        assert_eq!(c.idle_days(), 1);
        assert!(n.iter().any(|l| l.contains(IDLE_DAYS_VAR)), "{n:?}");
    }

    #[test]
    fn idle_never_exceeds_max() {
        let c = knobs(None, None, None, Some("7"));
        assert_eq!((c.idle_days(), c.max_days()), (7, 7));
        assert!(notices(&c).iter().any(|l| l.contains(IDLE_DAYS_VAR)));
        let c = knobs(None, None, Some("100"), None);
        assert_eq!((c.idle_days(), c.max_days()), (90, 90));
        assert!(notices(&c).iter().any(|l| l.contains(IDLE_DAYS_VAR)));
    }

    #[test]
    fn knob_notices_are_kept_while_disabled() {
        let c = fixed(&McpOauthEnv {
            mode: Some("off"),
            access_ttl_secs: Some("60"),
            ..Default::default()
        });
        assert!(notices(&c).iter().any(|l| l.contains(ACCESS_TTL_VAR)));
    }

    // ---- URLs ----

    #[test]
    fn url_methods_carry_the_base_path() {
        // Lib tests run on the default base path, "/drust".
        let c = McpOauthConfig::for_tests("https://drust.test");
        assert_eq!(c.issuer(), "https://drust.test/drust");
        assert_eq!(c.resource_url(), "https://drust.test/drust/mcp");
        assert_eq!(
            c.endpoint_url("/oauth/token"),
            "https://drust.test/drust/oauth/token"
        );
    }

    #[test]
    fn is_our_resource_default_port_origin() {
        let c = McpOauthConfig::for_tests("https://drust.test");
        for yes in [
            "https://drust.test/drust/mcp",
            "HTTPS://DRUST.TEST/drust/mcp",
            "https://drust.test:443/drust/mcp",
        ] {
            assert!(c.is_our_resource(yes), "{yes}");
        }
        for no in [
            "https://drust.test:443:443/drust/mcp",
            "https://drust.test:/drust/mcp",
            "https://drust.test:0443/drust/mcp",
            "https://drust.test:0/drust/mcp",
            "https://drust.test/drust/mcp/",
            "https://drust.test/drust/MCP",
            "https://drust.test/drust/%6Dcp",
            "https://drust.test/drust/./mcp",
            "https://drust.test/drust/mcp?x",
            "https://drust.test/drust/mcp#f",
            "http://drust.test/drust/mcp",
            "https://drust.test:8443/drust/mcp",
            "https://other.test/drust/mcp",
            "https://u@drust.test/drust/mcp",
            "https://drust.test",
            "",
        ] {
            assert!(!c.is_our_resource(no), "{no}");
        }
        let off = McpOauthConfig::disabled();
        assert!(!off.is_our_resource("https://drust.test/drust/mcp"));
        assert!(!off.is_our_resource(""));
    }

    #[test]
    fn is_our_resource_non_default_port_origin() {
        let c = McpOauthConfig::for_tests("https://drust.test:8443");
        assert!(c.is_our_resource("https://drust.test:8443/drust/mcp"));
        for no in [
            "https://drust.test:8443:443/drust/mcp",
            "https://drust.test/drust/mcp",
            "https://drust.test:/drust/mcp",
            "https://drust.test:08443/drust/mcp",
            "https://drust.test:70000/drust/mcp",
        ] {
            assert!(!c.is_our_resource(no), "{no}");
        }

        let c = McpOauthConfig::for_tests("http://localhost:8080");
        assert!(c.is_our_resource("http://localhost:8080/drust/mcp"));
        assert!(!c.is_our_resource("http://localhost:8080:80/drust/mcp"));

        let c = McpOauthConfig::for_tests("http://[::1]:8080");
        assert!(c.is_our_resource("http://[::1]:8080/drust/mcp"));
        for no in [
            "http://[::1]/drust/mcp",
            "http://[::1]:8080:80/drust/mcp",
            "http://[::1]x/drust/mcp",
        ] {
            assert!(!c.is_our_resource(no), "{no}");
        }
    }

    // ---- constructors ----

    #[test]
    #[should_panic(expected = "did not enable")]
    fn for_tests_panics_when_the_url_would_not_enable() {
        let _ = McpOauthConfig::for_tests("http://example.com");
    }

    #[test]
    fn with_ttls_for_tests_does_not_clamp() {
        let c = McpOauthConfig::for_tests("https://drust.test").with_ttls_for_tests(1, 0, 1, 1);
        assert_eq!(
            (
                c.access_ttl_secs(),
                c.refresh_grace_secs(),
                c.idle_days(),
                c.max_days()
            ),
            (1, 0, 1, 1)
        );
    }

    #[test]
    fn disabled_is_off() {
        let c = McpOauthConfig::disabled();
        assert!(!c.enabled());
        assert_eq!(c.mode(), McpMode::Off);
        assert_eq!(c.disabled_reason(), Some(&DisabledReason::ModeOff));
    }

    #[test]
    fn disabled_keys_are_random_never_zero() {
        let a = McpOauthConfig::disabled();
        let b = McpOauthConfig::disabled();
        assert_ne!(a.envelope_key, [0u8; 32]);
        assert_ne!(a.csrf_key, [0u8; 32]);
        assert_ne!(a.envelope_key, a.csrf_key);
        assert_ne!(a.envelope_key, b.envelope_key);
    }

    #[test]
    #[should_panic(expected = "read while MCP OAuth is disabled")]
    fn disabled_envelope_key_read_panics_in_debug() {
        let _ = McpOauthConfig::disabled().envelope_key();
    }

    #[test]
    #[should_panic(expected = "read while MCP OAuth is disabled")]
    fn disabled_csrf_key_read_panics_in_debug() {
        let _ = McpOauthConfig::disabled().csrf_key();
    }

    #[test]
    fn keys_pass_through_and_random_key_is_random() {
        let c = with_url(Some("https://drust.test"));
        assert_eq!(c.envelope_key(), &ENV_KEY);
        assert_eq!(c.csrf_key(), &CSRF_KEY);
        assert_ne!(random_key(), random_key());
    }

    // ---- boot log ----

    #[test]
    fn boot_log_never_echoes_a_rejected_public_url() {
        // One row per rejection branch; each input carries a unique marker that
        // must appear in no line. Host-position markers are lowercase because
        // the url crate lowercases hosts. (The no-host branch is unreachable for
        // the two special schemes http/https and is kept only as a guard.)
        let cases: [(&str, &str, DisabledReason); 9] = [
            (
                "ZQX1 not a url",
                "ZQX1",
                DisabledReason::PublicUrlInvalid("unparsable"),
            ),
            (
                "ftp://zqx2.test",
                "zqx2",
                DisabledReason::PublicUrlInvalid("scheme"),
            ),
            (
                "https://u:ZQX3@drust.test",
                "ZQX3",
                DisabledReason::PublicUrlInvalid("userinfo"),
            ),
            (
                "https://ZQX4@drust.test",
                "ZQX4",
                DisabledReason::PublicUrlInvalid("userinfo"),
            ),
            (
                "https://drust.test/ZQX5",
                "ZQX5",
                DisabledReason::PublicUrlInvalid("path"),
            ),
            (
                "https://drust.test?ZQX6",
                "ZQX6",
                DisabledReason::PublicUrlInvalid("query"),
            ),
            (
                "https://drust.test/#ZQX7",
                "ZQX7",
                DisabledReason::PublicUrlInvalid("fragment"),
            ),
            ("http://zqx8.test", "zqx8", DisabledReason::InsecureHttp),
            (
                "http://zqx9.test:8080",
                "zqx9",
                DisabledReason::InsecureHttp,
            ),
        ];
        for (raw, marker, want) in cases {
            let c = with_url(Some(raw));
            assert_eq!(c.disabled_reason(), Some(&want), "{raw}");
            for line in c.boot_log_lines() {
                assert!(
                    !line
                        .to_ascii_lowercase()
                        .contains(&marker.to_ascii_lowercase()),
                    "{raw}: marker leaked into {line:?}"
                );
            }
        }
    }

    #[test]
    fn boot_log_status_lines() {
        let c = McpOauthConfig::for_tests("https://drust.test");
        let l0 = &c.boot_log_lines()[0];
        assert!(l0.contains("enabled"), "{l0}");
        assert!(l0.contains(&c.issuer()), "{l0}");
        assert!(l0.contains(&c.resource_url()), "{l0}");

        let c = with_mode(Some("yes"));
        let l0 = &c.boot_log_lines()[0];
        assert!(l0.contains("\"yes\""), "{l0}");
        assert!(l0.contains("treated as off"), "{l0}");

        let c = with_mode(None);
        assert!(c.boot_log_lines()[0].contains("DRUST_MCP=auto"));
        let c = with_mode(Some("off"));
        assert_eq!(
            c.boot_log_lines()[0],
            "MCP OAuth AS disabled: DRUST_MCP=off"
        );

        let c = knobs(Some("60"), None, None, None);
        let lines = c.boot_log_lines();
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(lines[1].contains(ACCESS_TTL_VAR));
    }

    // ---- allowed hosts, PRM URL, Origin ----

    #[test]
    fn public_host_is_lowercase_and_portless() {
        for (raw, want) in [
            ("https://drust.test", "drust.test"),
            ("https://DRUST.Test:443", "drust.test"),
            ("https://drust.test:8443", "drust.test"),
            ("http://[::1]:8080", "::1"),
            ("https://[2001:db8::1]", "2001:db8::1"),
        ] {
            assert_eq!(with_url(Some(raw)).public_host(), Some(want), "{raw}");
        }
        assert_eq!(McpOauthConfig::disabled().public_host(), None);
        assert_eq!(
            with_url(Some("http://drust.test")).public_host(),
            None,
            "refused URL"
        );
    }

    #[test]
    fn allowed_hosts_are_loopback_plus_the_public_host() {
        let three = ["localhost", "127.0.0.1", "::1"];
        let cases: [(&str, &[&str]); 7] = [
            (
                "https://drust.test",
                &["localhost", "127.0.0.1", "::1", "drust.test"],
            ),
            (
                "https://DRUST.Test:8443",
                &["localhost", "127.0.0.1", "::1", "drust.test"],
            ),
            ("http://127.0.0.1:47826", &three),
            ("http://localhost:8080", &three),
            ("https://localhost", &three),
            ("http://[::1]:8080", &three),
            (
                "https://[2001:db8::1]",
                &["localhost", "127.0.0.1", "::1", "2001:db8::1"],
            ),
        ];
        for (raw, want) in cases {
            assert_eq!(with_url(Some(raw)).allowed_hosts(), want, "{raw}");
        }
        assert_eq!(McpOauthConfig::disabled().allowed_hosts(), three);
        assert_eq!(with_mode(Some("auto")).allowed_hosts(), three);
    }

    /// rmcp allows every host when the list is empty and silently drops an
    /// empty entry (tower.rs host_is_allowed / parse_allowed_authority), so
    /// both would turn its Host guard off.
    #[test]
    fn allowed_hosts_are_never_empty_and_well_formed() {
        let mut configs = vec![
            McpOauthConfig::disabled(),
            with_mode(None),
            with_mode(Some("off")),
            with_mode(Some("auto")),
            with_mode(Some("yes")),
            with_url(None),
            with_url(Some("http://drust.test")),
        ];
        for raw in [
            "https://drust.test",
            "https://DRUST.Test:443",
            "https://drust.test:8443",
            "http://127.0.0.1:47826",
            "http://localhost:8080",
            "https://localhost",
            "http://[::1]:8080",
            "https://[2001:db8::1]",
        ] {
            configs.push(with_url(Some(raw)));
        }
        for c in &configs {
            let hosts = c.allowed_hosts();
            assert!(hosts.len() >= 3, "{hosts:?}");
            for h in &hosts {
                assert!(!h.is_empty(), "{hosts:?}");
                assert!(
                    !h.chars()
                        .any(|ch| "/@[]".contains(ch) || ch.is_whitespace()),
                    "{h:?}"
                );
                assert!(
                    !h.contains(':') || h.parse::<std::net::Ipv6Addr>().is_ok(),
                    "a ':' is only allowed inside an unbracketed IPv6 address: {h:?}"
                );
                assert_eq!(h, &h.to_ascii_lowercase(), "{h:?}");
            }
        }
    }

    #[test]
    fn prm_url_carries_the_base_path() {
        // Lib tests run on the default base path, "/drust".
        let c = McpOauthConfig::for_tests("https://drust.test");
        assert_eq!(
            c.prm_url(),
            "https://drust.test/drust/.well-known/oauth-protected-resource/mcp"
        );
        assert_eq!(
            c.prm_url(),
            c.endpoint_url("/.well-known/oauth-protected-resource/mcp")
        );
    }

    #[test]
    fn origin_allowed_cases() {
        let c = McpOauthConfig::for_tests("https://drust.test");
        for yes in [
            "https://drust.test",
            "HTTPS://DRUST.TEST",
            "https://drust.test:443",
            "https://drust.test/",
            "http://localhost",
            "http://localhost:3000",
            "https://127.0.0.1:8443",
            "http://[::1]:5173",
        ] {
            assert!(c.origin_allowed(yes), "{yes}");
        }
        for no in [
            "https://evil.example",
            "null",
            "",
            "http://drust.test",
            "https://drust.test:8443",
            "https://drust.test.evil.example",
            "http://localhost.evil.example",
            "http://127.0.0.2",
            "ftp://localhost",
            "https://drust.test/x",
            "https://drust.test?x=1",
            "https://u@drust.test",
            // IPv4-mapped is not Ipv6Addr::LOCALHOST; a trailing dot is another name.
            "http://[::ffff:127.0.0.1]",
            "https://drust.test.",
            "http://localhost.:3000",
        ] {
            assert!(!c.origin_allowed(no), "{no}");
        }
        let off = McpOauthConfig::disabled();
        assert!(!off.origin_allowed("http://localhost"));
        assert!(!off.origin_allowed(""));
    }

    // ---- boot log: allowed hosts ----

    #[test]
    fn boot_log_enabled_line_lists_allowed_hosts() {
        let c = McpOauthConfig::for_tests("https://drust.test");
        assert_eq!(
            c.boot_log_lines()[0],
            "MCP OAuth AS enabled (DRUST_MCP=on): issuer=https://drust.test/drust \
             resource=https://drust.test/drust/mcp access_ttl=3600s refresh_grace=60s \
             idle=30d max=90d allowed_hosts=[localhost,127.0.0.1,::1,drust.test]"
        );
        let dev = McpOauthConfig::for_tests("http://127.0.0.1:47826");
        assert!(
            dev.boot_log_lines()[0].ends_with(" allowed_hosts=[localhost,127.0.0.1,::1]"),
            "{:?}",
            dev.boot_log_lines()
        );
    }

    #[test]
    fn boot_log_disabled_lines_do_not_list_hosts() {
        for c in [
            with_mode(None),
            with_mode(Some("off")),
            with_mode(Some("yes")),
            with_url(None),
            with_url(Some("http://drust.test")),
        ] {
            for l in c.boot_log_lines() {
                assert!(!l.contains("allowed_hosts"), "{l}");
            }
        }
    }

    #[test]
    fn public_origin_is_the_bare_origin_and_none_while_disabled() {
        assert_eq!(
            McpOauthConfig::for_tests("https://drust.test").public_origin(),
            Some("https://drust.test")
        );
        assert_eq!(
            McpOauthConfig::for_tests("https://drust.test:8443").public_origin(),
            Some("https://drust.test:8443")
        );
        assert_eq!(McpOauthConfig::disabled().public_origin(), None);
    }
}
