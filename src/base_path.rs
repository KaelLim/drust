//! Configurable external URL prefix. Every browser-facing path (redirect
//! Location, cookie Path, OAuth redirect_uri, template links, JSON-returned
//! paths) is prefixed with this. Default "/drust" reproduces the shared-VM
//! deployment byte-for-byte; Docker / drust.com set DRUST_BASE_PATH="" for root.
//! axum routes are always mounted at root — this is OUTBOUND-only.

use std::sync::OnceLock;

static BASE_PATH: OnceLock<String> = OnceLock::new();

/// Shape a configured value: trim; "" or "/" → "" (root); else ensure a single
/// leading '/' and strip trailing '/'.
pub fn normalize(raw: &str) -> String {
    let t = raw.trim();
    if t.is_empty() || t == "/" {
        return String::new();
    }
    let mut s = t.to_string();
    if !s.starts_with('/') {
        s.insert(0, '/');
    }
    while s.ends_with('/') {
        s.pop();
    }
    s
}

/// Set the process-global base path once at startup (normalized).
pub fn set(raw: &str) {
    let _ = BASE_PATH.set(normalize(raw));
}

/// The configured prefix. Defaults to "/drust" when unset so an un-migrated
/// prod (and the existing test suite) is byte-for-byte unchanged.
pub fn base_path() -> &'static str {
    BASE_PATH.get().map(String::as_str).unwrap_or("/drust")
}

fn prefixed(prefix: &str, rest: &str) -> String {
    format!("{prefix}{rest}")
}

fn cookie_path_with(prefix: &str, sub: &str) -> String {
    let p = format!("{prefix}{sub}");
    if p.is_empty() { "/".to_string() } else { p }
}

/// Prefix a root-relative path (`rest` MUST start with '/').
pub fn base(rest: &str) -> String {
    prefixed(base_path(), rest)
}

/// Cookie `Path` attribute for a sub-path under the base. Empty base + empty
/// sub → "/" (a bare empty Path is invalid).
pub fn cookie_path(sub: &str) -> String {
    cookie_path_with(base_path(), sub)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_shapes() {
        assert_eq!(normalize("/drust"), "/drust");
        assert_eq!(normalize("drust"), "/drust");
        assert_eq!(normalize("/drust/"), "/drust");
        assert_eq!(normalize(""), "");
        assert_eq!(normalize("/"), "");
        assert_eq!(normalize("  /drust  "), "/drust");
    }

    #[test]
    fn prefixed_both_modes() {
        assert_eq!(prefixed("/drust", "/admin/x"), "/drust/admin/x");
        assert_eq!(prefixed("", "/admin/x"), "/admin/x");
    }

    #[test]
    fn cookie_path_both_modes() {
        assert_eq!(cookie_path_with("/drust", ""), "/drust");
        assert_eq!(cookie_path_with("", ""), "/");
        assert_eq!(cookie_path_with("/drust", "/t/x/oauth/"), "/drust/t/x/oauth/");
        assert_eq!(cookie_path_with("", "/t/x/oauth/"), "/t/x/oauth/");
    }

    #[test]
    fn default_unset_is_drust() {
        assert_eq!(base_path(), "/drust");
        assert_eq!(base("/admin"), "/drust/admin");
    }
}
