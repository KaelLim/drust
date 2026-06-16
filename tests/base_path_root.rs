//! Empty-base (Docker root) mode proof for the configurable URL prefix.
//!
//! Default mode (`base_path() == "/drust"`) is covered byte-identically by the
//! entire integration + lib suite (every outbound link/cookie asserts `/drust`).
//! This dedicated binary is the counterpart: a separate process — so the
//! `OnceLock` starts unset — that pins the empty-prefix deployment (Docker /
//! root mount, `DRUST_BASE_PATH=""`). It exercises the real public API
//! (`set` -> `base_path` / `base` / `cookie_path`), not just the pure inner
//! helpers covered by the `src/base_path.rs` unit tests.

#[test]
fn empty_base_drops_the_prefix() {
    // First base_path mutation in this process: empty prefix = root mount.
    drust::base_path::set("");

    assert_eq!(drust::base_path::base_path(), "", "raw prefix must be empty");

    // URL builder: prefix vanishes, the remainder is returned verbatim.
    assert_eq!(drust::base_path::base("/login"), "/login");
    assert_eq!(drust::base_path::base("/admin/tenants"), "/admin/tenants");
    assert_eq!(drust::base_path::base("/t/abc/mcp"), "/t/abc/mcp");

    // Cookie Path builder: an otherwise-empty Path collapses to "/" (a cookie
    // Path attribute must be non-empty), non-empty subs pass through.
    assert_eq!(drust::base_path::cookie_path(""), "/");
    assert_eq!(drust::base_path::cookie_path("/admin"), "/admin");
    assert_eq!(drust::base_path::cookie_path("/t/abc/oauth/"), "/t/abc/oauth/");
}
