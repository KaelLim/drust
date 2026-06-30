//! Config file location, 0600 persistence, and bearer storage (keyring + inline fallback).
use crate::config::hosts::{Host, HostsConfig};
use std::path::PathBuf;

const KEYRING_SERVICE: &str = "drust-cli";

pub fn config_path() -> anyhow::Result<PathBuf> {
    let dirs = directories::ProjectDirs::from("tw", "drust", "drust")
        .ok_or_else(|| anyhow::anyhow!("cannot resolve config dir"))?;
    Ok(dirs.config_dir().join("hosts.toml"))
}

pub fn load() -> anyhow::Result<HostsConfig> {
    let p = config_path()?;
    if !p.exists() {
        return Ok(HostsConfig::default());
    }
    HostsConfig::parse(&std::fs::read_to_string(p)?)
}

pub fn save(cfg: &HostsConfig) -> anyhow::Result<()> {
    let p = config_path()?;
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&p, cfg.to_toml())?;
    set_0600(&p);
    Ok(())
}

#[cfg(unix)]
fn set_0600(p: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600));
}
#[cfg(not(unix))]
fn set_0600(_p: &std::path::Path) {}

/// Resolve the bearer: "inline:<pat>" → the pat; "keyring" → OS keyring lookup.
pub fn read_token(host_key: &str, host: &Host) -> anyhow::Result<String> {
    if let Some(rest) = host.token_ref.strip_prefix("inline:") {
        return Ok(rest.to_string());
    }
    let entry = keyring::Entry::new(KEYRING_SERVICE, host_key)?;
    Ok(entry.get_password()?)
}

/// Store the bearer in the keyring; on any keyring failure fall back to inline.
pub fn write_token(host_key: &str, token: &str) -> String {
    match keyring::Entry::new(KEYRING_SERVICE, host_key).and_then(|e| e.set_password(token)) {
        Ok(()) => "keyring".to_string(),
        Err(_) => write_token_inline(token),
    }
}

pub fn write_token_inline(token: &str) -> String {
    format!("inline:{token}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::hosts::Host;

    #[test]
    fn inline_token_roundtrips() {
        let host = Host {
            base_url: "https://x/drust".into(),
            token_ref: "inline:drust_pat_cli_XYZ".into(),
            default_console: None,
            default_tenant: None,
        };
        assert_eq!(read_token("x", &host).unwrap(), "drust_pat_cli_XYZ");
    }

    #[test]
    fn write_inline_when_no_keyring() {
        // force the inline path
        let r = write_token_inline("drust_pat_cli_ABC");
        assert_eq!(r, "inline:drust_pat_cli_ABC");
    }
}
