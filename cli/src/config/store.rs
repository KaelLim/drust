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
    write_0600(&p, &cfg.to_toml())?;
    Ok(())
}

#[cfg(unix)]
fn write_0600(p: &std::path::Path, contents: &str) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    // create-with-mode closes the umask 0644 window for a fresh file...
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(p)?;
    // ...and downgrade a pre-existing 0644 file (mode() is create-only).
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600))?;
    f.write_all(contents.as_bytes())?;
    Ok(())
}

#[cfg(not(unix))]
fn write_0600(p: &std::path::Path, contents: &str) -> anyhow::Result<()> {
    std::fs::write(p, contents)?;
    Ok(())
}

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

    #[cfg(unix)]
    #[test]
    fn write_0600_forces_owner_only_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("hosts.toml");
        // Pre-existing world-readable file must be downgraded, not left 0644.
        std::fs::write(&p, "old").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_0600(&p, "active_host = \"t\"\n").unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "active_host = \"t\"\n");
    }
}
