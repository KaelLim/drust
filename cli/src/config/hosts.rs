//! `~/.config/drust/hosts.toml` model + host resolution (spec §7.2).
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Host {
    /// External mount verbatim, INCLUDING the /drust base_path. Never modified by the CLI.
    pub base_url: String,
    /// "keyring" or "inline:<pat>".
    pub token_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_console: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_tenant: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HostsConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_host: Option<String>,
    #[serde(default)]
    pub hosts: BTreeMap<String, Host>,
}

impl HostsConfig {
    pub fn parse(toml_str: &str) -> anyhow::Result<HostsConfig> {
        Ok(toml::from_str(toml_str)?)
    }

    pub fn to_toml(&self) -> String {
        toml::to_string_pretty(self).unwrap_or_default()
    }

    /// Explicit flag (must exist) → else `active_host` → else error.
    pub fn resolve_host_key(&self, flag: Option<&str>) -> anyhow::Result<String> {
        if let Some(k) = flag {
            anyhow::ensure!(self.hosts.contains_key(k), "no such host '{k}' in config");
            return Ok(k.to_string());
        }
        self.active_host
            .clone()
            .filter(|k| self.hosts.contains_key(k))
            .ok_or_else(|| anyhow::anyhow!("no host configured — run 'drust auth login'"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
active_host = "tool"
[hosts.tool]
base_url = "https://tool.tzuchi-org.tw/drust"
token_ref = "inline:drust_pat_cli_abc"
default_tenant = "9f1c"
"#;

    #[test]
    fn parse_roundtrip_and_resolution() {
        let cfg = HostsConfig::parse(SAMPLE).unwrap();
        let h = &cfg.hosts["tool"];
        assert_eq!(h.base_url, "https://tool.tzuchi-org.tw/drust");
        assert_eq!(h.token_ref, "inline:drust_pat_cli_abc");
        assert_eq!(h.default_tenant.as_deref(), Some("9f1c"));
        // resolution: explicit flag wins, else active_host, else error
        assert_eq!(cfg.resolve_host_key(Some("tool")).unwrap(), "tool");
        assert_eq!(cfg.resolve_host_key(None).unwrap(), "tool");
        assert!(cfg.resolve_host_key(Some("nope")).is_err());
        // toml roundtrips
        let cfg2 = HostsConfig::parse(&cfg.to_toml()).unwrap();
        assert_eq!(cfg2.hosts["tool"].base_url, h.base_url);
    }
}
