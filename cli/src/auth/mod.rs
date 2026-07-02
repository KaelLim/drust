//! `drust auth login|logout|status` (Phase 1: --with-token only; device flow is Phase 2).
pub mod device;

use crate::cli::Cli;
use crate::client::http::DrustClient;
use crate::config::hosts::Host;
use crate::config::store;
use clap::{Args, Subcommand};

#[derive(Args, Debug)]
pub struct AuthArgs {
    #[command(subcommand)]
    pub cmd: AuthCmd,
}

#[derive(Subcommand, Debug)]
pub enum AuthCmd {
    /// Log in via the gh-style device flow (or --with-token to paste a PAT).
    Login(LoginArgs),
    /// Re-mint the CLI PAT (server soft-revokes the old one).
    Refresh,
    /// Revoke the CLI PAT server-side, then remove the stored credential.
    Logout,
    /// Show the active host + identity.
    Status,
}

#[derive(Args, Debug)]
pub struct LoginArgs {
    /// Instance base URL, including the /drust base_path, e.g. https://host/drust
    #[arg(long)]
    pub url: Option<String>,
    /// Use the baked drust.com cloud host (not yet available).
    #[arg(long)]
    pub cloud: bool,
    /// Paste an existing admin PAT (drust_pat_*) — Phase-1 escape hatch.
    #[arg(long)]
    pub with_token: Option<String>,
    /// Label for the minted CLI PAT (default drust-cli@<hostname>).
    #[arg(long)]
    pub label: Option<String>,
    /// Do not auto-open the verification URL in a browser.
    #[arg(long)]
    pub no_browser: bool,
    /// Allow cleartext http:// to a non-loopback host (NOT recommended).
    #[arg(long)]
    pub insecure: bool,
}

fn guard_scheme(url: &str, insecure: bool) -> anyhow::Result<()> {
    // Case-insensitive: reqwest lowercases the scheme, so `HTTP://` must not
    // slip past the guard (F12 review). Lowercasing is safe here — schemes and
    // hostnames are case-insensitive, and IP/port are numeric.
    let lower = url.trim_start().to_ascii_lowercase();
    if let Some(rest) = lower.strip_prefix("http://") {
        let host = rest.split('/').next().unwrap_or("");
        // Strip the port; handle the `[::1]:8793` IPv6 bracket form too.
        let host_only = if let Some(inner) = host.strip_prefix('[') {
            inner.split(']').next().unwrap_or(inner)
        } else {
            host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host)
        };
        // Loopback iff it is literally `localhost` OR parses as a loopback IP.
        // A hostname like `127.evil.com` / `127.0.0.1.evil.com` is NOT a valid
        // IpAddr, so it is correctly treated as remote (F12 review — the old
        // `starts_with("127.")` classified those as loopback).
        let is_loopback = host_only == "localhost"
            || host_only
                .parse::<std::net::IpAddr>()
                .map(|ip| ip.is_loopback())
                .unwrap_or(false);
        if !is_loopback && !insecure {
            anyhow::bail!(
                "refusing to send credentials over cleartext http:// to '{host_only}'; use https:// or pass --insecure for a trusted local network"
            );
        }
    }
    Ok(())
}

pub async fn run(cli: &Cli, a: &AuthArgs) -> anyhow::Result<i32> {
    match &a.cmd {
        AuthCmd::Login(l) => login(cli, l).await,
        AuthCmd::Refresh => refresh(cli).await,
        AuthCmd::Logout => logout(cli).await,
        AuthCmd::Status => status(cli),
    }
}

fn host_key(cli: &Cli) -> anyhow::Result<String> {
    cli.host
        .clone()
        .ok_or_else(|| anyhow::anyhow!("pass --host <name> to name this host"))
}

const DRUST_CLOUD_HOST: &str = "https://drust.com"; // D-12: forward-looking; OSS uses --url

/// Label stamped on the minted CLI PAT (`drust-cli@<hostname>`); falls back to a const.
fn default_label() -> String {
    let host = std::env::var("HOSTNAME")
        .ok()
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "cli".to_string());
    format!("drust-cli@{host}")
}

async fn login(cli: &Cli, l: &LoginArgs) -> anyhow::Result<i32> {
    let key = host_key(cli)?;
    let base_url = match (&l.url, l.cloud) {
        (Some(u), _) => u.trim_end_matches('/').to_string(),
        (None, true) => {
            anyhow::bail!(
                "cloud ({DRUST_CLOUD_HOST}) not yet available — pass --url <instance incl. /drust>"
            )
        }
        (None, false) => anyhow::bail!("pass --url <instance incl. /drust> or --cloud"),
    };
    guard_scheme(&base_url, l.insecure)?;
    let (token, console) = if let Some(pat_arg) = &l.with_token {
        let pat = if pat_arg == "-" {
            use std::io::Read;
            let mut s = String::new();
            std::io::stdin().read_to_string(&mut s)?;
            s.trim().to_string()
        } else {
            eprintln!(
                "warning: passing a token on the command line leaks it into shell history and `ps`; prefer `--with-token -` to read it from stdin, or the default device flow"
            );
            pat_arg.clone()
        };
        anyhow::ensure!(
            pat.starts_with("drust_pat_"),
            "token must be a drust_pat_* admin PAT"
        );
        (pat, Some("default".to_string()))
    } else {
        let label = l.label.clone().unwrap_or_else(default_label);
        let grant = crate::auth::device::run_device_flow(&base_url, &label, !l.no_browser).await?;
        if let Some(exp) = &grant.expires_at {
            eprintln!("CLI token expires at {exp}");
        }
        let console = grant
            .consoles
            .as_ref()
            .and_then(|c| c.get(0))
            .and_then(|c| c.get("id"))
            .and_then(|v| v.as_str())
            .unwrap_or("default")
            .to_string();
        (grant.token, Some(console))
    };
    let mut cfg = store::load()?;
    let token_ref = store::write_token(&key, &token);
    cfg.hosts.insert(
        key.clone(),
        Host {
            base_url: base_url.clone(),
            token_ref,
            default_console: console,
            default_tenant: None,
        },
    );
    cfg.active_host = Some(key.clone());
    store::save(&cfg)?;
    println!("logged in to host '{key}' ({base_url})");
    Ok(0)
}

async fn refresh(cli: &Cli) -> anyhow::Result<i32> {
    let cfg = store::load()?;
    let key = cfg.resolve_host_key(cli.host.as_deref())?;
    let host = cfg.hosts.get(&key).expect("resolved").clone();
    let client = DrustClient::new(host.base_url.clone(), store::read_token(&key, &host)?);
    let v = client
        .send_json(
            reqwest::Method::POST,
            "/auth/cli/token/refresh",
            serde_json::json!({}),
        )
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let new = v["access_token"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no access_token in refresh"))?;
    let mut cfg = cfg;
    cfg.hosts.get_mut(&key).unwrap().token_ref = store::write_token(&key, new);
    store::save(&cfg)?;
    println!("refreshed PAT for '{key}'");
    Ok(0)
}

async fn logout(cli: &Cli) -> anyhow::Result<i32> {
    let mut cfg = store::load()?;
    let key = cfg.resolve_host_key(cli.host.as_deref())?;
    if let Some(host) = cfg.hosts.get(&key).cloned() {
        // Best-effort server-side revoke before clearing local state.
        if let Ok(tok) = store::read_token(&key, &host) {
            match DrustClient::new(host.base_url, tok)
                .delete("/auth/cli/token")
                .await
            {
                Ok(_) => {}
                Err(e) => eprintln!(
                    "warning: server-side revoke failed ({e}); this token may remain valid until it expires — run `drust auth refresh` from a trusted host or revoke it in the admin UI"
                ),
            }
        }
    }
    cfg.hosts.remove(&key);
    if cfg.active_host.as_deref() == Some(&key) {
        cfg.active_host = cfg.hosts.keys().next().cloned();
    }
    let _ = keyring::Entry::new("drust-cli", &key).and_then(|e| e.delete_credential());
    store::save(&cfg)?;
    println!("logged out of '{key}'");
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::guard_scheme;

    #[test]
    fn guard_scheme_rules() {
        // cleartext to a public host is refused without --insecure
        assert!(guard_scheme("http://example.com/drust", false).is_err());
        // https is always fine
        assert!(guard_scheme("https://example.com/drust", false).is_ok());
        // loopback over http is fine (dev)
        assert!(guard_scheme("http://127.0.0.1:8793/drust", false).is_ok());
        assert!(guard_scheme("http://localhost:8793/drust", false).is_ok());
        assert!(guard_scheme("http://[::1]:8793/drust", false).is_ok());
        // --insecure opts into cleartext to a public host
        assert!(guard_scheme("http://example.com/drust", true).is_ok());
        // F12 review: a hostname that merely LOOKS loopback is remote — the
        // `127.evil.com` / `127.0.0.1.evil.com` subdomain trick must be refused.
        assert!(guard_scheme("http://127.evil.com/drust", false).is_err());
        assert!(guard_scheme("http://127.0.0.1.evil.com/drust", false).is_err());
        // F12 review: the scheme check is case-insensitive — `HTTP://` to a
        // remote host is still refused (reqwest lowercases the scheme).
        assert!(guard_scheme("HTTP://example.com/drust", false).is_err());
        assert!(guard_scheme("Http://example.com/drust", false).is_err());
        // and case-insensitive loopback still passes
        assert!(guard_scheme("HTTP://127.0.0.1:8793/drust", false).is_ok());
    }
}

fn status(cli: &Cli) -> anyhow::Result<i32> {
    let cfg = store::load()?;
    let key = cfg.resolve_host_key(cli.host.as_deref())?;
    let h = cfg.hosts.get(&key).expect("resolved");
    println!("host: {key}  ({})", h.base_url);
    if let Some(t) = &h.default_tenant {
        println!("tenant: {t}");
    }
    Ok(0)
}
