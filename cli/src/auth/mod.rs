//! `drust auth login|logout|status` (Phase 1: --with-token only; device flow is Phase 2).
pub mod device;

use crate::cli::Cli;
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
    /// Log in by pasting an existing admin PAT (Phase 1).
    Login(LoginArgs),
    /// Remove the stored credential for a host.
    Logout,
    /// Show the active host + identity.
    Status,
}

#[derive(Args, Debug)]
pub struct LoginArgs {
    /// Instance base URL, including the /drust base_path, e.g. https://host/drust
    #[arg(long)]
    pub url: String,
    /// Paste an existing admin PAT (drust_pat_*).
    #[arg(long)]
    pub with_token: String,
}

pub async fn run(cli: &Cli, a: &AuthArgs) -> anyhow::Result<i32> {
    match &a.cmd {
        AuthCmd::Login(l) => login(cli, l),
        AuthCmd::Logout => logout(cli),
        AuthCmd::Status => status(cli),
    }
}

fn host_key(cli: &Cli) -> anyhow::Result<String> {
    cli.host
        .clone()
        .ok_or_else(|| anyhow::anyhow!("pass --host <name> to name this host"))
}

fn login(cli: &Cli, l: &LoginArgs) -> anyhow::Result<i32> {
    let key = host_key(cli)?;
    anyhow::ensure!(
        l.with_token.starts_with("drust_pat_"),
        "token must be a drust_pat_* admin PAT"
    );
    let mut cfg = store::load()?;
    let token_ref = store::write_token(&key, &l.with_token);
    cfg.hosts.insert(
        key.clone(),
        Host {
            base_url: l.url.trim_end_matches('/').to_string(),
            token_ref,
            default_console: Some("default".into()),
            default_tenant: None,
        },
    );
    cfg.active_host = Some(key.clone());
    store::save(&cfg)?;
    println!("logged in to host '{key}' ({})", l.url);
    Ok(0)
}

fn logout(cli: &Cli) -> anyhow::Result<i32> {
    let mut cfg = store::load()?;
    let key = cfg.resolve_host_key(cli.host.as_deref())?;
    cfg.hosts.remove(&key);
    if cfg.active_host.as_deref() == Some(&key) {
        cfg.active_host = cfg.hosts.keys().next().cloned();
    }
    let _ = keyring::Entry::new("drust-cli", &key).and_then(|e| e.delete_credential());
    store::save(&cfg)?;
    println!("logged out of '{key}'");
    Ok(0)
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
