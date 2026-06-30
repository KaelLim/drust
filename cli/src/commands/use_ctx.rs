//! `drust use <tenant>` — set the active host's default tenant context.
use crate::cli::Cli;
use crate::config::store;
use clap::Args;

#[derive(Args, Debug)]
pub struct UseArgs {
    /// Tenant id to make the active data-plane context.
    pub tenant: String,
}

pub async fn run(cli: &Cli, u: &UseArgs) -> anyhow::Result<i32> {
    let mut cfg = store::load()?;
    let key = cfg.resolve_host_key(cli.host.as_deref())?;
    cfg.hosts.get_mut(&key).expect("resolved").default_tenant = Some(u.tenant.clone());
    store::save(&cfg)?;
    println!("using tenant '{}' on host '{key}'", u.tenant);
    Ok(0)
}
