//! `drust admin audit [--tenant]` — stub, implemented in P2-8.
use crate::cli::Cli;
use clap::Args;

#[derive(Args, Debug)]
pub struct AuditArgs {}

pub async fn run(_cli: &Cli, _a: &AuditArgs) -> anyhow::Result<i32> {
    anyhow::bail!("admin audit: not yet implemented")
}
