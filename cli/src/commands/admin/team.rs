//! `drust admin team list|invite|rm|role` — stub, implemented in P2-7.
use crate::cli::Cli;
use clap::Args;

#[derive(Args, Debug)]
pub struct TeamArgs {}

pub async fn run(_cli: &Cli, _a: &TeamArgs) -> anyhow::Result<i32> {
    anyhow::bail!("admin team: not yet implemented")
}
