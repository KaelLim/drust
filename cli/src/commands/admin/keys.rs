//! `drust admin keys reroll|list` — stub, implemented in P2-6.
use crate::cli::Cli;
use clap::Args;

#[derive(Args, Debug)]
pub struct KeysArgs {}

pub async fn run(_cli: &Cli, _a: &KeysArgs) -> anyhow::Result<i32> {
    anyhow::bail!("admin keys: not yet implemented")
}
