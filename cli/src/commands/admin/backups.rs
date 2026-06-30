//! `drust admin backups list|inspect|download|restore` — stub, implemented in P2-8.
use crate::cli::Cli;
use clap::Args;

#[derive(Args, Debug)]
pub struct BackupsArgs {}

pub async fn run(_cli: &Cli, _a: &BackupsArgs) -> anyhow::Result<i32> {
    anyhow::bail!("admin backups: not yet implemented")
}
