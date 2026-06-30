use clap::Args;
#[derive(Args, Debug)]
pub struct AuthArgs { #[command(subcommand)] pub cmd: AuthCmd }
#[derive(clap::Subcommand, Debug)]
pub enum AuthCmd { Status }
pub async fn run(_cli: &crate::cli::Cli, _a: &AuthArgs) -> anyhow::Result<i32> { Ok(0) }
