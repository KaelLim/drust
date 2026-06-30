use clap::Args;
#[derive(Args, Debug)]
pub struct UseArgs { pub tenant: String }
pub async fn run(_cli: &crate::cli::Cli, _u: &UseArgs) -> anyhow::Result<i32> { Ok(0) }
