mod auth;
mod cli;
mod commands;
mod ctx;

use clap::Parser;
use cli::{Cli, Command};
use drust_cli::{client, config, output};

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let code = run(cli).await;
    std::process::exit(code);
}

async fn run(cli: Cli) -> i32 {
    let res = match &cli.command {
        Command::Auth(a) => auth::run(&cli, a).await,
        Command::Use(u) => commands::use_ctx::run(&cli, u).await,
        Command::Records(a) => commands::records::run(&cli, a).await,
        Command::Collections(a) => commands::collections::run(&cli, a).await,
        Command::Query(a) => commands::query::run(&cli, a).await,
        Command::Search(a) => commands::search::run(&cli, a).await,
        Command::Rpc(a) => commands::rpc::run(&cli, a).await,
        Command::Functions(a) => commands::functions::run(&cli, a).await,
    };
    match res {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            64
        }
    }
}
