//! `drust rpc call|list` (spec §6.1, D-3: list reads schema/overview).
use crate::cli::Cli;
use crate::commands::records::finish;
use crate::ctx::Ctx;
use clap::{Args, Subcommand};
use reqwest::Method;

#[derive(Args, Debug)]
pub struct RpcArgs { #[command(subcommand)] pub cmd: RpcCmd }

#[derive(Subcommand, Debug)]
pub enum RpcCmd {
    Call { name: String, #[arg(long)] params: Option<String>, #[arg(long)] dry_run: bool },
    List,
}

pub async fn run(cli: &Cli, a: &RpcArgs) -> anyhow::Result<i32> {
    let ctx = Ctx::build(cli, true)?;
    let t = &ctx.tenant;
    match &a.cmd {
        RpcCmd::Call { name, params, dry_run } => {
            let body: serde_json::Value = match params { Some(p) => serde_json::from_str(p)?, None => serde_json::json!({}) };
            let q = if *dry_run { "?dry_run=true" } else { "" };
            finish(&ctx, ctx.client.send_json(Method::POST, &format!("/t/{t}/rpc/{name}{q}"), body).await)
        }
        RpcCmd::List => {
            match ctx.client.get(&format!("/t/{t}/schema/overview")).await {
                Ok(v) => { ctx.renderer.value(v.get("rpcs").unwrap_or(&serde_json::Value::Null)); Ok(0) }
                Err(e) => { ctx.renderer.error(&e); Ok(e.exit_code()) }
            }
        }
    }
}
