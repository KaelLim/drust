//! `drust admin keys reroll|list` — per-tenant anon/service API keys (/admin/api/tenants/<id>/tokens).
use crate::cli::Cli;
use crate::commands::records::finish;
use crate::ctx::Ctx;
use clap::{Args, Subcommand};
use reqwest::Method;

#[derive(Args, Debug)]
pub struct KeysArgs {
    #[command(subcommand)]
    pub cmd: KeysCmd,
}

#[derive(Subcommand, Debug)]
pub enum KeysCmd {
    /// List a tenant's anon + service keys (plaintext).
    List { tenant: String },
    /// Reroll one role's key (revokes the old, returns the new).
    Reroll { tenant: String, role: String },
}

pub async fn run(cli: &Cli, a: &KeysArgs) -> anyhow::Result<i32> {
    let ctx = Ctx::build(cli, false)?;
    let c = &ctx.client;
    match &a.cmd {
        KeysCmd::List { tenant } => finish(
            &ctx,
            c.get(&format!("/admin/api/tenants/{tenant}/tokens")).await,
        ),
        KeysCmd::Reroll { tenant, role } => finish(
            &ctx,
            c.send_json(
                Method::POST,
                &format!("/admin/api/tenants/{tenant}/tokens/{role}/reroll"),
                serde_json::json!({}),
            )
            .await,
        ),
    }
}
