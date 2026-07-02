//! `drust collections …` — reads via REST, schema mutation via MCP tools/call (spec §6.1, D-1).
use crate::cli::Cli;
use crate::client::mcp;
use crate::commands::records::finish;
use crate::ctx::Ctx;
use clap::{Args, Subcommand};

#[derive(Args, Debug)]
pub struct CollectionsArgs {
    #[command(subcommand)]
    pub cmd: CollectionsCmd,
}

#[derive(Subcommand, Debug)]
pub enum CollectionsCmd {
    List,
    Describe {
        coll: String,
    },
    Overview,
    Openapi,
    Types,
    Zod,
    /// create_collection via MCP
    Create {
        name: String,
        #[arg(long, default_value = "[]")]
        fields: String,
    },
    /// add_field via MCP
    AddField {
        coll: String,
        #[arg(long)]
        field: String,
    },
    /// drop_collection via MCP
    Drop {
        coll: String,
    },
    /// set_anon_caps / set_user_caps via MCP
    SetCaps {
        coll: String,
        #[arg(long)]
        anon: Option<String>,
        #[arg(long)]
        user: Option<String>,
    },
}

pub async fn run(cli: &Cli, a: &CollectionsArgs) -> anyhow::Result<i32> {
    let ctx = Ctx::build(cli, true)?;
    let (t, c) = (&ctx.tenant, &ctx.client);
    match &a.cmd {
        CollectionsCmd::List => finish(&ctx, c.get(&format!("/t/{t}/collections")).await),
        CollectionsCmd::Describe { coll } => finish(&ctx, c.get(&format!("/t/{t}/collections/{coll}")).await),
        CollectionsCmd::Overview => finish(&ctx, c.get(&format!("/t/{t}/schema/overview")).await),
        CollectionsCmd::Openapi => finish(&ctx, c.get(&format!("/t/{t}/openapi.json")).await),
        CollectionsCmd::Types => { print_text(&ctx, &format!("/t/{t}/types.ts")).await }
        CollectionsCmd::Zod => { print_text(&ctx, &format!("/t/{t}/zod.ts")).await }
        CollectionsCmd::Create { name, fields } =>
            finish(&ctx, mcp::call_tool(c, t, "create_collection",
                serde_json::json!({"name":name,"fields": serde_json::from_str::<serde_json::Value>(fields)?})).await),
        CollectionsCmd::AddField { coll, field } =>
            finish(&ctx, mcp::call_tool(c, t, "add_field",
                serde_json::json!({"collection":coll,"field": serde_json::from_str::<serde_json::Value>(field)?})).await),
        CollectionsCmd::Drop { coll } =>
            finish(&ctx, mcp::call_tool(c, t, "drop_collection", serde_json::json!({"collection":coll})).await),
        CollectionsCmd::SetCaps { coll, anon, user } => {
            if anon.is_none() && user.is_none() {
                anyhow::bail!("pass --anon and/or --user (a JSON caps array)");
            }
            if let Some(a) = anon {
                let r = mcp::call_tool(c, t, "set_anon_caps",
                    serde_json::json!({"collection":coll,"caps": serde_json::from_str::<serde_json::Value>(a)?})).await;
                if r.is_err() {
                    return finish(&ctx, r);
                }
            }
            if let Some(u) = user {
                let r = mcp::call_tool(c, t, "set_user_caps",
                    serde_json::json!({"collection":coll,"caps": serde_json::from_str::<serde_json::Value>(u)?})).await;
                if r.is_err() {
                    return finish(&ctx, r);
                }
            }
            ctx.renderer.value(&serde_json::json!({"ok":true}));
            Ok(0)
        }
    }
}

async fn print_text(ctx: &Ctx, path: &str) -> anyhow::Result<i32> {
    match ctx.client.get_bytes(path).await {
        Ok(b) => {
            print!("{}", String::from_utf8_lossy(&b));
            Ok(0)
        }
        Err(e) => {
            ctx.renderer.error(&e);
            Ok(e.exit_code())
        }
    }
}
