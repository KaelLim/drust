//! `drust functions …` — data-plane edge functions (spec §6.2). Create is multipart-only.
use crate::cli::Cli;
use crate::commands::records::finish;
use crate::ctx::Ctx;
use clap::{Args, Subcommand};
use reqwest::Method;

#[derive(Args, Debug)]
pub struct FunctionsArgs {
    #[command(subcommand)]
    pub cmd: FunctionsCmd,
}

#[derive(Subcommand, Debug)]
pub enum FunctionsCmd {
    List,
    Get {
        name: String,
    },
    Create {
        name: String,
        #[arg(long)]
        wasm: String,
        #[arg(long)]
        triggers: Option<String>,
        #[arg(long)]
        description: Option<String>,
    },
    SetActive {
        name: String,
        active: bool,
    },
    SetInvokeAcl {
        name: String,
        #[arg(long)]
        anon: Option<bool>,
        #[arg(long)]
        user: Option<bool>,
    },
    Delete {
        name: String,
    },
    Invoke {
        name: String,
        #[arg(long, default_value = "{}")]
        event: String,
    },
    Logs {
        name: String,
        #[arg(long, default_value_t = 50)]
        limit: u32,
    },
}

pub async fn run(cli: &Cli, a: &FunctionsArgs) -> anyhow::Result<i32> {
    let ctx = Ctx::build(cli, true)?;
    let (t, c) = (&ctx.tenant, &ctx.client);
    match &a.cmd {
        FunctionsCmd::List => finish(&ctx, c.get(&format!("/t/{t}/functions")).await),
        FunctionsCmd::Get { name } => {
            finish(&ctx, c.get(&format!("/t/{t}/functions/{name}")).await)
        }
        FunctionsCmd::Create {
            name,
            wasm,
            triggers,
            description,
        } => {
            let bytes = std::fs::read(wasm)?;
            let mut form = reqwest::multipart::Form::new()
                .text("name", name.clone())
                .part(
                    "wasm",
                    reqwest::multipart::Part::bytes(bytes).file_name("fn.wasm"),
                );
            if let Some(tr) = triggers {
                form = form.text("triggers", tr.clone());
            }
            if let Some(d) = description {
                form = form.text("description", d.clone());
            }
            finish(&ctx, c.multipart(&format!("/t/{t}/functions"), form).await)
        }
        FunctionsCmd::SetActive { name, active } => finish(
            &ctx,
            c.send_json(
                Method::PATCH,
                &format!("/t/{t}/functions/{name}"),
                serde_json::json!({"active":active}),
            )
            .await,
        ),
        FunctionsCmd::SetInvokeAcl { name, anon, user } => {
            let mut b = serde_json::Map::new();
            if let Some(a) = anon {
                b.insert("invoke_anon".into(), (*a).into());
            }
            if let Some(u) = user {
                b.insert("invoke_user".into(), (*u).into());
            }
            finish(
                &ctx,
                c.send_json(
                    Method::PATCH,
                    &format!("/t/{t}/functions/{name}"),
                    serde_json::Value::Object(b),
                )
                .await,
            )
        }
        FunctionsCmd::Delete { name } => {
            match c.delete(&format!("/t/{t}/functions/{name}")).await {
                Ok(()) => {
                    ctx.renderer
                        .value(&serde_json::json!({"deleted":true,"name":name}));
                    Ok(0)
                }
                Err(e) => {
                    ctx.renderer.error(&e);
                    Ok(e.exit_code())
                }
            }
        }
        FunctionsCmd::Invoke { name, event } => finish(
            &ctx,
            c.send_json(
                Method::POST,
                &format!("/t/{t}/functions/{name}/invoke"),
                serde_json::json!({"event": serde_json::from_str::<serde_json::Value>(event)?}),
            )
            .await,
        ),
        FunctionsCmd::Logs { name, limit } => finish(
            &ctx,
            c.get(&format!("/t/{t}/functions/{name}/logs?limit={limit}"))
                .await,
        ),
    }
}
