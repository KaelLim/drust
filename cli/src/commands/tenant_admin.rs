//! Per-tenant config subtrees: users / webhooks / oauth (service-only JSON, PAT reaches today).
use crate::cli::Cli;
use crate::commands::records::finish;
use crate::ctx::Ctx;
use clap::{Args, Subcommand};
use reqwest::Method;

#[derive(Args, Debug)]
pub struct UsersArgs {
    #[command(subcommand)]
    pub cmd: UsersCmd,
}
#[derive(Subcommand, Debug)]
pub enum UsersCmd {
    List,
    Create {
        #[arg(long)]
        data: String,
    },
    Delete {
        id: String,
    },
}

pub async fn users_run(cli: &Cli, a: &UsersArgs) -> anyhow::Result<i32> {
    let ctx = Ctx::build(cli, true)?;
    let (t, c) = (&ctx.tenant, &ctx.client);
    match &a.cmd {
        UsersCmd::List => finish(&ctx, c.get(&format!("/t/{t}/admin/users")).await),
        UsersCmd::Create { data } => finish(
            &ctx,
            c.send_json(
                Method::POST,
                &format!("/t/{t}/admin/users"),
                serde_json::from_str(data)?,
            )
            .await,
        ),
        UsersCmd::Delete { id } => match c.delete(&format!("/t/{t}/admin/users/{id}")).await {
            Ok(_) => {
                ctx.renderer
                    .value(&serde_json::json!({"deleted":true,"id":id}));
                Ok(0)
            }
            Err(e) => {
                ctx.renderer.error(&e);
                Ok(e.exit_code())
            }
        },
    }
}

#[derive(Args, Debug)]
pub struct WebhooksArgs {
    #[command(subcommand)]
    pub cmd: WebhooksCmd,
}
#[derive(Subcommand, Debug)]
pub enum WebhooksCmd {
    List,
    Create {
        #[arg(long)]
        data: String,
    },
    Delete {
        id: String,
    },
}

pub async fn webhooks_run(cli: &Cli, a: &WebhooksArgs) -> anyhow::Result<i32> {
    let ctx = Ctx::build(cli, true)?;
    let (t, c) = (&ctx.tenant, &ctx.client);
    match &a.cmd {
        WebhooksCmd::List => finish(&ctx, c.get(&format!("/t/{t}/admin/webhooks")).await),
        WebhooksCmd::Create { data } => finish(
            &ctx,
            c.send_json(
                Method::POST,
                &format!("/t/{t}/admin/webhooks"),
                serde_json::from_str(data)?,
            )
            .await,
        ),
        WebhooksCmd::Delete { id } => {
            match c.delete(&format!("/t/{t}/admin/webhooks/{id}")).await {
                Ok(_) => {
                    ctx.renderer
                        .value(&serde_json::json!({"deleted":true,"id":id}));
                    Ok(0)
                }
                Err(e) => {
                    ctx.renderer.error(&e);
                    Ok(e.exit_code())
                }
            }
        }
    }
}

#[derive(Args, Debug)]
pub struct OauthArgs {
    #[command(subcommand)]
    pub cmd: OauthCmd,
}
#[derive(Subcommand, Debug)]
pub enum OauthCmd {
    Get {
        provider: String,
    },
    Put {
        provider: String,
        #[arg(long)]
        data: String,
    },
    Delete {
        provider: String,
    },
}

pub async fn oauth_run(cli: &Cli, a: &OauthArgs) -> anyhow::Result<i32> {
    let ctx = Ctx::build(cli, true)?;
    let (t, c) = (&ctx.tenant, &ctx.client);
    match &a.cmd {
        OauthCmd::Get { provider } => finish(
            &ctx,
            c.get(&format!("/t/{t}/admin/oauth-providers/{provider}"))
                .await,
        ),
        OauthCmd::Put { provider, data } => finish(
            &ctx,
            c.send_json(
                Method::PUT,
                &format!("/t/{t}/admin/oauth-providers/{provider}"),
                serde_json::from_str(data)?,
            )
            .await,
        ),
        OauthCmd::Delete { provider } => match c
            .delete(&format!("/t/{t}/admin/oauth-providers/{provider}"))
            .await
        {
            Ok(_) => {
                ctx.renderer
                    .value(&serde_json::json!({"deleted":true,"provider":provider}));
                Ok(0)
            }
            Err(e) => {
                ctx.renderer.error(&e);
                Ok(e.exit_code())
            }
        },
    }
}
