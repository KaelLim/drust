//! `drust admin team list|invite|rm|role` — host admin team CRUD (/admin/team).
//! Role enforcement is server-side (NOT_OWNER surfaces as a 4xx); the CLI adds no client-side gate.
use crate::cli::Cli;
use crate::commands::records::finish;
use crate::ctx::Ctx;
use clap::{Args, Subcommand};
use reqwest::Method;

#[derive(Args, Debug)]
pub struct TeamArgs {
    #[command(subcommand)]
    pub cmd: TeamCmd,
}

#[derive(Subcommand, Debug)]
pub enum TeamCmd {
    /// List host admins.
    List,
    /// Invite an admin by email (optionally with a role).
    Invite {
        email: String,
        #[arg(long)]
        role: Option<String>,
    },
    /// Remove an admin by id.
    Rm { id: i64 },
    /// Change an admin's role.
    Role { id: i64, role: String },
}

pub async fn run(cli: &Cli, a: &TeamArgs) -> anyhow::Result<i32> {
    let ctx = Ctx::build(cli, false)?;
    let c = &ctx.client;
    match &a.cmd {
        TeamCmd::List => finish(&ctx, c.get("/admin/team").await),
        TeamCmd::Invite { email, role } => {
            let mut b = serde_json::Map::new();
            b.insert("email".into(), email.clone().into());
            if let Some(r) = role {
                b.insert("role".into(), r.clone().into());
            }
            finish(
                &ctx,
                c.send_json(Method::POST, "/admin/team", b.into()).await,
            )
        }
        TeamCmd::Role { id, role } => finish(
            &ctx,
            c.send_json(
                Method::PATCH,
                &format!("/admin/team/{id}/role"),
                serde_json::json!({ "role": role }),
            )
            .await,
        ),
        TeamCmd::Rm { id } => match c.delete(&format!("/admin/team/{id}")).await {
            Ok(()) => {
                ctx.renderer
                    .value(&serde_json::json!({"removed":true,"id":id}));
                Ok(0)
            }
            Err(e) => {
                ctx.renderer.error(&e);
                Ok(e.exit_code())
            }
        },
    }
}
