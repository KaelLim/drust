//! `drust admin tenants create|list|rm` — host-plane tenant lifecycle (/admin/api/tenants).
use crate::cli::Cli;
use crate::commands::records::finish;
use crate::ctx::Ctx;
use clap::{Args, Subcommand};
use reqwest::Method;

#[derive(Args, Debug)]
pub struct TenantsArgs {
    #[command(subcommand)]
    pub cmd: TenantsCmd,
}

#[derive(Subcommand, Debug)]
pub enum TenantsCmd {
    List,
    Create {
        #[arg(long)]
        name: String,
        #[arg(long)]
        id: Option<String>,
        #[arg(long)]
        quota_db_mb: Option<i64>,
        #[arg(long)]
        quota_rows: Option<i64>,
    },
    Rm {
        id: String,
    },
}

pub async fn run(cli: &Cli, a: &TenantsArgs) -> anyhow::Result<i32> {
    let ctx = Ctx::build(cli, false)?; // host-plane: no tenant context
    let c = &ctx.client;
    match &a.cmd {
        TenantsCmd::List => finish(&ctx, c.get("/admin/api/tenants").await),
        TenantsCmd::Create {
            name,
            id,
            quota_db_mb,
            quota_rows,
        } => {
            let mut b = serde_json::Map::new();
            b.insert("name".into(), name.clone().into());
            if let Some(i) = id {
                b.insert("id".into(), i.clone().into());
            }
            if let Some(q) = quota_db_mb {
                b.insert("quota_db_mb".into(), (*q).into());
            }
            if let Some(q) = quota_rows {
                b.insert("quota_rows".into(), (*q).into());
            }
            finish(
                &ctx,
                c.send_json(Method::POST, "/admin/api/tenants", b.into())
                    .await,
            )
        }
        TenantsCmd::Rm { id } => match c.delete(&format!("/admin/api/tenants/{id}")).await {
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
