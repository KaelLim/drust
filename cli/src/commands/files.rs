//! `drust files …` — per-tenant file storage (spec §6.3). Garage required; 404/503 → clean exit.
use crate::cli::Cli;
use crate::commands::records::finish;
use crate::ctx::Ctx;
use clap::{Args, Subcommand};
use reqwest::Method;

#[derive(Args, Debug)]
pub struct FilesArgs {
    #[command(subcommand)]
    pub cmd: FilesCmd,
}

#[derive(Subcommand, Debug)]
pub enum FilesCmd {
    List,
    Upload {
        path: String,
        #[arg(long)]
        key: Option<String>,
        #[arg(long)]
        public: bool,
    },
    Get {
        key: String,
    },
    Download {
        key: String,
        #[arg(short = 'o', long)]
        out: String,
    },
    Delete {
        key: String,
    },
    SetVisibility {
        key: String,
        visibility: String,
    },
    Sign {
        key: String,
    },
}

pub async fn run(cli: &Cli, a: &FilesArgs) -> anyhow::Result<i32> {
    let ctx = Ctx::build(cli, true)?;
    let (t, c) = (&ctx.tenant, &ctx.client);
    match &a.cmd {
        FilesCmd::List => finish(&ctx, c.get(&format!("/t/{t}/files")).await),
        FilesCmd::Upload { path, key, public } => {
            let bytes = std::fs::read(path)?;
            let fname = key.clone().unwrap_or_else(|| {
                std::path::Path::new(path)
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            });
            let mut form = reqwest::multipart::Form::new().part(
                "file",
                reqwest::multipart::Part::bytes(bytes).file_name(fname.clone()),
            );
            if *public {
                form = form.text("visibility", "public");
            }
            finish(&ctx, c.multipart(&format!("/t/{t}/files"), form).await)
        }
        FilesCmd::Get { key } => finish(&ctx, c.get(&format!("/t/{t}/files/{key}")).await),
        FilesCmd::Download { key, out } => {
            match c.get_bytes(&format!("/t/{t}/files/{key}/bytes")).await {
                Ok(b) => {
                    std::fs::write(out, b)?;
                    ctx.renderer
                        .value(&serde_json::json!({"downloaded":key,"out":out}));
                    Ok(0)
                }
                Err(e) => {
                    ctx.renderer.error(&e);
                    Ok(e.exit_code())
                }
            }
        }
        FilesCmd::Delete { key } => match c.delete(&format!("/t/{t}/files/{key}")).await {
            Ok(()) => {
                ctx.renderer
                    .value(&serde_json::json!({"deleted":true,"key":key}));
                Ok(0)
            }
            Err(e) => {
                ctx.renderer.error(&e);
                Ok(e.exit_code())
            }
        },
        FilesCmd::SetVisibility { key, visibility } => finish(
            &ctx,
            c.send_json(
                Method::PATCH,
                &format!("/t/{t}/files/{key}"),
                serde_json::json!({"visibility":visibility}),
            )
            .await,
        ),
        FilesCmd::Sign { key } => finish(
            &ctx,
            c.send_json(
                Method::POST,
                &format!("/t/{t}/files/{key}/sign"),
                serde_json::json!({}),
            )
            .await,
        ),
    }
}
