//! `drust admin backups list|inspect|download|restore` — snapshot management.
//! restore answers a 303 → inspect?dest=…; the CLI captures it (no auto-follow) and decodes the path.
use crate::cli::Cli;
use crate::commands::records::finish;
use crate::ctx::Ctx;
use clap::{Args, Subcommand};

#[derive(Args, Debug)]
pub struct BackupsArgs {
    #[command(subcommand)]
    pub cmd: BackupsCmd,
}

#[derive(Subcommand, Debug)]
pub enum BackupsCmd {
    /// List backup snapshots.
    List,
    /// Inspect one snapshot (tenants + sizes).
    Inspect { filename: String },
    /// Download a snapshot's raw bytes to a file.
    Download {
        filename: String,
        #[arg(short = 'o', long)]
        out: String,
    },
    /// Restore a snapshot into _trash (manual mv into place afterwards).
    Restore {
        filename: String,
        #[arg(long)]
        tenant: String,
    },
}

pub async fn run(cli: &Cli, a: &BackupsArgs) -> anyhow::Result<i32> {
    let ctx = Ctx::build(cli, false)?;
    let c = &ctx.client;
    match &a.cmd {
        BackupsCmd::List => finish(&ctx, c.get("/admin/api/backups").await),
        BackupsCmd::Inspect { filename } => finish(
            &ctx,
            c.get(&format!("/admin/api/backups/{filename}/inspect")).await,
        ),
        BackupsCmd::Download { filename, out } => {
            match c
                .get_bytes(&format!("/admin/backups/{filename}/download"))
                .await
            {
                Ok(b) => {
                    std::fs::write(out, b)?;
                    ctx.renderer
                        .value(&serde_json::json!({"downloaded":filename,"out":out}));
                    Ok(0)
                }
                Err(e) => {
                    ctx.renderer.error(&e);
                    Ok(e.exit_code())
                }
            }
        }
        BackupsCmd::Restore { filename, tenant } => {
            match c
                .post_form_capture_redirect(
                    &format!("/admin/backups/{filename}/restore"),
                    &[("tenant_id", tenant)],
                )
                .await
            {
                Ok(info) => {
                    let dest = info
                        .location
                        .split("dest=")
                        .nth(1)
                        .map(|s| {
                            urlencoding::decode(s)
                                .map(|c| c.into_owned())
                                .unwrap_or_default()
                        })
                        .unwrap_or_default();
                    ctx.renderer.value(&serde_json::json!({
                        "restored_to": dest,
                        "note": "extracted under _trash; review, then manually mv into place"}));
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
