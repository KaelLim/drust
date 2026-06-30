//! `drust admin audit [--tenant] [--op] [--status] [--window]` — host/per-tenant audit JSON.
use crate::cli::Cli;
use crate::commands::records::finish;
use crate::ctx::Ctx;
use clap::Args;

#[derive(Args, Debug)]
pub struct AuditArgs {
    #[arg(long)]
    tenant: Option<String>,
    #[arg(long)]
    op: Option<String>,
    #[arg(long)]
    status: Option<String>,
    #[arg(long)]
    window: Option<String>,
}

pub async fn run(cli: &Cli, a: &AuditArgs) -> anyhow::Result<i32> {
    let ctx = Ctx::build(cli, false)?;
    let mut q: Vec<String> = vec![];
    for (k, v) in [("op", &a.op), ("status", &a.status), ("window", &a.window)] {
        if let Some(val) = v {
            q.push(format!("{k}={}", urlencoding::encode(val)));
        }
    }
    let qs = if q.is_empty() {
        String::new()
    } else {
        format!("?{}", q.join("&"))
    };
    let path = match &a.tenant {
        Some(t) => format!("/admin/api/tenants/{t}/audit{qs}"),
        None => format!("/admin/api/audit{qs}"),
    };
    finish(&ctx, ctx.client.get(&path).await)
}
