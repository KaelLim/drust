//! `drust query <sql>` — service-only raw SELECT, hidden behind --unsafe (spec D-5).
use crate::cli::Cli;
use crate::commands::records::finish;
use crate::ctx::Ctx;
use clap::Args;
use reqwest::Method;

#[derive(Args, Debug)]
pub struct QueryArgs {
    pub sql: String,
    /// Required acknowledgement: /query is raw, service-only, 10k-row capped.
    #[arg(long)] pub r#unsafe: bool,
    #[arg(long)] pub explain: bool,
}

pub async fn run(cli: &Cli, a: &QueryArgs) -> anyhow::Result<i32> {
    anyhow::ensure!(a.r#unsafe, "drust query runs raw SQL (service-only); pass --unsafe to confirm, or use 'records list'/'search'");
    let ctx = Ctx::build(cli, true)?;
    let p = if a.explain { format!("/t/{}/query/explain", ctx.tenant) } else { format!("/t/{}/query", ctx.tenant) };
    finish(&ctx, ctx.client.send_json(Method::POST, &p, serde_json::json!({"sql": a.sql})).await)
}
