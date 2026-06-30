//! `drust search <coll>` — vector similarity (spec §6.1).
use crate::cli::Cli;
use crate::commands::records::finish;
use crate::ctx::Ctx;
use clap::Args;
use reqwest::Method;

#[derive(Args, Debug)]
pub struct SearchArgs {
    pub coll: String,
    #[arg(long)]
    pub field: String,
    #[arg(long, default_value_t = 10)]
    pub k: u32,
    #[arg(long, default_value = "cosine")]
    pub metric: String,
    #[arg(long, conflicts_with = "vector_file")]
    pub vector: Option<String>,
    #[arg(long)]
    pub vector_file: Option<String>,
    #[arg(long)]
    pub r#where: Option<String>,
    #[arg(long)]
    pub select: Option<String>,
}

pub async fn run(cli: &Cli, a: &SearchArgs) -> anyhow::Result<i32> {
    let ctx = Ctx::build(cli, true)?;
    let vec_json: serde_json::Value = match (&a.vector, &a.vector_file) {
        (Some(v), _) => serde_json::from_str(v)?,
        (_, Some(f)) => serde_json::from_str(&std::fs::read_to_string(f)?)?,
        _ => anyhow::bail!("pass --vector '[..]' or --vector-file <path>"),
    };
    let mut body = serde_json::json!({"field":a.field,"vector":vec_json,"k":a.k,"metric":a.metric});
    if let Some(w) = &a.r#where {
        body["where"] = serde_json::from_str(w)?;
    }
    if let Some(s) = &a.select {
        body["select"] = serde_json::json!(s.split(',').collect::<Vec<_>>());
    }
    finish(
        &ctx,
        ctx.client
            .send_json(
                Method::POST,
                &format!("/t/{}/collections/{}/search", ctx.tenant, a.coll),
                body,
            )
            .await,
    )
}
