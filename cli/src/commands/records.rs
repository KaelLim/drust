//! `drust records …` — data-plane record CRUD (spec §6.1).
use crate::cli::Cli;
use crate::ctx::Ctx;
use clap::{Args, Subcommand};
use reqwest::Method;

#[derive(Args, Debug)]
pub struct RecordsArgs {
    #[command(subcommand)]
    pub cmd: RecordsCmd,
}

#[derive(Subcommand, Debug)]
pub enum RecordsCmd {
    /// List records: POST /collections/<coll>/list
    List {
        coll: String,
        #[arg(long)] filter: Option<String>,
        #[arg(long)] sort: Option<String>,
        #[arg(long, default_value_t = 1)] page: u32,
        #[arg(long, default_value_t = 50)] per_page: u32,
        #[arg(long)] select: Option<String>,
    },
    Get { coll: String, id: i64 },
    Create { coll: String, #[arg(long)] data: String },
    Update { coll: String, id: i64, #[arg(long)] data: String },
    Delete { coll: String, id: i64, #[arg(long)] dry_run: bool },
}

pub async fn run(cli: &Cli, a: &RecordsArgs) -> anyhow::Result<i32> {
    let ctx = Ctx::build(cli, true)?;
    let t = &ctx.tenant;
    match &a.cmd {
        RecordsCmd::List { coll, filter, sort, page, per_page, select } => {
            let mut body = serde_json::Map::new();
            if let Some(f) = filter { body.insert("filter".into(), serde_json::from_str(f)?); }
            if let Some(s) = sort {
                let (field, dir) = s.split_once(':').unwrap_or((s, "asc"));
                body.insert("sort".into(), serde_json::json!({"field":field,"dir":dir}));
            }
            body.insert("page".into(), (*page).into());
            body.insert("per_page".into(), (*per_page).into());
            if let Some(sel) = select {
                body.insert("select".into(), serde_json::json!(sel.split(',').collect::<Vec<_>>()));
            }
            finish(&ctx, ctx.client.send_json(Method::POST,
                &format!("/t/{t}/collections/{coll}/list"), serde_json::Value::Object(body)).await)
        }
        RecordsCmd::Get { coll, id } =>
            finish(&ctx, ctx.client.get(&format!("/t/{t}/records/{coll}/{id}")).await),
        RecordsCmd::Create { coll, data } =>
            finish(&ctx, ctx.client.send_json(Method::POST,
                &format!("/t/{t}/records/{coll}"),
                serde_json::json!({"data": serde_json::from_str::<serde_json::Value>(data)?})).await),
        RecordsCmd::Update { coll, id, data } =>
            finish(&ctx, ctx.client.send_json(Method::PATCH,
                &format!("/t/{t}/records/{coll}/{id}"),
                serde_json::json!({"data": serde_json::from_str::<serde_json::Value>(data)?})).await),
        RecordsCmd::Delete { coll, id, dry_run } => {
            let q = if *dry_run { "?dry_run=true" } else { "" };
            if *dry_run {
                finish(&ctx, ctx.client.send_json(Method::DELETE,
                    &format!("/t/{t}/records/{coll}/{id}{q}"), serde_json::Value::Null).await)
            } else {
                match ctx.client.delete(&format!("/t/{t}/records/{coll}/{id}")).await {
                    Ok(()) => { ctx.renderer.value(&serde_json::json!({"deleted":true,"id":id})); Ok(0) }
                    Err(e) => { ctx.renderer.error(&e); Ok(e.exit_code()) }
                }
            }
        }
    }
}

/// Render a `Result<Value, ApiError>`: success → value+exit 0; error → stderr+exit code.
pub fn finish(ctx: &Ctx, r: Result<serde_json::Value, crate::client::error::ApiError>) -> anyhow::Result<i32> {
    match r {
        Ok(v) => { ctx.renderer.value(&v); Ok(0) }
        Err(e) => { ctx.renderer.error(&e); Ok(e.exit_code()) }
    }
}
