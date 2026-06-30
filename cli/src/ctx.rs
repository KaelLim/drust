//! Resolved per-invocation context: client + tenant + renderer.
use crate::cli::Cli;
use crate::client::http::DrustClient;
use crate::config::store;
use crate::output::Renderer;
use std::io::IsTerminal;

pub struct Ctx {
    pub client: DrustClient,
    pub tenant: String,
    pub renderer: Renderer,
    #[allow(dead_code)]
    pub host_key: String,
}

impl Ctx {
    /// Resolve host → token → tenant. `need_tenant=false` for admin/auth commands.
    pub fn build(cli: &Cli, need_tenant: bool) -> anyhow::Result<Ctx> {
        let cfg = store::load()?;
        let host_key = cfg.resolve_host_key(cli.host.as_deref())?;
        let host = cfg
            .hosts
            .get(&host_key)
            .expect("resolved key exists")
            .clone();
        let token = store::read_token(&host_key, &host)?;
        let tenant = if need_tenant {
            cli.tenant
                .clone()
                .or(host.default_tenant.clone())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "no tenant selected — run 'drust use <tenant>' or pass --tenant"
                    )
                })?
        } else {
            String::new()
        };
        let renderer = Renderer::resolve(
            cli.json,
            cli.output.as_deref(),
            std::io::stdout().is_terminal(),
        );
        Ok(Ctx {
            client: DrustClient::new(host.base_url, token),
            tenant,
            renderer,
            host_key,
        })
    }
}
