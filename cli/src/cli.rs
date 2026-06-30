//! Top-level clap parse + global flags. Subcommand argument structs live in their command modules.
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "drust", version, about = "drust CLI")]
pub struct Cli {
    /// Host key from hosts.toml (overrides active_host)
    #[arg(long, global = true, env = "DRUST_HOST")]
    pub host: Option<String>,
    /// Tenant id/context (overrides the host's default_tenant)
    #[arg(long, global = true, env = "DRUST_TENANT")]
    pub tenant: Option<String>,
    /// Force JSON output
    #[arg(long, global = true)]
    pub json: bool,
    /// Output mode: human | json
    #[arg(long, global = true)]
    pub output: Option<String>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Authenticate against an instance
    Auth(crate::auth::AuthArgs),
    /// Select the active tenant context
    Use(crate::commands::use_ctx::UseArgs),
    /// Data-plane record CRUD
    Records(crate::commands::records::RecordsArgs),
    /// Collection read + index/config + schema mutation (via MCP)
    Collections(crate::commands::collections::CollectionsArgs),
    /// Raw service-only SELECT (requires --unsafe)
    Query(crate::commands::query::QueryArgs),
    /// Vector similarity search
    Search(crate::commands::search::SearchArgs),
    /// Stored RPC call/list
    Rpc(crate::commands::rpc::RpcArgs),
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn parses_global_flags() {
        let cli = Cli::try_parse_from(["drust", "--host", "tool", "--tenant", "9f", "--json", "auth", "status"]).unwrap();
        assert_eq!(cli.host.as_deref(), Some("tool"));
        assert_eq!(cli.tenant.as_deref(), Some("9f"));
        assert!(cli.json);
        assert!(matches!(cli.command, Command::Auth(_)));
    }
}
