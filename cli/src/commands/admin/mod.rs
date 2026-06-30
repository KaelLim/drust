//! `drust admin …` — host admin-plane commands (PAT-gated /admin/api/* + /admin/*).
pub mod audit;
pub mod backups;
pub mod keys;
pub mod team;
pub mod tenants;

use clap::{Args, Subcommand};

#[derive(Args, Debug)]
pub struct AdminArgs {
    #[command(subcommand)]
    pub cmd: AdminCmd,
}

#[derive(Subcommand, Debug)]
pub enum AdminCmd {
    /// Tenant lifecycle (create/list/rm).
    Tenants(tenants::TenantsArgs),
    /// Per-tenant API key reroll/list.
    Keys(keys::KeysArgs),
    /// Host admin team management.
    Team(team::TeamArgs),
    /// Audit log query.
    Audit(audit::AuditArgs),
    /// Backup snapshot list/inspect/download/restore.
    Backups(backups::BackupsArgs),
}

pub async fn run(cli: &crate::cli::Cli, a: &AdminArgs) -> anyhow::Result<i32> {
    match &a.cmd {
        AdminCmd::Tenants(x) => tenants::run(cli, x).await,
        AdminCmd::Keys(x) => keys::run(cli, x).await,
        AdminCmd::Team(x) => team::run(cli, x).await,
        AdminCmd::Audit(x) => audit::run(cli, x).await,
        AdminCmd::Backups(x) => backups::run(cli, x).await,
    }
}
