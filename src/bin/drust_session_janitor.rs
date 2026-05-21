//! Daily janitor for expired user sessions. Invoked by the
//! `drust-janitor.timer` after the trash sweep.
//!
//! Writes go through the shared `TenantRegistry` pool so each DELETE is
//! serialized by the per-tenant writer mutex, matching the same pattern
//! used by the main drust process. The pool applies `busy_timeout = 5000`
//! via `apply_common_pragmas`, preventing deadlocks if drust is still
//! running when the janitor fires.

use std::path::PathBuf;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let data_dir: PathBuf = std::env::var("DRUST_DATA_DIR")
        .unwrap_or_else(|_| "/var/lib/drust".to_string())
        .into();
    let grace_days: i64 = std::env::var("DRUST_SESSION_GRACE_DAYS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let n = drust::storage::janitor::sweep_expired_sessions(&data_dir, grace_days).await?;
    eprintln!("drust_session_janitor: swept {n} expired session rows");
    Ok(())
}
