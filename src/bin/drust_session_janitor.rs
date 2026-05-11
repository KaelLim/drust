//! Daily janitor for expired user sessions. Invoked by the
//! `drust-janitor.timer` after the trash sweep.

use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    let data_dir: PathBuf = std::env::var("DRUST_DATA_DIR")
        .unwrap_or_else(|_| "/var/lib/drust".to_string())
        .into();
    let grace_days: i64 = std::env::var("DRUST_SESSION_GRACE_DAYS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let n = drust::storage::janitor::sweep_expired_sessions(&data_dir, grace_days)?;
    eprintln!("drust_session_janitor: swept {n} expired session rows");
    Ok(())
}
