//! Daily janitor for expired user + admin sessions. Invoked by the
//! `drust-janitor.timer` after the trash sweep.
//!
//! User sessions live in per-tenant `_system_sessions` tables; writes
//! go through the shared `TenantRegistry` pool so each DELETE is
//! serialized by the per-tenant writer mutex.
//!
//! Admin sessions live in `meta.sqlite.sessions`; v1.29.4 added the
//! synchronous sweep step that runs before the per-tenant async sweep.
//! Both use the same `grace_days` window.

use rusqlite::Connection;
use std::path::{Path, PathBuf};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let data_dir: PathBuf = std::env::var("DRUST_DATA_DIR")
        .unwrap_or_else(|_| "/var/lib/drust".to_string())
        .into();
    let grace_days: i64 = std::env::var("DRUST_SESSION_GRACE_DAYS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);

    // v1.29.4: sweep admin sessions from meta.sqlite. Admin sessions
    // use a different table shape than per-tenant _system_sessions —
    // straight DELETE with grace window, no per-tenant fan-out needed.
    let meta_n = sweep_meta_sessions(&data_dir, grace_days)?;
    eprintln!("drust_session_janitor: swept {meta_n} expired admin session rows");

    let user_n = drust::storage::janitor::sweep_expired_sessions(&data_dir, grace_days).await?;
    eprintln!("drust_session_janitor: swept {user_n} expired user session rows");

    Ok(())
}

/// Sweep expired admin browser sessions from meta.sqlite. Synchronous
/// because meta access uses a single connection at boot time and there's
/// no per-tenant fan-out.
fn sweep_meta_sessions(data_dir: &Path, grace_days: i64) -> anyhow::Result<usize> {
    let meta_path = data_dir.join("meta.sqlite");
    if !meta_path.exists() {
        return Ok(0);
    }
    let conn = Connection::open(&meta_path)?;
    let n = conn.execute(
        "DELETE FROM sessions WHERE expires_at <= datetime('now', ?1)",
        rusqlite::params![format!("-{grace_days} day")],
    )?;
    Ok(n)
}
