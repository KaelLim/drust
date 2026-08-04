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
//!
//! Both sweeps now also run in-process (`spawn_session_retention_task`),
//! because this binary is only ever invoked by the bare-metal systemd timer —
//! the image installs it but its `ENTRYPOINT` is `drust` alone. This binary
//! stays as the timer's entry point and as a manual one-shot; it shares the lib
//! functions so the two paths cannot drift apart.

use std::path::PathBuf;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let data_dir: PathBuf = std::env::var("DRUST_DATA_DIR")
        .unwrap_or_else(|_| "/var/lib/drust".to_string())
        .into();
    let grace_days = drust::storage::janitor::session_grace_days();

    // v1.29.4: sweep admin sessions from meta.sqlite. Admin sessions
    // use a different table shape than per-tenant _system_sessions —
    // straight DELETE with grace window, no per-tenant fan-out needed.
    let meta_n = drust::storage::janitor::sweep_meta_sessions(&data_dir, grace_days)?;
    eprintln!("drust_session_janitor: swept {meta_n} expired admin session rows");

    let user_n = drust::storage::janitor::sweep_expired_sessions(&data_dir, grace_days).await?;
    eprintln!("drust_session_janitor: swept {user_n} expired user session rows");

    Ok(())
}
