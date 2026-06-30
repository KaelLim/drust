//! CLI device-flow login (RFC 8628-shaped). v1.44 (CLI Phase 2).
//!
//! Host-plane rendezvous between a headless `drust` CLI and a logged-in admin
//! browser: the CLI `POST`s `/auth/cli/device/start` to mint a `device_code`
//! (returned once, stored only as a hash) + a human `user_code`; the admin
//! opens `/auth/cli/device?user_code=…`, confirms, and `approve` mints a
//! labeled, expiring `drust_pat_cli_*` PAT; the CLI's `poll` then collects it
//! exactly once. Rows live in `meta.sqlite._cli_device_codes` and are reaped
//! hourly by [`sweep_expired_device_codes`].

use rusqlite::Connection;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Best-effort hourly cleanup: delete every device-code row whose `expires_at`
/// is in the past. `expires_at` is the source of truth (poll/approve reject an
/// expired row regardless), so a missed sweep only leaves rows lingering until
/// the next one. Returns the number of rows deleted.
pub async fn sweep_expired_device_codes(meta: &Arc<Mutex<Connection>>) -> usize {
    let conn = meta.lock().await;
    conn.execute(
        "DELETE FROM _cli_device_codes WHERE datetime(expires_at) < datetime('now')",
        [],
    )
    .unwrap_or(0)
}
