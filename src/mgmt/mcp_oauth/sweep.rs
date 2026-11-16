//! Hourly MCP OAuth cleanup, run from the device-code reaper loop in main.rs.
//!
//! Unconditional — it runs whether or not `DRUST_MCP` is on, because a host
//! that once ran with it on keeps rows after switching it off. Best effort:
//! every lookup checks its own `expires_at`, so a skipped or failed tick only
//! means rows linger. Not on the boot path (CLAUDE.md invariant 1).

use std::sync::Arc;

use rusqlite::Connection;
use tokio::sync::Mutex;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SweepCounts {
    pub codes: usize,
    pub access: usize,
    pub refresh: usize,
    pub tickets: usize,
    pub grants: usize,
    /// Grants that can never be redeemed any more (MA0-PLAN §3.8.7).
    pub abandoned: usize,
    pub orphans: usize,
}

impl SweepCounts {
    pub fn total(&self) -> usize {
        self.codes
            + self.access
            + self.refresh
            + self.tickets
            + self.grants
            + self.abandoned
            + self.orphans
    }
}

// Children first so the counts are honest; a grant DELETE also CASCADEs its
// remaining children, and `changes()` does not count those.
const SQL_CODES: &str = "DELETE FROM _mcp_oauth_codes WHERE expires_at < datetime('now')";
const SQL_ACCESS: &str = "DELETE FROM _mcp_oauth_access WHERE expires_at < datetime('now')";
// A rotated refresh is kept until ITS expires_at: refresh-reuse detection needs the row.
const SQL_REFRESH: &str = "DELETE FROM _mcp_oauth_refresh WHERE expires_at < datetime('now')";
const SQL_TICKETS: &str = "DELETE FROM _mcp_upload_tickets WHERE expires_at < datetime('now')";
// 30 days AFTER end of life (revoked, else the earlier of idle/absolute),
// so the settings page still shows a recently expired connection.
const SQL_GRANTS: &str = "\
DELETE FROM _mcp_oauth_grants \
 WHERE COALESCE(revoked_at, MIN(idle_expires_at, absolute_expires_at)) < datetime('now', '-30 days')";
// MA0-PLAN §3.8.7: a grant that can never be redeemed any more — approve built
// it, but its code already expired (deleted above, same tx) and it never issued
// a token. Double-click approvals and cancelled logins leave these behind.
const SQL_ABANDONED: &str = "\
DELETE FROM _mcp_oauth_grants \
 WHERE kind = 'authorization_code' \
   AND last_used_at IS NULL \
   AND NOT EXISTS (SELECT 1 FROM _mcp_oauth_codes c WHERE c.grant_id = _mcp_oauth_grants.id) \
   AND NOT EXISTS (SELECT 1 FROM _mcp_oauth_refresh r WHERE r.grant_id = _mcp_oauth_grants.id)";
// Orphans: the admin is gone, or the id was recycled with a different created_at.
// The second layer behind remove_admin's explicit DELETE for any connection that
// ran without `PRAGMA foreign_keys = ON`.
const SQL_ORPHANS: &str = "\
DELETE FROM _mcp_oauth_grants \
 WHERE NOT EXISTS (SELECT 1 FROM admins ad \
                    WHERE ad.id = _mcp_oauth_grants.admin_id \
                      AND ad.created_at = _mcp_oauth_grants.admin_created_at)";

pub async fn sweep_mcp_oauth(meta: &Arc<Mutex<Connection>>) -> SweepCounts {
    let conn = meta.lock().await;
    match sweep_locked(&conn) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "mcp oauth sweep failed; rows linger until the next tick");
            SweepCounts::default()
        }
    }
}

/// One transaction: all seven DELETEs land, or none (the tx rolls back on drop).
fn sweep_locked(conn: &Connection) -> rusqlite::Result<SweepCounts> {
    let tx = conn.unchecked_transaction()?;
    let codes = tx.execute(SQL_CODES, [])?;
    let access = tx.execute(SQL_ACCESS, [])?;
    let refresh = tx.execute(SQL_REFRESH, [])?;
    let tickets = tx.execute(SQL_TICKETS, [])?;
    let grants = tx.execute(SQL_GRANTS, [])?;
    let abandoned = tx.execute(SQL_ABANDONED, [])?;
    let orphans = tx.execute(SQL_ORPHANS, [])?;
    tx.commit()?;
    Ok(SweepCounts {
        codes,
        access,
        refresh,
        tickets,
        grants,
        abandoned,
        orphans,
    })
}
