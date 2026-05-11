use rusqlite::Connection;
use std::path::Path;

/// Sweep expired sessions across every active tenant. Returns the total
/// number of rows deleted across all tenants. Soft-deleted tenants
/// (`tenants.deleted_at IS NOT NULL`) are skipped — their data.sqlite is
/// already destined for trash cleanup by the existing shell janitor.
///
/// `grace_days` is the buffer past `expires_at` before deletion. The
/// production cron uses 1 day so that very recently expired sessions
/// remain visible to debugging tools for one cycle.
pub fn sweep_expired_sessions(data_dir: &Path, grace_days: i64) -> anyhow::Result<usize> {
    let meta = Connection::open(data_dir.join("meta.sqlite"))?;
    let mut stmt = meta.prepare("SELECT id FROM tenants WHERE deleted_at IS NULL")?;
    let tenant_ids: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<Result<_, _>>()?;
    drop(stmt);
    drop(meta);

    let mut total = 0;
    for tid in tenant_ids {
        let p = data_dir.join("tenants").join(&tid).join("data.sqlite");
        if !p.exists() {
            continue;
        }
        let conn = Connection::open(&p)?;
        let n = conn.execute(
            "DELETE FROM _system_sessions WHERE expires_at < datetime('now', ?1)",
            rusqlite::params![format!("-{grace_days} day")],
        )?;
        total += n;
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn sweep_returns_zero_when_no_tenants() {
        let dir = tempdir().unwrap();
        // Create empty meta.sqlite with tenants table
        let c = Connection::open(dir.path().join("meta.sqlite")).unwrap();
        c.execute_batch("CREATE TABLE tenants (id TEXT PRIMARY KEY, deleted_at TEXT);")
            .unwrap();
        drop(c);
        let n = sweep_expired_sessions(dir.path(), 1).unwrap();
        assert_eq!(n, 0);
    }
}
