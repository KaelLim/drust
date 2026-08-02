use crate::storage::pool::TenantRegistry;
use rusqlite::Connection;
use std::path::Path;
use std::time::{Duration, SystemTime};

/// Retention for `_trash/<id>-<ts>/` soft-delete snapshots, in days.
/// `DRUST_TRASH_RETENTION_DAYS`, default 7 (the advertised recovery window,
/// matching `deploy/drust-janitor.sh`'s `find … -mtime +7`); `0` disables the
/// sweep and keeps snapshots forever. Same `env_or` posture as
/// `DRUST_AUDIT_HISTORY_RETENTION_DAYS`: unparseable → default.
pub fn trash_retention_days() -> u64 {
    std::env::var("DRUST_TRASH_RETENTION_DAYS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(7)
}

/// Delete `_trash/*` snapshot directories older than `retention_days`.
/// Returns how many were removed. `retention_days == 0` → disabled, `0`.
///
/// **Why this lives in-process and not only in `deploy/drust-janitor.sh`:** the
/// shell janitor is wired by a systemd timer that exists only in the bare-metal
/// deployment. The published image's `ENTRYPOINT` is `drust` alone, and
/// `docker-compose.yml` runs `caddy` + `drust` (+ optional MinIO) with no cron
/// and no timer — so for every GHCR/compose operator nothing swept `_trash` at
/// all. Until v1.58 the accidental reclaim was `make_tenant_inner`'s id-recycle
/// purge; removing that (correctly — it was destroying live recovery copies)
/// left those deployments retaining every snapshot forever. The snapshots are
/// whole tenant databases, so that is a credential-retention problem
/// (`_system_users` argon2 hashes, unexpired `_system_sessions`) before it is a
/// disk problem.
///
/// Age is the directory's own mtime, which `rename(2)` preserves — the snapshot
/// carries the live directory's mtime, i.e. the time of the last write to that
/// tenant, never later than the soft-delete. Erring old is fine here: the
/// bare-metal `find -mtime +7` already used exactly this clock, so both sweepers
/// agree, and running them together is idempotent.
///
/// `now` is a parameter so the retention decision is testable without touching
/// file mtimes.
pub fn sweep_trash(data_dir: &Path, retention_days: u64, now: SystemTime) -> usize {
    if retention_days == 0 {
        return 0;
    }
    let max_age = Duration::from_secs(retention_days * 24 * 60 * 60);
    let Ok(entries) = std::fs::read_dir(data_dir.join("_trash")) else {
        return 0; // no _trash yet — nothing has ever been soft-deleted
    };
    let mut removed = 0usize;
    for entry in entries.flatten() {
        if !entry.path().is_dir() {
            continue;
        }
        // An unreadable mtime, or one in the future (clock skew, a restored
        // archive), fails CLOSED: keep the snapshot. Deleting on a stat error
        // would turn a transient fs hiccup into data loss.
        let Ok(mtime) = entry.metadata().and_then(|m| m.modified()) else {
            continue;
        };
        let Ok(age) = now.duration_since(mtime) else {
            continue;
        };
        if age <= max_age {
            continue;
        }
        match std::fs::remove_dir_all(entry.path()) {
            Ok(()) => removed += 1,
            Err(e) => {
                tracing::warn!(path = %entry.path().display(), error = %e,
                    "trash janitor: could not remove expired snapshot")
            }
        }
    }
    removed
}

/// Daily `_trash` retention janitor, plus one sweep at boot so a long-running
/// deployment that has been accumulating snapshots reclaims on the next
/// restart rather than up to 24 h later.
/// `tokio::spawn(janitor::spawn_trash_retention_task(data_dir))`.
pub async fn spawn_trash_retention_task(data_dir: std::path::PathBuf) {
    let days = trash_retention_days();
    if days == 0 {
        tracing::info!(
            "trash retention disabled (DRUST_TRASH_RETENTION_DAYS=0); keeping soft-delete snapshots forever"
        );
        return;
    }
    let mut tick = tokio::time::interval(Duration::from_secs(24 * 60 * 60));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tick.tick().await; // fires immediately on the first pass — the boot sweep
        let dir = data_dir.clone();
        let removed =
            tokio::task::spawn_blocking(move || sweep_trash(&dir, days, SystemTime::now()))
                .await
                .unwrap_or(0);
        if removed > 0 {
            tracing::info!(removed, days, "trash janitor expired soft-delete snapshots");
        }
    }
}

/// Sweep expired sessions across every active tenant. Returns the total
/// number of rows deleted across all tenants. Soft-deleted tenants
/// (`tenants.deleted_at IS NOT NULL`) are skipped — their data.sqlite is
/// already destined for trash cleanup by the existing shell janitor.
///
/// `grace_days` is the buffer past `expires_at` before deletion. The
/// production cron uses 1 day so that very recently expired sessions
/// remain visible to debugging tools for one cycle.
///
/// Writes go through the shared `TenantRegistry` pool so each DELETE is
/// serialized by the per-tenant writer mutex, avoiding SQLITE_BUSY races
/// when drust is running concurrently. The pool's `open_write` already
/// applies `busy_timeout = 5000` via `apply_common_pragmas`, so a
/// stale-process flock does not deadlock. The create-free `get_if_live`
/// open (`open_write_existing`) applies the same pragmas and the same
/// idempotent `_system_*` catch-up, so only directory/file creation is
/// dropped.
pub async fn sweep_expired_sessions(data_dir: &Path, grace_days: i64) -> anyhow::Result<usize> {
    let meta = Connection::open(data_dir.join("meta.sqlite"))?;
    let mut stmt = meta.prepare("SELECT id FROM tenants WHERE deleted_at IS NULL")?;
    let tenant_ids: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<Result<_, _>>()?;
    drop(stmt);
    drop(meta);

    let registry = TenantRegistry::new(data_dir.to_path_buf(), 1);
    let mut total = 0;
    for tid in tenant_ids {
        // Background sweep: `get_if_live` resolves atomically. The previous
        // `exists()`-then-create-on-open pair left a check-then-act window in
        // which a soft-delete rebuilt `tenants/<id>/` outside `_trash`.
        let Some(pool) = registry.get_if_live(&tid) else {
            continue;
        };
        let n = pool
            .with_writer(move |conn| {
                conn.execute(
                    "DELETE FROM _system_sessions WHERE expires_at < datetime('now', ?1)",
                    rusqlite::params![format!("-{grace_days} day")],
                )
            })
            .await?;
        total += n;
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::tempdir;

    #[tokio::test]
    async fn sweep_returns_zero_when_no_tenants() {
        let dir = tempdir().unwrap();
        // Create empty meta.sqlite with tenants table
        let c = Connection::open(dir.path().join("meta.sqlite")).unwrap();
        c.execute_batch("CREATE TABLE tenants (id TEXT PRIMARY KEY, deleted_at TEXT);")
            .unwrap();
        drop(c);
        let n = sweep_expired_sessions(dir.path(), 1).await.unwrap();
        assert_eq!(n, 0);
    }

    /// A `_trash` snapshot must expire from INSIDE the process. `docker-compose`
    /// and the published image run `drust` and nothing else — no systemd timer,
    /// no cron — so `deploy/drust-janitor.sh` never fires there, and before this
    /// existed nothing in `src/` swept `_trash` at all.
    #[test]
    fn trash_snapshots_expire_after_the_retention_window() {
        let dir = tempdir().unwrap();
        let data = dir.path();
        let snap = data.join("_trash").join("acme-20260802T120000Z");
        std::fs::create_dir_all(&snap).unwrap();
        std::fs::write(snap.join("data.sqlite"), b"argon2 hashes live here").unwrap();

        // Fresh: inside the window, kept. (`now` is a parameter precisely so the
        // decision is testable without backdating file mtimes.)
        assert_eq!(sweep_trash(data, 7, SystemTime::now()), 0);
        assert!(snap.exists(), "a snapshot inside the window must be kept");

        // Eight days on: swept.
        let later = SystemTime::now() + Duration::from_secs(8 * 24 * 60 * 60);
        assert_eq!(sweep_trash(data, 7, later), 1);
        assert!(!snap.exists(), "an expired snapshot must be reclaimed");
    }

    #[test]
    fn trash_sweep_is_disabled_by_zero_and_tolerates_a_missing_dir() {
        let dir = tempdir().unwrap();
        let data = dir.path();
        let snap = data.join("_trash").join("acme-20260802T120000Z");
        std::fs::create_dir_all(&snap).unwrap();
        let later = SystemTime::now() + Duration::from_secs(400 * 24 * 60 * 60);

        assert_eq!(sweep_trash(data, 0, later), 0, "0 = keep forever");
        assert!(snap.exists());

        let empty = tempdir().unwrap();
        assert_eq!(sweep_trash(empty.path(), 7, later), 0, "no _trash yet");
    }

    /// A future mtime (clock skew, a restored archive) must not be treated as
    /// infinitely old. `duration_since` errors there; the sweep keeps the dir.
    #[test]
    fn a_future_mtime_is_kept_not_deleted() {
        let dir = tempdir().unwrap();
        let data = dir.path();
        let snap = data.join("_trash").join("acme-20260802T120000Z");
        std::fs::create_dir_all(&snap).unwrap();
        let long_ago = SystemTime::UNIX_EPOCH + Duration::from_secs(1);
        assert_eq!(sweep_trash(data, 7, long_ago), 0);
        assert!(snap.exists());
    }
}
