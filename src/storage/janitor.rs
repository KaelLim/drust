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
    // On a blocking thread, and in its own scope, for two reasons: it is a
    // synchronous SQLite open that has no business on the reactor, and keeping
    // the `Connection`/`Statement` out of this future's state is what makes the
    // future `Send` — without it `tokio::spawn` rejects the retention task,
    // since neither rusqlite type crosses threads.
    let dir = data_dir.to_path_buf();
    let tenant_ids: Vec<String> = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        let meta = Connection::open(dir.join("meta.sqlite"))?;
        let mut stmt = meta.prepare("SELECT id FROM tenants WHERE deleted_at IS NULL")?;
        let ids = stmt
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ids)
    })
    .await??;

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

/// Buffer past `expires_at` before a session row is deleted, in days.
/// `DRUST_SESSION_GRACE_DAYS`, default 1 — matching what
/// `bin/drust_session_janitor.rs` has always used, so the in-process sweep and
/// the bare-metal timer agree. Unlike `DRUST_TRASH_RETENTION_DAYS`, `0` does
/// **not** disable: it sweeps rows the moment they expire. Expiry is enforced
/// in the auth query itself, so there is no window in which a longer grace
/// grants access — the knob only decides how long dead rows stay legible to
/// debugging tools.
fn parse_session_grace_days(raw: Option<&str>) -> i64 {
    raw.and_then(|s| s.parse::<i64>().ok()).unwrap_or(1)
}

pub fn session_grace_days() -> i64 {
    parse_session_grace_days(std::env::var("DRUST_SESSION_GRACE_DAYS").ok().as_deref())
}

/// Sweep expired admin browser sessions from `meta.sqlite.sessions`.
/// Synchronous: admin sessions are one table with no per-tenant fan-out.
///
/// A missing `meta.sqlite` is `Ok(0)`, not an error — the boot sweep can race
/// a first-run process that has not created it yet.
pub fn sweep_meta_sessions(data_dir: &Path, grace_days: i64) -> anyhow::Result<usize> {
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

/// Daily session janitor — admin rows in `meta.sqlite.sessions` plus every live
/// tenant's `_system_sessions` — with one sweep at boot.
/// `tokio::spawn(janitor::spawn_session_retention_task(data_dir))`.
///
/// **Why this lives in-process**, for the same reason `spawn_trash_retention_task`
/// does and as the other half of the same gap: `deploy/drust-janitor.sh` runs the
/// trash sweep *and* `drust_session_janitor`, but its systemd timer exists only on
/// bare metal. The published image installs the `drust_session_janitor` binary
/// (Dockerfile) yet its `ENTRYPOINT` is `drust` alone, and `docker-compose.yml`
/// adds no cron — so for every GHCR, compose and k3s operator, expired sessions
/// were never swept at all. v1.58 moved the trash half in and left this one
/// behind. Rows accumulate `token_hash`, `user_id` and `ip_at_login` forever;
/// it is a retention problem, not an access one, because both auth paths filter
/// on `expires_at` themselves (`auth/user_session.rs` `AND expires_at > ?2`).
///
/// Idempotent alongside the shell janitor: a DELETE of already-deleted rows
/// affects 0 rows, so running both on bare metal is harmless.
pub async fn spawn_session_retention_task(data_dir: std::path::PathBuf) {
    let grace = session_grace_days();
    let mut tick = tokio::time::interval(Duration::from_secs(24 * 60 * 60));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tick.tick().await; // fires immediately on the first pass — the boot sweep

        let dir = data_dir.clone();
        let admin = tokio::task::spawn_blocking(move || sweep_meta_sessions(&dir, grace))
            .await
            .unwrap_or_else(|e| Err(anyhow::anyhow!(e)));
        match admin {
            Ok(n) if n > 0 => tracing::info!(removed = n, "session janitor swept admin sessions"),
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e, "session janitor: admin sweep failed"),
        }

        match sweep_expired_sessions(&data_dir, grace).await {
            Ok(n) if n > 0 => tracing::info!(removed = n, "session janitor swept user sessions"),
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e, "session janitor: per-tenant sweep failed"),
        }
    }
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

    fn meta_with_sessions(dir: &Path) {
        let c = Connection::open(dir.join("meta.sqlite")).unwrap();
        c.execute_batch(
            "CREATE TABLE sessions (token_hash TEXT PRIMARY KEY, expires_at TEXT NOT NULL);
             INSERT INTO sessions VALUES ('live',    datetime('now', '+7 day'));
             INSERT INTO sessions VALUES ('justnow', datetime('now', '-1 hour'));
             INSERT INTO sessions VALUES ('stale',   datetime('now', '-30 day'));",
        )
        .unwrap();
    }

    fn remaining(dir: &Path) -> Vec<String> {
        let c = Connection::open(dir.join("meta.sqlite")).unwrap();
        let mut stmt = c
            .prepare("SELECT token_hash FROM sessions ORDER BY token_hash")
            .unwrap();
        stmt.query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    }

    /// Admin sessions live in `meta.sqlite.sessions`, a different table shape
    /// from the per-tenant `_system_sessions` that `sweep_expired_sessions`
    /// handles — so closing the Docker/k3s gap needs BOTH sweeps in the lib.
    /// This one only ever ran inside `bin/drust_session_janitor.rs`, which the
    /// published image installs but never invokes (`ENTRYPOINT ["drust"]`).
    #[test]
    fn meta_sweep_expires_past_the_grace_window_and_keeps_the_rest() {
        let dir = tempdir().unwrap();
        meta_with_sessions(dir.path());

        // grace_days = 1: `justnow` expired an hour ago but is inside the
        // one-day debugging buffer, so only `stale` goes.
        assert_eq!(sweep_meta_sessions(dir.path(), 1).unwrap(), 1);
        assert_eq!(remaining(dir.path()), vec!["justnow", "live"]);

        // grace_days = 0 sweeps immediately-expired rows; it does NOT mean
        // "disabled" (unlike DRUST_TRASH_RETENTION_DAYS=0). `live` survives.
        assert_eq!(sweep_meta_sessions(dir.path(), 0).unwrap(), 1);
        assert_eq!(remaining(dir.path()), vec!["live"]);
    }

    #[test]
    fn meta_sweep_tolerates_a_missing_meta_db() {
        let dir = tempdir().unwrap();
        assert_eq!(sweep_meta_sessions(dir.path(), 1).unwrap(), 0);
    }

    #[test]
    fn session_grace_days_defaults_to_one_and_survives_garbage() {
        // Same env_or posture as trash_retention_days: unparseable → default.
        assert_eq!(parse_session_grace_days(None), 1);
        assert_eq!(parse_session_grace_days(Some("not a number")), 1);
        assert_eq!(parse_session_grace_days(Some("0")), 0);
        assert_eq!(parse_session_grace_days(Some("30")), 30);
    }
}
