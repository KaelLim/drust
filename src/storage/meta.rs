use crate::auth::admin::hash_password;
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use std::path::Path;

const SCHEMA_SQL: &str = r#"
BEGIN;

CREATE TABLE IF NOT EXISTS admins (
  id            INTEGER PRIMARY KEY,
  username      TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  email         TEXT,
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
-- Note: idx_admins_email is created in apply_migrations (not here)
-- because on x-era upgrade, the admins table exists without the email
-- column at SCHEMA_SQL time, so a CREATE INDEX referencing email would
-- fail. apply_migrations runs after add_column_if_missing fills it.

CREATE TABLE IF NOT EXISTS sessions (
  token         TEXT PRIMARY KEY,
  admin_id      INTEGER NOT NULL,
  created_at    TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at    TEXT NOT NULL,
  FOREIGN KEY (admin_id) REFERENCES admins(id)
);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS tenants (
  id                    TEXT PRIMARY KEY,
  name                  TEXT NOT NULL,
  created_at            TEXT NOT NULL DEFAULT (datetime('now')),
  deleted_at            TEXT,
  quota_db_mb           INTEGER NOT NULL DEFAULT 500,
  quota_rows            INTEGER NOT NULL DEFAULT 1000000,
  db_bytes              INTEGER NOT NULL DEFAULT 0,
  files_bytes           INTEGER NOT NULL DEFAULT 0,
  stats_updated_at      TEXT,
  -- v1.49 — per-tenant egress allowlist ({system,uri} tagged JSON, origin
  -- level, deny-all default). '[]' denies every outbound path; run_migrations
  -- adds this idempotently on upgraded DBs. See src/tenant/egress.rs.
  egress_allowlist_json TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_tenants_deleted ON tenants(deleted_at);

CREATE TABLE IF NOT EXISTS tokens (
  id            INTEGER PRIMARY KEY,
  tenant_id     TEXT NOT NULL,
  token_hash    TEXT NOT NULL UNIQUE,
  label         TEXT,
  created_at    TEXT NOT NULL DEFAULT (datetime('now')),
  revoked_at    TEXT,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
CREATE INDEX IF NOT EXISTS idx_tokens_hash_active ON tokens(token_hash) WHERE revoked_at IS NULL;

-- System collection: file metadata (admin-owned in meta.sqlite, tenant-owned
-- in each tenants/<id>/data.sqlite). Protected from `drop_collection` by
-- the `_system_` prefix rule in src/mcp/tools/schema.rs.
CREATE TABLE IF NOT EXISTS "_system_files" (
  id                  INTEGER PRIMARY KEY AUTOINCREMENT,
  key                 TEXT    NOT NULL UNIQUE,
  original_name       TEXT    NOT NULL,
  content_type        TEXT,
  size_bytes          INTEGER NOT NULL,
  content_disposition TEXT,
  visibility          TEXT    NOT NULL DEFAULT 'public',
  cache_control       TEXT,
  meta_json           TEXT,
  uploaded_at         TEXT    NOT NULL DEFAULT (datetime('now')),
  uploader            TEXT    NOT NULL,
  created_at          TEXT    NOT NULL DEFAULT (datetime('now')),
  updated_at          TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_system_files_uploaded_at
  ON "_system_files"(uploaded_at DESC);
CREATE INDEX IF NOT EXISTS idx_system_files_visibility
  ON "_system_files"(visibility);

CREATE TABLE IF NOT EXISTS "_trash_pending_revokes" (
  tenant_id       TEXT PRIMARY KEY,
  detected_at     TEXT NOT NULL DEFAULT (datetime('now')),
  last_attempt_at TEXT,
  last_error      TEXT
);

CREATE TABLE IF NOT EXISTS "_orphan_buckets" (
  bucket_name     TEXT PRIMARY KEY,
  detected_at     TEXT NOT NULL DEFAULT (datetime('now')),
  reason          TEXT NOT NULL
);

COMMIT;
"#;

fn apply_pragmas(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;
        PRAGMA cache_size = -65536;
        PRAGMA mmap_size = 268435456;
        PRAGMA temp_store = MEMORY;
        PRAGMA busy_timeout = 5000;
        PRAGMA foreign_keys = ON;
        ",
    )
}

pub fn open_meta(path: &Path) -> anyhow::Result<Connection> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
    )?;
    apply_pragmas(&conn)?;
    // Structural renames must happen BEFORE SCHEMA_SQL so that
    // `CREATE TABLE IF NOT EXISTS "_system_files"` is a no-op on upgraded DBs.
    pre_schema_migrations(&conn)?;
    conn.execute_batch(SCHEMA_SQL)?;
    apply_migrations(&conn)?;
    Ok(conn)
}

/// Migrations that must run BEFORE SCHEMA_SQL. These rename or drop tables
/// so that the `CREATE TABLE IF NOT EXISTS` stanzas in SCHEMA_SQL are safe.
fn pre_schema_migrations(conn: &Connection) -> anyhow::Result<()> {
    // v1.5.0-Y: rename _system_public_files → _system_files and add Y columns.
    // Runs only when the X-era table exists; CREATE TABLE IF NOT EXISTS in
    // SCHEMA_SQL covers fresh installs.
    let has_old: bool = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='_system_public_files'",
            [],
            |_| Ok(()),
        )
        .optional()
        .ok()
        .flatten()
        .is_some();

    if has_old {
        conn.execute_batch(
            r#"
            BEGIN;
            ALTER TABLE "_system_public_files" RENAME TO "_system_files";
            ALTER TABLE "_system_files" ADD COLUMN visibility    TEXT NOT NULL DEFAULT 'public';
            ALTER TABLE "_system_files" ADD COLUMN cache_control TEXT;
            ALTER TABLE "_system_files" ADD COLUMN meta_json     TEXT;
            UPDATE "_system_files"
              SET content_disposition = CASE
                  WHEN content_disposition LIKE 'attachment%' THEN 'attachment'
                  ELSE 'inline'
              END
              WHERE content_disposition IS NOT NULL;
            DROP INDEX IF EXISTS idx_public_files_uploaded_at;
            CREATE INDEX IF NOT EXISTS idx_system_files_uploaded_at
              ON "_system_files"(uploaded_at DESC);
            CREATE INDEX IF NOT EXISTS idx_system_files_visibility
              ON "_system_files"(visibility);
            COMMIT;
        "#,
        )?;
        tracing::info!("meta migration: renamed _system_public_files to _system_files");
    }

    Ok(())
}

/// Idempotent per-column migrations. Each migration tolerates the "duplicate
/// column" error so repeated startups on the same DB are safe.
fn apply_migrations(conn: &Connection) -> anyhow::Result<()> {
    // v1.1a: tokens.role (anon | service)
    if let Err(e) = conn.execute(
        "ALTER TABLE tokens \
         ADD COLUMN role TEXT NOT NULL DEFAULT 'service' \
         CHECK (role IN ('anon','service'))",
        [],
    ) {
        let msg = e.to_string();
        if !msg.contains("duplicate column") {
            return Err(e.into());
        }
    }
    // v1.1c: tokens.plaintext — store the raw key alongside the hash so the
    // admin UI can display + copy it later. Tokens created before this
    // migration have plaintext = NULL and can only be recovered by rerolling.
    if let Err(e) = conn.execute("ALTER TABLE tokens ADD COLUMN plaintext TEXT", []) {
        let msg = e.to_string();
        if !msg.contains("duplicate column") {
            return Err(e.into());
        }
    }
    // v1.11: admins.email — nullable, partial unique index for OAuth linking.
    crate::db::migrations::add_column_if_missing(conn, "admins", "email", "TEXT")?;
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_admins_email \
         ON admins(email) WHERE email IS NOT NULL",
        [],
    )?;
    // v1.22: admins.locale — nullable preferred UI language ("en" | "zh-TW" | NULL).
    // NULL means "fall through to cookie / Accept-Language / en default" (the
    // pre-v1.22 behaviour). Login + OAuth callback overwrite the `drust_locale`
    // cookie with this value when not NULL, so the admin's preference follows
    // them across devices.
    crate::db::migrations::add_column_if_missing(conn, "admins", "locale", "TEXT")?;

    // v1.23: admins.theme — nullable preferred UI theme code
    // ("system" | "cozy-dark" | "soft-light" | NULL). Same posture as locale:
    // NULL means "fall through to cookie / default". Login + OAuth callback
    // overwrite the `drust_theme` cookie with this value when not NULL.
    // Unknown values (e.g. a renamed theme that left an orphan row) fall
    // through at resolve time with a warn log; no DB-side CHECK constraint
    // so themes can be renamed in code without a DB cascade.
    crate::db::migrations::add_column_if_missing(conn, "admins", "theme", "TEXT")?;

    // v1.28.9: admins.display_name — nullable, mirrored from OAuth provider
    // `name` claim (Google id_token, GitHub userinfo). NULL until first OAuth
    // login after upgrade; sidebar falls back to email local-part initials.
    crate::db::migrations::add_column_if_missing(conn, "admins", "display_name", "TEXT")?;

    // v1.28.9: admins.picture_url — nullable, mirrored from OAuth provider
    // `picture` claim. Same posture as display_name; sidebar renders text
    // initials when NULL, <img> when populated.
    crate::db::migrations::add_column_if_missing(conn, "admins", "picture_url", "TEXT")?;

    Ok(())
}

/// Look up an admin's id by email (case-insensitive). Returns `Ok(None)`
/// when no row matches. Used by the OAuth callback to map a provider-
/// verified email to a local admin row before minting a session.
pub fn find_admin_id_by_email(conn: &Connection, email: &str) -> rusqlite::Result<Option<i64>> {
    conn.query_row(
        "SELECT id FROM admins WHERE email = ?1 COLLATE NOCASE",
        [email],
        |r| r.get(0),
    )
    .optional()
}

pub fn bootstrap_admin(
    conn: &mut Connection,
    username: &str,
    plaintext_password: &str,
) -> anyhow::Result<bool> {
    let existing: i64 = conn.query_row("SELECT COUNT(*) FROM admins", [], |r| r.get(0))?;
    if existing > 0 {
        return Ok(false);
    }
    let hash = hash_password(plaintext_password)?;
    conn.execute(
        "INSERT INTO admins (username, password_hash) VALUES (?1, ?2)",
        rusqlite::params![username, hash],
    )?;
    // v1.29.3 — the PAT row is created by the run_migrations backfill loop
    // that runs after bootstrap (see src/main.rs). Doing it here would fail
    // because _admin_tokens doesn't exist until migrations create it.
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_then_migrate_results_in_one_active_pat() {
        // Mirrors the production order in main.rs:
        //   bootstrap_admin → run_migrations.
        // run_migrations creates _admin_tokens and the backfill loop adds
        // a PAT row for the bootstrap admin. After both, exactly one
        // active PAT must exist for the bootstrap admin.
        let tmp = tempfile::tempdir().unwrap();
        let mut conn = open_meta(&tmp.path().join("meta.sqlite")).unwrap();

        let inserted = bootstrap_admin(&mut conn, "kael", "mysecret").unwrap();
        assert!(inserted, "first call inserts the admin");

        crate::db::migrations::run_migrations(&conn, tmp.path()).unwrap();

        let row: (i64, String) = conn
            .query_row(
                "SELECT admin_id, plaintext FROM _admin_tokens WHERE revoked_at IS NULL",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .expect("a PAT row should exist after bootstrap + migrate");
        assert_eq!(row.0, 1, "bootstrap admin id is 1");
        assert!(
            row.1.starts_with("drust_pat_"),
            "plaintext must have PAT prefix: {}",
            row.1
        );

        // Second bootstrap is a no-op (admins table non-empty).
        let inserted2 = bootstrap_admin(&mut conn, "other", "x").unwrap();
        assert!(!inserted2);
        let cnt: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM _admin_tokens WHERE revoked_at IS NULL",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            cnt, 1,
            "second bootstrap must not produce another active PAT"
        );
    }
}
