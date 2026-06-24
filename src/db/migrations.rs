use rusqlite::Connection;
use std::path::Path;

pub const SQL_CREATE_ADMIN_TOKENS_IF_NOT_EXISTS: &str = r#"
CREATE TABLE IF NOT EXISTS _admin_tokens (
    id              INTEGER PRIMARY KEY,
    admin_id        INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    token_hash      TEXT    NOT NULL UNIQUE,
    plaintext       TEXT,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    last_used_at    TEXT,
    revoked_at      TEXT
) STRICT;

CREATE INDEX IF NOT EXISTS idx_admin_tokens_admin ON _admin_tokens(admin_id);
"#;

pub const SQL_CREATE_SYSTEM_USERS_IF_NOT_EXISTS: &str = r#"
CREATE TABLE IF NOT EXISTS _system_users (
  id            TEXT PRIMARY KEY,
  email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  verified      INTEGER NOT NULL DEFAULT 0,
  profile       TEXT,
  created_at    TEXT NOT NULL,
  updated_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_system_users_email ON _system_users(email);
"#;

pub const SQL_CREATE_SYSTEM_SESSIONS_IF_NOT_EXISTS: &str = r#"
CREATE TABLE IF NOT EXISTS _system_sessions (
  token_hash    TEXT PRIMARY KEY,
  user_id       TEXT NOT NULL REFERENCES _system_users(id) ON DELETE CASCADE,
  created_at    TEXT NOT NULL,
  expires_at    TEXT NOT NULL,
  last_seen_at  TEXT NOT NULL,
  ip_at_login   TEXT
);
CREATE INDEX IF NOT EXISTS idx_system_sessions_user ON _system_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_system_sessions_expires ON _system_sessions(expires_at);
"#;

pub const SQL_CREATE_SYSTEM_OAUTH_PROVIDERS_IF_NOT_EXISTS: &str = r#"
CREATE TABLE IF NOT EXISTS _system_oauth_providers (
  provider              TEXT PRIMARY KEY,
  client_id             TEXT NOT NULL,
  client_secret         TEXT NOT NULL,
  allowed_redirect_uris TEXT NOT NULL,
  created_at            TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at            TEXT NOT NULL DEFAULT (datetime('now'))
);
"#;

pub const SQL_CREATE_SYSTEM_WEBHOOKS_IF_NOT_EXISTS: &str = r#"
CREATE TABLE IF NOT EXISTS _system_webhooks (
  id                   INTEGER PRIMARY KEY AUTOINCREMENT,
  collection           TEXT    NOT NULL,
  events               TEXT    NOT NULL,
  url                  TEXT    NOT NULL,
  secret               TEXT    NOT NULL,
  active               INTEGER NOT NULL DEFAULT 1,
  last_failure_at      TEXT,
  last_failure_reason  TEXT,
  created_at           TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_system_webhooks_collection
  ON _system_webhooks(collection) WHERE active = 1;
"#;

pub const SQL_CREATE_SYSTEM_UPLOAD_SESSIONS_IF_NOT_EXISTS: &str = r#"
CREATE TABLE IF NOT EXISTS "_system_upload_sessions" (
  upload_token   TEXT PRIMARY KEY,
  tenant_id      TEXT    NOT NULL,
  key            TEXT    NOT NULL,
  visibility     TEXT    NOT NULL,
  original_name  TEXT    NOT NULL,
  content_type   TEXT,
  total_length   INTEGER NOT NULL,
  created_at     TEXT    NOT NULL DEFAULT (datetime('now')),
  expires_at     TEXT    NOT NULL,
  uploader       TEXT    NOT NULL DEFAULT 'service'
);
CREATE INDEX IF NOT EXISTS idx_system_upload_sessions_expires
  ON "_system_upload_sessions"(expires_at);
"#;

pub fn add_column_if_missing(
    conn: &Connection,
    table: &str,
    col: &str,
    decl: &str,
) -> rusqlite::Result<()> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({})", table))?;
    let cols: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(1))?
        .collect::<rusqlite::Result<_>>()?;
    if !cols.iter().any(|c| c == col) {
        conn.execute(
            &format!("ALTER TABLE {} ADD COLUMN {} {}", table, col, decl),
            [],
        )?;
    }
    Ok(())
}

pub fn migrate_tenant_db(tenants_dir: &Path, tid: &str) -> rusqlite::Result<()> {
    let path = tenants_dir.join("tenants").join(tid).join("data.sqlite");
    if !path.exists() {
        return Ok(());
    }
    let mut conn = Connection::open(&path)?;
    let tx = conn.transaction()?;
    tx.execute_batch(SQL_CREATE_SYSTEM_USERS_IF_NOT_EXISTS)?;
    tx.execute_batch(SQL_CREATE_SYSTEM_SESSIONS_IF_NOT_EXISTS)?;
    tx.execute_batch(SQL_CREATE_SYSTEM_OAUTH_PROVIDERS_IF_NOT_EXISTS)?;
    tx.execute_batch(SQL_CREATE_SYSTEM_WEBHOOKS_IF_NOT_EXISTS)?;
    tx.execute_batch(SQL_CREATE_SYSTEM_UPLOAD_SESSIONS_IF_NOT_EXISTS)?;
    add_column_if_missing(&tx, "_system_collection_meta", "owner_field", "TEXT")?;
    add_column_if_missing(&tx, "_system_collection_meta", "read_scope", "TEXT")?;
    add_column_if_missing(
        &tx,
        "_system_collection_meta",
        "vector_fields_json",
        "TEXT NOT NULL DEFAULT '[]'",
    )?;
    add_column_if_missing(
        &tx,
        "_system_collection_meta",
        "realtime_enabled",
        "INTEGER NOT NULL DEFAULT 1",
    )?;
    add_column_if_missing(&tx, "_system_collection_meta", "description", "TEXT")?;
    add_column_if_missing(
        &tx,
        "_system_collection_meta",
        "field_descriptions_json",
        "TEXT NOT NULL DEFAULT '{}'",
    )?;
    add_column_if_missing(
        &tx,
        "_system_collection_meta",
        "index_descriptions_json",
        "TEXT NOT NULL DEFAULT '{}'",
    )?;
    // v1.43 — structured CHECK constraints per field (min/max/enum/max_length),
    // keyed by field name. NULL/absent = no constraints. Additive + idempotent.
    add_column_if_missing(
        &tx,
        "_system_collection_meta",
        "field_constraints_json",
        "TEXT NOT NULL DEFAULT '{}'",
    )?;
    // RLS v1 — per-op row-level security policies (nullable; NULL = no
    // explicit policy, governed by tier rules + owner_field).
    add_column_if_missing(&tx, "_system_collection_meta", "select_policy_json", "TEXT")?;
    add_column_if_missing(&tx, "_system_collection_meta", "insert_policy_json", "TEXT")?;
    add_column_if_missing(&tx, "_system_collection_meta", "update_policy_json", "TEXT")?;
    add_column_if_missing(&tx, "_system_collection_meta", "delete_policy_json", "TEXT")?;
    // v1.41 — per-collection user_caps (User role DML allowlist), parallel
    // to anon_caps. NULLABLE with NO default: a NULL reads back as
    // default_user_caps() = {select}, so an upsert helper that omits this
    // column never locks the User role out of select. The IS NULL backfill
    // faithfully inherits each row's existing anon_caps (today's User
    // behavior was "inherit anon_caps") and is idempotent across reboots —
    // once a row is non-NULL (backfill or a later admin set_user_caps) it is
    // never re-touched.
    add_column_if_missing(&tx, "_system_collection_meta", "user_caps_json", "TEXT")?;
    tx.execute(
        "UPDATE _system_collection_meta SET user_caps_json = anon_caps_json \
         WHERE user_caps_json IS NULL",
        [],
    )?;
    // v1.29.5 — _system_rpc.callable_by (H3-1 phase 1). Idempotent
    // backfill from anon_callable: 1 → ["anon","user"], 0 → [].
    // Guarded by table existence — _system_rpc only exists on tenants
    // that have shipped it. The WHERE callable_by = '[]' clause on the
    // UPDATE makes the backfill idempotent (second migration is no-op
    // for already-set rows).
    let has_rpc: i64 = tx
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='_system_rpc'",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    if has_rpc > 0 {
        add_column_if_missing(
            &tx,
            "_system_rpc",
            "callable_by",
            "TEXT NOT NULL DEFAULT '[]'",
        )?;
        tx.execute(
            "UPDATE _system_rpc SET callable_by = \
                CASE WHEN anon_callable = 1 THEN '[\"anon\",\"user\"]' ELSE '[]' END \
             WHERE callable_by = '[]'",
            [],
        )?;
        // v1.29.5 — _system_rpc.user_calls (H3-2 phase 1). Defaults to 0;
        // v1.30 RPC v2 will write user-role counts here instead of
        // lumping them into anon_calls.
        add_column_if_missing(
            &tx,
            "_system_rpc",
            "user_calls",
            "INTEGER NOT NULL DEFAULT 0",
        )?;
        // v1.30 — _system_rpc.mode (S1). 'read' default keeps every v1.29 RPC
        // on the existing v1.6 SELECT path. CHECK constraint is *not* applied
        // by ALTER TABLE ADD COLUMN (SQLite ignores it on alter); the constraint
        // is enforced on fresh DBs from SCHEMA SQL. For upgraded DBs we rely on
        // the application-layer registry::create signature taking RpcMode, so
        // invalid strings can't be inserted via our code path.
        add_column_if_missing(&tx, "_system_rpc", "mode", "TEXT NOT NULL DEFAULT 'read'")?;

        // v1.41.3 legacy one-time safety net: an anon-callable RPC that reads or
        // writes an owner-scoped collection without binding :user_id predates the
        // create/update + owner-scope-change guards and still leaks at call time
        // (the runtime call_rpc path does not re-check owner-scope). Neutralize it
        // fail-closed (anon_callable=0, callable_by='[]') so the leak is closed on
        // upgrade; an admin can re-enable after declaring :user_id. Best-effort —
        // a scan error (e.g. malformed legacy params_json) must never break the
        // startup migration, so it is logged and skipped, not propagated.
        match crate::rpc::prepare::scan_unsafe_anon_rpcs(&tx) {
            Ok(names) if !names.is_empty() => {
                for name in &names {
                    tx.execute(
                        "UPDATE _system_rpc SET anon_callable = 0, callable_by = '[]' \
                         WHERE name = ?1",
                        rusqlite::params![name],
                    )?;
                }
                tracing::warn!(
                    tenant = %tid,
                    rpcs = ?names,
                    "v1.41.3: neutralized legacy anon-callable RPC(s) exposing an owner-scoped \
                     collection without :user_id (set anon_callable=0; re-enable after adding :user_id)"
                );
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(tenant = %tid, error = %e, "v1.41.3 unsafe-anon-rpc scan skipped");
            }
        }
    }
    tx.commit()
}

/// Rewrite a clean single-statement `CREATE TABLE "x" (<body>);` into
/// `CREATE TABLE "<tmp>" (<body>) STRICT;`, preserving the body VERBATIM
/// (FK `ON DELETE`, `DEFAULT (...)`, COLLATE, CHECK — everything). Reusing the
/// original `sqlite_master.sql` is faithful where `codegen/ir.rs` is lossy.
/// Returns `None` if the SQL doesn't match the expected drust shape (a single
/// CREATE TABLE) — caller skips + warns rather than risk corrupting a table.
fn make_strict_ddl(original_sql: &str, tmp: &str) -> Option<String> {
    let open = original_sql.find('(')?;
    let close = original_sql.rfind(')')?;
    if close <= open {
        return None;
    }
    let body = &original_sql[open + 1..close];
    Some(format!(
        "CREATE TABLE \"{}\" ({}) STRICT;",
        tmp.replace('"', "\"\""),
        body
    ))
}

/// Boot-only: rebuild every NON-strict user collection in one tenant's
/// data.sqlite as STRICT, preserving rows/FKs/indexes/triggers/sqlite_sequence.
/// Idempotent — tables already STRICT are skipped (so re-running on every boot
/// is a no-op). Per-table atomic (copy-then-swap); a failing table rolls back
/// and is logged, others continue. MUST run before any pool opens (it uses a
/// dedicated bare `Connection` with `foreign_keys=OFF`, bypassing the per-tenant
/// writer mutex — only safe at boot, before any pool exists).
pub fn strict_rebuild_tenant(tenants_dir: &Path, tid: &str) -> rusqlite::Result<()> {
    let path = tenants_dir.join("tenants").join(tid).join("data.sqlite");
    if !path.exists() {
        return Ok(());
    }
    let conn = Connection::open(&path)?;
    // Must be OUTSIDE any transaction; bare connection defaults foreign_keys=OFF
    // but set it explicitly so DROP of an FK-referenced table is permitted.
    conn.execute_batch("PRAGMA foreign_keys=OFF;")?;

    // User collections only: exclude sqlite_* and _system_* (same predicate as
    // codegen/ir.rs build_collections). FTS shadows are _system_fts_* → excluded.
    let tables: Vec<String> = {
        let mut stmt = conn.prepare(
            "SELECT name FROM sqlite_master \
             WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '\\_system\\_%' ESCAPE '\\'",
        )?;
        stmt.query_map([], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<_>>()?
    };

    for name in tables {
        // Idempotency gate: skip tables already STRICT.
        let is_strict: i64 = conn
            .query_row(
                "SELECT strict FROM pragma_table_list WHERE name=?1",
                [&name],
                |r| r.get(0),
            )
            .unwrap_or(0);
        if is_strict == 1 {
            continue;
        }
        if let Err(e) = rebuild_one_table_strict(&conn, &name) {
            tracing::error!(tenant = %tid, table = %name, error = ?e, "STRICT rebuild of table failed; left original intact");
            // continue with other tables — per-table tx already rolled back.
        }
    }
    Ok(())
}

/// Per-table rebuild inside one transaction. On any error the tx rolls back
/// (DROP-after-copy ordering means the original always survives a failure).
fn rebuild_one_table_strict(conn: &Connection, name: &str) -> rusqlite::Result<()> {
    let original_sql: String = conn.query_row(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name=?1",
        [name],
        |r| r.get(0),
    )?;
    // Temp table name uses the `_system_` prefix so it can NEVER collide with a
    // user collection: tenants cannot create `_system_*` tables (identifier() +
    // is_protected_collection block it), and `_system_%` is excluded from the
    // rebuild scan. (The old `{name}__strict_tmp` was itself a valid collection
    // name, so a tenant collection literally named `<x>__strict_tmp` would make
    // CREATE fail and leave `<x>` permanently non-STRICT.) A leftover from a
    // crashed prior rebuild is cleared by DROP IF EXISTS at the top of the tx.
    let tmp = format!("_system_strict_tmp_{name}");
    let new_ddl = match make_strict_ddl(&original_sql, &tmp) {
        Some(s) => s,
        None => {
            tracing::warn!(table = %name, "unexpected CREATE TABLE shape; skipping STRICT rebuild");
            return Ok(());
        }
    };

    // Capture aux DDL (user indexes + the updated_at trigger) and the
    // AUTOINCREMENT high-water BEFORE the swap (DROP TABLE drops them).
    let aux: Vec<String> = {
        let mut s = conn.prepare(
            "SELECT sql FROM sqlite_master WHERE tbl_name=?1 \
             AND type IN ('index','trigger') AND sql IS NOT NULL",
        )?;
        s.query_map([name], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<_>>()?
    };
    let orig_seq: Option<i64> = conn
        .query_row(
            "SELECT seq FROM sqlite_sequence WHERE name=?1",
            [name],
            |r| r.get(0),
        )
        .ok();

    let q = |s: &str| s.replace('"', "\"\"");
    let tx = conn.unchecked_transaction()?;
    // Clear any leftover temp from a crashed prior rebuild (the `_system_`
    // prefix means this can only ever be our own debris, never tenant data).
    tx.execute_batch(&format!("DROP TABLE IF EXISTS \"{}\";", q(&tmp)))?;
    tx.execute_batch(&new_ddl)?;
    tx.execute_batch(&format!(
        "INSERT INTO \"{tmp}\" SELECT * FROM \"{name}\"; DROP TABLE \"{name}\"; \
         ALTER TABLE \"{tmp}\" RENAME TO \"{name}\";",
        tmp = q(&tmp),
        name = q(name)
    ))?;
    for ddl in &aux {
        // index/trigger DDL references the (restored) original name.
        tx.execute_batch(ddl)?;
    }
    if let Some(seq) = orig_seq {
        // Force the high-water back (copied rows may set a lower seq than the
        // pre-deletion max). Delete-then-insert is the simplest correct form.
        tx.execute("DELETE FROM sqlite_sequence WHERE name=?1", [name])?;
        tx.execute(
            "INSERT INTO sqlite_sequence(name, seq) VALUES (?1, ?2)",
            rusqlite::params![name, seq],
        )?;
    }
    // FK integrity gate before commit — SCOPED to the table being rebuilt.
    // A bare `PRAGMA foreign_key_check` scans the WHOLE database, so a single
    // pre-existing orphan in ANY other table (e.g. legacy data predating FK
    // enforcement, a restored backup) would fail THIS table's rebuild and,
    // applied to every table, silently nullify STRICT migration for the entire
    // tenant — including FK-free clean tables. `foreign_key_check("<name>")`
    // isolates the check to this table so only a genuinely-dirty table is held
    // back; clean tables still migrate.
    {
        let pragma = format!("PRAGMA foreign_key_check(\"{}\")", q(name));
        let mut chk = tx.prepare(&pragma)?;
        if chk.query_map([], |_| Ok(()))?.next().is_some() {
            return Err(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CONSTRAINT),
                Some(format!("foreign_key_check failed rebuilding {name}")),
            ));
        }
    }
    tx.commit()
}

#[derive(Debug, Default)]
pub struct MigrationReport {
    pub meta_done: bool,
    pub tenants_ok: Vec<String>,
    pub tenants_failed: Vec<(String, String)>,
}

pub fn run_migrations(meta: &Connection, tenants_root: &Path) -> rusqlite::Result<MigrationReport> {
    let mut report = MigrationReport::default();

    add_column_if_missing(
        meta,
        "tenants",
        "allow_self_register",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    // v1.32.5 — opt-in publish policy. Default off keeps the historical
    // service-only gate; flipping a flag lets user / anon tokens call
    // `op:publish` (WS) or POST /rooms/<r> (REST). MCP `broadcast` tool
    // stays service-only by MCP dispatch — these flags do not loosen it.
    add_column_if_missing(
        meta,
        "tenants",
        "allow_user_publish",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    add_column_if_missing(
        meta,
        "tenants",
        "allow_anon_publish",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    // v1.42 — opt-in file-storage caps. JSON arrays (subset of
    // {read,list,upload,delete}). Default '[]' = empty = service-only, so every
    // existing tenant keeps today's behaviour until it opts in. add_column_if_missing
    // is the idempotency guard (run_migrations runs every boot — never rewrite).
    add_column_if_missing(
        meta,
        "tenants",
        "file_anon_caps_json",
        "TEXT NOT NULL DEFAULT '[]'",
    )?;
    add_column_if_missing(
        meta,
        "tenants",
        "file_user_caps_json",
        "TEXT NOT NULL DEFAULT '[]'",
    )?;
    // v1.15.0 — denormalized dashboard stats sampled in background.
    add_column_if_missing(meta, "tenants", "db_bytes", "INTEGER NOT NULL DEFAULT 0")?;
    add_column_if_missing(meta, "tenants", "files_bytes", "INTEGER NOT NULL DEFAULT 0")?;
    add_column_if_missing(meta, "tenants", "stats_updated_at", "TEXT")?;

    // v1.29.0 — team management: role column + backfill
    add_column_if_missing(meta, "admins", "role", "TEXT NOT NULL DEFAULT 'member'")?;
    let any_owner: bool = meta
        .query_row(
            "SELECT 1 FROM admins WHERE role='owner' LIMIT 1",
            [],
            |_| Ok(()),
        )
        .is_ok();
    if !any_owner {
        meta.execute("UPDATE admins SET role='owner'", [])?;
    }

    // v1.29.0 — PAT table for headless admin attribution
    meta.execute_batch(SQL_CREATE_ADMIN_TOKENS_IF_NOT_EXISTS)?;

    // v1.29.2 — retract v1.29.0 OAuth AS bundle. Drop tables in dependency
    // order (FK children before parents). Idempotent: no-op when tables are
    // already absent (fresh installs that never saw v1.29.0).
    meta.execute_batch(
        "DROP TABLE IF EXISTS _oauth_refresh_tokens;
         DROP TABLE IF EXISTS _oauth_access_tokens;
         DROP TABLE IF EXISTS _oauth_authorization_codes;
         DROP TABLE IF EXISTS _oauth_clients;",
    )?;

    // v1.29.3 — collapse the two-PAT model (Task 8 manual + v1.29.2 auto_mcp)
    // into a single plaintext-retrievable PAT per admin. See spec
    // docs/superpowers/specs/2026-05-28-drust-v1293-one-pat-per-admin-design.md.

    // 1. Ensure revoked_at column exists (it does on v1.29.2; this is a
    //    defense-in-depth no-op for the constant-update path).
    add_column_if_missing(meta, "_admin_tokens", "revoked_at", "TEXT")?;

    // 2. Add plaintext column (NULL for any pre-existing hash-only rows).
    add_column_if_missing(meta, "_admin_tokens", "plaintext", "TEXT")?;

    // 3. Soft-revoke active LEGACY rows (kind='manual' from Task 8 and
    //    kind='auto_mcp' from v1.29.2 — neither stored plaintext). The backfill
    //    loop below produces fresh plaintext-bearing rows.
    //    audit (2026-06-23) — qualifying on `plaintext IS NULL` is load-bearing:
    //    run_migrations runs on EVERY boot, so an unqualified `WHERE revoked_at
    //    IS NULL` re-revoked the freshly-minted (plaintext-bearing) PATs on each
    //    restart and the backfill below minted new ones — rerolling every
    //    admin's PAT on every restart (breaking PAT-based integrations, e.g. an
    //    MCP connection keyed on a PAT, and accumulating junk rows). Legacy rows
    //    are exactly the plaintext-less ones; once migrated, this is a no-op.
    meta.execute_batch(
        "UPDATE _admin_tokens SET revoked_at = datetime('now') \
         WHERE revoked_at IS NULL AND plaintext IS NULL;",
    )?;

    // 4. Swap the partial unique index: drop the kind-based one, create one
    //    that enforces at-most-one-active-PAT-per-admin via revoked_at.
    meta.execute_batch(
        "DROP INDEX IF EXISTS uniq_admin_tokens_auto_mcp;
         CREATE UNIQUE INDEX IF NOT EXISTS uniq_admin_tokens_active \
             ON _admin_tokens(admin_id) WHERE revoked_at IS NULL;",
    )?;

    // 5 & 6. Drop the `kind` and `name` columns.
    //    SQLite 3.35+ supports DROP COLUMN but rejects it when the column
    //    is referenced by a constraint (UNIQUE(admin_id, name) blocks dropping
    //    `name` directly). We use the classic rename-create-insert-drop
    //    table rebuild when either column is present.
    let has_kind: i64 = meta
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('_admin_tokens') WHERE name = 'kind'",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let has_name: i64 = meta
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('_admin_tokens') WHERE name = 'name'",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    if has_kind > 0 || has_name > 0 {
        // Rebuild the table without the obsolete columns, preserving all rows.
        meta.execute_batch(
            "ALTER TABLE _admin_tokens RENAME TO _admin_tokens_legacy;
             CREATE TABLE _admin_tokens (
                 id              INTEGER PRIMARY KEY,
                 admin_id        INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
                 token_hash      TEXT    NOT NULL UNIQUE,
                 plaintext       TEXT,
                 created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
                 last_used_at    TEXT,
                 revoked_at      TEXT
             ) STRICT;
             INSERT INTO _admin_tokens
                 (id, admin_id, token_hash, plaintext, created_at, last_used_at, revoked_at)
             SELECT id, admin_id, token_hash, plaintext, created_at, last_used_at, revoked_at
             FROM _admin_tokens_legacy;
             DROP TABLE _admin_tokens_legacy;
             CREATE INDEX IF NOT EXISTS idx_admin_tokens_admin ON _admin_tokens(admin_id);
             CREATE UNIQUE INDEX IF NOT EXISTS uniq_admin_tokens_active
                 ON _admin_tokens(admin_id) WHERE revoked_at IS NULL;",
        )?;
    }

    // 7. Backfill: every admin missing an active PAT gets a fresh one.
    //    Idempotent — admins that already have an active row are skipped.
    let admin_ids: Vec<i64> = {
        let mut stmt = meta.prepare("SELECT id FROM admins")?;
        stmt.query_map([], |r| r.get(0))?
            .collect::<rusqlite::Result<Vec<i64>>>()?
    };
    for aid in admin_ids {
        let has_active: bool = meta
            .query_row(
                "SELECT 1 FROM _admin_tokens WHERE admin_id = ?1 AND revoked_at IS NULL",
                rusqlite::params![aid],
                |_| Ok(()),
            )
            .is_ok();
        if !has_active {
            let plaintext = crate::auth::admin_token::generate_token();
            let hash = crate::auth::admin_token::hash_token(&plaintext);
            meta.execute(
                "INSERT INTO _admin_tokens (admin_id, token_hash, plaintext) VALUES (?1, ?2, ?3)",
                rusqlite::params![aid, hash, plaintext],
            )?;
        }
    }

    // v1.29.5 — admin session token_hash column (H4-2 phase 1).
    // Dual-write phase: code writes both `token` (plaintext) and
    // `token_hash` (hex SHA-256). Reads accept either. v1.31+ will
    // drop the `token` column after a stability window.
    // Guard: `sessions` is always present on a real DB (created by
    // SCHEMA_SQL before run_migrations), but tests that seed only a
    // minimal subset of tables skip this step safely.
    let sessions_exists: bool = meta
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='sessions'",
            [],
            |_| Ok(()),
        )
        .is_ok();
    if sessions_exists {
        add_column_if_missing(meta, "sessions", "token_hash", "TEXT")?;
        meta.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash);",
        )?;
    }

    report.meta_done = true;

    let mut stmt = meta.prepare("SELECT id FROM tenants")?;
    let ids: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<_>>()?;

    for tid in ids {
        match migrate_tenant_db(tenants_root, &tid) {
            Ok(_) => report.tenants_ok.push(tid.clone()),
            Err(e) => {
                tracing::error!(tenant = %tid, error = ?e, "tenant migration failed");
                report.tenants_failed.push((tid, e.to_string()));
                // Don't attempt the STRICT rebuild on a tenant whose additive
                // migration failed — the schema may be in an unexpected state.
                continue;
            }
        }
        // v1.43 — boot-time STRICT rebuild of pre-STRICT tenant collections.
        // Runs AFTER migrate_tenant_db, on a dedicated bare connection (the
        // additive migration above already committed + closed its own conn).
        // Idempotent: tables already STRICT are skipped.
        if let Err(e) = strict_rebuild_tenant(tenants_root, &tid) {
            tracing::error!(tenant = %tid, error = ?e, "STRICT rebuild pass failed");
            report.tenants_failed.push((tid, e.to_string()));
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::TempDir;

    fn fresh() -> Connection {
        Connection::open_in_memory().unwrap()
    }

    #[test]
    fn v129_admins_role_column_added_and_backfilled_to_owner() {
        let conn = Connection::open_in_memory().unwrap();
        // Mimic pre-v1.29 admins table shape + minimal meta tables run_migrations needs
        conn.execute_batch(
            "CREATE TABLE tenants (id TEXT PRIMARY KEY, allow_self_register INTEGER NOT NULL DEFAULT 0, db_bytes INTEGER NOT NULL DEFAULT 0, files_bytes INTEGER NOT NULL DEFAULT 0, stats_updated_at TEXT);
            CREATE TABLE admins (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            INSERT INTO admins (username, password_hash, email) VALUES ('alice', 'hash', 'a@x');
            INSERT INTO admins (username, password_hash, email) VALUES ('bob',   'hash', 'b@x');"
        ).unwrap();

        let tmp = TempDir::new().unwrap();
        run_migrations(&conn, tmp.path()).unwrap();

        // Column exists
        let cols: Vec<String> = conn
            .prepare("PRAGMA table_info(admins)")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert!(
            cols.contains(&"role".to_string()),
            "missing role column: {cols:?}"
        );

        // All existing admins backfilled to 'owner'
        let roles: Vec<String> = conn
            .prepare("SELECT role FROM admins ORDER BY id")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(
            roles,
            vec!["owner", "owner"],
            "backfill should lift all existing admins"
        );

        // Idempotent: second run is a no-op
        run_migrations(&conn, tmp.path()).unwrap();
        let roles: Vec<String> = conn
            .prepare("SELECT role FROM admins ORDER BY id")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(roles, vec!["owner", "owner"]);
    }

    #[test]
    fn v1292_oauth_tables_dropped() {
        // Simulate a v1.29.0 install: meta has the 4 OAuth tables.
        // After run_migrations, they MUST be dropped.
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE tenants (id TEXT PRIMARY KEY, allow_self_register INTEGER NOT NULL DEFAULT 0, db_bytes INTEGER NOT NULL DEFAULT 0, files_bytes INTEGER NOT NULL DEFAULT 0, stats_updated_at TEXT);
            CREATE TABLE admins (id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT NOT NULL, email TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now')));
            CREATE TABLE _oauth_clients (id TEXT PRIMARY KEY);
            CREATE TABLE _oauth_authorization_codes (code_hash TEXT PRIMARY KEY);
            CREATE TABLE _oauth_access_tokens (token_hash TEXT PRIMARY KEY);
            CREATE TABLE _oauth_refresh_tokens (token_hash TEXT PRIMARY KEY);"
        ).unwrap();
        let tmp = TempDir::new().unwrap();
        run_migrations(&conn, tmp.path()).unwrap();

        for table in &[
            "_oauth_clients",
            "_oauth_authorization_codes",
            "_oauth_access_tokens",
            "_oauth_refresh_tokens",
        ] {
            let row: i64 = conn
                .query_row(
                    &format!(
                        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='{table}'"
                    ),
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(row, 0, "table {table} should have been dropped");
        }
    }

    #[test]
    fn v1293_fresh_admin_tokens_table_shape() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE tenants (id TEXT PRIMARY KEY, allow_self_register INTEGER NOT NULL DEFAULT 0, db_bytes INTEGER NOT NULL DEFAULT 0, files_bytes INTEGER NOT NULL DEFAULT 0, stats_updated_at TEXT);
             CREATE TABLE admins (id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT NOT NULL, email TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now')));"
        ).unwrap();
        let tmp = TempDir::new().unwrap();
        run_migrations(&conn, tmp.path()).unwrap();

        let cols: Vec<String> = conn
            .prepare("PRAGMA table_info(_admin_tokens)")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert!(
            cols.contains(&"plaintext".to_string()),
            "plaintext column missing: {:?}",
            cols
        );
        assert!(
            !cols.contains(&"kind".to_string()),
            "kind column should be dropped: {:?}",
            cols
        );
        assert!(
            !cols.contains(&"name".to_string()),
            "name column should be dropped: {:?}",
            cols
        );
    }

    #[test]
    fn v1293_migration_drops_kind_softrevokes_legacy_and_backfills() {
        let conn = Connection::open_in_memory().unwrap();
        // Seed a v1.29.2-shaped DB.
        conn.execute_batch(
            "CREATE TABLE tenants (id TEXT PRIMARY KEY, allow_self_register INTEGER NOT NULL DEFAULT 0, db_bytes INTEGER NOT NULL DEFAULT 0, files_bytes INTEGER NOT NULL DEFAULT 0, stats_updated_at TEXT);
             CREATE TABLE admins (id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT NOT NULL, email TEXT, role TEXT NOT NULL DEFAULT 'member', created_at TEXT NOT NULL DEFAULT (datetime('now')));
             CREATE TABLE _admin_tokens (
                id INTEGER PRIMARY KEY,
                admin_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                last_used_at TEXT,
                revoked_at TEXT,
                kind TEXT NOT NULL DEFAULT 'manual',
                UNIQUE(admin_id, name)
             );
             CREATE UNIQUE INDEX uniq_admin_tokens_auto_mcp ON _admin_tokens(admin_id) WHERE kind='auto_mcp' AND revoked_at IS NULL;
             INSERT INTO admins (id, username, password_hash, email, role) VALUES (1, 'alice', 'h', 'a@x', 'owner');
             INSERT INTO admins (id, username, password_hash, email, role) VALUES (2, 'bob',   'h', 'b@x', 'member');
             INSERT INTO _admin_tokens (admin_id, name, token_hash, kind) VALUES (1, 'legacy', 'hash_legacy', 'manual');"
        ).unwrap();
        let tmp = TempDir::new().unwrap();
        run_migrations(&conn, tmp.path()).unwrap();

        // (a) kind column dropped.
        let cols: Vec<String> = conn
            .prepare("PRAGMA table_info(_admin_tokens)")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert!(
            !cols.contains(&"kind".to_string()),
            "kind should be dropped"
        );
        assert!(
            cols.contains(&"plaintext".to_string()),
            "plaintext should be added"
        );

        // (b) Old auto_mcp index gone, new active index present.
        let old: Option<String> = conn.query_row(
            "SELECT name FROM sqlite_master WHERE type='index' AND name='uniq_admin_tokens_auto_mcp'",
            [], |r| r.get(0)
        ).ok();
        assert!(old.is_none(), "old auto_mcp index should be dropped");
        let new_sql: String = conn.query_row(
            "SELECT sql FROM sqlite_master WHERE type='index' AND name='uniq_admin_tokens_active'",
            [], |r| r.get(0)
        ).expect("new uniq_admin_tokens_active index should exist");
        assert!(new_sql.contains("revoked_at IS NULL"));

        // (c) Legacy hash_legacy row was soft-revoked.
        let legacy_revoked: Option<String> = conn
            .query_row(
                "SELECT revoked_at FROM _admin_tokens WHERE token_hash = 'hash_legacy'",
                [],
                |r| r.get(0),
            )
            .ok()
            .flatten();
        assert!(legacy_revoked.is_some(), "legacy PAT must be soft-revoked");

        // (d) Backfill: both admins have one active PAT with non-NULL plaintext.
        for aid in [1, 2] {
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM _admin_tokens WHERE admin_id = ?1 AND revoked_at IS NULL AND plaintext IS NOT NULL",
                rusqlite::params![aid], |r| r.get(0)
            ).unwrap();
            assert_eq!(
                count, 1,
                "admin {} must have exactly 1 active plaintext PAT, got {}",
                aid, count
            );
        }

        // (e) Partial unique index prevents a second active row.
        conn.execute(
            "INSERT INTO _admin_tokens (admin_id, token_hash, plaintext) VALUES (1, 'h2', 'p2')",
            [],
        )
        .expect_err("second active row should violate uniq_admin_tokens_active");
    }

    #[test]
    fn create_system_users_idempotent() {
        let c = fresh();
        c.execute_batch(SQL_CREATE_SYSTEM_USERS_IF_NOT_EXISTS)
            .unwrap();
        c.execute_batch(SQL_CREATE_SYSTEM_USERS_IF_NOT_EXISTS)
            .unwrap();
        let n: i64 = c
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='_system_users'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn create_system_sessions_idempotent() {
        let c = fresh();
        c.execute_batch(SQL_CREATE_SYSTEM_SESSIONS_IF_NOT_EXISTS)
            .unwrap();
        c.execute_batch(SQL_CREATE_SYSTEM_SESSIONS_IF_NOT_EXISTS)
            .unwrap();
        let n: i64 = c
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='_system_sessions'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn create_system_oauth_providers_idempotent() {
        let c = fresh();
        c.execute_batch(SQL_CREATE_SYSTEM_OAUTH_PROVIDERS_IF_NOT_EXISTS)
            .unwrap();
        c.execute_batch(SQL_CREATE_SYSTEM_OAUTH_PROVIDERS_IF_NOT_EXISTS)
            .unwrap();
        let n: i64 = c.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='_system_oauth_providers'",
            [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn create_system_webhooks_idempotent() {
        let c = fresh();
        c.execute_batch(SQL_CREATE_SYSTEM_WEBHOOKS_IF_NOT_EXISTS)
            .unwrap();
        c.execute_batch(SQL_CREATE_SYSTEM_WEBHOOKS_IF_NOT_EXISTS)
            .unwrap(); // second run is a no-op
        let n: i64 = c
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='_system_webhooks'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn add_column_if_missing_adds_once() {
        let c = fresh();
        c.execute("CREATE TABLE t (a TEXT)", []).unwrap();
        add_column_if_missing(&c, "t", "b", "INTEGER NOT NULL DEFAULT 0").unwrap();
        add_column_if_missing(&c, "t", "b", "INTEGER NOT NULL DEFAULT 0").unwrap();
        let cols: Vec<String> = c
            .prepare("PRAGMA table_info(t)")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(cols, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn migrate_tenant_db_creates_tables_and_columns() {
        let dir = tempfile::tempdir().unwrap();
        let tdir = dir.path().join("tenants").join("t-x");
        std::fs::create_dir_all(&tdir).unwrap();
        let p = tdir.join("data.sqlite");
        // Simulate existing tenant DB with a _system_collection_meta table
        {
            let c = Connection::open(&p).unwrap();
            c.execute_batch(
                "CREATE TABLE _system_collection_meta (collection_name TEXT PRIMARY KEY, anon_caps_json TEXT, updated_at TEXT)",
            )
            .unwrap();
        }

        migrate_tenant_db(dir.path(), "t-x").unwrap();
        migrate_tenant_db(dir.path(), "t-x").unwrap(); // idempotent

        let c = Connection::open(&p).unwrap();
        let n_users: i64 = c
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='_system_users'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let n_sess: i64 = c
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='_system_sessions'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n_users, 1);
        assert_eq!(n_sess, 1);

        let cols: Vec<String> = c
            .prepare("PRAGMA table_info(_system_collection_meta)")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(cols.contains(&"owner_field".to_string()));
        assert!(cols.contains(&"read_scope".to_string()));
    }

    #[test]
    fn migrate_tenant_db_neutralizes_legacy_unsafe_anon_rpc() {
        use crate::rpc::registry::{self, RpcMode};
        let dir = tempfile::tempdir().unwrap();
        {
            let conn = crate::storage::tenant_db::open_write(dir.path(), "t-leak").unwrap();
            conn.execute_batch("CREATE TABLE orders (id INTEGER PRIMARY KEY, qty INTEGER);")
                .unwrap();
            crate::storage::schema::set_owner_field(&conn, "orders", Some("user_id"), Some("own"))
                .unwrap();
            // Legacy UNSAFE: anon-callable, reads owner-scoped `orders`, no :user_id.
            registry::create(
                &conn,
                "leak",
                "SELECT id, qty FROM orders",
                "[]",
                None,
                true,
                RpcMode::Read,
            )
            .unwrap();
            // SAFE: anon-callable but binds :user_id → must be left untouched.
            registry::create(
                &conn,
                "mine",
                "SELECT id, qty FROM orders WHERE user_id = :user_id",
                r#"[{"name":"user_id","type":"text","required":true}]"#,
                None,
                true,
                RpcMode::Read,
            )
            .unwrap();
        } // drop the writer before migrate opens its own connection

        migrate_tenant_db(dir.path(), "t-leak").unwrap();

        let conn = crate::storage::tenant_db::open_write(dir.path(), "t-leak").unwrap();
        let anon = |name: &str| -> i64 {
            conn.query_row(
                "SELECT anon_callable FROM _system_rpc WHERE name = ?1",
                rusqlite::params![name],
                |r| r.get(0),
            )
            .unwrap()
        };
        assert_eq!(
            anon("leak"),
            0,
            "legacy unsafe anon RPC must be neutralized"
        );
        assert_eq!(
            anon("mine"),
            1,
            "safe :user_id-bound anon RPC must be left as-is"
        );
        // Idempotent: re-running keeps `leak` neutralized and does not error.
        migrate_tenant_db(dir.path(), "t-leak").unwrap();
        assert_eq!(anon("leak"), 0);
    }

    #[test]
    fn migrate_tenant_db_adds_vector_fields_json() {
        let dir = tempfile::tempdir().unwrap();
        let tdir = dir.path().join("tenants").join("t-vec");
        std::fs::create_dir_all(&tdir).unwrap();
        let p = tdir.join("data.sqlite");
        {
            let c = Connection::open(&p).unwrap();
            c.execute_batch(
                "CREATE TABLE _system_collection_meta (
                    collection_name TEXT PRIMARY KEY,
                    anon_caps_json  TEXT NOT NULL,
                    updated_at      TEXT NOT NULL)",
            )
            .unwrap();
        }
        migrate_tenant_db(dir.path(), "t-vec").unwrap();
        migrate_tenant_db(dir.path(), "t-vec").unwrap(); // idempotent

        let c = Connection::open(&p).unwrap();
        let cols: Vec<String> = c
            .prepare("PRAGMA table_info(_system_collection_meta)")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(
            cols.contains(&"vector_fields_json".to_string()),
            "vector_fields_json column missing after migration; cols = {cols:?}"
        );
    }

    #[test]
    fn migrate_tenant_db_adds_realtime_enabled_defaulting_to_one() {
        let dir = tempfile::tempdir().unwrap();
        let tdir = dir.path().join("tenants").join("t-rt");
        std::fs::create_dir_all(&tdir).unwrap();
        let p = tdir.join("data.sqlite");
        // v1.15-shape meta table: no realtime_enabled column, one row present.
        {
            let c = Connection::open(&p).unwrap();
            c.execute_batch(
                "CREATE TABLE _system_collection_meta (
                    collection_name TEXT PRIMARY KEY,
                    anon_caps_json  TEXT NOT NULL,
                    updated_at      TEXT NOT NULL);
                 INSERT INTO _system_collection_meta
                    (collection_name, anon_caps_json, updated_at)
                    VALUES ('legacy', '[\"select\"]', '2026-01-01');",
            )
            .unwrap();
        }
        migrate_tenant_db(dir.path(), "t-rt").unwrap();
        migrate_tenant_db(dir.path(), "t-rt").unwrap(); // idempotent

        let c = Connection::open(&p).unwrap();
        // Column exists.
        let cols: Vec<String> = c
            .prepare("PRAGMA table_info(_system_collection_meta)")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(
            cols.contains(&"realtime_enabled".to_string()),
            "realtime_enabled column missing after migration; cols = {cols:?}"
        );
        // Existing row backfilled to 1 by the column DEFAULT.
        let v: i64 = c
            .query_row(
                "SELECT realtime_enabled FROM _system_collection_meta WHERE collection_name = 'legacy'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            v, 1,
            "existing row should preserve current SSE behaviour (= 1)"
        );
    }

    #[test]
    fn migrate_tenant_db_adds_description_columns() {
        let dir = tempfile::tempdir().unwrap();
        let tdir = dir.path().join("tenants").join("t-desc");
        std::fs::create_dir_all(&tdir).unwrap();
        let p = tdir.join("data.sqlite");
        // v1.16-shape meta table: has owner_field/read_scope/vector_fields_json/realtime_enabled
        // but no description / field_descriptions_json / index_descriptions_json.
        {
            let c = Connection::open(&p).unwrap();
            c.execute_batch(
                "CREATE TABLE _system_collection_meta (
                    collection_name     TEXT PRIMARY KEY,
                    anon_caps_json      TEXT NOT NULL,
                    updated_at          TEXT NOT NULL,
                    owner_field         TEXT,
                    read_scope          TEXT,
                    vector_fields_json  TEXT NOT NULL DEFAULT '[]',
                    realtime_enabled    INTEGER NOT NULL DEFAULT 1);
                 INSERT INTO _system_collection_meta
                    (collection_name, anon_caps_json, updated_at)
                    VALUES ('legacy', '[\"select\"]', '2026-01-01');",
            )
            .unwrap();
        }

        migrate_tenant_db(dir.path(), "t-desc").unwrap();
        migrate_tenant_db(dir.path(), "t-desc").unwrap(); // idempotent

        let c = Connection::open(&p).unwrap();
        let cols: Vec<String> = c
            .prepare("PRAGMA table_info(_system_collection_meta)")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(
            cols.contains(&"description".to_string()),
            "description column missing; cols = {cols:?}"
        );
        assert!(
            cols.contains(&"field_descriptions_json".to_string()),
            "field_descriptions_json column missing; cols = {cols:?}"
        );
        assert!(
            cols.contains(&"index_descriptions_json".to_string()),
            "index_descriptions_json column missing; cols = {cols:?}"
        );

        // Existing row defaults: description NULL, both JSON blobs '{}'.
        let (d, fd, id): (Option<String>, String, String) = c
            .query_row(
                "SELECT description, field_descriptions_json, index_descriptions_json
               FROM _system_collection_meta WHERE collection_name='legacy'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert!(d.is_none(), "legacy row description should default to NULL");
        assert_eq!(
            fd, "{}",
            "legacy row field_descriptions_json should default to {{}}"
        );
        assert_eq!(
            id, "{}",
            "legacy row index_descriptions_json should default to {{}}"
        );
    }

    #[test]
    fn migrate_tenant_db_adds_policy_columns() {
        let tmp = tempfile::TempDir::new().unwrap();
        let tid = "tpolicy";
        let dir = tmp.path().join("tenants").join(tid);
        std::fs::create_dir_all(&dir).unwrap();
        // Legacy meta table WITHOUT the policy columns.
        {
            let c = Connection::open(dir.join("data.sqlite")).unwrap();
            c.execute_batch(
                "CREATE TABLE _system_collection_meta (
                    collection_name TEXT PRIMARY KEY,
                    anon_caps_json  TEXT NOT NULL DEFAULT '[\"select\"]',
                    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
                );",
            )
            .unwrap();
        }
        migrate_tenant_db(tmp.path(), tid).unwrap();
        let c = Connection::open(dir.join("data.sqlite")).unwrap();
        let cols: Vec<String> = c
            .prepare("PRAGMA table_info(_system_collection_meta)")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        for col in [
            "select_policy_json",
            "insert_policy_json",
            "update_policy_json",
            "delete_policy_json",
        ] {
            assert!(
                cols.contains(&col.to_string()),
                "missing {col}; cols={cols:?}"
            );
        }
    }

    #[test]
    fn migrate_tenant_db_skips_missing_path() {
        let dir = tempfile::tempdir().unwrap();
        // No tenants/t-gone/ dir at all
        migrate_tenant_db(dir.path(), "t-gone").unwrap();
    }

    #[test]
    fn run_migrations_isolates_per_tenant_failure() {
        let dir = tempfile::tempdir().unwrap();
        let meta_path = dir.path().join("meta.sqlite");
        // meta.sqlite with two tenants
        let meta = Connection::open(&meta_path).unwrap();
        meta.execute_batch(
            "CREATE TABLE tenants (id TEXT PRIMARY KEY); \
             INSERT INTO tenants VALUES ('t-ok'), ('t-locked'); \
             CREATE TABLE admins (id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT NOT NULL, email TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now')));",
        ).unwrap();

        // t-ok has a normal data.sqlite with the old _system_collection_meta
        let ok_dir = dir.path().join("tenants").join("t-ok");
        std::fs::create_dir_all(&ok_dir).unwrap();
        Connection::open(ok_dir.join("data.sqlite")).unwrap().execute_batch(
            "CREATE TABLE _system_collection_meta (collection_name TEXT PRIMARY KEY, anon_caps_json TEXT, updated_at TEXT)",
        ).unwrap();
        // t-locked's data.sqlite has a corrupt path (use a directory instead of file to provoke open failure)
        let bad_dir = dir.path().join("tenants").join("t-locked");
        std::fs::create_dir_all(bad_dir.join("data.sqlite")).unwrap(); // dir where a file should be → open fails

        let report = run_migrations(&meta, dir.path()).unwrap();
        assert!(report.tenants_ok.contains(&"t-ok".to_string()));
        assert!(report.tenants_failed.iter().any(|(t, _)| t == "t-locked"));
        // t-ok must have been migrated despite t-locked failing
        let c = Connection::open(ok_dir.join("data.sqlite")).unwrap();
        let n: i64 = c
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='_system_users'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn run_migrations_does_not_reroll_pat_on_every_boot() {
        // audit (2026-06-23) — the v1.29.3 "collapse legacy PATs" step revoked
        // EVERY active PAT unconditionally, and run_migrations runs on every
        // boot, so each restart rerolled every admin's PAT (broke PAT-based
        // integrations + accumulated junk rows; admin 1 had 68 in prod). Running
        // migrations twice MUST keep the same active PAT.
        let dir = tempfile::tempdir().unwrap();
        let meta = Connection::open(dir.path().join("meta.sqlite")).unwrap();
        meta.execute_batch(
            "CREATE TABLE tenants (id TEXT PRIMARY KEY);
             CREATE TABLE admins (id INTEGER PRIMARY KEY, username TEXT, \
                 password_hash TEXT NOT NULL, email TEXT, \
                 created_at TEXT NOT NULL DEFAULT (datetime('now')));
             INSERT INTO admins (username, password_hash) VALUES ('kael', 'h');",
        )
        .unwrap();

        // First boot: the backfill mints one active, plaintext-bearing PAT.
        run_migrations(&meta, dir.path()).unwrap();
        let first: String = meta
            .query_row(
                "SELECT token_hash FROM _admin_tokens WHERE admin_id=1 AND revoked_at IS NULL",
                [],
                |r| r.get(0),
            )
            .expect("exactly one active PAT after the first migrate");

        // Second boot (simulated restart): must NOT reroll.
        run_migrations(&meta, dir.path()).unwrap();
        let active_count: i64 = meta
            .query_row(
                "SELECT COUNT(*) FROM _admin_tokens WHERE admin_id=1 AND revoked_at IS NULL",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            active_count, 1,
            "still exactly one active PAT after a second boot"
        );
        let second: String = meta
            .query_row(
                "SELECT token_hash FROM _admin_tokens WHERE admin_id=1 AND revoked_at IS NULL",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            first, second,
            "the active PAT must survive a restart — no reroll on every boot"
        );
    }

    #[test]
    fn v1295_callable_by_column_added_and_backfilled() {
        let dir = tempfile::tempdir().unwrap();
        let tdir = dir.path().join("tenants").join("t-rpc");
        std::fs::create_dir_all(&tdir).unwrap();
        let p = tdir.join("data.sqlite");
        {
            let c = Connection::open(&p).unwrap();
            c.execute_batch(
                "CREATE TABLE _system_collection_meta (collection_name TEXT PRIMARY KEY, anon_caps_json TEXT, updated_at TEXT);
                 CREATE TABLE _system_rpc (
                    name TEXT PRIMARY KEY, sql TEXT NOT NULL, params_json TEXT NOT NULL,
                    description TEXT, anon_callable INTEGER NOT NULL DEFAULT 0,
                    anon_calls INTEGER NOT NULL DEFAULT 0,
                    service_calls INTEGER NOT NULL DEFAULT 0,
                    last_called_at TEXT,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
                 );
                 INSERT INTO _system_rpc (name, sql, params_json, anon_callable) VALUES ('public_fn', 'SELECT 1', '[]', 1);
                 INSERT INTO _system_rpc (name, sql, params_json, anon_callable) VALUES ('service_fn', 'SELECT 2', '[]', 0);"
            ).unwrap();
        }
        migrate_tenant_db(dir.path(), "t-rpc").unwrap();
        migrate_tenant_db(dir.path(), "t-rpc").unwrap(); // idempotent — second run no-op

        let c = Connection::open(&p).unwrap();
        let pub_cb: String = c
            .query_row(
                "SELECT callable_by FROM _system_rpc WHERE name='public_fn'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let svc_cb: String = c
            .query_row(
                "SELECT callable_by FROM _system_rpc WHERE name='service_fn'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(pub_cb, r#"["anon","user"]"#);
        assert_eq!(svc_cb, "[]");
    }

    #[test]
    fn v141_user_caps_json_added_and_backfilled_from_anon() {
        let dir = tempfile::tempdir().unwrap();
        let tdir = dir.path().join("tenants").join("t-uc-caps");
        std::fs::create_dir_all(&tdir).unwrap();
        let p = tdir.join("data.sqlite");
        {
            let c = Connection::open(&p).unwrap();
            // Pre-v1.41 meta shape: anon_caps_json present, no user_caps_json.
            // Seed a row with a NON-default anon_caps_json so the backfill is
            // observable (not just the {select} default).
            c.execute_batch(
                "CREATE TABLE _system_collection_meta (collection_name TEXT PRIMARY KEY, anon_caps_json TEXT, updated_at TEXT);
                 INSERT INTO _system_collection_meta (collection_name, anon_caps_json) VALUES ('posts', '[\"select\",\"insert\"]');",
            )
            .unwrap();
        }
        migrate_tenant_db(dir.path(), "t-uc-caps").unwrap();
        migrate_tenant_db(dir.path(), "t-uc-caps").unwrap(); // idempotent — second run no-op

        let c = Connection::open(&p).unwrap();
        // Faithful inherit: user_caps_json == anon_caps_json after backfill.
        let (user_caps, anon_caps): (String, String) = c
            .query_row(
                "SELECT user_caps_json, anon_caps_json FROM _system_collection_meta WHERE collection_name='posts'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(user_caps, r#"["select","insert"]"#);
        assert_eq!(
            user_caps, anon_caps,
            "user_caps_json must equal anon_caps_json after backfill"
        );
    }

    #[test]
    fn v141_user_caps_json_left_null_when_anon_caps_is_null() {
        // A meta row whose anon_caps_json is NULL: the backfill copies NULL,
        // leaving user_caps_json NULL — which read_user_caps falls back to
        // default_user_caps() = {select}. Proves no spurious value is written.
        let dir = tempfile::tempdir().unwrap();
        let tdir = dir.path().join("tenants").join("t-uc-null");
        std::fs::create_dir_all(&tdir).unwrap();
        let p = tdir.join("data.sqlite");
        {
            let c = Connection::open(&p).unwrap();
            c.execute_batch(
                "CREATE TABLE _system_collection_meta (collection_name TEXT PRIMARY KEY, anon_caps_json TEXT, updated_at TEXT);
                 INSERT INTO _system_collection_meta (collection_name, anon_caps_json) VALUES ('nullcaps', NULL);",
            )
            .unwrap();
        }
        migrate_tenant_db(dir.path(), "t-uc-null").unwrap();
        migrate_tenant_db(dir.path(), "t-uc-null").unwrap();

        let c = Connection::open(&p).unwrap();
        let user_caps: Option<String> = c
            .query_row(
                "SELECT user_caps_json FROM _system_collection_meta WHERE collection_name='nullcaps'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            user_caps, None,
            "NULL anon_caps_json must backfill to NULL user_caps_json"
        );
    }

    #[test]
    fn v1295_user_calls_column_added_default_zero() {
        let dir = tempfile::tempdir().unwrap();
        let tdir = dir.path().join("tenants").join("t-uc");
        std::fs::create_dir_all(&tdir).unwrap();
        let p = tdir.join("data.sqlite");
        {
            let c = Connection::open(&p).unwrap();
            c.execute_batch(
                "CREATE TABLE _system_collection_meta (collection_name TEXT PRIMARY KEY, anon_caps_json TEXT, updated_at TEXT);
                 CREATE TABLE _system_rpc (
                    name TEXT PRIMARY KEY, sql TEXT NOT NULL, params_json TEXT NOT NULL,
                    description TEXT, anon_callable INTEGER NOT NULL DEFAULT 0,
                    anon_calls INTEGER NOT NULL DEFAULT 0, service_calls INTEGER NOT NULL DEFAULT 0,
                    last_called_at TEXT,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
                 );
                 INSERT INTO _system_rpc (name, sql, params_json) VALUES ('x', 'SELECT 1', '[]');"
            ).unwrap();
        }
        migrate_tenant_db(dir.path(), "t-uc").unwrap();
        migrate_tenant_db(dir.path(), "t-uc").unwrap(); // idempotent

        let c = Connection::open(&p).unwrap();
        let uc: i64 = c
            .query_row(
                "SELECT user_calls FROM _system_rpc WHERE name='x'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(uc, 0);
    }

    #[test]
    fn v1295_callable_by_skipped_when_rpc_table_absent() {
        // Confirm migration doesn't fail on tenant DBs that never
        // shipped _system_rpc (legacy edge case).
        let dir = tempfile::tempdir().unwrap();
        let tdir = dir.path().join("tenants").join("t-norpc");
        std::fs::create_dir_all(&tdir).unwrap();
        let p = tdir.join("data.sqlite");
        {
            let c = Connection::open(&p).unwrap();
            c.execute_batch(
                "CREATE TABLE _system_collection_meta (collection_name TEXT PRIMARY KEY, anon_caps_json TEXT, updated_at TEXT);"
            ).unwrap();
        }
        // Must not panic / error.
        migrate_tenant_db(dir.path(), "t-norpc").unwrap();
    }

    // ----- v1.30 S1: _system_rpc.mode column -----

    #[test]
    fn v130_fresh_db_has_mode_column_defaulting_to_read() {
        // Fresh tenant DB through open_write → SCHEMA SQL applies; migrate is
        // a defense-in-depth idempotent pass on top.
        let tmp = TempDir::new().unwrap();
        let conn = crate::storage::tenant_db::open_write(tmp.path(), "fresh130").unwrap();
        drop(conn);
        migrate_tenant_db(tmp.path(), "fresh130").unwrap();

        let c = Connection::open(
            tmp.path()
                .join("tenants")
                .join("fresh130")
                .join("data.sqlite"),
        )
        .unwrap();
        // (a) Column present.
        let cols: Vec<String> = c
            .prepare("PRAGMA table_info(_system_rpc)")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert!(
            cols.contains(&"mode".to_string()),
            "_system_rpc.mode column missing on fresh DB; cols = {cols:?}"
        );

        // (b) Default-value check: insert omitting `mode`, then read it back.
        c.execute(
            "INSERT INTO _system_rpc (name, sql, params_json) VALUES ('m1', 'SELECT 1', '[]')",
            [],
        )
        .unwrap();
        let m: String = c
            .query_row("SELECT mode FROM _system_rpc WHERE name = 'm1'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(
            m, "read",
            "fresh-DB default for _system_rpc.mode must be 'read'"
        );
    }

    #[test]
    fn v130_upgrade_preserves_existing_rpcs_as_read() {
        // Build a pre-v1.30 _system_rpc by hand (no `mode` column), populate
        // two rows, then run the migration. Existing rows must report 'read'.
        let dir = tempfile::tempdir().unwrap();
        let tdir = dir.path().join("tenants").join("t-up130");
        std::fs::create_dir_all(&tdir).unwrap();
        let p = tdir.join("data.sqlite");
        {
            let c = Connection::open(&p).unwrap();
            c.execute_batch(
                "CREATE TABLE _system_collection_meta (collection_name TEXT PRIMARY KEY, anon_caps_json TEXT, updated_at TEXT);
                 CREATE TABLE _system_rpc (
                    name TEXT PRIMARY KEY, sql TEXT NOT NULL, params_json TEXT NOT NULL,
                    description TEXT, anon_callable INTEGER NOT NULL DEFAULT 0,
                    anon_calls INTEGER NOT NULL DEFAULT 0,
                    service_calls INTEGER NOT NULL DEFAULT 0,
                    last_called_at TEXT,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
                 );
                 INSERT INTO _system_rpc (name, sql, params_json) VALUES ('old_a', 'SELECT 1', '[]');
                 INSERT INTO _system_rpc (name, sql, params_json) VALUES ('old_b', 'SELECT 2', '[]');"
            ).unwrap();
        }
        migrate_tenant_db(dir.path(), "t-up130").unwrap();

        let c = Connection::open(&p).unwrap();
        let cols: Vec<String> = c
            .prepare("PRAGMA table_info(_system_rpc)")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert!(
            cols.contains(&"mode".to_string()),
            "mode column missing after upgrade; cols = {cols:?}"
        );

        for name in ["old_a", "old_b"] {
            let m: String = c
                .query_row(
                    "SELECT mode FROM _system_rpc WHERE name = ?1",
                    rusqlite::params![name],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(
                m, "read",
                "pre-v1.30 row {name} should default to 'read', got {m:?}"
            );
        }
    }

    #[test]
    fn v130_migration_idempotent() {
        // Running migrate_tenant_db twice on the same DB must succeed.
        // add_column_if_missing silently skips re-adding existing columns.
        let dir = tempfile::tempdir().unwrap();
        let tdir = dir.path().join("tenants").join("t-idem130");
        std::fs::create_dir_all(&tdir).unwrap();
        let p = tdir.join("data.sqlite");
        {
            let c = Connection::open(&p).unwrap();
            c.execute_batch(
                "CREATE TABLE _system_collection_meta (collection_name TEXT PRIMARY KEY, anon_caps_json TEXT, updated_at TEXT);
                 CREATE TABLE _system_rpc (
                    name TEXT PRIMARY KEY, sql TEXT NOT NULL, params_json TEXT NOT NULL,
                    description TEXT, anon_callable INTEGER NOT NULL DEFAULT 0,
                    anon_calls INTEGER NOT NULL DEFAULT 0,
                    service_calls INTEGER NOT NULL DEFAULT 0,
                    last_called_at TEXT,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
                 );"
            ).unwrap();
        }
        migrate_tenant_db(dir.path(), "t-idem130").unwrap();
        migrate_tenant_db(dir.path(), "t-idem130").unwrap(); // second run = no-op

        // Sanity: column exists exactly once.
        let c = Connection::open(&p).unwrap();
        let mode_count: i64 = c
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('_system_rpc') WHERE name = 'mode'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            mode_count, 1,
            "mode column must appear exactly once after double-migrate"
        );
    }

    #[test]
    fn v130_fresh_db_check_constraint_rejects_invalid_mode() {
        // Fresh DB via open_write → SCHEMA SQL's CHECK(mode IN ('read','write'))
        // must reject an out-of-set value.
        let tmp = TempDir::new().unwrap();
        let conn = crate::storage::tenant_db::open_write(tmp.path(), "chkmode").unwrap();
        let err = conn
            .execute(
                "INSERT INTO _system_rpc (name, sql, params_json, mode)
             VALUES ('x', 'SELECT 1', '[]', 'execute')",
                [],
            )
            .unwrap_err();
        // Any SQLite error is acceptable; the test guarantees the row was
        // not accepted. We additionally assert the message mentions CHECK
        // to catch a future drift where the constraint silently disappears.
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("check") || msg.contains("constraint"),
            "expected CHECK constraint violation, got: {err}"
        );
    }

    #[test]
    fn migrate_tenant_db_creates_upload_sessions() {
        let dir = tempfile::tempdir().unwrap();
        let tdir = dir.path().join("tenants").join("t-up");
        std::fs::create_dir_all(&tdir).unwrap();
        let p = tdir.join("data.sqlite");
        {
            let c = Connection::open(&p).unwrap();
            c.execute_batch(
                "CREATE TABLE _system_collection_meta (collection_name TEXT PRIMARY KEY, anon_caps_json TEXT, updated_at TEXT)",
            ).unwrap();
        }
        migrate_tenant_db(dir.path(), "t-up").unwrap();
        migrate_tenant_db(dir.path(), "t-up").unwrap(); // idempotent
        let c = Connection::open(&p).unwrap();
        let n: i64 = c.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='_system_upload_sessions'",
            [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn make_strict_ddl_preserves_body_and_appends_strict() {
        let orig = r#"CREATE TABLE "posts" ("id" INTEGER PRIMARY KEY AUTOINCREMENT,"title" TEXT NOT NULL,"author" INTEGER REFERENCES "users"("id") ON DELETE RESTRICT,created_at TEXT NOT NULL DEFAULT (datetime('now')));"#;
        let got = super::make_strict_ddl(orig, "posts__strict_tmp").unwrap();
        assert!(got.starts_with(r#"CREATE TABLE "posts__strict_tmp" ("#));
        assert!(got.trim_end().ends_with(") STRICT;"));
        // Body (FK ON DELETE RESTRICT, the datetime default with nested parens) preserved verbatim.
        assert!(got.contains(r#"REFERENCES "users"("id") ON DELETE RESTRICT"#));
        assert!(got.contains("DEFAULT (datetime('now'))"));
    }

    #[test]
    fn make_strict_ddl_rejects_unexpected_shape() {
        assert!(super::make_strict_ddl("not a create table", "x").is_none());
    }
}
