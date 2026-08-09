//! Wave 2 M3 Task 7 — end-to-end integration pins proving the FTS5 feature
//! composes with drust's existing machinery. These are PINS: a failing one is a
//! genuine defect in an earlier task, not a signal to weaken the assertion.
//!
//! 1. A real `run_write_rpc` (`src/rpc/exec_write.rs`) INSERT/UPDATE/DELETE on an
//!    fts-indexed collection indexes each change, and `_system_record_history`
//!    carries the parent rows with correct old/new images AND **zero** rows for
//!    any `_system_search_*` table — the preupdate-hook `_system_` filter
//!    (`record_history.rs`) keeps shadow churn out of history.
//! 2. A dry-run write-RPC leaves the index + parent untouched (savepoint
//!    rollback also unwinds the fts sync-trigger head writes; integrity holds).
//! 3. `strict_rebuild_tenant` on a non-STRICT fts-indexed collection rebuilds the
//!    parent yet preserves the three sync triggers and the head/shadows, and a
//!    post-rebuild INSERT is still indexed.
//! 4. A HOST `sqlite3` `VACUUM INTO` (the production backup engine, not drust's
//!    bundled one) of a bundled-created fts DB still answers MATCH + passes
//!    fts5 `('integrity-check')`. Skips gracefully below sqlite 3.34.

use drust::mcp::server::{DrustMcp, McpRegistry};
use drust::mcp::tools::fts::create_fts_index;
use drust::mcp::tools::schema::{FieldSpec, create_collection};
use drust::storage::pool::{SharedTenantPool, TenantRegistry};
use drust::storage::record_history::{AuditActor, CaptureLimits};
use drust::storage::search_names::{fts_head_name, fts_trigger_names};
use rusqlite::Connection;
use std::collections::BTreeMap;
use std::sync::Arc;

// ── fixtures ───────────────────────────────────────────────────────────────

async fn svc(dir: &tempfile::TempDir, tenant: &str) -> DrustMcp {
    let data = dir.path().to_path_buf();
    let tr = Arc::new(TenantRegistry::new(data.clone(), 2));
    let _ = drust::storage::tenant_db::open_write(&data, tenant).unwrap();
    McpRegistry::new(tr).get_or_create(tenant).await.unwrap()
}

fn text_field(name: &str) -> FieldSpec {
    FieldSpec {
        name: name.into(),
        sql_type: "text".into(),
        nullable: true,
        ..Default::default()
    }
}

fn pool_of(s: &DrustMcp) -> SharedTenantPool {
    s.inner().pool.clone()
}

/// Drive the REAL write-mode RPC executor (unlimited capture, service actor,
/// tier 1). Panics with the surfaced error if the tx or a statement fails, so a
/// pin that expects success reads as a plain call.
async fn run_rpc(
    pool: &SharedTenantPool,
    sql: &str,
    dry_run: bool,
) -> drust::rpc::exec_write::WriteRpcOutcome {
    drust::rpc::exec_write::run_write_rpc(
        pool,
        sql.to_string(),
        BTreeMap::new(),
        dry_run,
        AuditActor::service(),
        CaptureLimits {
            max_rows: 0,
            max_bytes: 0,
        },
        1,
    )
    .await
    .expect("write-RPC committed without a TxCommitError")
    .expect("write-RPC statement executed without error")
}

/// Rows the external-content head matches for `term` (direct SQL on the head —
/// same shape as tests/fts_index_lifecycle.rs).
async fn match_count(pool: &SharedTenantPool, head: &str, term: &str) -> i64 {
    let head = head.to_string();
    let term = term.to_string();
    pool.with_reader(move |c| {
        c.query_row(
            &format!(
                "SELECT count(*) FROM \"{h}\" WHERE \"{h}\" MATCH ?1",
                h = head.replace('"', "\"\"")
            ),
            rusqlite::params![term],
            |r| r.get::<_, i64>(0),
        )
    })
    .await
    .unwrap()
}

async fn parent_count(pool: &SharedTenantPool, coll: &str) -> i64 {
    let sql = format!("SELECT count(*) FROM \"{}\"", coll.replace('"', "\"\""));
    pool.with_reader(move |c| c.query_row(&sql, [], |r| r.get(0)))
        .await
        .unwrap()
}

/// fts5 `('integrity-check')`: the module raises if the shadow disagrees with
/// the external content. A clean run returns Ok.
async fn integrity_check(pool: &SharedTenantPool, head: &str) {
    let head = head.to_string();
    pool.with_writer(move |c| {
        c.execute_batch(&format!(
            "INSERT INTO \"{h}\"(\"{h}\") VALUES('integrity-check');",
            h = head.replace('"', "\"\"")
        ))
    })
    .await
    .expect("fts5 integrity-check must pass");
}

/// One `_system_record_history` row projected for assertions. The collection
/// column is named `collection` (NOT `table_name` — the task's shorthand); the
/// shadow-exclusion pin greps it.
#[derive(Debug)]
struct HistRow {
    collection: String,
    op: String,
    record_id: i64,
    old_json: Option<String>,
    new_json: Option<String>,
}

async fn history_rows(pool: &SharedTenantPool) -> Vec<HistRow> {
    pool.with_reader(|c| {
        let mut stmt = c.prepare(
            "SELECT collection, op, record_id, old_json, new_json \
             FROM _system_record_history ORDER BY id",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(HistRow {
                    collection: r.get(0)?,
                    op: r.get(1)?,
                    record_id: r.get(2)?,
                    old_json: r.get(3)?,
                    new_json: r.get(4)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    })
    .await
    .unwrap()
}

fn title_of(json: &Option<String>) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(json.as_deref()?).ok()?;
    v.get("title")?.as_str().map(|s| s.to_string())
}

// ── Pin 1 — write-RPC end to end + history excludes the fts shadows ─────────

#[tokio::test]
async fn write_rpc_on_fts_collection_indexes_each_change_and_history_excludes_shadows() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d, "t-fts-wr").await;
    create_collection(&s, "notes", &[text_field("title"), text_field("body")])
        .await
        .unwrap();
    create_fts_index(&s, "notes", "main", &["title".into(), "body".into()], None)
        .await
        .unwrap();
    let pool = pool_of(&s);
    // Audit ON explicitly (canonical create_collection already defaults ON).
    pool.with_writer(|c| drust::storage::schema::write_audit_enabled(c, "notes", true))
        .await
        .unwrap();
    let head = fts_head_name("notes", "main");

    // INSERT — indexed by the _ai sync trigger.
    let ins = run_rpc(
        &pool,
        "INSERT INTO notes (title, body) VALUES ('alpha report', 'quarterly numbers')",
        false,
    )
    .await;
    assert_eq!(ins.affected_rows, 1);
    let id = ins.last_insert_rowid.expect("insert rowid");
    assert_eq!(
        match_count(&pool, &head, "alpha").await,
        1,
        "inserted row is indexed"
    );

    // UPDATE — re-indexed by the _au sync trigger (delete-old + insert-new).
    run_rpc(
        &pool,
        &format!("UPDATE notes SET title='gamma memo' WHERE id={id}"),
        false,
    )
    .await;
    assert_eq!(
        match_count(&pool, &head, "alpha").await,
        0,
        "old term gone after update re-index"
    );
    assert_eq!(
        match_count(&pool, &head, "gamma").await,
        1,
        "new term indexed after update"
    );

    // DELETE — removed by the _ad sync trigger.
    run_rpc(&pool, &format!("DELETE FROM notes WHERE id={id}"), false).await;
    assert_eq!(
        match_count(&pool, &head, "gamma").await,
        0,
        "deleted row gone from index"
    );
    assert_eq!(match_count(&pool, &head, "quarterly").await, 0);

    // ── history: exactly the three PARENT rows, correct old/new images. ──
    let rows = history_rows(&pool).await;
    let parent: Vec<&HistRow> = rows.iter().filter(|r| r.collection == "notes").collect();
    assert_eq!(
        parent.iter().map(|r| r.op.as_str()).collect::<Vec<_>>(),
        vec!["insert", "update", "delete"],
        "one parent history row per write, in order: {rows:?}"
    );
    for r in &parent {
        assert_eq!(r.record_id, id, "every parent row records the same id");
    }
    // insert: no pre-image, post-image carries the inserted title.
    assert!(parent[0].old_json.is_none(), "insert has no pre-image");
    assert_eq!(
        title_of(&parent[0].new_json).as_deref(),
        Some("alpha report")
    );
    // update: old title → new title (trigger events on `notes` merge; fts head
    // events are filtered, so exactly ONE op=update row).
    assert_eq!(
        title_of(&parent[1].old_json).as_deref(),
        Some("alpha report")
    );
    assert_eq!(title_of(&parent[1].new_json).as_deref(), Some("gamma memo"));
    // delete: pre-image carries the last title, no post-image.
    assert_eq!(title_of(&parent[2].old_json).as_deref(), Some("gamma memo"));
    assert!(parent[2].new_json.is_none(), "delete has no post-image");

    // ── THE load-bearing pin: not one shadow row leaked into history. ──
    let shadow_rows: i64 = pool
        .with_reader(|c| {
            c.query_row(
                "SELECT count(*) FROM _system_record_history \
                 WHERE collection LIKE '\\_system\\_search\\_%' ESCAPE '\\'",
                [],
                |r| r.get(0),
            )
        })
        .await
        .unwrap();
    assert_eq!(
        shadow_rows, 0,
        "the preupdate _system_ filter must keep every _system_search_* change \
         out of record history: {rows:?}"
    );
}

// ── Pin 2 — dry-run leaves index + parent untouched ────────────────────────

#[tokio::test]
async fn dry_run_write_rpc_leaves_index_and_parent_untouched() {
    let d = tempfile::tempdir().unwrap();
    let s = svc(&d, "t-fts-dry").await;
    create_collection(&s, "notes", &[text_field("title"), text_field("body")])
        .await
        .unwrap();
    create_fts_index(&s, "notes", "main", &["title".into(), "body".into()], None)
        .await
        .unwrap();
    let pool = pool_of(&s);
    let head = fts_head_name("notes", "main");

    // One committed row so the index has real content to protect.
    run_rpc(
        &pool,
        "INSERT INTO notes (title, body) VALUES ('committed row', 'stays put')",
        false,
    )
    .await;
    let before = parent_count(&pool, "notes").await;
    assert_eq!(before, 1);

    // Dry-run INSERT: the savepoint rolls back, taking the _ai trigger's head
    // write with it.
    let dry = run_rpc(
        &pool,
        "INSERT INTO notes (title, body) VALUES ('phantom entry', 'never lands')",
        true,
    )
    .await;
    assert!(dry.dry_run, "outcome flags the dry run");

    assert_eq!(
        parent_count(&pool, "notes").await,
        before,
        "dry-run persisted no parent row"
    );
    assert_eq!(
        match_count(&pool, &head, "phantom").await,
        0,
        "would-be term is NOT indexed after a dry run"
    );
    assert_eq!(
        match_count(&pool, &head, "committed").await,
        1,
        "the committed row is still indexed"
    );
    integrity_check(&pool, &head).await;
}

// ── Pin 3 — STRICT rebuild preserves the sync triggers + head ──────────────

#[tokio::test]
async fn strict_rebuild_preserves_fts_sync_triggers_and_head() {
    let d = tempfile::tempdir().unwrap();
    let data = d.path().to_path_buf();
    let tr = Arc::new(TenantRegistry::new(data.clone(), 2));
    drust::storage::tenant_db::open_write(&data, "t-fts-rb").unwrap();
    let reg = McpRegistry::new(tr.clone());
    let s = reg.get_or_create("t-fts-rb").await.unwrap();
    let pool = pool_of(&s);

    // A LEGACY, non-STRICT `notes` collection (raw CREATE TABLE, no STRICT) with
    // the canonical `updated_at` trigger — exactly the pre-STRICT shape
    // strict_rebuild_tenant exists to migrate. Then attach a REAL fts index over
    // it (create_fts_index reads schema from PRAGMA, not STRICT-ness).
    pool.with_writer(|c| {
        c.execute_batch(
            r#"CREATE TABLE "notes" (
                   "id" INTEGER PRIMARY KEY AUTOINCREMENT,
                   "title" TEXT, "body" TEXT,
                   created_at TEXT NOT NULL DEFAULT (datetime('now')),
                   updated_at TEXT NOT NULL DEFAULT (datetime('now')));
               CREATE TRIGGER "notes_updated_at" AFTER UPDATE ON "notes"
                   BEGIN UPDATE "notes" SET updated_at = datetime('now') WHERE id = OLD.id; END;
               INSERT INTO "notes"(title, body) VALUES ('seed alpha', 'seed body');"#,
        )
    })
    .await
    .unwrap();
    create_fts_index(&s, "notes", "main", &["title".into(), "body".into()], None)
        .await
        .unwrap();

    let head = fts_head_name("notes", "main");
    // Sanity: non-STRICT before the rebuild, and the seed row is indexed.
    assert_eq!(match_count(&pool, &head, "seed").await, 1);

    // Flush WAL into the main file, then release EVERY pool handle so the
    // rebuild's bare connection owns the file (mirrors strict_rebuild.rs, which
    // rebuilds a file with no live pool).
    pool.with_writer(|c| c.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);"))
        .await
        .unwrap();
    drop(pool);
    drop(s);
    drop(reg);
    drop(tr);

    // Run the real rebuild. `notes` is clean (only non-STRICT), so it rebuilds;
    // nothing is held back.
    let held = drust::db::migrations::strict_rebuild_tenant(d.path(), "t-fts-rb").unwrap();
    assert!(
        held.is_empty(),
        "clean fts collection must rebuild without being held back: {held:?}"
    );

    let path = d
        .path()
        .join("tenants")
        .join("t-fts-rb")
        .join("data.sqlite");
    let c = Connection::open(&path).unwrap();

    // Parent is STRICT now (the pre-existing rebuild contract).
    let strict: i64 = c
        .query_row(
            "SELECT strict FROM pragma_table_list WHERE name='notes'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(strict, 1, "parent collection must be STRICT after rebuild");

    // The THREE sync triggers survive (they are `ON notes`, so the rebuild's aux
    // capture recreates them). `_` is a LIKE wildcard, so escape it.
    let trig_like = format!("{}%", head.replace('_', "\\_"));
    let triggers: i64 = c
        .query_row(
            "SELECT count(*) FROM sqlite_master \
             WHERE type='trigger' AND name LIKE ?1 ESCAPE '\\'",
            rusqlite::params![trig_like],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        triggers, 3,
        "all three fts sync triggers must survive the parent rebuild"
    );
    // Belt-and-braces: assert each exact trigger name is present.
    let [ai, ad, au] = fts_trigger_names("notes", "main");
    for t in [&ai, &ad, &au] {
        let n: i64 = c
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='trigger' AND name=?1",
                rusqlite::params![t],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1, "sync trigger {t} must survive the rebuild");
    }

    // Head is untouched (still a virtual table) and its shadows still listed.
    let kind: String = c
        .query_row(
            "SELECT type FROM pragma_table_list WHERE name=?1",
            rusqlite::params![head],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(kind, "virtual", "the fts head must stay a virtual table");
    for shadow in ["_data", "_idx", "_docsize", "_config"] {
        let n: i64 = c
            .query_row(
                "SELECT count(*) FROM pragma_table_list WHERE name=?1",
                rusqlite::params![format!("{head}{shadow}")],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            n, 1,
            "shadow {head}{shadow} must remain present after rebuild"
        );
    }

    // The seed row was preserved AND is still indexed (head not disturbed).
    let seed_hits: i64 = c
        .query_row(
            &format!(
                "SELECT count(*) FROM \"{h}\" WHERE \"{h}\" MATCH ?1",
                h = head.replace('"', "\"\"")
            ),
            rusqlite::params!["seed"],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(seed_hits, 1, "the pre-rebuild row is still indexed");

    // A post-rebuild INSERT into the parent is still indexed by the surviving
    // triggers.
    c.execute(
        "INSERT INTO notes (title, body) VALUES ('delta signal', 'post rebuild')",
        [],
    )
    .unwrap();
    let delta_hits: i64 = c
        .query_row(
            &format!(
                "SELECT count(*) FROM \"{h}\" WHERE \"{h}\" MATCH ?1",
                h = head.replace('"', "\"\"")
            ),
            rusqlite::params!["delta"],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        delta_hits, 1,
        "a post-rebuild INSERT must still be indexed — the sync triggers survived"
    );
}

// ── Pin 4 — host sqlite3 VACUUM INTO backup restores MATCH ──────────────────

/// Parse `sqlite3 --version` → (major, minor). None if the binary is absent or
/// the output is unparseable.
fn host_sqlite3_version() -> Option<(u32, u32)> {
    let out = std::process::Command::new("sqlite3")
        .arg("--version")
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let first = stdout.split_whitespace().next()?; // e.g. "3.45.1"
    let mut parts = first.split('.');
    let major: u32 = parts.next()?.parse().ok()?;
    let minor: u32 = parts.next()?.parse().ok()?;
    Some((major, minor))
}

#[tokio::test]
async fn host_sqlite3_vacuum_into_of_fts_db_restores_match() {
    // Guard: production backup shells out to the HOST sqlite3. Trigram needs
    // >= 3.34; skip gracefully otherwise (test still passes).
    let ver = match host_sqlite3_version() {
        Some(v) => v,
        None => {
            eprintln!(
                "SKIP host_sqlite3_vacuum_into_of_fts_db_restores_match: host `sqlite3` not found"
            );
            return;
        }
    };
    if ver < (3, 34) {
        eprintln!(
            "SKIP host_sqlite3_vacuum_into_of_fts_db_restores_match: host sqlite3 {}.{} < 3.34 \
             (fts5 trigram floor)",
            ver.0, ver.1
        );
        return;
    }

    let d = tempfile::tempdir().unwrap();
    let s = svc(&d, "t-fts-bkp").await;
    create_collection(&s, "notes", &[text_field("title"), text_field("body")])
        .await
        .unwrap();
    create_fts_index(&s, "notes", "main", &["title".into(), "body".into()], None)
        .await
        .unwrap();
    let pool = pool_of(&s);
    // Populate via the bundled engine.
    run_rpc(
        &pool,
        "INSERT INTO notes (title, body) VALUES ('backup alpha', 'restore me')",
        false,
    )
    .await;
    run_rpc(
        &pool,
        "INSERT INTO notes (title, body) VALUES ('second row', 'more text')",
        false,
    )
    .await;
    // Flush WAL so a standalone sqlite3 process sees every committed row.
    pool.with_writer(|c| c.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);"))
        .await
        .unwrap();

    let src = d
        .path()
        .join("tenants")
        .join("t-fts-bkp")
        .join("data.sqlite");
    let copy = d.path().join("backup-copy.sqlite");

    // HOST sqlite3 (NOT drust's bundled engine) runs the production backup verb.
    let out = std::process::Command::new("sqlite3")
        .arg(&src)
        .arg(format!("VACUUM INTO '{}'", copy.display()))
        .output()
        .expect("spawn host sqlite3 for VACUUM INTO");
    assert!(
        out.status.success(),
        "host sqlite3 VACUUM INTO failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Open the copy with rusqlite (bundled) and assert the index survived.
    let c = Connection::open(&copy).unwrap();
    let head = fts_head_name("notes", "main");
    let hits: i64 = c
        .query_row(
            &format!(
                "SELECT count(*) FROM \"{h}\" WHERE \"{h}\" MATCH ?1",
                h = head.replace('"', "\"\"")
            ),
            rusqlite::params!["backup"],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        hits, 1,
        "MATCH must still answer on the host-sqlite3 VACUUM INTO copy (host sqlite3 {}.{})",
        ver.0, ver.1
    );
    c.execute_batch(&format!(
        "INSERT INTO \"{h}\"(\"{h}\") VALUES('integrity-check');",
        h = head.replace('"', "\"\"")
    ))
    .expect("fts5 integrity-check must pass on the backup copy");
}
