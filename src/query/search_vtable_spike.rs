//! Phase 0 spike — FTS5 / R-tree vtables × the SQL authorizers.
//!
//! De-risks the Wave 2 assumptions of
//! `docs/superpowers/specs/2026-07-22-drust-sqlite-native-quickwins-design.md`
//! (§7) BEFORE any production change lands:
//!
//!   1. the bundled SQLite really ships FTS5 + R-tree at runtime;
//!   2. drust's `id INTEGER PRIMARY KEY AUTOINCREMENT` (STRICT) is a rowid
//!      alias, so external-content FTS5 can use `content_rowid='id'`;
//!   3. today's `attach_readonly_authorizer` denies `_system_search_*`
//!      (pre-D2 baseline), and a narrowed arm admits the `$fts` / `$near`
//!      query shapes end-to-end — including the module-internal shadow
//!      tables (`*_data`, `*_idx`, `*_node`, …) — while ATTACH,
//!      `sqlite_master` and other `_system_*` reads stay denied. The arm
//!      must allow WRITE ACTIONS on `_system_search_*` too (rtree
//!      pre-compiles internal DML while preparing a SELECT), which is
//!      harmless only where the CONNECTION is the backstop — and the
//!      review proved that is NOT everywhere the readonly authorizer
//!      goes: `validate_rpc_sql` attaches it on the WRITER (MCP
//!      create/update_rpc run it inside `pool.with_writer`), see
//!      `spiked_arms_are_unguarded_on_a_writer_without_defensive`;
//!   4. the landmine §7 does NOT list: `attach_writable_authorizer`
//!      (write-RPC) vs the D1 sync triggers — a trigger body inserting
//!      into an FTS shadow is a `_system_*` write and is denied today.
//!      The trigger's own vtable write IS accessor-attributable, but the
//!      MODULE's internal shadow writes (`*_docsize`, `*_data`, `*_idx`)
//!      arrive with accessor None, so the fix is two clauses (trigger-
//!      scoped head + by-name internals) AND it is only safe when paired
//!      with DEFENSIVE on every writer open — unpaired, the by-name
//!      clause executes direct corruption (pinned below);
//!   5. the internal-shadow suffix grammar COLLIDES with user-chosen
//!      index names (`main_data` → the vtable head ends in `_data`);
//!      DEFENSIVE does not cover the head, so Plan C must make the name
//!      classes disjoint by construction (e.g. a `$` delimiter that
//!      `identifier()` can never emit) — pinned as a known defect;
//!   6. one outer UPDATE fires every AFTER UPDATE trigger body TWICE
//!      (the `_updated_at` trigger's inner UPDATE cascades); the index
//!      converges only because the inner UPDATE writes no indexed
//!      column. `recursive_triggers` must stay OFF.
//!
//! The `spiked_*` authorizers below are LOCAL PROTOTYPES of decision D2.
//! Production `attach_readonly_authorizer` / `attach_writable_authorizer`
//! are deliberately untouched; Plan C replaces the prototypes with the
//! real arms (with the collision fix) and keeps these tests as the
//! regression suite.

use std::sync::{Arc, Mutex};

use rusqlite::Connection;
use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
use tempfile::TempDir;

use crate::storage::tenant_db::{open_read, open_write};

const TENANT: &str = "spike";

/// Parent-collection DDL replicated from
/// `mcp::tools::schema::create_collection_with_desc` (id column, STRICT,
/// the convergent `_updated_at` AFTER trigger). Replicated rather than
/// called because the real fn needs a full `DrustMcp`; the spike question
/// is pure SQLite semantics of this exact shape.
fn create_notes_parent(conn: &Connection) {
    conn.execute_batch(
        r#"CREATE TABLE "notes" (
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             title TEXT,
             body TEXT,
             created_at TEXT NOT NULL DEFAULT (datetime('now')),
             updated_at TEXT NOT NULL DEFAULT (datetime('now'))
           ) STRICT;
           CREATE TRIGGER "notes_updated_at" AFTER UPDATE ON "notes"
           BEGIN UPDATE "notes" SET updated_at = datetime('now') WHERE id = OLD.id; END;"#,
    )
    .expect("parent DDL (replicated create_collection shape) must succeed");
}

/// External-content FTS5 shadow + the canonical content-sync triggers
/// (spec D1). Trigger names carry the `_system_search_` prefix — that is
/// what the accessor-scoped writable arm keys on.
fn create_fts_shadow_and_triggers(conn: &Connection) {
    conn.execute_batch(
        r#"CREATE VIRTUAL TABLE "_system_search_fts_notes_main"
             USING fts5(title, body, content='notes', content_rowid='id');
           CREATE TRIGGER "_system_search_fts_notes_main_ai" AFTER INSERT ON "notes" BEGIN
             INSERT INTO "_system_search_fts_notes_main"(rowid, title, body)
               VALUES (new.id, new.title, new.body);
           END;
           CREATE TRIGGER "_system_search_fts_notes_main_ad" AFTER DELETE ON "notes" BEGIN
             INSERT INTO "_system_search_fts_notes_main"("_system_search_fts_notes_main", rowid, title, body)
               VALUES ('delete', old.id, old.title, old.body);
           END;
           CREATE TRIGGER "_system_search_fts_notes_main_au" AFTER UPDATE ON "notes" BEGIN
             INSERT INTO "_system_search_fts_notes_main"("_system_search_fts_notes_main", rowid, title, body)
               VALUES ('delete', old.id, old.title, old.body);
             INSERT INTO "_system_search_fts_notes_main"(rowid, title, body)
               VALUES (new.id, new.title, new.body);
           END;"#,
    )
    .expect("external-content fts5 + sync triggers must create");
}

/// R-tree shadow for a `geo`-typed field stored as JSON `[lng,lat]` TEXT
/// (spec D4), maintained by `json_extract` triggers.
fn create_places_with_rtree(conn: &Connection) {
    conn.execute_batch(
        r#"CREATE TABLE "places" (
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             name TEXT,
             loc TEXT,
             created_at TEXT NOT NULL DEFAULT (datetime('now')),
             updated_at TEXT NOT NULL DEFAULT (datetime('now'))
           ) STRICT;
           CREATE VIRTUAL TABLE "_system_search_geo_places_loc"
             USING rtree(id, minLng, maxLng, minLat, maxLat);
           CREATE TRIGGER "_system_search_geo_places_loc_ai" AFTER INSERT ON "places" BEGIN
             INSERT INTO "_system_search_geo_places_loc"(id, minLng, maxLng, minLat, maxLat)
               VALUES (new.id,
                       json_extract(new.loc, '$[0]'), json_extract(new.loc, '$[0]'),
                       json_extract(new.loc, '$[1]'), json_extract(new.loc, '$[1]'));
           END;"#,
    )
    .expect("rtree shadow + json_extract trigger must create");
}

fn seed_notes(conn: &Connection) {
    conn.execute_batch(
        r#"INSERT INTO "notes"(title, body) VALUES ('alpha report', 'quarterly numbers');
           INSERT INTO "notes"(title, body) VALUES ('beta memo', 'lunch schedule');"#,
    )
    .expect("seed rows");
    conn.execute_batch(
        r#"INSERT INTO "_system_search_fts_notes_main"("_system_search_fts_notes_main")
             VALUES ('rebuild');"#,
    )
    .expect("fts rebuild over existing content");
}

/// The D3 `$fts` compilation target: candidate rowids from the shadow,
/// authorization applied on the PARENT by the outer statement.
const FTS_QUERY: &str = r#"SELECT id FROM "notes" WHERE id IN
    (SELECT rowid FROM "_system_search_fts_notes_main"
      WHERE "_system_search_fts_notes_main" MATCH ?)"#;

/// PROTOTYPE of D2's readonly arm — `attach_readonly_authorizer` plus the
/// `_system_search_*` narrowing. TWO loosenings proved necessary by this
/// spike, not one:
///
///   * Read on `_system_search_*` — the obvious one (§7.2);
///   * Insert/Update/Delete on `_system_search_*` — because the R-TREE
///     module PRE-COMPILES its internal DML (INSERT into `*_node` etc.)
///     while PREPARING a plain SELECT, and a Deny at that point fails the
///     whole statement. Allowing the *authorization* is safe on this
///     connection class: SQLITE_OPEN_READONLY + `query_only=ON` +
///     DEFENSIVE make actual execution of any write impossible — a test
///     below proves that backstop empirically.
///
/// Fully instrumented: every decision is appended to `log` so a failing
/// test prints exactly which action fell into which arm.
fn attach_spiked_readonly_authorizer(conn: &Connection, log: Arc<Mutex<Vec<String>>>) {
    conn.authorizer(Some(move |ctx: AuthContext<'_>| -> Authorization {
        let verdict = match ctx.action {
            AuthAction::Select => Authorization::Allow,
            AuthAction::Read { table_name, .. } => {
                if table_name.starts_with("_system_search_") {
                    Authorization::Allow
                } else if crate::storage::schema::is_protected_collection(table_name) {
                    Authorization::Deny
                } else {
                    Authorization::Allow
                }
            }
            AuthAction::Insert { table_name }
            | AuthAction::Update { table_name, .. }
            | AuthAction::Delete { table_name }
                if table_name.starts_with("_system_search_") =>
            {
                // rtree pre-compiles internal DML during a SELECT's
                // prepare; execution stays impossible (readonly conn).
                Authorization::Allow
            }
            AuthAction::Function { .. } => Authorization::Allow,
            AuthAction::Pragma { pragma_name, .. } => match pragma_name {
                "table_info" | "index_list" | "index_info" | "foreign_key_list" | "table_xinfo" => {
                    Authorization::Allow
                }
                _ => Authorization::Ignore,
            },
            AuthAction::Recursive => Authorization::Allow,
            _ => Authorization::Deny,
        };
        log.lock().unwrap().push(format!(
            "{verdict:?} <- {:?} (accessor={:?})",
            ctx.action, ctx.accessor
        ));
        verdict
    }))
    .expect("spiked readonly authorizer must install");
}

/// What the instrumented writable authorizer records for every write
/// action that targets a `_system_search_*` table.
#[derive(Debug, Clone)]
struct ShadowWrite {
    #[allow(dead_code)] // read via Debug in assertion messages
    kind: &'static str,
    table: String,
    accessor: Option<String>,
    verdict: &'static str,
}

/// FTS5 / R-tree module-internal shadow tables. The MODULE writes these
/// itself while servicing a vtable write, and the spike proved those
/// writes reach the authorizer with `accessor: None` — they cannot be
/// attributed to the sync trigger. They must therefore be allowed by
/// NAME; what keeps top-level SQL from writing them directly is SQLite's
/// DEFENSIVE flag (xShadowName protection), proved by a test below.
fn is_search_internal_shadow(table: &str) -> bool {
    table.starts_with("_system_search_")
        && [
            "_data", "_idx", "_docsize", "_config", "_content", "_node", "_rowid", "_parent",
        ]
        .iter()
        .any(|s| table.ends_with(s))
}

/// PROTOTYPE of D2's writable arm, instrumented. Byte-matches
/// `attach_writable_authorizer` EXCEPT for `_system_search_*` writes,
/// which split three ways (both facts spike-proven):
///
///   * the vtable ITSELF (`_system_search_fts_<c>_<n>`): allowed IFF the
///     access is attributed to a `_system_search_*` trigger
///     (`AuthContext::accessor`); top-level SQL (accessor None) denied —
///     RPC SQL cannot poison the index by hand;
///   * module-INTERNAL shadows (`*_data`, `*_idx`, `*_docsize`, …):
///     allowed unconditionally, because the module writes them with
///     accessor None; direct-SQL abuse is blocked one layer down by
///     DEFENSIVE, not by the authorizer;
///   * Read on `_system_search_*` allowed (module reads its own shadow
///     during a vtable write).
///
/// Every shadow-write decision is logged so the test can assert WHO
/// actually touched the shadow.
fn attach_spiked_writable_authorizer(conn: &Connection, log: Arc<Mutex<Vec<ShadowWrite>>>) {
    conn.authorizer(Some(move |ctx: AuthContext<'_>| -> Authorization {
        let accessor_is_search_trigger = ctx
            .accessor
            .map(|a| a.starts_with("_system_search_"))
            .unwrap_or(false);
        match ctx.action {
            AuthAction::Select => Authorization::Allow,
            AuthAction::Read { table_name, .. } => {
                if table_name.starts_with("_system_search_") {
                    Authorization::Allow
                } else if crate::storage::schema::is_protected_collection(table_name) {
                    Authorization::Deny
                } else {
                    Authorization::Allow
                }
            }
            AuthAction::Function { .. } => Authorization::Allow,
            AuthAction::Pragma { pragma_name, .. } => match pragma_name {
                "table_info" | "index_list" | "index_info" | "foreign_key_list" | "table_xinfo" => {
                    Authorization::Allow
                }
                _ => Authorization::Ignore,
            },
            AuthAction::Recursive => Authorization::Allow,
            AuthAction::Insert { table_name } => {
                write_verdict("insert", table_name, &ctx, accessor_is_search_trigger, &log)
            }
            AuthAction::Update { table_name, .. } => {
                write_verdict("update", table_name, &ctx, accessor_is_search_trigger, &log)
            }
            AuthAction::Delete { table_name } => {
                write_verdict("delete", table_name, &ctx, accessor_is_search_trigger, &log)
            }
            _ => Authorization::Deny,
        }
    }))
    .expect("spiked writable authorizer must install");
}

fn write_verdict(
    kind: &'static str,
    table_name: &str,
    ctx: &AuthContext<'_>,
    accessor_is_search_trigger: bool,
    log: &Arc<Mutex<Vec<ShadowWrite>>>,
) -> Authorization {
    if table_name.starts_with("_system_search_") {
        let verdict = if is_search_internal_shadow(table_name) {
            "allow-internal"
        } else if accessor_is_search_trigger {
            "allow-trigger"
        } else {
            "deny"
        };
        log.lock().unwrap().push(ShadowWrite {
            kind,
            table: table_name.to_string(),
            accessor: ctx.accessor.map(str::to_string),
            verdict,
        });
        if verdict == "deny" {
            Authorization::Deny
        } else {
            Authorization::Allow
        }
    } else if crate::storage::schema::is_protected_collection(table_name) {
        Authorization::Deny
    } else {
        Authorization::Allow
    }
}

// ---------------------------------------------------------------------------
// §7.1 — runtime availability of the bundled vtable modules
// ---------------------------------------------------------------------------

#[test]
fn bundled_sqlite_has_fts5_and_rtree() {
    let tmp = TempDir::new().unwrap();
    let conn = open_write(tmp.path(), TENANT).unwrap();
    conn.execute_batch(r#"CREATE VIRTUAL TABLE fts_probe USING fts5(x);"#)
        .expect("fts5 module must be compiled into the bundled SQLite");
    conn.execute_batch(r#"CREATE VIRTUAL TABLE rt_probe USING rtree(id, minx, maxx, miny, maxy);"#)
        .expect("rtree module must be compiled into the bundled SQLite");
    // Informative double-check straight from the compiled binary.
    let opts: Vec<String> = conn
        .prepare("PRAGMA compile_options")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(
        opts.iter().any(|o| o == "ENABLE_FTS5"),
        "compile_options missing ENABLE_FTS5: {opts:?}"
    );
    assert!(
        opts.iter().any(|o| o == "ENABLE_RTREE"),
        "compile_options missing ENABLE_RTREE: {opts:?}"
    );
}

// ---------------------------------------------------------------------------
// §7.3 — `id` is a rowid alias; external-content wiring works end to end
// ---------------------------------------------------------------------------

#[test]
fn collection_id_is_a_rowid_alias_and_external_content_matches() {
    let tmp = TempDir::new().unwrap();
    let conn = open_write(tmp.path(), TENANT).unwrap();
    create_notes_parent(&conn);
    conn.execute(
        r#"INSERT INTO "notes"(title, body) VALUES ('alpha report', 'quarterly numbers')"#,
        [],
    )
    .unwrap();
    let id = conn.last_insert_rowid();
    let (row_id, row_rowid): (i64, i64) = conn
        .query_row(r#"SELECT id, rowid FROM "notes""#, [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!(row_id, id, "last_insert_rowid must be the id column");
    assert_eq!(
        row_id, row_rowid,
        "id must alias rowid (content_rowid='id' premise)"
    );

    create_fts_shadow_and_triggers(&conn);
    conn.execute_batch(
        r#"INSERT INTO "_system_search_fts_notes_main"("_system_search_fts_notes_main")
             VALUES ('rebuild');"#,
    )
    .expect("rebuild against external content");
    let hit: i64 = conn
        .query_row(FTS_QUERY, ["alpha"], |r| r.get(0))
        .expect("MATCH on the writer connection (no authorizer) must work");
    assert_eq!(hit, id);
}

// ---------------------------------------------------------------------------
// §7.2 — authorizer × vtable: deny today, admit under the narrowed arm
// ---------------------------------------------------------------------------

fn fts_fixture() -> TempDir {
    let tmp = TempDir::new().unwrap();
    let conn = open_write(tmp.path(), TENANT).unwrap();
    create_notes_parent(&conn);
    create_fts_shadow_and_triggers(&conn);
    seed_notes(&conn);
    tmp
}

#[test]
fn readonly_authorizer_denies_search_shadow_today() {
    let tmp = fts_fixture();
    let conn = open_read(tmp.path(), TENANT).unwrap();
    crate::query::authorizer::attach_readonly_authorizer(&conn);
    let r: rusqlite::Result<i64> = conn.query_row(FTS_QUERY, ["alpha"], |r| r.get(0));
    assert!(
        r.is_err(),
        "pre-D2 baseline: _system_search_* read must be denied, got {r:?}"
    );
}

#[test]
fn spiked_readonly_arm_admits_match_including_internal_shadows() {
    let tmp = fts_fixture();
    // Reader connection carries the full production posture:
    // SQLITE_OPEN_READONLY + query_only + DEFENSIVE.
    let conn = open_read(tmp.path(), TENANT).unwrap();
    let log = Arc::new(Mutex::new(Vec::new()));
    attach_spiked_readonly_authorizer(&conn, log.clone());
    let hit: i64 = conn
        .query_row(FTS_QUERY, ["alpha"], |r| r.get(0))
        .unwrap_or_else(|e| {
            panic!(
                "narrowed Read arm must admit the $fts shape end to end; err={e}\nlog: {:#?}",
                log.lock().unwrap()
            )
        });
    assert_eq!(hit, 1);
    // ORDER BY rank exercises the *_docsize / *_config internal shadows.
    let ranked: Vec<i64> = conn
        .prepare(
            r#"SELECT rowid FROM "_system_search_fts_notes_main"
                WHERE "_system_search_fts_notes_main" MATCH ? ORDER BY rank"#,
        )
        .expect("prepare with rank must pass the authorizer")
        .query_map(["report OR memo"], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .expect("stepping must survive fts5's internal shadow reads");
    assert_eq!(ranked.len(), 2, "both seeded rows should match: {ranked:?}");
}

#[test]
fn spiked_readonly_arm_admits_rtree_bbox() {
    let tmp = TempDir::new().unwrap();
    let conn = open_write(tmp.path(), TENANT).unwrap();
    create_places_with_rtree(&conn);
    conn.execute(
        r#"INSERT INTO "places"(name, loc) VALUES ('taipei', '[121.5654,25.0330]')"#,
        [],
    )
    .unwrap();
    conn.execute(
        r#"INSERT INTO "places"(name, loc) VALUES ('kaohsiung', '[120.3014,22.6273]')"#,
        [],
    )
    .unwrap();
    drop(conn);

    let conn = open_read(tmp.path(), TENANT).unwrap();
    let log = Arc::new(Mutex::new(Vec::new()));
    attach_spiked_readonly_authorizer(&conn, log.clone());
    // The D3 `$geo_within` shape: bbox candidates from the R-tree, parent
    // authorization outside.
    let hits: Vec<String> = conn
        .prepare(
            r#"SELECT name FROM "places" WHERE id IN
                 (SELECT id FROM "_system_search_geo_places_loc"
                   WHERE minLng <= ?1 AND maxLng >= ?2 AND minLat <= ?3 AND maxLat >= ?4)"#,
        )
        .unwrap_or_else(|e| {
            panic!(
                "rtree bbox prepare must pass the authorizer; err={e}\nlog: {:#?}",
                log.lock().unwrap()
            )
        })
        .query_map(rusqlite::params![122.0, 121.0, 26.0, 24.5], |r| {
            r.get::<_, String>(0)
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .expect("stepping must survive rtree's internal shadow reads");
    assert_eq!(hits, vec!["taipei".to_string()]);
}

#[test]
fn spiked_readonly_arm_does_not_widen_anything_else() {
    let tmp = fts_fixture();
    let conn = open_read(tmp.path(), TENANT).unwrap();
    attach_spiked_readonly_authorizer(&conn, Arc::new(Mutex::new(Vec::new())));

    // (re-proof a) ATTACH stays denied.
    let attach = conn.execute_batch("ATTACH DATABASE ':memory:' AS side");
    assert!(attach.is_err(), "ATTACH must stay denied, got {attach:?}");

    // (re-proof b) sqlite_master reads stay denied.
    let master: rusqlite::Result<i64> =
        conn.query_row("SELECT COUNT(*) FROM sqlite_master", [], |r| r.get(0));
    assert!(
        master.is_err(),
        "sqlite_master must stay denied, got {master:?}"
    );

    // (re-proof c) write actions stay denied on the read connection.
    let ins = conn.execute(r#"INSERT INTO "notes"(title, body) VALUES ('x','y')"#, []);
    assert!(ins.is_err(), "INSERT must stay denied, got {ins:?}");
    let ddl = conn.execute_batch("CREATE VIRTUAL TABLE z USING fts5(a)");
    assert!(
        ddl.is_err(),
        "CREATE VIRTUAL TABLE must stay denied, got {ddl:?}"
    );

    // Non-search protected tables stay denied — the narrowing really is
    // `_system_search_*`, not `_system_*`.
    let rpc: rusqlite::Result<i64> =
        conn.query_row("SELECT COUNT(*) FROM _system_rpc", [], |r| r.get(0));
    assert!(rpc.is_err(), "_system_rpc must stay denied, got {rpc:?}");

    // The readonly arm ALLOWS `_system_search_*` write actions at the
    // authorizer level (rtree's prepare-time internal DML needs it), so
    // the enforcement that actually stops a write on this connection is
    // the layer below: SQLITE_OPEN_READONLY + query_only. Prove that
    // backstop is real — for the vtable itself AND for a module-internal
    // shadow — by asserting the failure is the readonly refusal, not an
    // authorizer denial.
    let sw = conn.execute_batch(
        r#"INSERT INTO "_system_search_fts_notes_main"(rowid, title, body)
             VALUES (99, 'evil', 'evil')"#,
    );
    let msg = format!("{:?}", sw.as_ref().unwrap_err());
    assert!(
        msg.contains("readonly") || msg.contains("ReadOnly"),
        "vtable write on reader must be stopped by the readonly layer, got {msg}"
    );
    // For a module-INTERNAL shadow, the reader's DEFENSIVE flag (set in
    // `open_read`) fires even before the readonly refusal: xShadowName
    // marks the table "may not be modified". Either backstop suffices;
    // pin the one that actually answers.
    let siw = conn.execute_batch(
        r#"INSERT INTO "_system_search_fts_notes_main_config"(k, v) VALUES ('evil', 1)"#,
    );
    let msg = format!("{:?}", siw.as_ref().unwrap_err());
    assert!(
        msg.contains("may not be modified") || msg.contains("readonly") || msg.contains("ReadOnly"),
        "internal-shadow write on reader must be stopped below the authorizer, got {msg}"
    );
}

// ---------------------------------------------------------------------------
// D1 — trigger-driven sync: same-tx atomicity on the plain writer
// ---------------------------------------------------------------------------

#[test]
fn sync_triggers_are_same_tx_and_rollback_atomically() {
    let tmp = fts_fixture();
    let conn = open_write(tmp.path(), TENANT).unwrap();

    // Live insert via triggers (no rebuild) is immediately searchable.
    conn.execute(
        r#"INSERT INTO "notes"(title, body) VALUES ('gamma plan', 'roadmap')"#,
        [],
    )
    .unwrap();
    let hit: i64 = conn.query_row(FTS_QUERY, ["gamma"], |r| r.get(0)).unwrap();
    assert_eq!(hit, 3);

    // UPDATE re-indexes: old term gone, new term found. This also fires
    // the convergent `notes_updated_at` trigger — the cascade must stay
    // convergent for the index (exactly one hit, no duplicates).
    conn.execute(
        r#"UPDATE "notes" SET title = 'delta plan' WHERE id = 3"#,
        [],
    )
    .unwrap();
    let old_term: rusqlite::Result<i64> = conn.query_row(FTS_QUERY, ["gamma"], |r| r.get(0));
    assert!(old_term.is_err(), "old term must be gone, got {old_term:?}");
    let new_hits: Vec<i64> = conn
        .prepare(FTS_QUERY)
        .unwrap()
        .query_map(["delta"], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(new_hits, vec![3], "exactly one hit after cascade, no dupes");

    // DELETE removes from the index.
    conn.execute(r#"DELETE FROM "notes" WHERE id = 3"#, [])
        .unwrap();
    let gone: rusqlite::Result<i64> = conn.query_row(FTS_QUERY, ["delta"], |r| r.get(0));
    assert!(
        gone.is_err(),
        "deleted row must leave the index, got {gone:?}"
    );

    // Rollback discards parent AND shadow together (same-tx guarantee).
    conn.execute_batch("BEGIN").unwrap();
    conn.execute(
        r#"INSERT INTO "notes"(title, body) VALUES ('epsilon draft', 'wip')"#,
        [],
    )
    .unwrap();
    conn.execute_batch("ROLLBACK").unwrap();
    let rolled: rusqlite::Result<i64> = conn.query_row(FTS_QUERY, ["epsilon"], |r| r.get(0));
    assert!(
        rolled.is_err(),
        "rolled-back row must not be indexed, got {rolled:?}"
    );

    // The index agrees with the content table after all of the above.
    conn.execute_batch(
        r#"INSERT INTO "_system_search_fts_notes_main"("_system_search_fts_notes_main")
             VALUES ('integrity-check');"#,
    )
    .expect("fts5 integrity-check must pass after trigger-driven churn");
}

// ---------------------------------------------------------------------------
// The unlisted landmine — write-RPC's writable authorizer vs sync triggers
// ---------------------------------------------------------------------------

#[test]
fn writable_authorizer_denies_trigger_shadow_sync_today() {
    let tmp = fts_fixture();
    let conn = open_write(tmp.path(), TENANT).unwrap();
    // A control collection with NO fts triggers, so the test can prove the
    // denial below is the trigger's shadow write and not something else
    // about the fixture (verifier finding: without this control the test
    // could stay green for the wrong reason).
    conn.execute_batch(
        r#"CREATE TABLE "plain" (
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             title TEXT,
             created_at TEXT NOT NULL DEFAULT (datetime('now')),
             updated_at TEXT NOT NULL DEFAULT (datetime('now'))
           ) STRICT;"#,
    )
    .unwrap();
    // Mimic run_write_rpc's real sequence (exec_write.rs: SAVEPOINT at
    // :417 → attach at :423 → detach at :528 → RELEASE at :625). A
    // verifier additionally drove the REAL run_write_rpc (pool + preupdate
    // hook + quota) against this fixture and observed the same failure at
    // the same point, so the mimic is faithful today.
    conn.execute_batch("SAVEPOINT spike_rpc").unwrap();
    crate::query::authorizer::attach_writable_authorizer(&conn);
    let r = conn.execute(
        r#"INSERT INTO "notes"(title, body) VALUES ('zeta note', 'from rpc')"#,
        [],
    );
    let control = conn.execute(r#"INSERT INTO "plain"(title) VALUES ('fine')"#, []);
    crate::query::authorizer::detach_authorizer(&conn);
    conn.execute_batch("ROLLBACK TO spike_rpc; RELEASE spike_rpc")
        .unwrap();
    // TODAY's behavior, pinned: the sync trigger's shadow INSERT is a
    // `_system_*` write, so the whole parent INSERT is rejected — and it
    // is rejected specifically as an AUTHORIZER denial, not any other
    // failure. This is why Plan C's D2 must ALSO widen the writable
    // authorizer — a Read allowance alone breaks write-RPC on any
    // fts-indexed collection.
    let msg = format!("{:?}", r.as_ref().unwrap_err());
    assert!(
        msg.contains("AuthorizationForStatementDenied") || msg.contains("not authorized"),
        "expected an authorizer denial of the trigger's shadow write, got {msg}"
    );
    assert!(
        control.is_ok(),
        "control INSERT on a trigger-less collection must pass, got {control:?} — \
         if this fails the denial above proves nothing about triggers"
    );
}

#[test]
fn spiked_writable_arm_is_scoped_to_the_sync_trigger_accessor() {
    let tmp = fts_fixture();
    let conn = open_write(tmp.path(), TENANT).unwrap();
    let log: Arc<Mutex<Vec<ShadowWrite>>> = Arc::new(Mutex::new(Vec::new()));

    conn.execute_batch("SAVEPOINT spike_rpc").unwrap();
    attach_spiked_writable_authorizer(&conn, log.clone());

    // 1. A parent write is admitted: the shadow sync happens via the
    //    `_system_search_*` triggers, which the accessor scoping allows.
    conn.execute(
        r#"INSERT INTO "notes"(title, body) VALUES ('zeta note', 'from rpc')"#,
        [],
    )
    .unwrap_or_else(|e| {
        panic!(
            "parent INSERT must pass under the accessor-scoped arm; err={e}\nshadow log: {:#?}",
            log.lock().unwrap()
        )
    });

    // 2. A DIRECT shadow write (top-level SQL, accessor None) stays denied
    //    — RPC SQL cannot poison the index by hand.
    let direct = conn.execute(
        r#"INSERT INTO "_system_search_fts_notes_main"(rowid, title, body)
             VALUES (99, 'evil', 'evil')"#,
        [],
    );
    assert!(
        direct.is_err(),
        "direct shadow write must stay denied under the scoped arm, got {direct:?}"
    );

    detach_and_release(&conn);

    // 3. The sync really happened — the new row is searchable.
    let hit: i64 = conn
        .query_row(FTS_QUERY, ["zeta"], |r| r.get(0))
        .expect("row written under the scoped arm must be indexed");
    let expected: i64 = conn
        .query_row(
            r#"SELECT id FROM "notes" WHERE title = 'zeta note'"#,
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(hit, expected);

    // 4. The log proves attribution, three-way:
    //    * writes on the vtable ITSELF were allowed only with a
    //      `_system_search_*` trigger accessor;
    //    * module-internal shadow writes (`*_docsize`, `*_data`, …) came
    //      in with accessor None and were allowed by NAME — the fact that
    //      forces the internal-shadow arm + DEFENSIVE backstop design;
    //    * the only denial is the direct top-level vtable insert.
    let log = log.lock().unwrap();
    assert!(
        !log.is_empty(),
        "authorizer must have seen the shadow writes (else the scoping is untested)"
    );
    for w in log.iter() {
        match w.verdict {
            "allow-trigger" => assert!(
                w.accessor
                    .as_deref()
                    .is_some_and(|a| a.starts_with("_system_search_")),
                "vtable write allowed without a sync-trigger accessor: {w:?}"
            ),
            "allow-internal" => assert!(
                is_search_internal_shadow(&w.table),
                "internal-shadow allowance hit a non-internal table: {w:?}"
            ),
            _ => assert!(
                !is_search_internal_shadow(&w.table) && w.accessor.is_none(),
                "denied shadow write should be the top-level direct vtable one: {w:?}"
            ),
        }
    }
    assert!(
        log.iter().any(|w| w.verdict == "allow-trigger"),
        "at least one trigger-attributed vtable write must be logged: {:#?}",
        *log
    );
    assert!(
        log.iter()
            .any(|w| w.verdict == "allow-internal" && w.accessor.is_none()),
        "the module's accessor-less internal write is the load-bearing spike fact: {:#?}",
        *log
    );
    assert!(
        log.iter().any(|w| w.verdict == "deny"),
        "the direct vtable insert must appear as denied: {:#?}",
        *log
    );
}

// ---------------------------------------------------------------------------
// DEFENSIVE — the layer that guards module-internal shadows on WRITERS
// ---------------------------------------------------------------------------

/// The writable arm must allow accessor-less writes on `*_data` /
/// `*_docsize` / … (the module makes them), so the authorizer cannot be
/// what stops raw RPC SQL from corrupting those tables directly. SQLite's
/// DEFENSIVE flag is that layer: it rejects direct DML on any table a
/// vtable module claims via xShadowName, while the module's own writes —
/// including trigger-driven ones — keep working. Plan C must pair the
/// writable-arm loosening with DEFENSIVE on writer connections.
#[test]
fn defensive_blocks_direct_internal_shadow_writes_but_not_module_writes() {
    let tmp = fts_fixture();
    let conn = open_write(tmp.path(), TENANT).unwrap();
    conn.set_db_config(rusqlite::config::DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
        .unwrap();

    // Module writes (via the sync triggers) still work under DEFENSIVE...
    conn.execute(
        r#"INSERT INTO "notes"(title, body) VALUES ('eta entry', 'defensive check')"#,
        [],
    )
    .expect("trigger-driven vtable write must survive DEFENSIVE");
    let hit: i64 = conn
        .query_row(FTS_QUERY, ["eta"], |r| r.get(0))
        .expect("row indexed under DEFENSIVE");
    assert_eq!(hit, 3);

    // ...but DIRECT DML on a module-internal shadow table is refused.
    let direct = conn.execute_batch(
        r#"INSERT INTO "_system_search_fts_notes_main_config"(k, v) VALUES ('evil', 1)"#,
    );
    assert!(
        direct.is_err(),
        "DEFENSIVE must reject direct DML on an fts5 internal shadow, got {direct:?}"
    );
    let rt_tmp = TempDir::new().unwrap();
    let rt = open_write(rt_tmp.path(), TENANT).unwrap();
    create_places_with_rtree(&rt);
    rt.set_db_config(rusqlite::config::DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
        .unwrap();
    rt.execute(
        r#"INSERT INTO "places"(name, loc) VALUES ('tainan', '[120.2130,22.9997]')"#,
        [],
    )
    .expect("rtree trigger sync must survive DEFENSIVE");
    let direct_rt = rt.execute_batch(r#"DELETE FROM "_system_search_geo_places_loc_rowid""#);
    assert!(
        direct_rt.is_err(),
        "DEFENSIVE must reject direct DML on an rtree internal shadow, got {direct_rt:?}"
    );
}

fn detach_and_release(conn: &Connection) {
    crate::query::authorizer::detach_authorizer(conn);
    conn.execute_batch("RELEASE spike_rpc").unwrap();
}

// ---------------------------------------------------------------------------
// Two-engine review round — three more facts, pinned
// ---------------------------------------------------------------------------

/// FACT (refuter probe, pinned here): one outer UPDATE runs every AFTER
/// UPDATE trigger body TWICE — the convergent `<coll>_updated_at` trigger's
/// inner `UPDATE ... SET updated_at` re-fires them. `recursive_triggers`
/// is OFF on drust connections, but OFF only stops a trigger re-entering
/// ITSELF; a different trigger's statement fires the rest normally.
///
/// The fts index survives NOT because updated_at is "convergent" (the
/// index never sees that column) but because the inner UPDATE writes no
/// INDEXED column, so the second delete+reinsert self-cancels. Plan C
/// must therefore treat "may `updated_at` be an indexed field?" as an
/// open design question — nothing pins that shape safe — and must NEVER
/// set `recursive_triggers=ON` (the `_updated_at` trigger would then
/// re-enter itself until the depth limit fails every UPDATE).
#[test]
fn after_update_triggers_fire_twice_per_update_yet_index_converges() {
    let tmp = fts_fixture();
    let conn = open_write(tmp.path(), TENANT).unwrap();
    // Observer trigger: counts how many times AFTER UPDATE trigger bodies
    // run on `notes`, without touching the canonical sync triggers.
    conn.execute_batch(
        r#"CREATE TABLE fire_log (i INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT);
           CREATE TRIGGER "obs_notes_au" AFTER UPDATE ON "notes"
           BEGIN INSERT INTO fire_log(at) VALUES ('fired'); END;"#,
    )
    .unwrap();
    conn.execute(
        r#"UPDATE "notes" SET title = 'alpha revised' WHERE id = 1"#,
        [],
    )
    .unwrap();
    let fires: i64 = conn
        .query_row("SELECT COUNT(*) FROM fire_log", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        fires, 2,
        "one outer UPDATE must run AFTER UPDATE bodies twice (outer + \
         `notes_updated_at`'s inner UPDATE); if this stops holding, the \
         convergence reasoning below changes"
    );
    // Despite the double firing, the index converges in the shipped shape
    // (inner UPDATE touches no indexed column): exactly one hit, clean
    // integrity.
    let hits: Vec<i64> = conn
        .prepare(FTS_QUERY)
        .unwrap()
        .query_map(["revised"], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(hits, vec![1], "exactly one hit after double-fired sync");
    conn.execute_batch(
        r#"INSERT INTO "_system_search_fts_notes_main"("_system_search_fts_notes_main")
             VALUES ('integrity-check');"#,
    )
    .expect("index must stay consistent under the double firing");
}

/// KNOWN DEFECT, pinned (both engines converged on it): the internal-
/// shadow suffix grammar is purely lexical over a name whose last
/// component is USER-CHOSEN. An fts index named `main_data` yields the
/// vtable `_system_search_fts_notes_main_data`, which ends in `_data`
/// and is therefore misclassified as module-internal — the writable arm
/// would allow accessor-less top-level DML on the vtable HEAD itself,
/// and DEFENSIVE does NOT protect the head (xShadowName covers only the
/// real shadow tables). Plan C must make the classes disjoint by
/// construction — e.g. a `$` delimiter, which `identifier()`'s
/// `[a-z0-9_]` grammar can never emit — instead of shipping this suffix
/// heuristic.
#[test]
fn suffix_grammar_misclassifies_user_named_index_ending_in_data() {
    // The lexical defect itself:
    assert!(
        is_search_internal_shadow("_system_search_fts_notes_main_data"),
        "vtable head named by index `main_data` is misclassified as internal — \
         this assertion documents the defect; if a fixed classifier lands, \
         flip it and delete the consequence proof below"
    );
    // The consequence, executed: under the spiked writable arm, top-level
    // SQL writes the misnamed vtable HEAD directly — even with DEFENSIVE
    // on — because `allow-internal` skips the accessor check and
    // xShadowName does not claim the head.
    let tmp = TempDir::new().unwrap();
    let conn = open_write(tmp.path(), TENANT).unwrap();
    create_notes_parent(&conn);
    conn.execute_batch(
        r#"CREATE VIRTUAL TABLE "_system_search_fts_notes_main_data"
             USING fts5(title, body, content='notes', content_rowid='id');"#,
    )
    .unwrap();
    conn.set_db_config(rusqlite::config::DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
        .unwrap();
    let log: Arc<Mutex<Vec<ShadowWrite>>> = Arc::new(Mutex::new(Vec::new()));
    conn.execute_batch("SAVEPOINT spike_rpc").unwrap();
    attach_spiked_writable_authorizer(&conn, log.clone());
    let poison = conn.execute(
        r#"INSERT INTO "_system_search_fts_notes_main_data"(rowid, title, body)
             VALUES (77, 'poisoned', 'poisoned')"#,
        [],
    );
    detach_and_release(&conn);
    assert!(
        poison.is_ok(),
        "expected the misclassification to let top-level SQL write the vtable \
         head (that is the defect this test pins); got {poison:?}"
    );
}

/// FACT (both engines converged, one executed it): the "reader backstop"
/// justification for the readonly arm's write-action allowance is NOT a
/// property of the authorizer — it is a property of the CONNECTION, and
/// production attaches the readonly authorizer to the WRITER too:
/// `validate_rpc_sql` (src/rpc/prepare.rs) runs inside `pool.with_writer`
/// at MCP `create_rpc` / `update_rpc` (src/mcp/handler.rs). On such a
/// connection — no SQLITE_OPEN_READONLY, no query_only, and (today) no
/// DEFENSIVE — the spiked arms alone let top-level SQL write the
/// module-internal shadows. Pinned here so Plan C MUST pair the arm with
/// its guards: DEFENSIVE on every writer open (`open_write`,
/// `open_write_existing`, and the bare migration/rebuild opens in
/// src/db/migrations.rs), and/or keep the strict arm on validation
/// call sites.
#[test]
fn spiked_arms_are_unguarded_on_a_writer_without_defensive() {
    let tmp = fts_fixture();

    // Production writer posture today: open_write, no DEFENSIVE.
    let conn = open_write(tmp.path(), TENANT).unwrap();
    let log: Arc<Mutex<Vec<ShadowWrite>>> = Arc::new(Mutex::new(Vec::new()));
    conn.execute_batch("SAVEPOINT spike_rpc").unwrap();
    attach_spiked_writable_authorizer(&conn, log.clone());
    let hole = conn.execute(
        r#"INSERT INTO "_system_search_fts_notes_main_config"(k, v) VALUES ('evil', 1)"#,
        [],
    );
    detach_and_release(&conn);
    assert!(
        hole.is_ok(),
        "on an unguarded writer the internal-shadow allowance EXECUTES a direct \
         write (the hole Plan C must close with DEFENSIVE); got {hole:?}"
    );

    // Same hazard through the READONLY arm attached to a writer (the
    // validate_rpc_sql shape). DEFENSIVE closes both.
    let conn2 = open_write(tmp.path(), TENANT).unwrap();
    conn2
        .set_db_config(rusqlite::config::DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
        .unwrap();
    let log2 = Arc::new(Mutex::new(Vec::new()));
    attach_spiked_readonly_authorizer(&conn2, log2.clone());
    let guarded = conn2.execute(
        r#"INSERT INTO "_system_search_fts_notes_main_config"(k, v) VALUES ('evil2', 2)"#,
        [],
    );
    crate::query::authorizer::detach_authorizer(&conn2);
    let msg = format!("{:?}", guarded.as_ref().unwrap_err());
    assert!(
        msg.contains("may not be modified"),
        "with DEFENSIVE on the writer, the same direct shadow write must be \
         refused by xShadowName, got {msg}"
    );
}
