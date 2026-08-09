//! FTS5 / R-tree vtables × the SQL authorizers — the surviving regression
//! suite of the Phase 0 spike.
//!
//! **The prototypes are gone.** The `spiked_*` authorizers this file once
//! carried were local mock-ups of decision D2; Wave 2 M3 Task 3 landed the
//! real arms — `attach_search_readonly_authorizer` (additive, for readers
//! running drust-BUILT SQL) and the `SearchTables`-classifier
//! `attach_writable_authorizer` — so every assertion below drives PRODUCTION
//! code. The two tests that used to pin the pre-fix denials are inverted
//! accordingly. The collision defect the spike pinned (a user index named
//! `main_data` making the vtable HEAD look like a module internal under the
//! old suffix grammar) is closed by construction in Task 1: names join on `$`,
//! which `identifier()` can never emit, and head-vs-internal is decided by
//! `pragma_table_list.type`, never by name.
//!
//! What still lives here is the set of raw SQLite FACTS the design rests on,
//! each of which would silently invalidate the feature if it changed:
//!
//!   1. the bundled SQLite really ships FTS5 + R-tree at runtime;
//!   2. drust's `id INTEGER PRIMARY KEY AUTOINCREMENT` (STRICT) is a rowid
//!      alias, so external-content FTS5 can use `content_rowid='id'`;
//!   3. the D1 sync triggers run in the parent's transaction and roll back
//!      with it;
//!   4. one outer UPDATE fires every AFTER UPDATE trigger body TWICE (the
//!      `_updated_at` trigger's inner UPDATE cascades); the index converges
//!      only because that inner UPDATE writes no indexed column, and
//!      `recursive_triggers` must stay OFF;
//!   5. DEFENSIVE — now inherent to every writer open — refuses direct DML
//!      on a module-internal shadow while letting the module's own
//!      (trigger-driven) writes through. That is the layer the writable
//!      arm's by-name internal allowance depends on.
//!
//! Sibling coverage: the arms' own allow/deny matrix is in
//! `query::authorizer`'s `search_arm_tests` (including the anon-leak
//! regression), and `tests/defensive_writer.rs` proves DEFENSIVE holds on
//! EVERY writer open rather than on a hand-configured connection.

use rusqlite::Connection;
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
// §7.2 — authorizer × vtable: the two production reader arms, side by side
// ---------------------------------------------------------------------------

fn fts_fixture() -> TempDir {
    let tmp = TempDir::new().unwrap();
    let conn = open_write(tmp.path(), TENANT).unwrap();
    create_notes_parent(&conn);
    create_fts_shadow_and_triggers(&conn);
    seed_notes(&conn);
    tmp
}

/// Inverted from the spike's `readonly_authorizer_denies_search_shadow_today`:
/// the additive reader now ADMITS the compiled `$fts` shape, and the strict
/// reader — the one every caller-authored-SQL site still attaches — keeps
/// denying it. Both halves in one test, on one connection, so the pair can
/// never drift into "we widened the wrong function".
#[test]
fn search_reader_admits_shadow_but_strict_reader_denies() {
    let tmp = fts_fixture();
    let conn = open_read(tmp.path(), TENANT).unwrap();

    crate::query::authorizer::attach_readonly_authorizer(&conn);
    let strict: rusqlite::Result<i64> = conn.query_row(FTS_QUERY, ["alpha"], |r| r.get(0));
    crate::query::authorizer::detach_authorizer(&conn);
    assert!(
        strict.is_err(),
        "the STRICT arm must keep denying _system_search_* reads — it is what a \
         stored read-RPC body runs under; got {strict:?}"
    );

    crate::query::authorizer::attach_search_readonly_authorizer(&conn);
    let admitted: i64 = conn
        .query_row(FTS_QUERY, ["alpha"], |r| r.get(0))
        .expect("the search reader must admit the compiled $fts shape");
    crate::query::authorizer::detach_authorizer(&conn);
    assert_eq!(admitted, 1);
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
// The unlisted landmine, now closed — write-RPC's writable authorizer
// vs the D1 sync triggers
// ---------------------------------------------------------------------------

/// Inverted from the spike's `writable_authorizer_denies_trigger_shadow_sync_today`.
/// A trigger body inserting into an FTS head used to be "just a `_system_*`
/// write", so the whole parent INSERT died at the authorizer and write-RPC was
/// broken on any fts-indexed collection. The `SearchTables` classifier fixes it
/// without opening the head to hand-written SQL: the head is writable ONLY when
/// the accessor names a `_system_search_*` trigger.
#[test]
fn writable_authorizer_allows_trigger_shadow_sync() {
    let tmp = fts_fixture();
    let conn = open_write(tmp.path(), TENANT).unwrap();
    // A control collection with NO fts triggers, so the assertions below prove
    // something about triggers and not about the fixture (verifier finding:
    // without this control the test could pass for the wrong reason).
    conn.execute_batch(
        r#"CREATE TABLE "plain" (
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             title TEXT,
             created_at TEXT NOT NULL DEFAULT (datetime('now')),
             updated_at TEXT NOT NULL DEFAULT (datetime('now'))
           ) STRICT;"#,
    )
    .unwrap();
    // The classifier must be snapshotted while the connection is unrestricted,
    // exactly as `run_write_rpc` does it (STEP 1c, before the SAVEPOINT).
    let search = crate::storage::search_names::snapshot_search_tables(&conn).unwrap();
    assert!(
        search.is_head("_system_search_fts_notes_main"),
        "the fixture's vtable must classify as a HEAD, else the arm below is untested"
    );

    // Mimic run_write_rpc's real sequence: SAVEPOINT → attach → body → detach
    // → RELEASE. A verifier additionally drove the REAL run_write_rpc (pool +
    // preupdate hook + quota) against this fixture, so the mimic is faithful.
    conn.execute_batch("SAVEPOINT spike_rpc").unwrap();
    crate::query::authorizer::attach_writable_authorizer(&conn, &search);
    let r = conn.execute(
        r#"INSERT INTO "notes"(title, body) VALUES ('zeta note', 'from rpc')"#,
        [],
    );
    let control = conn.execute(r#"INSERT INTO "plain"(title) VALUES ('fine')"#, []);
    // Top-level (accessor-less) DML on the HEAD must still be denied — a write
    // RPC cannot poison the index by hand.
    let direct = conn.execute(
        r#"INSERT INTO "_system_search_fts_notes_main"(rowid, title, body)
             VALUES (99, 'evil', 'evil')"#,
        [],
    );
    crate::query::authorizer::detach_authorizer(&conn);
    conn.execute_batch("RELEASE spike_rpc").unwrap();

    r.expect("the parent INSERT (and its trigger-driven shadow sync) must now succeed");
    control.expect("control INSERT on a trigger-less collection must pass");
    let msg = format!("{:?}", direct.as_ref().unwrap_err());
    assert!(
        msg.contains("AuthorizationForStatementDenied") || msg.contains("not authorized"),
        "hand-written head DML must be an AUTHORIZER denial, got {msg}"
    );

    // The sync really happened: the new row is searchable, and the index still
    // agrees with the content table.
    let hit: i64 = conn
        .query_row(FTS_QUERY, ["zeta"], |r| r.get(0))
        .expect("row written under the classifier arm must be indexed");
    let expected: i64 = conn
        .query_row(
            r#"SELECT id FROM "notes" WHERE title = 'zeta note'"#,
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(hit, expected);
    conn.execute_batch(
        r#"INSERT INTO "_system_search_fts_notes_main"("_system_search_fts_notes_main")
             VALUES ('integrity-check');"#,
    )
    .expect("fts5 integrity-check must pass after the authorized sync");
}

// ---------------------------------------------------------------------------
// DEFENSIVE — the layer that guards module-internal shadows on WRITERS
// ---------------------------------------------------------------------------

/// The writable arm must allow accessor-less writes on `*_data` /
/// `*_docsize` / … (the module makes them), so the authorizer cannot be
/// what stops raw RPC SQL from corrupting those tables directly. SQLite's
/// DEFENSIVE flag is that layer: it rejects direct DML on any table a
/// vtable module claims via xShadowName, while the module's own writes —
/// including trigger-driven ones — keep working. Task 2 made DEFENSIVE
/// INHERENT to `open_write` / `open_write_existing` / `open_read`, so both
/// connections below get it without a manual `set_db_config`; that it is set
/// on every writer open (not just here) is proved by
/// `tests/defensive_writer.rs`.
#[test]
fn defensive_blocks_direct_internal_shadow_writes_but_not_module_writes() {
    let tmp = fts_fixture();
    let conn = open_write(tmp.path(), TENANT).unwrap();

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

// RETIRED by Wave 2 M3 Task 2 (DEFENSIVE on every writer open).
//
// This slot held `spiked_arms_are_unguarded_on_a_writer_without_defensive`,
// which pinned the pre-fix hole: on a writer with no DEFENSIVE, the spiked
// arms' by-name internal-shadow allowance let top-level SQL write the
// module-internal shadows (the `validate_rpc_sql`-on-a-writer shape). It
// asserted `hole.is_ok()`, so it is logically incompatible with the fix —
// `open_write` now sets DEFENSIVE, and the plan's Task 3 accounting lists
// this test for deletion by name.
//
// The surviving half (with DEFENSIVE, the same direct shadow write is refused
// by xShadowName) is covered by
// `defensive_blocks_direct_internal_shadow_writes_but_not_module_writes` above
// and by `tests/defensive_writer.rs`, which proves the guard holds on EVERY
// writer open rather than on a manually-configured connection.
