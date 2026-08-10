//! RPC-RLS Phase-0 spike — raw SQLite FACTS the TEMP-VIEW-shadowing design
//! would rest on. Modeled on `search_vtable_spike.rs` (the FTS5 Phase-0
//! survivor): every test pins ONE empirical behavior of the bundled SQLite,
//! so a design decision is grounded in a runnable fact, not doc folklore.
//!
//! The three candidate blockers under test (two-engine assessment 2026-08-10):
//!   B1 (codex #1)  INSTEAD OF trigger on a same-named TEMP view — can its body
//!                  reach `main.<table>` at all? If not, write-mode is dead.
//!   B2 (codex #4)  read connections are READONLY + query_only=ON + DEFENSIVE —
//!                  can they even CREATE TEMP VIEW? If not, read-mode needs a
//!                  different connection class.
//!   B3 (codex #3 / D2)  can an authorizer DISTINGUISH "read of main.<t>
//!                  through our temp view" (allow) from "direct read of
//!                  main.<t>" (deny), using (database_name, accessor)?
//!
//! Secondary hazards pinned alongside: sqlite_temp_master leaking the view
//! definition (codex #10), views refusing bound parameters (D4), and circular
//! self-reference when the view body forgets to qualify `main.`.

#![allow(clippy::unwrap_used)]

#[cfg(test)]
mod rls_spike {
    use crate::query::authorizer::{attach_readonly_authorizer, detach_authorizer};
    use crate::storage::tenant_db::{open_read, open_write};
    use rusqlite::Connection;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;

    const TENANT: &str = "rlsspike";

    /// An owner-scoped-shaped table with two users' rows.
    fn fixture() -> (TempDir, Connection) {
        let tmp = TempDir::new().unwrap();
        let conn = open_write(tmp.path(), TENANT).unwrap();
        conn.execute_batch(
            r#"CREATE TABLE "posts" (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 owner TEXT NOT NULL,
                 body TEXT
               ) STRICT;
               INSERT INTO "posts"(owner, body) VALUES ('u1', 'mine');
               INSERT INTO "posts"(owner, body) VALUES ('u2', 'theirs');"#,
        )
        .unwrap();
        (tmp, conn)
    }

    /// The masking view the design would build per call: SAME NAME as the base
    /// table, body MUST qualify `main.` (see the circular-definition probe).
    fn create_mask(conn: &Connection, owner: &str) {
        conn.execute_batch(&format!(
            r#"CREATE TEMP VIEW "posts" AS
                 SELECT * FROM main."posts" WHERE owner = '{owner}'"#,
        ))
        .unwrap();
    }

    // ── S1: shadowing basics + the bypass shape ────────────────────────────

    #[test]
    fn s1_temp_view_shadows_unqualified_but_main_qualified_bypasses() {
        let (_t, conn) = fixture();
        create_mask(&conn, "u1");
        let via_view: i64 = conn
            .query_row(r#"SELECT COUNT(*) FROM "posts""#, [], |r| r.get(0))
            .unwrap();
        assert_eq!(via_view, 1, "unqualified name must resolve temp-first");
        let via_main: i64 = conn
            .query_row(r#"SELECT COUNT(*) FROM main."posts""#, [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            via_main, 2,
            "main.<t> bypasses the shadow — THE hole the new authorizer must close"
        );
    }

    // ── S2 / B3: what the authorizer actually sees ─────────────────────────

    type Seen = Arc<Mutex<Vec<(String, String, Option<String>, Option<String>)>>>;

    fn capture_reads(conn: &Connection) -> Seen {
        let seen: Seen = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        conn.authorizer(Some(move |ctx: AuthContext<'_>| -> Authorization {
            if let AuthAction::Read {
                table_name,
                column_name,
            } = ctx.action
            {
                sink.lock().unwrap().push((
                    table_name.to_string(),
                    column_name.to_string(),
                    ctx.database_name.map(|s| s.to_string()),
                    ctx.accessor.map(|s| s.to_string()),
                ));
            }
            Authorization::Allow
        }))
        .unwrap();
        seen
    }

    #[test]
    fn s2_authorizer_distinguishes_view_reads_from_direct_reads() {
        let (_t, conn) = fixture();
        create_mask(&conn, "u1");

        // Through the view (unqualified).
        let seen = capture_reads(&conn);
        conn.prepare(r#"SELECT body FROM "posts""#).unwrap();
        let via_view = seen.lock().unwrap().clone();
        detach_authorizer(&conn);

        // Direct (qualified).
        let seen2 = capture_reads(&conn);
        conn.prepare(r#"SELECT body FROM main."posts""#).unwrap();
        let direct = seen2.lock().unwrap().clone();
        detach_authorizer(&conn);

        eprintln!("S2 via_view Read tuples: {via_view:?}");
        eprintln!("S2 direct   Read tuples: {direct:?}");

        // FACT under test: every base-table (database=main) Read that flows
        // through the view carries accessor=Some(view name); a direct read
        // carries accessor=None. If this holds, (db==main && accessor==None)
        // is the deny discriminator for B3.
        let base_via_view: Vec<_> = via_view
            .iter()
            .filter(|(_, _, db, _)| db.as_deref() == Some("main"))
            .collect();
        assert!(
            !base_via_view.is_empty(),
            "view expansion must surface base-table reads to the authorizer"
        );
        assert!(
            base_via_view
                .iter()
                .all(|(_, _, _, acc)| acc.as_deref() == Some("posts")),
            "base reads through the view must carry the view as accessor: {base_via_view:?}"
        );
        let base_direct: Vec<_> = direct
            .iter()
            .filter(|(_, _, db, _)| db.as_deref() == Some("main"))
            .collect();
        assert!(
            base_direct.iter().all(|(_, _, _, acc)| acc.is_none()),
            "direct main.<t> reads must carry NO accessor: {base_direct:?}"
        );
    }

    #[test]
    fn s2b_discriminator_prototype_allows_view_and_denies_direct() {
        let (_t, conn) = fixture();
        create_mask(&conn, "u1");
        // Prototype of the real arm: deny Read on main.posts unless it flows
        // through an accessor (our view); allow everything else.
        conn.authorizer(Some(|ctx: AuthContext<'_>| -> Authorization {
            match ctx.action {
                AuthAction::Read { table_name, .. }
                    if table_name == "posts"
                        && ctx.database_name == Some("main")
                        && ctx.accessor.is_none() =>
                {
                    Authorization::Deny
                }
                _ => Authorization::Allow,
            }
        }))
        .unwrap();
        let via_view: rusqlite::Result<i64> =
            conn.query_row(r#"SELECT COUNT(*) FROM "posts""#, [], |r| r.get(0));
        let direct: rusqlite::Result<i64> =
            conn.query_row(r#"SELECT COUNT(*) FROM main."posts""#, [], |r| r.get(0));
        detach_authorizer(&conn);
        eprintln!("S2b via_view={via_view:?} direct={direct:?}");
        assert_eq!(via_view.unwrap(), 1, "the masked path must stay usable");
        assert!(direct.is_err(), "the direct path must be denied");
    }

    // ── S3 / B2: can a read connection build the mask at all? ──────────────

    #[test]
    fn s3_readonly_query_only_conn_and_temp_view_ddl() {
        let (t, conn) = fixture();
        drop(conn); // flush
        let rconn = open_read(t.path(), TENANT).unwrap();
        let attempt = rconn.execute_batch(
            r#"CREATE TEMP VIEW "posts" AS
                 SELECT * FROM main."posts" WHERE owner = 'u1'"#,
        );
        eprintln!("S3 create-on-readonly: {attempt:?}");
        // Second half: does flipping query_only off (still READONLY file
        // handle) unlock temp DDL?
        let flip = rconn.execute_batch(
            r#"PRAGMA query_only = OFF;
               CREATE TEMP VIEW "posts2" AS
                 SELECT * FROM main."posts" WHERE owner = 'u1';
               PRAGMA query_only = ON;"#,
        );
        eprintln!("S3 create-after-flip: {flip:?}");
        // Pins added after first run — see spike log.
    }

    // ── S4 / B1: write forwarding through a same-named view ────────────────

    #[test]
    fn s4_instead_of_trigger_forwarding_probes() {
        let (_t, conn) = fixture();
        create_mask(&conn, "u1");

        // Attempt A: qualified base name in a TEMP trigger body.
        let qualified = conn.execute_batch(
            r#"CREATE TEMP TRIGGER "posts_ins" INSTEAD OF INSERT ON "posts"
               BEGIN
                 INSERT INTO main."posts"(owner, body) VALUES (new.owner, new.body);
               END;"#,
        );
        eprintln!("S4A create qualified-body trigger: {qualified:?}");
        if qualified.is_ok() {
            let ins = conn.execute(
                r#"INSERT INTO "posts"(owner, body) VALUES ('u1', 'forwarded')"#,
                [],
            );
            eprintln!("S4A insert through view: {ins:?}");
            let n: i64 = conn
                .query_row(r#"SELECT COUNT(*) FROM main."posts""#, [], |r| r.get(0))
                .unwrap();
            eprintln!("S4A base rows after forward: {n}");
        }

        // Attempt B: unqualified body (expected self-resolution hazard).
        let _ = conn.execute_batch(r#"DROP TRIGGER IF EXISTS "posts_ins""#);
        let unqualified = conn.execute_batch(
            r#"CREATE TEMP TRIGGER "posts_ins2" INSTEAD OF INSERT ON "posts"
               BEGIN
                 INSERT INTO "posts"(owner, body) VALUES (new.owner, new.body);
               END;"#,
        );
        eprintln!("S4B create unqualified-body trigger: {unqualified:?}");
        if unqualified.is_ok() {
            let ins = conn.execute(
                r#"INSERT INTO "posts"(owner, body) VALUES ('u1', 'looped?')"#,
                [],
            );
            eprintln!("S4B insert through view: {ins:?}");
        }
        // Pins added after first run — see spike log.
    }

    // ── S5 / codex #10: does the strict reader hide the view definition? ───

    #[test]
    fn s5_temp_master_under_strict_reader() {
        let (_t, conn) = fixture();
        create_mask(&conn, "u1");
        attach_readonly_authorizer(&conn);
        let leak: rusqlite::Result<String> = conn.query_row(
            "SELECT sql FROM sqlite_temp_master WHERE name = 'posts'",
            [],
            |r| r.get(0),
        );
        detach_authorizer(&conn);
        eprintln!("S5 sqlite_temp_master under strict reader: {leak:?}");
        assert!(
            leak.is_err(),
            "the strict reader must deny sqlite_temp_master or the inlined \
             caller id in the view WHERE leaks: {leak:?}"
        );
    }

    // ── S6 / D4: views refuse bound parameters ─────────────────────────────

    #[test]
    fn s6_view_definitions_refuse_bound_parameters() {
        let (_t, conn) = fixture();
        let r = conn.execute_batch(
            r#"CREATE TEMP VIEW "masked" AS
                 SELECT * FROM main."posts" WHERE owner = ?"#,
        );
        eprintln!("S6 view-with-parameter: {r:?}");
        assert!(
            r.is_err(),
            "views cannot carry ?-binds, so $auth must be INLINED as a literal \
             — the injection-surface fact D4 rests on"
        );
    }

    // ── S9: the view body must qualify main. or it self-references ─────────

    #[test]
    fn s9_unqualified_view_body_is_circular() {
        let (_t, conn) = fixture();
        let r = conn.execute_batch(
            r#"CREATE TEMP VIEW "posts" AS SELECT * FROM "posts" WHERE owner = 'u1'"#,
        );
        let probe: rusqlite::Result<i64> =
            conn.query_row(r#"SELECT COUNT(*) FROM "posts""#, [], |r| r.get(0));
        eprintln!("S9 create={r:?} probe={probe:?}");
        assert!(
            r.is_err() || probe.is_err(),
            "an unqualified self-named view body must fail (circular), not \
             silently read the base table"
        );
    }
}
