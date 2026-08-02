//! v1.58 P1-2 — `sqlite_*` internals must be write-denied, not just read-denied.
//!
//! The predicate was asymmetric: the authorizer blocked `sqlite_` with its own
//! private prefix test, while `is_protected_collection` — the gate every
//! API-facing write path consults — blocked only `_system_`.
//!
//! No live exploit was found: the authorizer's copy did cover raw RPC writes,
//! and drust's structured writes key on an `id` column that `sqlite_*` tables
//! lack, so they error rather than land. These tests exist to keep the merged
//! predicate honest, because the next write path with a different shape would
//! not have been so lucky.
//!
//! The case-variant cases are not paranoia. The authorizer callback receives the
//! name as SQLite resolved it, which we BELIEVE is the canonical lowercase form
//! — but "we believe" is how `application/rss+xml` got past the first version of
//! the content-type classifier, so these tests prove it rather than assuming it.

use drust::storage::schema::is_protected_collection;

#[test]
fn write_gate_rejects_sqlite_internals_in_any_casing() {
    for name in [
        "sqlite_sequence",
        "SQLITE_SEQUENCE",
        "SqLiTe_sequence",
        "sqlite_master",
    ] {
        assert!(
            is_protected_collection(name),
            "{name} must be refused by the write gate"
        );
    }
}

fn seeded_conn() -> rusqlite::Connection {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "CREATE TABLE things (id INTEGER PRIMARY KEY AUTOINCREMENT, v TEXT) STRICT;
         INSERT INTO things (v) VALUES ('a');",
    )
    .unwrap();
    conn
}

#[test]
fn reader_authorizer_denies_sqlite_sequence_reads() {
    let conn = seeded_conn();
    drust::query::authorizer::attach_readonly_authorizer(&conn);

    let denied = conn
        .prepare("SELECT seq FROM sqlite_sequence")
        .and_then(|mut s| s.query_row([], |r| r.get::<_, i64>(0)));
    assert!(denied.is_err(), "sqlite_sequence must stay read-denied");

    // And the same through an uppercase spelling, which resolves to the same
    // table. If this ever passes, the authorizer is matching the literal the
    // caller typed rather than the resolved name, and the predicate must become
    // case-insensitive at the authorizer too.
    let denied_upper = conn
        .prepare("SELECT seq FROM SQLITE_SEQUENCE")
        .and_then(|mut s| s.query_row([], |r| r.get::<_, i64>(0)));
    assert!(
        denied_upper.is_err(),
        "SQLITE_SEQUENCE must stay read-denied too"
    );
}

/// Answers the question the two tests above only imply: WHICH spelling does the
/// authorizer callback actually see? If SQLite hands back the caller's literal,
/// a case-sensitive prefix test is an exploitable bypass; if it hands back the
/// schema's canonical spelling, it is merely fragile. We assume neither and
/// record what SQLite does, so a future rusqlite/SQLite change that flips it is
/// a red test rather than a silent hole.
#[test]
fn authorizer_receives_the_canonical_table_spelling() {
    use std::sync::{Arc, Mutex};

    let conn = seeded_conn();
    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    conn.authorizer(Some(
        move |ctx: rusqlite::hooks::AuthContext<'_>| -> rusqlite::hooks::Authorization {
            if let rusqlite::hooks::AuthAction::Read { table_name, .. } = ctx.action {
                sink.lock().unwrap().push(table_name.to_string());
            }
            rusqlite::hooks::Authorization::Allow
        },
    ))
    .unwrap();

    let _ = conn.prepare("SELECT seq FROM SQLITE_SEQUENCE");
    let _ = conn.prepare("SELECT v FROM THINGS");
    conn.authorizer::<fn(rusqlite::hooks::AuthContext<'_>) -> rusqlite::hooks::Authorization>(None)
        .unwrap();

    let seen = seen.lock().unwrap().clone();
    assert!(
        seen.iter().any(|n| n == "sqlite_sequence"),
        "expected the canonical lowercase spelling, saw {seen:?}"
    );
    assert!(
        seen.iter().any(|n| n == "things"),
        "expected the canonical declared spelling for a user table, saw {seen:?}"
    );
    // The literal the caller typed must NOT be what we gate on.
    assert!(
        !seen.iter().any(|n| n == "SQLITE_SEQUENCE" || n == "THINGS"),
        "authorizer echoed the caller's literal casing, saw {seen:?} — the \
         predicate MUST be case-insensitive (it is) and any other gate keyed \
         on the callback's table_name must be audited too"
    );
}

/// The RPC `mode='write'` authorizer is the only surface that can reach a raw
/// INSERT/UPDATE/DELETE, so it is where an `INSERT INTO sqlite_sequence` would
/// have landed. Prove the mutation verbs are denied, in both spellings.
#[test]
fn writable_authorizer_denies_sqlite_sequence_writes() {
    let conn = seeded_conn();
    conn.execute_batch("SAVEPOINT drust_rpc_v2").unwrap();
    drust::query::authorizer::attach_writable_authorizer(&conn);

    for sql in [
        "UPDATE sqlite_sequence SET seq = 9223372036854775807 WHERE name = 'things'",
        "UPDATE SQLITE_SEQUENCE SET seq = 9223372036854775807 WHERE name = 'things'",
        "DELETE FROM sqlite_sequence",
        "INSERT INTO sqlite_sequence (name, seq) VALUES ('other', 1)",
    ] {
        let r = conn.execute(sql, []);
        assert!(r.is_err(), "must be denied but succeeded: {sql}");
    }

    // Control: a normal collection is still writable under the same authorizer,
    // so the assertions above are proving the gate, not a blanket refusal.
    drust::query::authorizer::detach_authorizer(&conn);
    conn.execute_batch("ROLLBACK TO drust_rpc_v2; RELEASE drust_rpc_v2")
        .unwrap();
    conn.execute_batch("SAVEPOINT drust_rpc_v2").unwrap();
    drust::query::authorizer::attach_writable_authorizer(&conn);
    conn.execute("UPDATE things SET v = 'b' WHERE id = 1", [])
        .expect("a normal collection must still be writable");

    drust::query::authorizer::detach_authorizer(&conn);
    conn.execute_batch("RELEASE drust_rpc_v2").unwrap();
}
