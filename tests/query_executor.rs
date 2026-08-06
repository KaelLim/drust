use drust::query::authorizer::attach_readonly_authorizer;
use drust::query::executor::{ExecError, execute_read_query, execute_read_query_with_named};
use drust::rpc::params::BoundValue;
use drust::storage::tenant_db::{open_read, open_write};
use tempfile::tempdir;

fn seed() -> tempfile::TempDir {
    let d = tempdir().unwrap();
    let conn = open_write(d.path(), "t").unwrap();
    conn.execute_batch(
        "CREATE TABLE posts (id INTEGER PRIMARY KEY, title TEXT);
         INSERT INTO posts (title) VALUES ('a'), ('b'), ('c');",
    )
    .unwrap();
    d
}

#[test]
fn returns_rows_and_column_names() {
    let d = seed();
    let conn = open_read(d.path(), "t").unwrap();
    attach_readonly_authorizer(&conn);
    let out =
        execute_read_query(&conn, "SELECT id, title FROM posts ORDER BY id", 10, 5_000).unwrap();
    assert_eq!(out.column_names, vec!["id", "title"]);
    assert_eq!(out.rows.len(), 3);
    assert!(!out.truncated);
}

#[test]
fn enforces_row_cap() {
    let d = seed();
    let conn = open_read(d.path(), "t").unwrap();
    attach_readonly_authorizer(&conn);
    let out = execute_read_query(&conn, "SELECT * FROM posts", 2, 5_000).unwrap();
    assert_eq!(out.rows.len(), 2);
    assert!(out.truncated);
}

#[test]
fn rejects_too_large_sql() {
    let d = seed();
    let conn = open_read(d.path(), "t").unwrap();
    attach_readonly_authorizer(&conn);
    let big = format!("SELECT * FROM posts /* {} */", "x".repeat(20_000));
    let err = execute_read_query(&conn, &big, 10, 5_000).unwrap_err();
    assert!(matches!(err, ExecError::TooLarge { .. }));
}

#[test]
fn forbidden_returns_forbidden_error() {
    let d = seed();
    let conn = open_read(d.path(), "t").unwrap();
    attach_readonly_authorizer(&conn);
    let err = execute_read_query(&conn, "DROP TABLE posts", 10, 5_000).unwrap_err();
    assert!(matches!(err, ExecError::Forbidden { .. }));
}

/// A caller-controlled query that would run for far longer than the deadline
/// must be interrupted and reported as Timeout, AND the handler must be removed
/// afterwards so it does not abort an innocent later query on the same pooled
/// connection. Both halves live in one test because `query_deadline()` caches
/// the env var in a process-global OnceLock — two tests setting different values
/// would race.
///
/// Before this, `ExecError::Timeout` had zero constructors and a recursive CTE
/// ran unbounded on a Tokio worker; three of them froze even `/health` for 25s
/// against the live service. The row cap does not save you — `count(*)` returns
/// one row after consuming all the CPU.
#[test]
fn a_runaway_query_times_out_and_the_handler_is_removed_afterwards() {
    // SAFETY: set before query_deadline()'s OnceLock is first read. This is the
    // only test in this binary that touches DRUST_QUERY_DEADLINE_MS.
    unsafe {
        std::env::set_var("DRUST_QUERY_DEADLINE_MS", "300");
    }
    let d = seed();
    let conn = open_read(d.path(), "t").unwrap();
    attach_readonly_authorizer(&conn);
    // ~2 billion iterations: many seconds uninterrupted, but count(*) is one row.
    let runaway = "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x < 2000000000) SELECT count(*) FROM c";

    let start = std::time::Instant::now();
    let err = execute_read_query(&conn, runaway, 10_000, 1_000_000).unwrap_err();
    let elapsed = start.elapsed();
    assert!(
        matches!(err, ExecError::Timeout(_)),
        "expected Timeout, got {err:?}"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(3),
        "deadline was 300ms but the query ran {elapsed:?} — the handler did not fire"
    );

    // Handler removed on drop: sleep past the now-elapsed captured deadline, then
    // a trivial query on the SAME connection must still succeed. If the handler
    // were still armed it would abort this immediately.
    std::thread::sleep(std::time::Duration::from_millis(500));
    let ok = execute_read_query(&conn, "SELECT count(*) FROM posts", 10, 5_000);
    assert!(
        ok.is_ok(),
        "a stale deadline handler aborted an innocent later query: {ok:?}"
    );

    // The NAMED-bind entry (stored RPC / cron RPC / MCP RPC) runs through a
    // SEPARATE inner function that arms its OWN deadline guard. A stored RPC body
    // is caller-supplied SQL and can hold this same recursive CTE, and RPC is
    // anon/user-callable when `anon_callable` — so this parallel site must be
    // bounded too. Reverting the `DeadlineGuard::arm` in
    // execute_read_query_with_named_inner leaves the interrupt un-triggered and
    // this query runs for billions of iterations (the harness kills the test),
    // which is exactly the DoS the guard closes.
    let mut binds = std::collections::BTreeMap::new();
    binds.insert("lim".to_string(), BoundValue::Int(2_000_000_000));
    let runaway_named = "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x < :lim) SELECT count(*) FROM c";
    let start2 = std::time::Instant::now();
    let err2 =
        execute_read_query_with_named(&conn, runaway_named, &binds, 10_000, 1_000_000).unwrap_err();
    let elapsed2 = start2.elapsed();
    assert!(
        matches!(err2, ExecError::Timeout(_)),
        "named path: expected Timeout, got {err2:?}"
    );
    assert!(
        elapsed2 < std::time::Duration::from_secs(3),
        "named path ran {elapsed2:?} — its deadline guard is not armed"
    );
}
