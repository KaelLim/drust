//! #950-B T5 — the FILE-policy two-evaluator consistency corpus.
//!
//! `authorize_file` decides ONE file in memory; `build_file_list_filter`
//! compiles the SAME decision into a `WHERE` clause so the list face never
//! materializes a row the single-file face would 404. Two implementations of
//! one rule is exactly the shape CLAUDE.md invariant 12 exists to police, so
//! this file is the file-side sibling of `tests/policy_expression.rs`: for every
//! (registry, caller) pair it asserts the SQL result SET equals the set the
//! in-memory gate admits, over one shared corpus of file rows.
//!
//! The cases that earn their place (each one is a bug that shipped somewhere
//! before, or a divergence the spec measured):
//!
//! * **CJK prefixes.** The first SQL sketch used `substr(path,1,?len)=?prefix`.
//!   SQLite's `substr` counts CHARACTERS and Rust's `len()` counts BYTES, so
//!   `照片/alice/`'s arm never fired and the looser `照片/` arm won — a silent
//!   fail-OPEN. The corpus pins `照片師/` too: it shares two characters with
//!   `照片/` and must NOT be swept into it.
//! * **`path IS NULL`.** `NOT (path >= ? AND path < ?)` is NULL, not TRUE, for
//!   an unfiled row — so the root/default arm must say `path IS NULL OR NOT
//!   (…)` explicitly or every unfiled file silently vanishes from the list.
//! * **System columns.** `created_at` / `updated_at` are addressable by a policy
//!   without appearing in the synthetic schema. `updated_at $is_null` is the
//!   fail-OPEN shape (a row map missing the key reads as Null ⇒ TRUE), so both
//!   evaluators must agree it is FALSE on a real row.
//! * **Literal `%` and `_` in a path.** They are ordinary path characters; the
//!   prefix match is a binary range, never `LIKE`.
//! * **Nesting and `$or`.** Three levels of override prove the exclusion chain,
//!   and an `$or` policy under two prefixes proves each fragment is parenthesized
//!   rather than trusting operator precedence.

use drust::auth::middleware::AuthCtx;
use drust::query::vector_filter::FilterAst;
use drust::storage::file_policy::{
    FileAccess, FilePolicyRow, authorize_file, build_file_list_filter,
};
use rusqlite::Connection;
use serde_json::{Map, Value, json};
use std::collections::BTreeSet;

// ── registry constructors ────────────────────────────────────────────────────

fn ast(v: Value) -> FilterAst {
    serde_json::from_value(v).unwrap()
}

fn rule(prefix: &str) -> FilePolicyRow {
    FilePolicyRow {
        prefix: prefix.to_string(),
        owner_scoped: false,
        public_read: false,
        select_policy: None,
        delete_policy: None,
    }
}

/// `owner_scoped=1` — only the uploader.
fn owner(prefix: &str) -> FilePolicyRow {
    FilePolicyRow {
        owner_scoped: true,
        ..rule(prefix)
    }
}

/// `public_read=1` — the explicit open flag.
fn open(prefix: &str) -> FilePolicyRow {
    FilePolicyRow {
        public_read: true,
        ..rule(prefix)
    }
}

/// A select clause with no owner scope (the shape `public_read` is not needed
/// for, because the clause itself is the restriction).
fn sel(prefix: &str, clause: Value) -> FilePolicyRow {
    FilePolicyRow {
        select_policy: Some(ast(clause)),
        ..rule(prefix)
    }
}

/// `owner_scoped=0`, no clause, no flag — the deny-all shape the write face
/// refuses to create and the read face must refuse to honour.
fn clause_less(prefix: &str) -> FilePolicyRow {
    rule(prefix)
}

// ── the corpus of file rows ──────────────────────────────────────────────────

fn file(key: &str, path: Option<&str>, uploader: &str) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("key".into(), json!(key));
    m.insert("original_name".into(), json!("f.bin"));
    m.insert("content_type".into(), json!("text/plain"));
    m.insert("size_bytes".into(), json!(10));
    m.insert("content_disposition".into(), Value::Null);
    m.insert("visibility".into(), json!("private"));
    m.insert("cache_control".into(), Value::Null);
    m.insert("meta_json".into(), Value::Null);
    m.insert("uploaded_at".into(), json!("2026-08-11 00:00:00"));
    m.insert("uploader".into(), json!(uploader));
    m.insert(
        "path".into(),
        match path {
            Some(p) => json!(p),
            None => Value::Null,
        },
    );
    m.insert("created_at".into(), json!("2026-08-11 00:00:00"));
    m.insert("updated_at".into(), json!("2026-08-11 00:00:00"));
    m
}

fn with(mut m: Map<String, Value>, field: &str, v: Value) -> Map<String, Value> {
    m.insert(field.into(), v);
    m
}

fn corpus() -> Vec<Map<String, Value>> {
    vec![
        file("k01", Some("avatars/alice/a.png"), "u-alice"),
        file("k02", Some("avatars/bob/b.png"), "u-bob"),
        file("k03", Some("avatars/top.png"), "u-alice"),
        // `avatarss/` shares every byte of `avatars` but is a different folder:
        // the trailing '/' in the registered prefix is what separates them.
        file("k04", Some("avatarss/x.png"), "u-alice"),
        file("k05", Some("照片/alice/x.png"), "u-alice"),
        file("k06", Some("照片/bob.png"), "u-bob"),
        // The substr() trap: two shared CHARACTERS, a different folder.
        file("k07", Some("照片師/y.png"), "u-alice"),
        // Unfiled rows — reachable only through the root arm.
        file("k08", None, "u-alice"),
        file("k09", None, "service"),
        // `%` and `_` are literal path characters, not wildcards.
        file("k10", Some("docs/100%_off.txt"), "u-bob"),
        with(
            with(
                file("k11", Some("docs/plain.txt"), "u-alice"),
                "visibility",
                json!("public"),
            ),
            "created_at",
            json!("2025-01-01 00:00:00"),
        ),
        file("k12", Some("x/secret.bin"), "u-alice"),
        file("k13", Some("shared/note.txt"), "u-bob"),
        file("k14", Some("shared/hr/pay.csv"), "u-alice"),
        with(
            file("k15", Some("avatars/null-ct.png"), "u-bob"),
            "content_type",
            Value::Null,
        ),
        file("k16", Some("a/1.bin"), "u-bob"),
        file("k17", Some("a/b/2.bin"), "u-bob"),
        file("k18", Some("a/b/c/3.bin"), "u-bob"),
    ]
}

// ── the two evaluators ───────────────────────────────────────────────────────

fn seed(conn: &Connection, rows: &[Map<String, Value>]) {
    for r in rows {
        let keys: Vec<&String> = r.keys().collect();
        let cols = keys
            .iter()
            .map(|k| format!("\"{k}\""))
            .collect::<Vec<_>>()
            .join(",");
        let ph = (1..=keys.len())
            .map(|i| format!("?{i}"))
            .collect::<Vec<_>>()
            .join(",");
        let params: Vec<rusqlite::types::Value> = keys
            .iter()
            .map(|k| drust::query::vector_filter::json_to_value(&r[*k]))
            .collect();
        let refs: Vec<&dyn rusqlite::ToSql> =
            params.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
        conn.execute(
            &format!("INSERT INTO \"_system_files\" ({cols}) VALUES ({ph})"),
            &refs[..],
        )
        .unwrap();
    }
}

fn sql_visible(conn: &Connection, policies: &[FilePolicyRow], auth: &AuthCtx) -> BTreeSet<String> {
    let (where_sql, binds) = build_file_list_filter(policies, auth);
    assert!(
        !where_sql.contains("substr"),
        "prefix matching must be a binary range, never substr(): {where_sql}"
    );
    assert_eq!(
        where_sql.matches('?').count(),
        binds.len(),
        "bind count must equal placeholder count, in appearance order: {where_sql}"
    );
    let q = format!("SELECT \"key\" FROM \"_system_files\" WHERE ({where_sql})");
    let refs: Vec<&dyn rusqlite::ToSql> = binds.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
    let mut stmt = conn.prepare(&q).unwrap();
    stmt.query_map(&refs[..], |r| r.get::<_, String>(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
}

fn mem_visible(
    rows: &[Map<String, Value>],
    policies: &[FilePolicyRow],
    auth: &AuthCtx,
) -> BTreeSet<String> {
    rows.iter()
        .filter(|r| authorize_file(policies, r, auth, FileAccess::Read))
        .map(|r| r["key"].as_str().unwrap().to_string())
        .collect()
}

fn user(id: &str) -> AuthCtx {
    AuthCtx::User {
        user_id: id.to_string(),
        token_hash: String::new(),
    }
}

// ── the corpus run ───────────────────────────────────────────────────────────

#[test]
fn the_two_file_evaluators_agree_on_the_corpus() {
    let dir = tempfile::tempdir().unwrap();
    // The real per-tenant DDL, so column affinity and (absent) COLLATE are the
    // production ones — a BINARY comparison is what makes the range arms exact.
    let conn = drust::storage::tenant_db::open_write(dir.path(), "corpus").unwrap();
    let rows = corpus();
    seed(&conn, &rows);

    let registries: Vec<(&str, Vec<FilePolicyRow>)> = vec![
        ("empty registry — the owner-scoped default", vec![]),
        ("root open only", vec![open("")]),
        (
            "root open + an owner-scoped folder",
            vec![open(""), owner("avatars/")],
        ),
        (
            "a folder rule with NO root — everything else falls to the default arm",
            vec![owner("avatars/")],
        ),
        (
            "CJK: an open parent with an owner-scoped child",
            vec![open("照片/"), owner("照片/alice/")],
        ),
        (
            "a select clause instead of owner_scoped",
            vec![sel("docs/", json!({"uploader": {"$auth": "id"}}))],
        ),
        (
            "a clause-less row under an open root",
            vec![open(""), clause_less("x/")],
        ),
        (
            "a system-column clause on the root",
            vec![sel("", json!({"created_at": {"$gt": "2026-01-01"}}))],
        ),
        (
            "the is_null fail-open shape on a system column",
            vec![sel("", json!({"updated_at": {"$is_null": true}}))],
        ),
        (
            "an $or clause across two prefixes",
            vec![
                sel(
                    "shared/",
                    json!({"or": [{"uploader": {"$auth": "id"}}, {"visibility": "public"}]}),
                ),
                owner("shared/hr/"),
            ],
        ),
        (
            "an OPEN child under an owner-scoped parent (override, loosening)",
            vec![owner("avatars/"), open("avatars/alice/")],
        ),
        ("an owner-scoped root", vec![owner("")]),
        (
            "a clause over a column that is NULL on one row",
            vec![sel("avatars/", json!({"content_type": "text/plain"}))],
        ),
        (
            "a numeric clause (INTEGER column vs INTEGER literal)",
            vec![sel("", json!({"size_bytes": {"$gt": 5}}))],
        ),
        (
            "a LIKE clause whose pattern meets a path holding literal % and _",
            vec![sel("docs/", json!({"path": {"$like": "docs/1%"}}))],
        ),
        (
            "three levels of override — the exclusion chain",
            vec![open(""), owner("a/"), open("a/b/"), owner("a/b/c/")],
        ),
        (
            "a not-clause, whose NULL handling is Kleene on both sides",
            vec![sel("", json!({"not": {"content_type": "text/plain"}}))],
        ),
    ];

    let callers: Vec<(&str, AuthCtx)> = vec![
        ("alice", user("u-alice")),
        ("bob", user("u-bob")),
        ("anon", AuthCtx::Anon),
        // Service bypasses upstream of both evaluators; passing it here is a
        // caller bug, and both sides must round it the same (fail-closed) way.
        ("service", AuthCtx::Service { admin_id: None }),
    ];

    for (label, policies) in &registries {
        for (who, auth) in &callers {
            let mem = mem_visible(&rows, policies, auth);
            let sql = sql_visible(&conn, policies, auth);
            assert_eq!(
                mem, sql,
                "DISAGREE registry={label:?} caller={who}\n  in-memory: {mem:?}\n  sql:       {sql:?}"
            );
        }
    }
}

/// The corpus above proves agreement; this proves the answer is not trivially
/// "everything" or "nothing" — a filter that returned every row would agree
/// with an in-memory gate that also returned every row.
#[test]
fn the_corpus_actually_discriminates() {
    let dir = tempfile::tempdir().unwrap();
    let conn = drust::storage::tenant_db::open_write(dir.path(), "discriminate").unwrap();
    let rows = corpus();
    seed(&conn, &rows);

    let ps = vec![open("照片/"), owner("照片/alice/")];
    let bob = sql_visible(&conn, &ps, &user("u-bob"));
    assert!(
        bob.contains("k06"),
        "an open CJK prefix is readable: {bob:?}"
    );
    assert!(
        !bob.contains("k05"),
        "the deeper owner-scoped CJK prefix overrides it: {bob:?}"
    );
    assert!(
        !bob.contains("k07"),
        "照片師/ is NOT inside 照片/ — a character-counting prefix match would \
         wrongly include it (fail-open): {bob:?}"
    );
    assert!(
        !bob.contains("k08"),
        "an unfiled row matches no folder rule and falls to the owner-scoped \
         default, which bob does not satisfy: {bob:?}"
    );

    // The unfiled rows are the ones a missing `path IS NULL` branch loses.
    let alice = sql_visible(&conn, &[open("avatars/")], &user("u-alice"));
    assert!(
        alice.contains("k08"),
        "alice's unfiled row survives the default arm: {alice:?}"
    );
    assert!(
        !alice.contains("k09"),
        "…but the service-uploaded unfiled row does not: {alice:?}"
    );

    let anon_open_root = sql_visible(&conn, &[open("")], &AuthCtx::Anon);
    assert_eq!(
        anon_open_root.len(),
        rows.len(),
        "an explicitly-open root shows anon everything (the seeded upgrade state)"
    );
    let anon_no_root = sql_visible(&conn, &[], &AuthCtx::Anon);
    assert!(
        anon_no_root.is_empty(),
        "…and with nothing registered anon sees nothing: $auth is NULL, so \
         `uploader = NULL` is Unknown on every row"
    );
}

/// A clause the SQL compiler refuses (a column kept out of the synthetic
/// schema, reachable only by a hand-INSERTed registry row) must collapse that
/// arm to `0=1`, never drop the arm's restriction.
#[test]
fn an_uncompilable_clause_denies_its_prefix() {
    let ps = vec![sel("bad/", json!({"meta_json": "x"}))];
    let (sql, binds) = build_file_list_filter(&ps, &user("u-alice"));
    assert!(
        sql.contains("0=1"),
        "an unusable clause must deny its prefix: {sql}"
    );
    assert_eq!(
        sql.matches('?').count(),
        binds.len(),
        "the abandoned clause must not leave orphan binds: {sql}"
    );
}
