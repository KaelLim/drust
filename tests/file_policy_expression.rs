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
//! * **The composed arm — `owner_scoped` AND a select clause.** The only shape
//!   whose decision has TWO sub-clauses, so the only one that can desynchronize
//!   binds from placeholders: `decision_sql` emits the owner comparison first
//!   and must push its bind first (CLAUDE.md invariant 12's "policies
//!   AND-compose with the unchanged owner clause", carried to files). The
//!   bind-COUNT assertion below cannot see an ORDER swap — only a differing row
//!   SET can — so each composed registry binds a clause value that is NOT a
//!   user id, and four of them place the shape where the pushes interleave
//!   differently: alone, on the root behind other arms' range binds, under an
//!   open root with a looser child, and on a CJK prefix. The uncompilable
//!   variant is the other half: it is the only shape that can leave an ORPHAN
//!   bind, since bailing out after pushing the owner bind would shift every
//!   later arm's placeholders by one.

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
        // #974: the publish grant is an UPLOAD-side column. Neither evaluator
        // in this corpus reads it, and that is the property being asserted by
        // leaving it `None` on every rule here.
        public_upload_roles: None,
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

/// `owner_scoped=1` AND a select clause — the composed shape. Both sub-clauses
/// are emitted, owner first, so this is the only registry shape whose bind
/// order can drift from its placeholder order.
fn owner_sel(prefix: &str, clause: Value) -> FilePolicyRow {
    FilePolicyRow {
        owner_scoped: true,
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
        // ── the composed arm: owner_scoped AND a select clause ───────────────
        //
        // Every clause below binds a value no caller id can equal, so a swapped
        // bind pair degenerates to `uploader = 'public'` — a set difference the
        // corpus sees, where a bind-count check sees nothing.
        (
            "owner-scoped AND a select clause on one prefix",
            vec![owner_sel("docs/", json!({"visibility": "public"}))],
        ),
        (
            "the composed shape on the ROOT, behind another arm's range binds",
            vec![
                owner_sel("", json!({"visibility": "private"})),
                open("docs/"),
            ],
        ),
        (
            "the composed shape under an open root, with a looser child",
            vec![
                open(""),
                owner_sel("avatars/", json!({"content_type": "text/plain"})),
                open("avatars/alice/"),
            ],
        ),
        (
            "CJK: the composed shape with an open child",
            vec![
                owner_sel("照片/", json!({"visibility": "private"})),
                open("照片/alice/"),
            ],
        ),
        // The orphan-bind shape. Both evaluators deny every row under `x/` —
        // SQL because the clause will not compile (a column kept out of the
        // synthetic schema), memory because `authorize_file` runs the SAME
        // compile as its gate before evaluating. The compile refusal itself is
        // pinned directly in `an_uncompilable_clause_denies_its_prefix`.
        (
            "an uncompilable clause on an owner-scoped prefix, ahead of a root arm",
            vec![owner_sel("x/", json!({"meta_json": "x"})), open("")],
        ),
        // …and the same shape in the direction that used to DIVERGE (#973).
        // `meta_json` is deliberately absent from the synthetic schema, so the
        // SQL face collapses the arm to `0=1`; the in-memory face reads the row
        // map BY KEY, where `meta_json` is present-and-NULL, so `$is_null` was
        // TRUE and the single-file face ADMITTED a row the list face hid. The
        // agreement in the case above was accidental — it held only because
        // that clause's operand happened to compare against NULL. Both of the
        // shapes below are in-memory ADMITs on the pre-fix code.
        (
            "an uncompilable clause whose in-memory answer would be ADMIT",
            vec![
                sel("x/", json!({"meta_json": {"$is_null": true}})),
                open(""),
            ],
        ),
        (
            "…and one naming a column that exists in NEITHER the schema nor the row",
            vec![
                sel("x/", json!({"no_such_column": {"$is_null": true}})),
                open(""),
            ],
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

    // The shape above cannot orphan anything: with `owner_scoped=0` no bind is
    // pushed before the compile is attempted. THIS one can — the owner
    // comparison is the first thing the composed arm emits, so a bail-out that
    // pushed before compiling would leave a bind with no placeholder and read
    // every later arm's binds one slot early. `owner_scoped` must also not
    // survive as a lone surviving restriction: the arm denies outright.
    let ps = vec![owner_sel("bad/", json!({"meta_json": "x"})), open("")];
    let (sql, binds) = build_file_list_filter(&ps, &user("u-alice"));
    assert!(sql.contains("0=1"), "the composed arm denies too: {sql}");
    assert!(
        !sql.contains("uploader"),
        "the refused arm emits NO owner comparison, so it may push no owner \
         bind either: {sql}"
    );
    assert_eq!(
        sql.matches('?').count(),
        binds.len(),
        "an owner bind pushed before the refused compile would be an orphan: {sql}"
    );
}

/// The composed arm's two sub-clauses are emitted owner-first, and their binds
/// are pushed in that same order.
///
/// The corpus proves this by result set; this proves it by construction, so a
/// desync is named rather than showing up as a puzzling row difference. It is
/// deliberately position-relative, not an exact bind vector: how many binds a
/// clause compiles to is `compile_policy_using`'s business, and the contract
/// here is only "appearance order".
#[test]
fn the_composed_arm_pushes_the_owner_bind_before_the_clause_binds() {
    let ps = vec![owner_sel("docs/", json!({"visibility": "public"}))];
    let (sql, binds) = build_file_list_filter(&ps, &user("u-alice"));
    assert!(
        sql.contains("\"uploader\" = ?") && sql.contains("visibility"),
        "both sub-clauses compose; neither replaces the other: {sql}"
    );
    let texts: Vec<String> = binds
        .iter()
        .map(|v| match v {
            rusqlite::types::Value::Text(t) => t.clone(),
            other => format!("{other:?}"),
        })
        .collect();
    assert_eq!(
        &texts[..2],
        &["docs/".to_string(), "docs0".to_string()],
        "the arm opens with its half-open byte range ('/' + 1 == '0'): {texts:?}"
    );
    let pos = |needle: &str| texts.iter().position(|t| t == needle);
    assert!(
        pos("u-alice") < pos("public") && pos("public").is_some(),
        "owner bind first, exactly as the SQL orders the two fragments: {texts:?}"
    );
}
