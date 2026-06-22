//! Consistency corpus: the two policy evaluators MUST agree. For each
//! (ast, row, ctx) we (a) compile the USING to SQL, insert the row into a
//! throwaway in-memory table, and check whether the row survives the WHERE;
//! (b) run eval_policy in memory. They must return the same bool.

use drust::query::policy::{PolicyCtx, compile_policy_using, eval_policy};
use drust::query::vector_filter::FilterAst;
use drust::storage::schema::{CollectionSchema, Field};
use rusqlite::Connection;
use std::collections::BTreeSet;

fn schema(fields: &[(&str, &str)]) -> CollectionSchema {
    CollectionSchema {
        name: "t".into(),
        fields: fields
            .iter()
            .map(|(n, ty)| Field {
                name: n.to_string(),
                sql_type: ty.to_string(),
                nullable: true,
                pk: false,
                default_value: None,
                foreign_key: None,
                description: None,
            })
            .collect(),
        indices: vec![],
        row_count: 0,
        anon_caps: BTreeSet::new(),
        user_caps: BTreeSet::new(),
        owner_field: None,
        read_scope: None,
        vector_fields: vec![],
        realtime_enabled: true,
        description: None,
        policies: Default::default(),
    }
}

fn sql_says_match(s: &CollectionSchema, ast: &FilterAst, ctx: &PolicyCtx, row_json: &str) -> bool {
    let conn = Connection::open_in_memory().unwrap();
    let cols: Vec<String> = s
        .fields
        .iter()
        .map(|f| format!("\"{}\" {}", f.name, f.sql_type))
        .collect();
    conn.execute_batch(&format!(
        "CREATE TABLE t (id INTEGER PRIMARY KEY, {});",
        cols.join(", ")
    ))
    .unwrap();
    let row: serde_json::Map<String, serde_json::Value> = serde_json::from_str(row_json).unwrap();
    let keys: Vec<&String> = row.keys().collect();
    let ph: Vec<String> = (1..=keys.len()).map(|i| format!("?{i}")).collect();
    let insert = format!(
        "INSERT INTO t ({}) VALUES ({})",
        keys.iter()
            .map(|k| format!("\"{k}\""))
            .collect::<Vec<_>>()
            .join(","),
        ph.join(",")
    );
    let params: Vec<rusqlite::types::Value> = keys
        .iter()
        .map(|k| drust::query::vector_filter::json_to_value(&row[*k]))
        .collect();
    let refs: Vec<&dyn rusqlite::ToSql> =
        params.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
    conn.execute(&insert, &refs[..]).unwrap();
    let (frag, binds) = compile_policy_using(s, ast, ctx).unwrap();
    let q = format!("SELECT COUNT(*) FROM t WHERE {frag}");
    let brefs: Vec<&dyn rusqlite::ToSql> =
        binds.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
    let n: i64 = conn.query_row(&q, &brefs[..], |r| r.get(0)).unwrap();
    n > 0
}

#[test]
fn evaluators_agree_on_corpus() {
    let s = schema(&[("status", "TEXT"), ("author", "TEXT"), ("n", "INTEGER")]);
    let asts = [
        r#"{"status":"published"}"#,
        r#"{"status":{"$ne":"draft"}}"#,
        r#"{"n":{"$gte":5}}"#,
        r#"{"author":{"$eq":{"$auth":"id"}}}"#,
        r#"{"$authenticated":true}"#,
        r#"{"or":[{"status":"published"},{"author":{"$eq":{"$auth":"id"}}}]}"#,
        r#"{"and":[{"$authenticated":true},{"n":{"$lt":10}}]}"#,
        r#"{"status":{"$in":["published","featured"]}}"#,
        r#"{"author":{"$is_null":true}}"#,
    ];
    let rows = [
        r#"{"status":"published","author":"u-1","n":5}"#,
        r#"{"status":"draft","author":"u-2","n":20}"#,
        r#"{"status":"featured","author":null,"n":3}"#,
    ];
    let ctxs = [
        PolicyCtx {
            auth_id: Some("u-1".into()),
            data: None,
        },
        PolicyCtx {
            auth_id: None,
            data: None,
        },
    ];
    for a in asts {
        let ast: FilterAst = serde_json::from_str(a).unwrap();
        for r in rows {
            let row: serde_json::Map<String, serde_json::Value> = serde_json::from_str(r).unwrap();
            for ctx in &ctxs {
                let mem = eval_policy(&ast, &row, ctx);
                let sql = sql_says_match(&s, &ast, ctx, r);
                assert_eq!(mem, sql, "DISAGREE ast={a} row={r} auth={:?}", ctx.auth_id);
            }
        }
    }
}

/// H3/H3b regression: the two evaluators diverged on `in`/`nin` against a NULL
/// field (SQLite excludes a NULL lhs from both IN and NOT IN, but `eval_leaf`'s
/// `!hit` wrongly matched a NULL row on `$nin`) and on ASCII `LIKE` case (SQL
/// LIKE is case-insensitive; the in-memory regex was case-sensitive). Each pair
/// must agree exactly between `eval_policy` and the compiled `?`-bound SQL.
#[test]
fn evaluators_agree_on_in_nin_null_and_like_case() {
    let s = schema(&[("name", "TEXT")]);
    let anon = PolicyCtx {
        auth_id: None,
        data: None,
    };
    // (ast, row): each must produce identical eval vs SQL verdicts.
    let cases = [
        // (a) $nin against a NULL field — SQL excludes (NULL NOT IN → not-true).
        (r#"{"name":{"$nin":["a","b"]}}"#, r#"{"name":null}"#),
        // (b) $nin against a non-matching, non-null field — SQL keeps the row.
        (r#"{"name":{"$nin":["a"]}}"#, r#"{"name":"c"}"#),
        // (c) $in against a NULL field — SQL excludes (NULL IN → not-true).
        (r#"{"name":{"$in":["a"]}}"#, r#"{"name":null}"#),
        // (d) LIKE with case-varying text — SQLite LIKE is ASCII case-insensitive.
        (r#"{"name":{"$like":"ABC%"}}"#, r#"{"name":"abcdef"}"#),
        // (e) $nin with a literal NULL operand — SQL `c NOT IN (NULL)` → NULL
        //     (not-true) → excluded; eval must agree (was fail-open true).
        (r#"{"name":{"$nin":[null]}}"#, r#"{"name":"c"}"#),
        // (f) $nin with a {"$auth":"id"} operand that resolves to NULL for the
        //     anon ctx — same SQL exclusion; eval must agree.
        (r#"{"name":{"$nin":[{"$auth":"id"}]}}"#, r#"{"name":"c"}"#),
        // (g) $in with a literal NULL operand — both exclude (sanity, no regression).
        (r#"{"name":{"$in":[null]}}"#, r#"{"name":"c"}"#),
        // (h) F4 — empty $nin against a NULL field. SQL compiles to `1=1`
        //     (`NOT IN ()` is true for ALL x incl. NULL); eval must agree (was
        //     false because the NULL-lhs guard fired before the empty check).
        (r#"{"name":{"$nin":[]}}"#, r#"{"name":null}"#),
        // (i) empty $nin against a non-null field — both keep (sanity).
        (r#"{"name":{"$nin":[]}}"#, r#"{"name":"c"}"#),
        // (j) empty $in against a NULL field — SQL `1=0` excludes; eval agrees.
        (r#"{"name":{"$in":[]}}"#, r#"{"name":null}"#),
        // (k) empty $in against a non-null field — both exclude (sanity).
        (r#"{"name":{"$in":[]}}"#, r#"{"name":"c"}"#),
        // (l) F4 — empty $nin wrapped in `not` against a NULL field: the
        //     weaponizable form. SQL `NOT (1=1)` excludes; eval must agree
        //     (was fail-open true: `!false` from the unfixed empty-$nin eval).
        (r#"{"not":{"name":{"$nin":[]}}}"#, r#"{"name":null}"#),
    ];
    for (a, r) in cases {
        let ast: FilterAst = serde_json::from_str(a).unwrap();
        let row: serde_json::Map<String, serde_json::Value> = serde_json::from_str(r).unwrap();
        let mem = eval_policy(&ast, &row, &anon);
        let sql = sql_says_match(&s, &ast, &anon, r);
        assert_eq!(mem, sql, "DISAGREE ast={a} row={r}");
    }
}

/// GAP-1: lock the `{"$data":"<field>"}` operand contract — the consistency
/// corpus above never exercised it. `$data` is CHECK-only: it reads the
/// post-image row from `PolicyCtx.data`, NOT the SQL table row. Two halves:
///
///  (A) When `PolicyCtx.data` is `Some(map)` (the CHECK path), BOTH evaluators
///      resolve `$data` from `ctx.data` identically, so `compile_policy_using`
///      (→ `?`-bound SQL) and `eval_policy` must return the same verdict. We
///      reuse `sql_says_match`, which inserts the table row (the lhs column
///      source) independently of `ctx.data` (the `$data` operand source), so we
///      control both sides. A future divergence (e.g. one evaluator starting to
///      pull `$data` from the table row instead of `ctx.data`, or dropping the
///      operand) would flip one verdict and fail this lockstep assert.
///
///  (B) When `PolicyCtx.data` is `None` (the standard USING / read / pre-flight
///      compile path built by `PolicyCtx::from_auth`), `compile_policy_using`
///      MUST reject a `$data` ref (`PolicyError::DataUnavailable`) — the
///      fail-closed contract that keeps a CHECK-only operand from ever binding
///      into a read/target-pre-flight WHERE. Passes on current code; would RED
///      if the compiler ever silently bound `$data` under `data: None`.
#[test]
fn evaluators_agree_on_data_operand() {
    let s = schema(&[("status", "TEXT"), ("author", "TEXT"), ("n", "INTEGER")]);

    // --- Half (A): data: Some(...) — both evaluators must agree. ---
    // Each case: (ast, table_row_json, ctx.data_json). The table row supplies
    // the lhs column; ctx.data supplies the $data operand; they are chosen
    // independently so equality / inequality is under our control.
    let agree_cases = [
        // $data match: lhs author "u-1" == ctx.data.author "u-1" → both true.
        (
            r#"{"author":{"$eq":{"$data":"author"}}}"#,
            r#"{"status":"published","author":"u-1","n":5}"#,
            r#"{"author":"u-1"}"#,
        ),
        // $data mismatch: lhs author "u-1" != ctx.data.author "u-2" → both false.
        (
            r#"{"author":{"$eq":{"$data":"author"}}}"#,
            r#"{"status":"published","author":"u-1","n":5}"#,
            r#"{"author":"u-2"}"#,
        ),
        // $data eq-shorthand (object body that is itself the {$data} ref).
        (
            r#"{"status":{"$data":"status"}}"#,
            r#"{"status":"published","author":"u-1","n":5}"#,
            r#"{"status":"published"}"#,
        ),
        // $data against an INTEGER column, numeric equality.
        (
            r#"{"n":{"$gte":{"$data":"n"}}}"#,
            r#"{"status":"x","author":"u-1","n":5}"#,
            r#"{"n":3}"#,
        ),
        // $data ref to a field MISSING from ctx.data → resolves to NULL on both
        // sides; `"author" = NULL` is not-true in SQL and value_cmp(_, Null) is
        // None in eval → both false.
        (
            r#"{"author":{"$eq":{"$data":"author"}}}"#,
            r#"{"status":"x","author":"u-1","n":5}"#,
            r#"{"status":"x"}"#,
        ),
    ];
    for (a, table_row, data_json) in agree_cases {
        let ast: FilterAst = serde_json::from_str(a).unwrap();
        let data: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(data_json).unwrap();
        let ctx = PolicyCtx {
            auth_id: Some("u-1".into()),
            data: Some(data),
        };
        let row: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(table_row).unwrap();
        let mem = eval_policy(&ast, &row, &ctx);
        let sql = sql_says_match(&s, &ast, &ctx, table_row);
        assert_eq!(mem, sql, "DISAGREE ast={a} table_row={table_row} data={data_json}");
    }

    // $data combined with $auth in one AND: lhs author "u-1" == $auth "u-1"
    // AND lhs status "published" == $data.status "published" → both true; flip
    // the $data half (ctx.data.status "draft") → both false. Locks that the two
    // dynamic-operand kinds compose identically across evaluators.
    let combo: FilterAst = serde_json::from_str(
        r#"{"and":[{"author":{"$eq":{"$auth":"id"}}},{"status":{"$eq":{"$data":"status"}}}]}"#,
    )
    .unwrap();
    let table_row = r#"{"status":"published","author":"u-1","n":5}"#;
    let row: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(table_row).unwrap();
    for (data_json, _label) in [
        (r#"{"status":"published"}"#, "match"),
        (r#"{"status":"draft"}"#, "mismatch"),
    ] {
        let data: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(data_json).unwrap();
        let ctx = PolicyCtx {
            auth_id: Some("u-1".into()),
            data: Some(data),
        };
        let mem = eval_policy(&combo, &row, &ctx);
        let sql = sql_says_match(&s, &combo, &ctx, table_row);
        assert_eq!(mem, sql, "DISAGREE combo data={data_json}");
    }

    // --- Half (B): data: None — compiler MUST reject $data (CHECK-only). ---
    // The USING / read / pre-flight path never has a post-image row; a $data
    // ref under `data: None` is unbindable and fail-closed-rejected. (Checked
    // via the Display string to avoid importing PolicyError into this file.)
    let data_ast: FilterAst =
        serde_json::from_str(r#"{"author":{"$eq":{"$data":"author"}}}"#).unwrap();
    let no_data = PolicyCtx {
        auth_id: Some("u-1".into()),
        data: None,
    };
    let err = compile_policy_using(&s, &data_ast, &no_data)
        .expect_err("compile_policy_using must reject $data when ctx.data is None");
    assert!(
        err.to_string().contains("$data"),
        "expected a $data-unavailable error, got: {err}"
    );
}
