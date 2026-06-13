//! Consistency corpus: the two policy evaluators MUST agree. For each
//! (ast, row, ctx) we (a) compile the USING to SQL, insert the row into a
//! throwaway in-memory table, and check whether the row survives the WHERE;
//! (b) run eval_policy in memory. They must return the same bool.

use drust::query::policy::{compile_policy_using, eval_policy, PolicyCtx};
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
    let refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
    conn.execute(&insert, &refs[..]).unwrap();
    let (frag, binds) = compile_policy_using(s, ast, ctx).unwrap();
    let q = format!("SELECT COUNT(*) FROM t WHERE {frag}");
    let brefs: Vec<&dyn rusqlite::ToSql> = binds.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
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
            let row: serde_json::Map<String, serde_json::Value> =
                serde_json::from_str(r).unwrap();
            for ctx in &ctxs {
                let mem = eval_policy(&ast, &row, ctx);
                let sql = sql_says_match(&s, &ast, ctx, r);
                assert_eq!(mem, sql, "DISAGREE ast={a} row={r} auth={:?}", ctx.auth_id);
            }
        }
    }
}
