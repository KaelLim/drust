//! Wave 2 M3 Task 5 — the `$fts` reserved-Leaf-key filter operand.
//!
//! `$fts` is a reserved KEY inside a `FilterAst::Leaf` map (NOT an enum variant
//! — Leaf matches every object under serde untagged), resolved against
//! `schema.fts_indexes` and compiled to either a `?`-bound MATCH subquery or a
//! per-field trigram short-term LIKE fallback. Two things are pinned here:
//!   * golden SQL for BOTH compile shapes + the tokenizer branch + the
//!     substring-fallback semantics (CJK 2-gram matches; a mixed-length query
//!     never drops its short term); and
//!   * THE security invariant: on an owner-scoped `/list`, the shadow subquery
//!     only supplies candidate rowids — the unchanged owner WHERE filters them,
//!     so User A only ever searches their own rows.

#[path = "helpers.rs"]
mod helpers;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::query::vector_filter::{FilterAst, FilterError, compile};
use drust::storage::schema::{CollectionSchema, Field, FtsIndex};
use rusqlite::Connection;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::sync::Arc;
use tower::ServiceExt;

use drust::mcp::server::McpRegistry;
use drust::mcp::tools::fts::create_fts_index;
use drust::storage::pool::TenantRegistry;
use helpers::{grab_pool, register_and_login_via_app, spin_up_dual_role_self_register};

// ── schema fixtures (unit-level, no tenant) ───────────────────────────

fn text_field(name: &str) -> Field {
    Field {
        name: name.to_string(),
        sql_type: "TEXT".into(),
        nullable: true,
        pk: false,
        default_value: None,
        foreign_key: None,
        description: None,
        ..Default::default()
    }
}

/// A `notes` collection with the given fts index registered.
fn schema_with_index(fields: &[&str], index: FtsIndex) -> CollectionSchema {
    CollectionSchema {
        name: "notes".into(),
        fields: fields.iter().map(|n| text_field(n)).collect(),
        indices: vec![],
        row_count: 0,
        anon_caps: BTreeSet::new(),
        user_caps: BTreeSet::new(),
        owner_field: None,
        read_scope: None,
        vector_fields: vec![],
        fts_indexes: vec![index],
        realtime_enabled: true,
        audit_enabled: true,
        description: None,
        policies: Default::default(),
    }
}

fn fts_index(name: &str, fields: &[&str], tokenizer: &str) -> FtsIndex {
    FtsIndex {
        name: name.into(),
        fields: fields.iter().map(|s| s.to_string()).collect(),
        tokenizer: tokenizer.into(),
    }
}

fn ast(json_str: &str) -> FilterAst {
    serde_json::from_str(json_str).unwrap()
}

/// Compile a `$fts` fallback filter and run it against an in-memory
/// `notes(id, title, body)`; return the matching titles. Only the LIKE fallback
/// path touches parent columns, so this drives it without a real fts5 head.
fn fallback_titles(
    schema: &CollectionSchema,
    a: &FilterAst,
    rows: &[(&str, Option<&str>)],
) -> Vec<String> {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch("CREATE TABLE notes(id INTEGER PRIMARY KEY, title TEXT, body TEXT);")
        .unwrap();
    for (i, (t, b)) in rows.iter().enumerate() {
        conn.execute(
            "INSERT INTO notes(id, title, body) VALUES(?1, ?2, ?3)",
            rusqlite::params![i as i64 + 1, t, b],
        )
        .unwrap();
    }
    let (frag, binds) = compile(schema, a).unwrap();
    let sql = format!("SELECT title FROM notes WHERE {frag} ORDER BY id");
    let brefs: Vec<&dyn rusqlite::ToSql> =
        binds.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
    let mut stmt = conn.prepare(&sql).unwrap();
    stmt.query_map(&brefs[..], |r| r.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

// ── golden SQL ─────────────────────────────────────────────────────────

#[test]
fn golden_match_subquery_all_terms_long() {
    // trigram index, one 8-char term → MATCH subquery, single bind.
    let s = schema_with_index(
        &["title", "body"],
        fts_index("main", &["title", "body"], "trigram"),
    );
    let (sql, binds) =
        compile(&s, &ast(r#"{"$fts":{"index":"main","query":"hospital"}}"#)).unwrap();
    assert_eq!(
        sql,
        r#""id" IN (SELECT rowid FROM "_system_search_fts$notes$main" WHERE "_system_search_fts$notes$main" MATCH ?)"#
    );
    assert_eq!(binds, vec![rusqlite::types::Value::Text("hospital".into())]);
}

#[test]
fn golden_unicode61_uses_match_even_for_short_term() {
    // unicode61 never takes the trigram fallback, even for a 2-char CJK query.
    let s = schema_with_index(&["title"], fts_index("uni", &["title"], "unicode61"));
    let (sql, binds) = compile(&s, &ast(r#"{"$fts":{"index":"uni","query":"慈濟"}}"#)).unwrap();
    assert_eq!(
        sql,
        r#""id" IN (SELECT rowid FROM "_system_search_fts$notes$uni" WHERE "_system_search_fts$notes$uni" MATCH ?)"#
    );
    assert_eq!(binds, vec![rusqlite::types::Value::Text("慈濟".into())]);
}

#[test]
fn golden_trigram_short_term_falls_back_to_per_field_like() {
    // trigram index, a 2-char term → per-field `%…%` LIKE, one bind per field.
    let s = schema_with_index(
        &["title", "body"],
        fts_index("main", &["title", "body"], "trigram"),
    );
    let (sql, binds) = compile(&s, &ast(r#"{"$fts":{"index":"main","query":"慈濟"}}"#)).unwrap();
    assert_eq!(
        sql,
        r#"("title" LIKE ? ESCAPE '\' OR "body" LIKE ? ESCAPE '\')"#
    );
    assert_eq!(
        binds,
        vec![
            rusqlite::types::Value::Text("%慈濟%".into()),
            rusqlite::types::Value::Text("%慈濟%".into()),
        ]
    );
}

#[test]
fn golden_like_metacharacters_are_escaped() {
    // A short leading term ('z') forces the fallback; the WHOLE query — incl. the
    // `%` `_` `\` metacharacters — is `\`-escaped in the `?`-bound pattern.
    let s = schema_with_index(&["title"], fts_index("main", &["title"], "trigram"));
    let (_sql, binds) = compile(&s, &ast(r#"{"$fts":{"index":"main","query":"z %_\\"}}"#)).unwrap();
    assert_eq!(
        binds,
        vec![rusqlite::types::Value::Text(r"%z \%\_\\%".into())]
    );
}

#[test]
fn unknown_index_yields_fts_index_not_found() {
    let s = schema_with_index(&["title"], fts_index("main", &["title"], "trigram"));
    let err = compile(&s, &ast(r#"{"$fts":{"index":"ghost","query":"x"}}"#)).unwrap_err();
    match err {
        FilterError::Fts { code, .. } => assert_eq!(code, "FTS_INDEX_NOT_FOUND"),
        other => panic!("expected FilterError::Fts(FTS_INDEX_NOT_FOUND), got {other:?}"),
    }
}

#[test]
fn malformed_fts_operand_shapes_are_rejected() {
    let s = schema_with_index(&["title"], fts_index("main", &["title"], "trigram"));
    for bad in [
        r#"{"$fts":{"index":"main"}}"#,                   // missing query
        r#"{"$fts":{"query":"x"}}"#,                      // missing index
        r#"{"$fts":{"index":"main","query":"x","z":1}}"#, // extra key
        r#"{"$fts":{"index":5,"query":"x"}}"#,            // non-string index
        r#"{"$fts":"main"}"#,                             // not an object
    ] {
        let err = compile(&s, &ast(bad)).unwrap_err();
        assert!(
            matches!(err, FilterError::Parse(_)),
            "{bad}: expected Parse shape error, got {err:?}"
        );
    }
}

// ── fallback semantics (compile + run on parent columns) ───────────────

#[test]
fn cjk_two_gram_matches_via_fallback() {
    // 慈濟 (2 chars) against a trigram index over 高雄慈濟醫院 → matched.
    let s = schema_with_index(
        &["title", "body"],
        fts_index("main", &["title", "body"], "trigram"),
    );
    let titles = fallback_titles(
        &s,
        &ast(r#"{"$fts":{"index":"main","query":"慈濟"}}"#),
        &[("高雄慈濟醫院", None), ("台北榮總", None)],
    );
    assert_eq!(titles, vec!["高雄慈濟醫院".to_string()]);
}

#[test]
fn mixed_length_query_does_not_drop_the_short_term() {
    // 'zz 醫院年度' is phrase-substring: a row with 醫院年度 but no 'zz' must NOT
    // match (a per-term MATCH would satisfy 醫院年度 and no-op 'zz', over-matching).
    let s = schema_with_index(
        &["title", "body"],
        fts_index("main", &["title", "body"], "trigram"),
    );
    let rows = [("高雄慈濟醫院年度報告", None)];
    let none = fallback_titles(
        &s,
        &ast(r#"{"$fts":{"index":"main","query":"zz 醫院年度"}}"#),
        &rows,
    );
    assert!(
        none.is_empty(),
        "short term 'zz' must not be dropped: {none:?}"
    );
    // Positive control: the same row DOES match a 2-gram it actually contains.
    let some = fallback_titles(
        &s,
        &ast(r#"{"$fts":{"index":"main","query":"慈濟"}}"#),
        &rows,
    );
    assert_eq!(some, vec!["高雄慈濟醫院年度報告".to_string()]);
}

// ── THE security pin: owner scoping on /list ───────────────────────────

/// Build the fts index over the tenant files via a DrustMcp sharing the same
/// data dir (create_fts_index needs the service, not the HTTP router). Runs
/// BEFORE the app first describes `notes`, so the app reads it fresh.
async fn build_index(
    dir: &tempfile::TempDir,
    tenant: &str,
    coll: &str,
    name: &str,
    fields: &[String],
) {
    let data = dir.path().to_path_buf();
    let tr = Arc::new(TenantRegistry::new(data.clone(), 2));
    let _ = drust::storage::tenant_db::open_write(&data, tenant).unwrap();
    let s = McpRegistry::new(tr).get_or_create(tenant).await.unwrap();
    create_fts_index(&s, coll, name, fields, None)
        .await
        .unwrap();
}

async fn service_insert(app: &axum::Router, tid: &str, svc: &str, title: &str, owner_id: &str) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{tid}/records/notes"))
                .header(header::AUTHORIZATION, format!("Bearer {svc}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"data": {"title": title, "owner_id": owner_id}}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED, "insert {title}");
}

async fn list_fts(app: &axum::Router, tid: &str, tok: &str, query: &str) -> (StatusCode, Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{tid}/collections/notes/list"))
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"filter": {"$fts": {"index": "main", "query": query}}}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn uid_for(dir: &tempfile::TempDir, tenant: &str, email: &str) -> String {
    let pool = grab_pool(tenant, dir).await;
    let email = email.to_string();
    pool.with_reader(move |c| {
        c.query_row(
            "SELECT id FROM _system_users WHERE email = ?1",
            rusqlite::params![email],
            |r| r.get::<_, String>(0),
        )
    })
    .await
    .unwrap()
}

/// The load-bearing pin: a `$fts` MATCH subquery yields candidate rowids across
/// ALL owners, but the unchanged owner WHERE (read_scope="own") filters them, so
/// User A's `/list` returns only A's matching row — never B's.
#[tokio::test]
async fn fts_list_is_scoped_to_the_calling_owner() {
    let (app, tid, svc, _anon, dir) = spin_up_dual_role_self_register("fts-owner-scope").await;

    // Owner-scoped notes(title, body, owner_id) with read_scope=own; user_caps
    // grants read so the two User tokens can /list.
    let pool = grab_pool(&tid, &dir).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                body TEXT,
                owner_id TEXT REFERENCES _system_users(id),
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
             );
             INSERT INTO _system_collection_meta
                  (collection_name, anon_caps_json, user_caps_json, owner_field, read_scope)
                  VALUES ('notes', '[\"select\"]', '[\"select\"]', 'owner_id', 'own')
                  ON CONFLICT(collection_name) DO UPDATE SET
                    anon_caps_json = '[\"select\"]',
                    user_caps_json = '[\"select\"]',
                    owner_field = 'owner_id',
                    read_scope = 'own';",
        )
    })
    .await
    .unwrap();

    // Two users, each with a row that shares the search term "hospital".
    let user_a = register_and_login_via_app(&app, &tid, "a@x.com", "longpassword").await;
    let user_b = register_and_login_via_app(&app, &tid, "b@x.com", "longpassword").await;
    let uid_a = uid_for(&dir, &tid, "a@x.com").await;
    let uid_b = uid_for(&dir, &tid, "b@x.com").await;

    // Index built BEFORE any app request touches `notes` (app cache still cold).
    build_index(
        &dir,
        &tid,
        "notes",
        "main",
        &["title".into(), "body".into()],
    )
    .await;

    service_insert(&app, &tid, &svc, "hospital alpha", &uid_a).await;
    service_insert(&app, &tid, &svc, "hospital beta", &uid_b).await;

    // User A searches "hospital": the shadow yields BOTH rowids, the owner WHERE
    // keeps only A's row.
    let (sa, va) = list_fts(&app, &tid, &user_a, "hospital").await;
    assert_eq!(sa, StatusCode::OK, "{va:?}");
    assert_eq!(va["total"], 1, "A must see exactly their own match: {va:?}");
    assert_eq!(va["records"][0]["title"], "hospital alpha");

    // User B sees only their own row — never A's.
    let (sb, vb) = list_fts(&app, &tid, &user_b, "hospital").await;
    assert_eq!(sb, StatusCode::OK, "{vb:?}");
    assert_eq!(vb["total"], 1, "B must see exactly their own match: {vb:?}");
    assert_eq!(vb["records"][0]["title"], "hospital beta");

    // Unknown index name surfaces the stable sentinel on /list.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{tid}/collections/notes/list"))
                .header(header::AUTHORIZATION, format!("Bearer {user_a}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"filter": {"$fts": {"index": "ghost", "query": "x"}}}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["error_code"], "FTS_INDEX_NOT_FOUND", "{v:?}");
}
