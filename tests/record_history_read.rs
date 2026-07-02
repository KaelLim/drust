//! v1.46 Task 7 — service-only REST read surface over `_system_record_history`.
//!
//! `GET /t/<id>/collections/<coll>/history?record_id=&page=&per_page=` returns
//! `{rows:[{id,op,old,new,actor_kind,actor_id,ts}], page, per_page, total}`
//! for the SERVICE bearer only; anon and user bearers get
//! `403 HISTORY_READ_DENIED` (alias `WRITE_DENIED`) — same posture as `/query`
//! (history aggregates every user's row values).

mod helpers;

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use helpers::{grab_pool, spin_up_tenant_with_fn_seed};
use tower::ServiceExt;

/// Raw-SQL collection seed, same shape the canonical `create_collection`
/// produces (id PK + timestamps). No `_system_collection_meta` row → the
/// audit gate falls back to its default ON, so writes below leave history.
async fn seed_notes(tenant: &str, dir: &tempfile::TempDir) {
    let pool = grab_pool(tenant, dir).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                body TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );",
        )
    })
    .await
    .unwrap();
}

/// POST one note through the REST route; returns the new record id.
async fn insert_note(app: &Router, tenant: &str, tok: &str, body_text: &str) -> i64 {
    let r = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/t/{tenant}/records/notes"))
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(format!(
                    r#"{{"data":{{"body":"{body_text}"}}}}"#
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    let b = axum::body::to_bytes(r.into_body(), 65_536).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
    v["id"].as_i64().unwrap()
}

/// PATCH one note through the REST route.
async fn update_note(app: &Router, tenant: &str, tok: &str, id: i64, body_text: &str) {
    let r = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PATCH)
                .uri(format!("/t/{tenant}/records/notes/{id}"))
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(format!(
                    r#"{{"data":{{"body":"{body_text}"}}}}"#
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
}

/// GET the history endpoint; returns (status, parsed JSON body).
async fn get_history(app: &Router, tok: &str, uri: &str) -> (StatusCode, serde_json::Value) {
    let r = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = r.status();
    let b = axum::body::to_bytes(r.into_body(), 262_144).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap_or(serde_json::Value::Null);
    (status, v)
}

#[tokio::test]
async fn history_read_service_only() {
    let (app, service, anon, user, d) = spin_up_tenant_with_fn_seed("histread").await;
    seed_notes("histread", &d).await;

    // Seed: service inserts + updates one row → two history rows for it.
    let id = insert_note(&app, "histread", &service, "a").await;
    update_note(&app, "histread", &service, id, "b").await;

    // Service → 200 with both rows for the record, newest first (id DESC).
    let (st, body) = get_history(
        &app,
        &service,
        &format!("/t/histread/collections/notes/history?record_id={id}"),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body["total"].as_i64(), Some(2));
    assert_eq!(body["page"].as_i64(), Some(1));
    assert_eq!(
        body["per_page"].as_i64(),
        Some(50),
        "default per_page is 50"
    );
    let rows = body["rows"].as_array().expect("rows array");
    assert_eq!(rows.len(), 2);
    // Response order is id DESC (newest first); ascending by id the op
    // sequence is [insert, update].
    assert!(
        rows[0]["id"].as_i64().unwrap() > rows[1]["id"].as_i64().unwrap(),
        "rows ordered by history id DESC"
    );
    assert_eq!(rows[0]["op"], "update");
    assert_eq!(rows[1]["op"], "insert");
    // old/new come back as parsed JSON (not strings); insert has old=null.
    assert!(rows[1]["old"].is_null(), "insert pre-image is null");
    assert_eq!(rows[1]["new"]["body"], "a");
    assert_eq!(rows[0]["old"]["body"], "a");
    assert_eq!(rows[0]["new"]["body"], "b");
    assert_eq!(rows[0]["actor_kind"], "service");
    assert!(rows[0]["ts"].as_str().is_some(), "ts present");

    // Anon bearer → 403 HISTORY_READ_DENIED.
    let (st, body) = get_history(&app, &anon, "/t/histread/collections/notes/history").await;
    assert_eq!(st, StatusCode::FORBIDDEN, "anon must not read history");
    assert_eq!(body["error_code"], "HISTORY_READ_DENIED");
    assert!(
        body["error_aliases"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a == "WRITE_DENIED"),
        "legacy WRITE_DENIED alias retained"
    );

    // User bearer → 403 HISTORY_READ_DENIED.
    let (st, body) = get_history(&app, &user, "/t/histread/collections/notes/history").await;
    assert_eq!(st, StatusCode::FORBIDDEN, "user must not read history");
    assert_eq!(body["error_code"], "HISTORY_READ_DENIED");
}

#[tokio::test]
async fn history_read_paginates() {
    let (app, service, _anon, _user, d) = spin_up_tenant_with_fn_seed("histpage").await;
    seed_notes("histpage", &d).await;

    for i in 0..5 {
        insert_note(&app, "histpage", &service, &format!("n{i}")).await;
    }

    // No record_id filter → all 5 insert rows are visible.
    let (st, body) = get_history(
        &app,
        &service,
        "/t/histpage/collections/notes/history?per_page=2&page=1",
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body["total"].as_i64(), Some(5));
    assert_eq!(body["per_page"].as_i64(), Some(2));
    assert_eq!(body["page"].as_i64(), Some(1));
    let rows = body["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 2, "page 1 carries per_page rows");
    // id DESC → page 1 holds the two newest history rows.
    assert!(rows[0]["id"].as_i64().unwrap() > rows[1]["id"].as_i64().unwrap());

    // Last page holds the remainder.
    let (st, body) = get_history(
        &app,
        &service,
        "/t/histpage/collections/notes/history?per_page=2&page=3",
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body["rows"].as_array().unwrap().len(), 1);
    assert_eq!(body["page"].as_i64(), Some(3));

    // per_page caps at 200.
    let (st, body) = get_history(
        &app,
        &service,
        "/t/histpage/collections/notes/history?per_page=999",
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        body["per_page"].as_i64(),
        Some(200),
        "per_page clamps to 200"
    );

    // Defaults: page=1, per_page=50.
    let (st, body) = get_history(&app, &service, "/t/histpage/collections/notes/history").await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body["page"].as_i64(), Some(1));
    assert_eq!(body["per_page"].as_i64(), Some(50));
    assert_eq!(body["rows"].as_array().unwrap().len(), 5);
}

// ---------------------------------------------------------------------------
// Task 8 — MCP tools (`get_record_history` + `set_audit_enabled`) and the
// service-only REST config route `PUT .../audit`.
// ---------------------------------------------------------------------------

/// DrustMcp harness, same shape as `tests/mcp_write_schema.rs::svc` — the MCP
/// endpoint is service-only by dispatch, so the tool fns are exercised
/// directly (no bearer layering to re-prove here).
async fn mcp_svc(tenant: &str) -> (drust::mcp::server::DrustMcp, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let tr = std::sync::Arc::new(drust::storage::pool::TenantRegistry::new(data.clone(), 2));
    let _ = drust::storage::tenant_db::open_write(&data, tenant).unwrap();
    let reg = drust::mcp::server::McpRegistry::new(tr);
    (reg.get_or_create(tenant).await.unwrap(), dir)
}

fn body_field() -> drust::mcp::tools::schema::FieldSpec {
    drust::mcp::tools::schema::FieldSpec {
        name: "body".into(),
        sql_type: "text".into(),
        nullable: false,
        ..Default::default()
    }
}

#[tokio::test]
async fn mcp_get_record_history_returns_rows() {
    let (s, _d) = mcp_svc("mcphist").await;
    drust::mcp::tools::schema::create_collection(&s, "notes", &[body_field()])
        .await
        .unwrap();
    let ins = drust::mcp::tools::write::insert_record(&s, "notes", serde_json::json!({"body":"x"}))
        .await
        .unwrap();
    let id = ins["id"].as_i64().expect("insert returns id");
    drust::mcp::tools::write::update_record(&s, "notes", id, serde_json::json!({"body":"y"}))
        .await
        .unwrap();

    let v = drust::mcp::tools::audit::get_record_history(&s, "notes", Some(id), None)
        .await
        .unwrap();
    assert_eq!(v["total"].as_i64(), Some(2));
    let rows = v["rows"].as_array().expect("rows array");
    assert_eq!(rows.len(), 2);
    // Same row shape + ordering as the REST endpoint: id DESC (newest first).
    assert_eq!(rows[0]["op"], "update");
    assert_eq!(rows[1]["op"], "insert");
    assert_eq!(rows[0]["actor_kind"], "service");
    assert!(rows[1]["old"].is_null(), "insert pre-image is null");
    assert_eq!(rows[1]["new"]["body"], "x");
    assert_eq!(rows[0]["old"]["body"], "x");
    assert_eq!(rows[0]["new"]["body"], "y");
    assert!(rows[0]["ts"].as_str().is_some(), "ts present");

    // `limit` truncates rows but not `total`; caps at 200 like REST per_page.
    let v = drust::mcp::tools::audit::get_record_history(&s, "notes", None, Some(1))
        .await
        .unwrap();
    assert_eq!(v["rows"].as_array().unwrap().len(), 1);
    assert_eq!(v["total"].as_i64(), Some(2), "total unaffected by limit");
    let v = drust::mcp::tools::audit::get_record_history(&s, "notes", None, Some(999))
        .await
        .unwrap();
    assert_eq!(v["limit"].as_i64(), Some(200), "limit clamps to 200");
}

#[tokio::test]
async fn mcp_set_audit_enabled_round_trip() {
    let (s, _d) = mcp_svc("mcpaudit").await;
    drust::mcp::tools::schema::create_collection(&s, "notes", &[body_field()])
        .await
        .unwrap();

    // Off → describe_collection reflects it → a write leaves no history.
    let v = drust::mcp::tools::audit::set_audit_enabled(&s, "notes", false)
        .await
        .unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["collection"], "notes");
    assert_eq!(v["audit_enabled"], false);
    let schema = s
        .inner()
        .pool
        .with_reader(|c| drust::storage::schema::describe_collection(c, "notes"))
        .await
        .unwrap()
        .unwrap();
    assert!(!schema.audit_enabled, "gate persisted off");
    drust::mcp::tools::write::insert_record(&s, "notes", serde_json::json!({"body":"quiet"}))
        .await
        .unwrap();
    let n: i64 = s
        .inner()
        .pool
        .with_reader(|c| {
            c.query_row("SELECT COUNT(*) FROM _system_record_history", [], |r| {
                r.get(0)
            })
        })
        .await
        .unwrap();
    assert_eq!(n, 0, "audit off → no history rows");

    // Back on → capture resumes.
    drust::mcp::tools::audit::set_audit_enabled(&s, "notes", true)
        .await
        .unwrap();
    drust::mcp::tools::write::insert_record(&s, "notes", serde_json::json!({"body":"loud"}))
        .await
        .unwrap();
    let n: i64 = s
        .inner()
        .pool
        .with_reader(|c| {
            c.query_row("SELECT COUNT(*) FROM _system_record_history", [], |r| {
                r.get(0)
            })
        })
        .await
        .unwrap();
    assert_eq!(n, 1, "audit back on → capture resumes");

    // Unknown collection → typed failure (existence folded in the writer).
    let err = drust::mcp::tools::audit::set_audit_enabled(&s, "ghost", false)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("unknown collection"), "{err}");

    // `_system_*` refused.
    let err = drust::mcp::tools::audit::set_audit_enabled(&s, "_system_users", false)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("protected"), "{err}");
}

/// PUT the audit config route; returns (status, parsed JSON body).
async fn put_audit(
    app: &Router,
    tenant: &str,
    tok: &str,
    coll: &str,
    body: &str,
) -> (StatusCode, serde_json::Value) {
    let r = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(format!("/t/{tenant}/collections/{coll}/audit"))
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = r.status();
    let b = axum::body::to_bytes(r.into_body(), 65_536).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap_or(serde_json::Value::Null);
    (status, v)
}

#[tokio::test]
async fn rest_put_audit_service_only_toggles_capture() {
    let (app, service, anon, user, d) = spin_up_tenant_with_fn_seed("histcfg").await;
    seed_notes("histcfg", &d).await;

    // Non-service bearers → 403 (config surface is service-only).
    let (st, body) = put_audit(&app, "histcfg", &anon, "notes", r#"{"enabled":false}"#).await;
    assert_eq!(st, StatusCode::FORBIDDEN, "anon cannot toggle audit");
    assert_eq!(body["error_code"], "WRITE_DENIED");
    let (st, _) = put_audit(&app, "histcfg", &user, "notes", r#"{"enabled":false}"#).await;
    assert_eq!(st, StatusCode::FORBIDDEN, "user cannot toggle audit");

    // Service toggles off → 200; a REST write then leaves no history.
    let (st, body) = put_audit(&app, "histcfg", &service, "notes", r#"{"enabled":false}"#).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body["ok"], true);
    assert_eq!(body["audit_enabled"], false);
    let id = insert_note(&app, "histcfg", &service, "quiet").await;
    let (st, body) = get_history(
        &app,
        &service,
        &format!("/t/histcfg/collections/notes/history?record_id={id}"),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        body["total"].as_i64(),
        Some(0),
        "gate off → REST write not captured"
    );

    // Toggle back on → capture resumes (schema cache invalidated).
    let (st, _) = put_audit(&app, "histcfg", &service, "notes", r#"{"enabled":true}"#).await;
    assert_eq!(st, StatusCode::OK);
    let id2 = insert_note(&app, "histcfg", &service, "loud").await;
    let (_, body) = get_history(
        &app,
        &service,
        &format!("/t/histcfg/collections/notes/history?record_id={id2}"),
    )
    .await;
    assert_eq!(body["total"].as_i64(), Some(1), "gate on → capture resumes");

    // `_system_*` refused; unknown collection → 404.
    let (st, body) = put_audit(
        &app,
        "histcfg",
        &service,
        "_system_users",
        r#"{"enabled":false}"#,
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_eq!(body["error_code"], "PROTECTED_COLLECTION");
    let (st, body) = put_audit(&app, "histcfg", &service, "ghost", r#"{"enabled":false}"#).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    assert_eq!(body["error_code"], "COLLECTION_NOT_FOUND");
}
