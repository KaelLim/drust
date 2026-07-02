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
