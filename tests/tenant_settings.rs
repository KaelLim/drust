//! Task 9 (v1.46) — tenant Settings backend on the full mgmt router:
//! `PATCH /admin/tenants/{id}` (display-name rename + `audit_default` flip,
//! one-sided merge) and `POST /admin/tenants/{id}/audit/apply-all` (push the
//! tenant default onto every existing collection's `audit_enabled`).
//!
//! Harness mirrors `tests/admin_pat_admin_plane.rs`: real `MgmtState` router
//! (so `admin_session_layer` cookie-or-PAT gating is exercised end to end)
//! authenticated with a known admin PAT bearer.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::auth::admin_token;
use drust::mgmt::routes::MgmtState;
use drust::storage::meta::{bootstrap_admin, open_meta};
use drust::storage::pool::TenantRegistry;
use rusqlite::params;
use serde_json::json;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::Mutex;
use tower::ServiceExt;

const TID: &str = "tenant-settings-0001";

/// Full mgmt router + one tenant (name "Old Name") + a known active admin
/// PAT. Returns `(router, pat, tenants_registry, tempdir)` — the registry is
/// the SAME Arc the router's handlers use, so tests can create collections
/// and observe the shared per-tenant schema cache.
async fn app() -> (axum::Router, String, Arc<TenantRegistry>, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let mut conn = open_meta(&data_dir.join("meta.sqlite")).unwrap();
    bootstrap_admin(&mut conn, "root", "pw").unwrap();
    conn.execute(
        "INSERT INTO tenants (id, name) VALUES (?1, 'Old Name')",
        params![TID],
    )
    .unwrap();
    let _ = drust::storage::tenant_db::open_write(&data_dir, TID).unwrap();
    // Production boot sequence: run_migrations adds `tenants.audit_default`
    // (meta) + `_system_collection_meta.audit_enabled` (tenant db).
    drust::db::migrations::run_migrations(&conn, &data_dir).unwrap();
    conn.execute(
        "UPDATE _admin_tokens SET revoked_at = datetime('now') \
         WHERE admin_id = 1 AND revoked_at IS NULL",
        [],
    )
    .unwrap();
    let pat = admin_token::generate_token();
    conn.execute(
        "INSERT INTO _admin_tokens (admin_id, token_hash) VALUES (1, ?1)",
        params![admin_token::hash_token(&pat)],
    )
    .unwrap();

    let tenants = Arc::new(TenantRegistry::new(data_dir.clone(), 2));
    let bus = drust::tenant::events::EventBus::new();
    let mcp = Arc::new(drust::mcp::http_registry::McpHttpRegistry::new(Arc::new(
        drust::mcp::server::McpRegistry::new(tenants.clone()),
    )));
    let state = MgmtState::test_default(
        Arc::new(Mutex::new(conn)),
        data_dir.clone(),
        tenants.clone(),
        mcp,
        bus,
        drust::tenant::rooms::RoomBus::new(),
    );
    let router = state.with_data_dir(data_dir);
    (router, pat, tenants, dir)
}

/// Send a JSON request with the PAT bearer; returns (status, parsed body).
async fn send_json(
    app: &axum::Router,
    method: &str,
    uri: String,
    pat: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {pat}"))
        .header(header::ACCEPT, "application/json");
    let body = match body {
        Some(v) => {
            b = b.header(header::CONTENT_TYPE, "application/json");
            Body::from(v.to_string())
        }
        None => Body::empty(),
    };
    let resp = app.clone().oneshot(b.body(body).unwrap()).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let v = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, v)
}

fn meta_conn(dir: &tempfile::TempDir) -> rusqlite::Connection {
    rusqlite::Connection::open(dir.path().join("meta.sqlite")).unwrap()
}

fn tenant_name(dir: &tempfile::TempDir) -> String {
    meta_conn(dir)
        .query_row(
            "SELECT name FROM tenants WHERE id = ?1",
            params![TID],
            |r| r.get(0),
        )
        .unwrap()
}

/// `(collection_name, audit_enabled)` rows off the tenant db, name-ordered.
fn audit_flags(dir: &tempfile::TempDir) -> Vec<(String, i64)> {
    let c = rusqlite::Connection::open(dir.path().join("tenants").join(TID).join("data.sqlite"))
        .unwrap();
    let mut stmt = c
        .prepare(
            "SELECT collection_name, audit_enabled FROM _system_collection_meta \
             ORDER BY collection_name",
        )
        .unwrap();
    stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

fn fld(name: &str) -> drust::mcp::tools::schema::FieldSpec {
    drust::mcp::tools::schema::FieldSpec {
        name: name.into(),
        sql_type: "text".into(),
        nullable: false,
        unique: false,
        default_value: None,
        foreign_key: None,
        dim: None,
        description: None,
        ..Default::default()
    }
}

#[tokio::test]
async fn rename_updates_display_name() {
    let (app, pat, _tenants, dir) = app().await;
    let (status, body) = send_json(
        &app,
        "PATCH",
        format!("/admin/tenants/{TID}"),
        &pat,
        Some(json!({"name": "New Name"})),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "PATCH rename must 200; body: {body}"
    );
    assert_eq!(body["name"], "New Name", "response echoes the new name");
    assert_eq!(tenant_name(&dir), "New Name", "meta row must be renamed");
}

#[tokio::test]
async fn rename_rejects_empty_and_nul() {
    let (app, pat, _tenants, dir) = app().await;
    let cases: Vec<(serde_json::Value, &str)> = vec![
        (json!({"name": "  "}), "whitespace-only (empty after trim)"),
        (json!({"name": "a\u{0}b"}), "embedded NUL"),
        (json!({"name": "a\nb"}), "control character"),
        (json!({"name": "x".repeat(201)}), "over 200 bytes"),
    ];
    for (bad, why) in cases {
        let (status, body) = send_json(
            &app,
            "PATCH",
            format!("/admin/tenants/{TID}"),
            &pat,
            Some(bad),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{why} must 400; body: {body}"
        );
        assert_eq!(
            body["error_code"], "INVALID_NAME",
            "{why} must carry error_code INVALID_NAME; body: {body}"
        );
    }
    assert_eq!(
        tenant_name(&dir),
        "Old Name",
        "rejected renames must leave the stored name untouched"
    );
}

#[tokio::test]
async fn audit_default_flip_and_apply_all() {
    let (app, pat, tenants, dir) = app().await;

    // Two collections created while audit_default is still 1 → stamped ON.
    // Same TenantRegistry as the router, so the pool + schema cache is shared.
    let reg = drust::mcp::server::McpRegistry::new(tenants.clone());
    let svc = reg.get_or_create(TID).await.unwrap();
    for coll in ["c_one", "c_two"] {
        drust::mcp::tools::schema::create_collection(&svc, coll, &[fld("body")])
            .await
            .unwrap();
    }
    assert_eq!(
        audit_flags(&dir),
        vec![("c_one".into(), 1), ("c_two".into(), 1)],
        "new collections inherit audit_default=1"
    );

    // Flip the tenant default OFF — a one-sided merge that must NOT touch
    // collections created before the flip.
    let (status, body) = send_json(
        &app,
        "PATCH",
        format!("/admin/tenants/{TID}"),
        &pat,
        Some(json!({"audit_default": false})),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "PATCH audit_default must 200; body: {body}"
    );
    let d: i64 = meta_conn(&dir)
        .query_row(
            "SELECT audit_default FROM tenants WHERE id = ?1",
            params![TID],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(d, 0, "tenants.audit_default must be 0 after the flip");
    assert_eq!(
        tenant_name(&dir),
        "Old Name",
        "one-sided merge: absent name field stays untouched"
    );
    assert_eq!(
        audit_flags(&dir),
        vec![("c_one".into(), 1), ("c_two".into(), 1)],
        "flipping the default alone must not touch existing collections"
    );

    // Prime the shared schema cache so apply-all's invalidation is observable.
    let pool = tenants.get_or_open(TID).unwrap();
    let cache = pool.schema_cache.clone();
    pool.with_reader(move |c| {
        cache.ensure_loaded(c, "c_one")?;
        Ok(())
    })
    .await
    .unwrap();
    assert!(pool.schema_cache.get("c_one").is_some(), "cache primed");

    // Apply-all pushes the (now-off) default onto every existing collection.
    let (status, body) = send_json(
        &app,
        "POST",
        format!("/admin/tenants/{TID}/audit/apply-all"),
        &pat,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "apply-all must 200; body: {body}");
    assert_eq!(
        body["updated"], 2,
        "apply-all reports the row count; body: {body}"
    );
    assert_eq!(
        audit_flags(&dir),
        vec![("c_one".into(), 0), ("c_two".into(), 0)],
        "apply-all must set every collection's audit_enabled to the default"
    );
    assert!(
        pool.schema_cache.get("c_one").is_none(),
        "apply-all must clear the schema cache so the write path re-reads flags"
    );
}

/// Both routes live inside the `admin_session_layer`-gated router: with no
/// bearer and a JSON Accept they must 401 (never reach the handler).
#[tokio::test]
async fn settings_routes_require_admin_auth() {
    let (app, _pat, _tenants, _dir) = app().await;
    for (method, uri) in [
        ("PATCH", format!("/admin/tenants/{TID}")),
        ("POST", format!("/admin/tenants/{TID}/audit/apply-all")),
    ] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(&uri)
                    .header(header::ACCEPT, "application/json")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "{method} {uri} must be admin-gated"
        );
    }
}
