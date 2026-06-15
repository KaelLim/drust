//! Verify the v1.28 admin _list endpoint can read _system_* tables
//! (authorizer bypass for admin path) and that password_hash is masked.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::mgmt::routes::MgmtState;
use drust::storage::meta::{bootstrap_admin, open_meta};
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::Mutex;
use tower::ServiceExt;

const ADMIN: &str = "root";
const PWD: &str = "hunter2";
const TENANT: &str = "acme";

async fn app_with_tenant() -> (axum::Router, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let mut conn = open_meta(&data_dir.join("meta.sqlite")).unwrap();
    bootstrap_admin(&mut conn, ADMIN, PWD).unwrap();
    conn.execute(
        "INSERT INTO tenants (id, name) VALUES (?1, ?2)",
        rusqlite::params![TENANT, "Acme"],
    )
    .unwrap();
    // Open tenant DB so the tenant directory + SCHEMA_SQL tables get created.
    let _ = drust::storage::tenant_db::open_write(&data_dir, TENANT).unwrap();
    // run_migrations creates _system_users, _system_sessions, etc.
    drust::db::migrations::run_migrations(&conn, &data_dir).unwrap();

    let tenants = Arc::new(drust::storage::pool::TenantRegistry::new(
        data_dir.clone(),
        2,
    ));
    let bus = drust::tenant::events::EventBus::new();
    let mcp = Arc::new(drust::mcp::http_registry::McpHttpRegistry::new(Arc::new(
        drust::mcp::server::McpRegistry::new(tenants.clone()),
    )));
    let mut state = MgmtState::test_default(
        Arc::new(Mutex::new(conn)),
        data_dir.clone(),
        tenants,
        mcp,
        bus,
        drust::tenant::rooms::RoomBus::new(),
    );
    state.log_dir = std::env::temp_dir();
    let router = state.with_data_dir(data_dir);
    (router, dir)
}

async fn login(app: &axum::Router) -> String {
    let form = format!("username={ADMIN}&password={PWD}");
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    let sc = resp
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap();
    sc.split(';').next().unwrap().to_string()
}

async fn body_json(resp: axum::http::Response<Body>) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 4_000_000)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap_or_else(
        |_| serde_json::json!({ "_raw": String::from_utf8_lossy(&bytes).to_string() }),
    )
}

async fn post_list(
    app: &axum::Router,
    cookie: &str,
    coll: &str,
    body: serde_json::Value,
) -> axum::http::Response<Body> {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/admin/tenants/{TENANT}/collections/{coll}/_list"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, cookie)
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn admin_list_can_read_system_users() {
    let (app, _dir) = app_with_tenant().await;
    let cookie = login(&app).await;
    let resp = post_list(
        &app,
        &cookie,
        "_system_users",
        serde_json::json!({"filters": [], "page": 1, "per_page": 10}),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "admin path must bypass authorizer for _system_*; body: {:?}",
        body_json(resp).await
    );
}

#[tokio::test]
async fn password_hash_is_masked() {
    let (app, dir) = app_with_tenant().await;

    // Insert a user directly into the tenant DB to keep this test self-contained.
    let data_dir = dir.path();
    let writer = drust::storage::tenant_db::open_write(data_dir, TENANT).unwrap();
    writer
        .execute(
            "INSERT INTO _system_users \
             (id, email, password_hash, verified, created_at, updated_at) \
             VALUES (?1, ?2, ?3, 0, datetime('now'), datetime('now'))",
            rusqlite::params!["u-1", "alice@example.com", "$argon2id$totally-fake-hash"],
        )
        .unwrap();
    drop(writer);

    let cookie = login(&app).await;
    let resp = post_list(
        &app,
        &cookie,
        "_system_users",
        serde_json::json!({"filters": [], "page": 1, "per_page": 10}),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let j = body_json(resp).await;
    let cols = j["columns"].as_array().unwrap();
    let pw_idx = cols
        .iter()
        .position(|c| c == "password_hash")
        .expect("password_hash must appear in columns");
    let rows = j["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 1, "expected exactly one user row");
    let masked = rows[0][pw_idx].as_str().unwrap();
    assert_eq!(
        masked, "\u{25cf}\u{25cf}\u{25cf}\u{25cf}",
        "password_hash must be masked with 4 bullet characters"
    );
}

/// Regression: a `_list` whose query errors INSIDE the read closure (after the
/// read-only authorizer is attached) must still detach the authorizer before
/// returning, so the pooled reader connection is clean for the next request.
///
/// We force the inner error deterministically with an oversized `IN (...)`
/// list: it passes `filter_triples_to_ast` + `compile` (neither bounds the
/// array length) and the sort/field validation, then fails at `c.prepare(...)`
/// inside the closure with SQLite's "too many SQL variables" — i.e. the `?`
/// early-return between `attach_readonly_authorizer` and `detach_authorizer`.
///
/// Before the fix the authorizer stayed installed on the (deterministically
/// reused, serial oneshot) reader connection, so the FOLLOWING `_list` on a
/// `_system_*` collection — which by design neither attaches nor detaches —
/// inherited the restrictive authorizer and over-denied (`Read` on a
/// `_system_*` table → Deny → SQL error → 400). After the fix the detach is
/// unconditional, so the subsequent `_system_users` list succeeds (200).
#[tokio::test]
async fn errored_list_does_not_leave_authorizer_attached_for_next_system_list() {
    let (app, dir) = app_with_tenant().await;

    // Seed a tiny user-defined collection to error against (non-protected).
    {
        let writer = drust::storage::tenant_db::open_write(dir.path(), TENANT).unwrap();
        writer
            .execute_batch(
                "CREATE TABLE notes (
                    id    INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL
                );
                INSERT INTO notes (title) VALUES ('alpha'), ('beta');",
            )
            .unwrap();
    }
    let cookie = login(&app).await;

    // 1) Force an in-closure prepare failure. SQLite's default
    //    SQLITE_MAX_VARIABLE_NUMBER is 32766; a 40_000-element IN list exceeds
    //    it. compile() builds `("title" IN (?, ?, …))` with no length guard,
    //    so the error surfaces at prepare(), AFTER the authorizer is attached.
    let huge: Vec<serde_json::Value> = (0..40_000).map(serde_json::Value::from).collect();
    let resp = post_list(
        &app,
        &cookie,
        "notes",
        serde_json::json!({
            "filters": [{"field": "title", "op": "in", "value": huge}],
            "page": 1,
            "per_page": 10
        }),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "oversized IN list must fail inside the read closure; body: {:?}",
        body_json(resp).await
    );

    // 2) A subsequent _list on a _system_* collection must still succeed —
    //    proving the authorizer was detached on the errored path. Pre-fix this
    //    over-denies (400) because the leftover read-only authorizer denies the
    //    _system_* read.
    let resp2 = post_list(
        &app,
        &cookie,
        "_system_users",
        serde_json::json!({"filters": [], "page": 1, "per_page": 10}),
    )
    .await;
    assert_eq!(
        resp2.status(),
        StatusCode::OK,
        "subsequent _system_* list must succeed (authorizer was detached on error); body: {:?}",
        body_json(resp2).await
    );
}
