//! #950-B T7 — the `_files` admin page's Files-RLS surface: the folder-rule
//! card (list / register / clear), the `path` column, and the fake folder tree.
//!
//! Why an integration test for a UI task: the card is not decoration. It is the
//! only face of `_system_file_policy` an operator holding an admin session can
//! reach — the REST and MCP faces both demand a service BEARER, which the admin
//! plane does not have (same reason `admin_update_policies` exists next to the
//! data-plane `PUT …/policies`). So the two write endpoints are real
//! authorization surface, and they are pinned here:
//!
//! * they live INSIDE the protected admin router (no session ⇒ no write), and
//! * they share T3's validation core, so the four registry error codes reach
//!   the browser unchanged rather than being re-invented in the admin plane.
//!
//! The page assertions are deliberately keyed on `data-policy-prefix` /
//! `data-folder-prefix` attributes rather than on visible copy: copy is
//! i18n-owned and changes, while those hooks are what the page's own JS binds
//! to.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::auth::session::create_session;
use drust::mgmt::routes::MgmtState;
use drust::storage::meta::{bootstrap_admin, open_meta};
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::Mutex;
use tower::ServiceExt;

// ─── harness (mirrors tests/admin_relocated_pages_smoke.rs) ──────────────────

async fn app() -> (axum::Router, String, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let mut conn = open_meta(&data_dir.join("meta.sqlite")).unwrap();
    bootstrap_admin(&mut conn, "root", "pw").unwrap();
    drust::db::migrations::run_migrations(&conn, &data_dir).unwrap();
    let tok = create_session(&mut conn, 1, 3600).unwrap();
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
    state.log_dir = data_dir.join("audit");
    // The file table (and therefore the folder tree) only renders when object
    // storage is configured — an in-memory store is enough, nothing here puts
    // or gets bytes.
    state.garage = Some(Arc::new(drust::storage::garage::GarageClient::from_store(
        Arc::new(object_store::memory::InMemory::new()),
        "public",
    )));
    state.disk_min_free_pct = 0;
    (state.with_data_dir(data_dir.clone()), tok, dir)
}

async fn create_tenant(app: &axum::Router, tok: &str, id: &str) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/api/tenants")
                .header(header::COOKIE, format!("drust_session={tok}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(format!(r#"{{"id":"{id}","name":"Files"}}"#)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED, "tenant create failed");
}

async fn page(app: &axum::Router, tok: &str, id: &str) -> (StatusCode, String) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/admin/tenants/{id}/_files"))
                .header(header::COOKIE, format!("drust_session={tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 4_194_304)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

async fn post_json(
    app: &axum::Router,
    tok: Option<&str>,
    uri: String,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let mut b = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(tok) = tok {
        b = b.header(header::COOKIE, format!("drust_session={tok}"));
    }
    let resp = app
        .clone()
        .oneshot(b.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1_048_576)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

/// Insert a `_system_files` row straight into the tenant DB. The upload path is
/// covered by `files_rls_upload.rs`; here the row is just fixture data for the
/// tree renderer.
fn insert_file(data_dir: &std::path::Path, tenant: &str, key: &str, path: Option<&str>) {
    let conn = drust::storage::tenant_db::open_write(data_dir, tenant).unwrap();
    conn.execute(
        "INSERT INTO \"_system_files\" \
           (key, original_name, content_type, size_bytes, visibility, uploader, path) \
         VALUES (?1, ?2, 'text/plain', 12, 'private', 'service', ?3)",
        rusqlite::params![key, key, path],
    )
    .unwrap();
}

// ─── the folder-rule card ────────────────────────────────────────────────────

/// A tenant born after v1.63 carries the seeded root rule, and the card renders
/// it. The root prefix is the EMPTY string, which is exactly the value most
/// likely to be dropped by a template that treats "no prefix" as "no rule".
#[tokio::test]
async fn policy_card_lists_the_seeded_root_rule() {
    let (app, tok, _d) = app().await;
    create_tenant(&app, &tok, "fp1").await;
    let (status, body) = page(&app, &tok, "fp1").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#"data-policy-prefix="""#),
        "the folder-rule card must render the seeded root policy row"
    );
}

/// Register → the page shows it; clear → it is gone; clear again → the shared
/// `FILE_POLICY_NOT_FOUND` (never a silent success).
#[tokio::test]
async fn register_then_clear_a_prefix_rule() {
    let (app, tok, _d) = app().await;
    create_tenant(&app, &tok, "fp2").await;

    let (status, json) = post_json(
        &app,
        Some(&tok),
        "/admin/tenants/fp2/_files/policies".into(),
        serde_json::json!({"prefix": "avatars/", "owner_scoped": true}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "register failed: {json}");

    let (_, body) = page(&app, &tok, "fp2").await;
    assert!(
        body.contains(r#"data-policy-prefix="avatars/""#),
        "the registered prefix must appear in the card"
    );

    let (status, _) = post_json(
        &app,
        Some(&tok),
        "/admin/tenants/fp2/_files/policies/clear".into(),
        serde_json::json!({"prefix": "avatars/"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "clear failed");

    let (_, body) = page(&app, &tok, "fp2").await;
    assert!(
        !body.contains(r#"data-policy-prefix="avatars/""#),
        "the cleared prefix must be gone from the card"
    );

    let (status, json) = post_json(
        &app,
        Some(&tok),
        "/admin/tenants/fp2/_files/policies/clear".into(),
        serde_json::json!({"prefix": "avatars/"}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(json["error_code"], "FILE_POLICY_NOT_FOUND");
}

/// v1.64 (#974) — the publish grant is admin-editable, and the card SHOWS it.
///
/// An operator who cannot see which prefixes may publish has no way to answer
/// "why did this upload get refused / why is this file public", and the card is
/// the only face an admin session can reach.
#[tokio::test]
async fn the_publish_grant_round_trips_through_the_card() {
    let (app, tok, _d) = app().await;
    create_tenant(&app, &tok, "fp5").await;

    let (status, json) = post_json(
        &app,
        Some(&tok),
        "/admin/tenants/fp5/_files/policies".into(),
        serde_json::json!({
            "prefix": "avatars/",
            "owner_scoped": true,
            "public_upload_roles": ["user", "anon"]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "register failed: {json}");

    let (_, body) = page(&app, &tok, "fp5").await;
    assert!(
        body.contains(r#"data-policy-grant="anon, user""#),
        "the card must render the grant, canonicalized: it is the only place an \
         admin session can see who may publish"
    );

    // Re-register WITHOUT the field (what the card's own form sends when neither
    // box is ticked) — the grant is revoked and the pill disappears.
    let (status, _) = post_json(
        &app,
        Some(&tok),
        "/admin/tenants/fp5/_files/policies".into(),
        serde_json::json!({"prefix": "avatars/", "owner_scoped": true}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, body) = page(&app, &tok, "fp5").await;
    assert!(
        body.contains(r#"data-policy-prefix="avatars/""#),
        "the rule itself survives"
    );
    assert!(
        !body.contains("data-policy-grant"),
        "…but no prefix shows a grant pill once the grant is revoked"
    );

    // The admin face shares the one validator, so an illegal role is the same
    // refusal here as over REST and MCP.
    let (status, json) = post_json(
        &app,
        Some(&tok),
        "/admin/tenants/fp5/_files/policies".into(),
        serde_json::json!({"prefix": "avatars/", "owner_scoped": true,
                           "public_upload_roles": ["service"]}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["error_code"], "FILE_POLICY_INVALID");
}

/// The admin face reuses T3's `validate_file_policy` — it does not re-implement
/// it. Both refusals therefore arrive with the registry's own codes.
#[tokio::test]
async fn register_refuses_bad_prefix_and_the_clause_less_shape() {
    let (app, tok, _d) = app().await;
    create_tenant(&app, &tok, "fp3").await;

    let (status, json) = post_json(
        &app,
        Some(&tok),
        "/admin/tenants/fp3/_files/policies".into(),
        serde_json::json!({"prefix": "avatars", "owner_scoped": true}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["error_code"], "FILE_POLICY_PREFIX_INVALID");

    let (status, json) = post_json(
        &app,
        Some(&tok),
        "/admin/tenants/fp3/_files/policies".into(),
        serde_json::json!({"prefix": "open/"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["error_code"], "FILE_POLICY_OPEN_REQUIRES_FLAG");
}

/// Both write endpoints sit inside the protected admin router. Without a
/// session cookie the request must never reach the registry.
#[tokio::test]
async fn policy_endpoints_require_an_admin_session() {
    let (app, tok, _d) = app().await;
    create_tenant(&app, &tok, "fp4").await;
    for uri in [
        "/admin/tenants/fp4/_files/policies",
        "/admin/tenants/fp4/_files/policies/clear",
    ] {
        let (status, _) = post_json(
            &app,
            None,
            uri.into(),
            serde_json::json!({"prefix": "x/", "owner_scoped": true}),
        )
        .await;
        assert!(
            status != StatusCode::OK,
            "{uri} answered 200 with no admin session"
        );
    }
}

// ─── path column + fake folder tree ──────────────────────────────────────────

/// The tree is pure rendering over the `path` column: rows group by everything
/// up to the last `/`, unfiled rows (path IS NULL) group on their own, and a
/// row whose path carries no `/` lands in the tenant root group. No folder
/// exists anywhere in the backend.
#[tokio::test]
async fn path_column_groups_rows_into_folders() {
    let (app, tok, d) = app().await;
    create_tenant(&app, &tok, "fp5").await;
    let data_dir = d.path();
    insert_file(data_dir, "fp5", "a.txt", Some("avatars/alice/me.png"));
    insert_file(data_dir, "fp5", "b.txt", Some("avatars/bob/me.png"));
    insert_file(data_dir, "fp5", "c.txt", Some("top.png"));
    insert_file(data_dir, "fp5", "d.txt", None);

    let (status, body) = page(&app, &tok, "fp5").await;
    assert_eq!(status, StatusCode::OK);
    for folder in ["avatars/alice/", "avatars/bob/"] {
        assert!(
            body.contains(&format!(r#"data-folder-prefix="{folder}""#)),
            "missing folder group {folder}"
        );
    }
    assert!(
        body.contains(r#"data-folder-prefix="""#),
        "a path with no slash belongs to the tenant root group"
    );
    assert!(
        body.contains(r#"data-folder-unfiled="1""#),
        "rows with no declared path need their own group"
    );
    assert!(
        body.contains("avatars/alice/me.png"),
        "the path column must show the full declared path"
    );
}
