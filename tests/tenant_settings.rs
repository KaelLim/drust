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

/// A legacy collection with NO `_system_collection_meta` row must still be
/// covered by apply-all: the runtime gate (`read_audit_enabled`) defaults a
/// missing row to ON, so a blanket `UPDATE _system_collection_meta` that
/// skips row-less collections would leave them silently capturing after a
/// tenant-wide disable. Apply-all must upsert (create the missing row) and
/// count the collection as updated.
#[tokio::test]
async fn apply_all_covers_meta_row_less_legacy_collections() {
    let (app, pat, tenants, dir) = app().await;
    let reg = drust::mcp::server::McpRegistry::new(tenants.clone());
    let svc = reg.get_or_create(TID).await.unwrap();
    for coll in ["c_legacy", "c_meta"] {
        drust::mcp::tools::schema::create_collection(&svc, coll, &[fld("body")])
            .await
            .unwrap();
    }
    let db_path = dir.path().join("tenants").join(TID).join("data.sqlite");
    // Simulate a pre-meta legacy collection: delete its meta row by hand.
    {
        let c = rusqlite::Connection::open(&db_path).unwrap();
        c.execute(
            "DELETE FROM _system_collection_meta WHERE collection_name = 'c_legacy'",
            [],
        )
        .unwrap();
        // Sanity: the runtime gate defaults the missing row to ON.
        assert!(
            drust::storage::schema::read_audit_enabled(&c, "c_legacy").unwrap(),
            "missing meta row must default the capture gate to ON"
        );
    }
    assert_eq!(
        audit_flags(&dir),
        vec![("c_meta".into(), 1)],
        "precondition: c_legacy has no meta row"
    );

    // Tenant-wide disable: flip the default off, then push it to all.
    let (status, body) = send_json(
        &app,
        "PATCH",
        format!("/admin/tenants/{TID}"),
        &pat,
        Some(json!({"audit_default": false})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "PATCH must 200; body: {body}");
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
        "updated count must include the row-less legacy collection; body: {body}"
    );
    assert_eq!(
        audit_flags(&dir),
        vec![("c_legacy".into(), 0), ("c_meta".into(), 0)],
        "apply-all must CREATE the missing meta row with audit_enabled=0"
    );
    // The runtime gate now reads OFF for the legacy collection.
    let c = rusqlite::Connection::open(&db_path).unwrap();
    assert!(
        !drust::storage::schema::read_audit_enabled(&c, "c_legacy").unwrap(),
        "capture gate must be OFF after apply-all"
    );
}

/// Fetch an admin HTML page with the PAT bearer; returns (status, body).
async fn send_page(app: &axum::Router, uri: String, pat: &str) -> (StatusCode, String) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {pat}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 8 << 20)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// Task 10: `GET /admin/tenants/{id}/_settings` renders the Settings page
/// (rename form + audit-default toggle + read-only retention display +
/// apply-to-all wired to the Task 9 bulk endpoint), and the shared sidebar
/// gains the `⚙ _settings` virtual entry on other tenant pages.
#[tokio::test]
async fn settings_page_renders_with_sidebar_entry() {
    let (app, pat, tenants, _dir) = app().await;

    let (status, html) = send_page(&app, format!("/admin/tenants/{TID}/_settings"), &pat).await;
    assert_eq!(status, StatusCode::OK, "settings page must render");
    assert!(
        html.contains(r#"id="tenant-name-input""#),
        "rename input must be present"
    );
    assert!(
        html.contains(r#"value="Old Name""#),
        "rename input must be prefilled with the current display name"
    );
    assert!(
        html.contains(&format!("/admin/tenants/{TID}/audit/apply-all")),
        "apply-to-all must target the Task 9 bulk endpoint"
    );
    assert!(
        html.contains(r#"id="audit-default-toggle""#),
        "tenant audit-default toggle must be present"
    );
    assert!(
        html.contains(r#"id="retention-days""#),
        "read-only retention-days display must be present"
    );

    // A collection page (any page including the shared sidebar) must link to
    // the new `⚙ _settings` virtual entry.
    let reg = drust::mcp::server::McpRegistry::new(tenants.clone());
    let svc = reg.get_or_create(TID).await.unwrap();
    drust::mcp::tools::schema::create_collection(&svc, "c_side", &[fld("body")])
        .await
        .unwrap();
    let (status, html) = send_page(
        &app,
        format!("/admin/tenants/{TID}/collections/c_side"),
        &pat,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "collection page must render");
    assert!(
        html.contains(&format!("/admin/tenants/{TID}/_settings")),
        "sidebar must contain the _settings entry"
    );
}

/// The settings page 404s for a missing / soft-deleted tenant instead of
/// rendering an empty shell.
#[tokio::test]
async fn settings_page_unknown_tenant_404s() {
    let (app, pat, _tenants, _dir) = app().await;
    let (status, _html) =
        send_page(&app, "/admin/tenants/no-such-tenant/_settings".into(), &pat).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ───────────────── Task 11: collection editor audit toggle + History ─────────

/// Send a form-encoded POST with the PAT bearer (the [⚙] popover toggles
/// submit `application/x-www-form-urlencoded` via fetch); returns status.
async fn send_form(app: &axum::Router, uri: String, pat: &str, body: &'static str) -> StatusCode {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {pat}"))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    resp.status()
}

/// Slice the audit form out of the page so ` checked` assertions can't
/// accidentally match the realtime / caps checkboxes elsewhere in the
/// popover.
fn audit_form_fragment(html: &str) -> &str {
    let start = html
        .find(r#"id="audit-form""#)
        .expect("[⚙] popover must contain the audit form");
    let end = html[start..].find("</form>").expect("audit form closes") + start;
    &html[start..end]
}

/// Task 11: the [⚙] settings popover carries a Record-history toggle whose
/// checkbox reflects `describe_collection().audit_enabled` and posts to the
/// admin-plane audit toggle route (the browser holds an admin session, not
/// a service bearer, so it cannot call the data-plane `PUT …/audit`).
#[tokio::test]
async fn collection_settings_popover_has_audit_toggle() {
    let (app, pat, tenants, dir) = app().await;
    let reg = drust::mcp::server::McpRegistry::new(tenants.clone());
    let svc = reg.get_or_create(TID).await.unwrap();
    drust::mcp::tools::schema::create_collection(&svc, "c_aud", &[fld("body")])
        .await
        .unwrap();

    let (status, html) = send_page(
        &app,
        format!("/admin/tenants/{TID}/collections/c_aud"),
        &pat,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "collection page must render");
    let form = audit_form_fragment(&html);
    assert!(
        form.contains(&format!("/admin/tenants/{TID}/collections/c_aud/audit")),
        "audit form must target the admin audit toggle route; got: {form}"
    );
    assert!(
        form.contains(" checked"),
        "audit checkbox must reflect audit_enabled=true (the stamped default); got: {form}"
    );

    // Unchecking the box submits an empty form (checkbox semantics: absent
    // field = off) — the flag flips in _system_collection_meta…
    let st = send_form(
        &app,
        format!("/admin/tenants/{TID}/collections/c_aud/audit"),
        &pat,
        "",
    )
    .await;
    assert_eq!(st, StatusCode::SEE_OTHER, "toggle POST redirects back");
    assert_eq!(
        audit_flags(&dir),
        vec![("c_aud".into(), 0)],
        "toggle-off must write audit_enabled=0"
    );

    // …and the re-rendered popover reflects the new describe_collection state.
    let (_, html) = send_page(
        &app,
        format!("/admin/tenants/{TID}/collections/c_aud"),
        &pat,
    )
    .await;
    let form = audit_form_fragment(&html);
    assert!(
        !form.contains(" checked"),
        "audit checkbox must reflect audit_enabled=false after toggle-off; got: {form}"
    );

    // Toggle back on round-trips.
    let st = send_form(
        &app,
        format!("/admin/tenants/{TID}/collections/c_aud/audit"),
        &pat,
        "enabled=1",
    )
    .await;
    assert_eq!(st, StatusCode::SEE_OTHER);
    assert_eq!(audit_flags(&dir), vec![("c_aud".into(), 1)]);
}

/// The admin toggle must refresh the cached CollectionSchema the write
/// choke points read (same invalidation the data-plane PUT does) and must
/// refuse `_system_*` names outright.
#[tokio::test]
async fn admin_audit_toggle_invalidates_cache_and_rejects_system() {
    let (app, pat, tenants, dir) = app().await;
    let reg = drust::mcp::server::McpRegistry::new(tenants.clone());
    let svc = reg.get_or_create(TID).await.unwrap();
    drust::mcp::tools::schema::create_collection(&svc, "c_gate", &[fld("body")])
        .await
        .unwrap();

    let pool = tenants.get_or_open(TID).unwrap();
    let cache = pool.schema_cache.clone();
    pool.with_reader(move |c| {
        cache.ensure_loaded(c, "c_gate")?;
        Ok(())
    })
    .await
    .unwrap();
    assert!(pool.schema_cache.get("c_gate").is_some(), "cache primed");

    let st = send_form(
        &app,
        format!("/admin/tenants/{TID}/collections/c_gate/audit"),
        &pat,
        "",
    )
    .await;
    assert_eq!(st, StatusCode::SEE_OTHER);
    assert_eq!(audit_flags(&dir), vec![("c_gate".into(), 0)]);
    assert!(
        pool.schema_cache.get("c_gate").is_none(),
        "toggle must invalidate the schema cache so capture re-reads the gate"
    );

    // _system_* stays un-togglable from the admin plane too (the popover
    // never renders for them; a hand-crafted POST gets a hard 403).
    let st = send_form(
        &app,
        format!("/admin/tenants/{TID}/collections/_system_users/audit"),
        &pat,
        "enabled=1",
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
}

/// Task 11: the collection editor embeds the per-record History action —
/// a row-level button + modal wired to the existing admin `_list` endpoint
/// over `_system_record_history` (the old→new diff is computed client-side
/// from old_json/new_json, never stored). Assert the embedded hooks AND
/// that the exact request shape the JS sends works server-side.
#[tokio::test]
async fn collection_page_embeds_history_viewer() {
    let (app, pat, tenants, _dir) = app().await;
    let reg = drust::mcp::server::McpRegistry::new(tenants.clone());
    let svc = reg.get_or_create(TID).await.unwrap();
    drust::mcp::tools::schema::create_collection(&svc, "c_hist", &[fld("body")])
        .await
        .unwrap();

    let (status, html) = send_page(
        &app,
        format!("/admin/tenants/{TID}/collections/c_hist"),
        &pat,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains("/collections/_system_record_history/_list"),
        "history viewer must fetch through the admin _list endpoint"
    );
    assert!(
        html.contains("row-history-btn"),
        "table rows must carry the per-record History action"
    );
    assert!(
        html.contains(r#"id="history-modal""#),
        "history timeline modal must be present"
    );

    // Server side of the viewer: capture one insert, then issue the exact
    // filter shape the JS sends and expect the captured row back.
    drust::mcp::tools::write::insert_record(&svc, "c_hist", json!({"body": "b1"}))
        .await
        .unwrap();
    let (st, body) = send_json(
        &app,
        "POST",
        format!("/admin/tenants/{TID}/collections/_system_record_history/_list"),
        &pat,
        Some(json!({
            "filters": [
                {"field": "collection", "op": "eq", "value": "c_hist"},
                {"field": "record_id", "op": "eq", "value": 1}
            ],
            "sort": {"field": "id", "dir": "desc"},
            "page": 1,
            "per_page": 200
        })),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::OK,
        "viewer _list request must succeed; body: {body}"
    );
    assert_eq!(body["total"], 1, "one captured insert; body: {body}");
    let cols: Vec<String> = body["columns"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    let op_idx = cols.iter().position(|c| c == "op").unwrap();
    let new_idx = cols.iter().position(|c| c == "new_json").unwrap();
    let row = body["rows"][0].as_array().unwrap();
    assert_eq!(row[op_idx], "insert");
    let new_obj: serde_json::Value = serde_json::from_str(row[new_idx].as_str().unwrap()).unwrap();
    assert_eq!(new_obj["body"], "b1", "new_json carries the inserted row");
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
