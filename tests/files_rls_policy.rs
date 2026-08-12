//! #950-B T3 — the `_system_file_policy` registry: its service-only REST face,
//! its write-time validation, and the marker-guarded root seed.
//!
//! Three things are being pinned here, and each one is a hole if it is missing:
//!
//! 1. **Config is service-only.** A policy decides who may read which files, so
//!    an end user able to write one is a privilege escalation, not a feature.
//!    Every verb answers `SERVICE_REQUIRED` to user and anon.
//! 2. **The clause-less shape cannot be created.** `owner_scoped=0` with no
//!    select clause and no `public_read` flag is "restricted but unspecified":
//!    the read path (T4/T5) DENIES it, so letting it be written by accident
//!    would silently hide a tenant's files. The flag is a stored column, which
//!    is what makes "explicitly open" a fact the schema carries rather than a
//!    convention the write face remembers.
//! 3. **The root seed is one-shot.** `run_migrations` runs on EVERY boot, so a
//!    bare `INSERT OR IGNORE` would resurrect the root policy a tenant
//!    DELIBERATELY cleared, once per restart — the v1.41.5 idempotency
//!    invariant. `tenants.file_policy_seeded` is the marker, and a tenant born
//!    after v1.63 is stamped as already-seeded at create time.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::auth::bearer::{generate_token, hash_token};
use drust::storage::meta::open_meta;
use drust::storage::pool::TenantRegistry;
use drust::tenant::events::EventBus;
use drust::tenant::rooms::{RoomBus, RoomsConfig};
use drust::tenant::router::TenantAuthState;
use drust::tenant::{TenantStack, WebhookDispatcher, build_tenant_router};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::Mutex;
use tower::ServiceExt;

// ─── harness ─────────────────────────────────────────────────────────────────

struct Stack {
    app: axum::Router,
    service: String,
    anon: String,
    dir: tempfile::TempDir,
}

/// Production `build_tenant_router` over a real meta + tenant db. Storage is
/// deliberately unconfigured — the registry is a CONFIG surface on the core
/// router, reachable with no Garage at all.
async fn stack(tenant: &str) -> Stack {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let conn = open_meta(&data.join("meta.sqlite")).unwrap();
    conn.execute(
        "INSERT INTO tenants (id, name) VALUES (?1, 'x')",
        rusqlite::params![tenant],
    )
    .unwrap();
    let service = generate_token();
    let anon = generate_token();
    conn.execute(
        "INSERT INTO tokens (tenant_id, token_hash, label, role) VALUES (?1, ?2, 'svc', 'service')",
        rusqlite::params![tenant, hash_token(&service)],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO tokens (tenant_id, token_hash, label, role) VALUES (?1, ?2, 'anon', 'anon')",
        rusqlite::params![tenant, hash_token(&anon)],
    )
    .unwrap();
    drust::storage::tenant_db::open_write(&data, tenant).unwrap();
    drust::db::migrations::run_migrations(&conn, &data).unwrap();
    // Self-registration is what gives the authz test a real `drust_user_*`
    // session; the column only exists after the migration above.
    conn.execute(
        "UPDATE tenants SET allow_self_register = 1 WHERE id = ?1",
        rusqlite::params![tenant],
    )
    .unwrap();

    let tenants = Arc::new(TenantRegistry::new(data.clone(), 2));
    let bus = EventBus::new();
    let webhooks = WebhookDispatcher::new(tenants.clone(), None);
    let meta = Arc::new(Mutex::new(conn));
    let auth_state = TenantAuthState::test_default(meta, tenants.clone());
    let mcp = Arc::new(drust::mcp::http_registry::McpHttpRegistry::new(Arc::new(
        drust::mcp::server::McpRegistry::with_bus(tenants.clone(), bus.clone()),
    )));
    let (functions, functions_exec, fn_cfg) = drust::functions::test_stack_parts(tenants.clone());
    let app = build_tenant_router(TenantStack {
        auth: auth_state,
        bus: bus.clone(),
        bus_rooms: RoomBus::new(),
        bucket: RoomsConfig::test_defaults().bucket(),
        rooms_cfg: RoomsConfig::test_defaults(),
        mcp,
        files: None,
        webhooks,
        functions,
        functions_exec,
        fn_cfg,
        cron: Arc::new(drust::cron::CronState::test_default()),
        cors_origins: Vec::new(),
    });
    Stack {
        app,
        service,
        anon,
        dir,
    }
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1_048_576)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

async fn send(
    app: &axum::Router,
    method: &str,
    uri: String,
    token: &str,
    body: Option<Value>,
) -> axum::response::Response {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"));
    let body = match body {
        Some(v) => {
            b = b.header(header::CONTENT_TYPE, "application/json");
            Body::from(v.to_string())
        }
        None => Body::empty(),
    };
    app.clone().oneshot(b.body(body).unwrap()).await.unwrap()
}

async fn put_policy(
    app: &axum::Router,
    tid: &str,
    token: &str,
    body: Value,
) -> (StatusCode, Value) {
    let resp = send(
        app,
        "PUT",
        format!("/t/{tid}/file-policies"),
        token,
        Some(body),
    )
    .await;
    let status = resp.status();
    (status, body_json(resp).await)
}

async fn list_policies(app: &axum::Router, tid: &str, token: &str) -> (StatusCode, Value) {
    let resp = send(app, "GET", format!("/t/{tid}/file-policies"), token, None).await;
    let status = resp.status();
    (status, body_json(resp).await)
}

async fn clear_policy(
    app: &axum::Router,
    tid: &str,
    token: &str,
    prefix: &str,
) -> (StatusCode, Value) {
    let encoded: String = prefix
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            other => format!("%{other:02X}"),
        })
        .collect();
    let resp = send(
        app,
        "DELETE",
        format!("/t/{tid}/file-policies?prefix={encoded}"),
        token,
        None,
    )
    .await;
    let status = resp.status();
    (status, body_json(resp).await)
}

/// Register + log in an end user; returns the `drust_user_*` session token.
async fn user_token(app: &axum::Router, tenant: &str) -> String {
    let mut token = String::new();
    for path in ["register", "login"] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/t/{tenant}/auth/{path}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({"email": "alice@x.com", "password": "longpassword"}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        if path == "login" {
            token = body_json(resp).await["token"].as_str().unwrap().to_string();
        }
    }
    token
}

/// Every registered prefix in a tenant's db, with its two flags — read straight
/// from the table so a seed is proven by storage, not by an API echo.
fn policy_rows(data_root: &std::path::Path, tenant: &str) -> Vec<(String, i64, i64)> {
    let db = data_root.join("tenants").join(tenant).join("data.sqlite");
    let conn = rusqlite::Connection::open(db).unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT prefix, owner_scoped, public_read FROM _system_file_policy ORDER BY prefix",
        )
        .unwrap();
    let rows = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap();
    rows.collect::<rusqlite::Result<Vec<_>>>().unwrap()
}

// ─── (a) the happy path: register → list → clear → clear again ───────────────

#[tokio::test]
async fn service_registers_lists_and_clears_a_prefix_policy() {
    let tid = "fp-crud";
    let s = stack(tid).await;

    let (status, body) = put_policy(
        &s.app,
        tid,
        &s.service,
        json!({"prefix": "avatars/", "owner_scoped": true}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "registering a prefix: {body}");

    let (status, body) = list_policies(&s.app, tid, &s.service).await;
    assert_eq!(status, StatusCode::OK);
    let listed = body["policies"].as_array().expect("policies array");
    let avatars = listed
        .iter()
        .find(|p| p["prefix"] == "avatars/")
        .unwrap_or_else(|| panic!("avatars/ must be listed, got {body}"));
    assert_eq!(avatars["owner_scoped"], json!(true));
    assert_eq!(
        avatars["public_read"],
        json!(false),
        "public_read defaults to false — owner_scoped is what opens this prefix"
    );

    let (status, body) = clear_policy(&s.app, tid, &s.service, "avatars/").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "clearing a registered prefix: {body}"
    );
    assert!(
        !policy_rows(s.dir.path(), tid)
            .iter()
            .any(|(p, _, _)| p == "avatars/"),
        "the row must be gone from storage, not merely hidden"
    );

    let (status, body) = clear_policy(&s.app, tid, &s.service, "avatars/").await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "clearing an absent prefix is a 404, not a silent success"
    );
    assert_eq!(body["error_code"], "FILE_POLICY_NOT_FOUND");
}

// ─── (b) the clause-less shape needs the explicit flag ───────────────────────

#[tokio::test]
async fn an_open_prefix_must_carry_the_public_read_flag() {
    let tid = "fp-open";
    let s = stack(tid).await;

    let (status, body) = put_policy(
        &s.app,
        tid,
        &s.service,
        json!({"prefix": "open/", "owner_scoped": false}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "not owner-scoped, no select clause and no flag is the DENY-ALL shape"
    );
    assert_eq!(body["error_code"], "FILE_POLICY_OPEN_REQUIRES_FLAG");
    assert!(
        policy_rows(s.dir.path(), tid)
            .iter()
            .all(|(p, _, _)| p != "open/"),
        "a refused registration must leave nothing behind"
    );

    // The same shape WITH the flag is the legitimate "anyone with a cap" case.
    let (status, body) = put_policy(
        &s.app,
        tid,
        &s.service,
        json!({"prefix": "open/", "public_read": true}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "explicit open is allowed: {body}");

    // …and a select clause is the other way to be specific.
    let (status, body) = put_policy(
        &s.app,
        tid,
        &s.service,
        json!({"prefix": "shared/", "select": {"visibility": "private"}}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a select clause specifies it: {body}"
    );
}

// ─── (c) prefix grammar ──────────────────────────────────────────────────────

#[tokio::test]
async fn prefix_grammar_is_enforced_at_the_registry() {
    let tid = "fp-prefix";
    let s = stack(tid).await;

    for bad in ["avatars", "a/../", "/a/", "a//"] {
        let (status, body) = put_policy(
            &s.app,
            tid,
            &s.service,
            json!({"prefix": bad, "owner_scoped": true}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{bad:?} must be refused as a prefix"
        );
        assert_eq!(body["error_code"], "FILE_POLICY_PREFIX_INVALID", "{bad:?}");
    }

    // The root prefix is the EMPTY string and is perfectly legal.
    let (status, body) = put_policy(
        &s.app,
        tid,
        &s.service,
        json!({"prefix": "", "public_read": true}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "'' is the tenant root: {body}");
}

// ─── (d) the #954 class check reaches file policies ──────────────────────────

#[tokio::test]
async fn cross_class_and_unknown_field_operands_are_refused() {
    let tid = "fp-operand";
    let s = stack(tid).await;

    // size_bytes is INTEGER; $auth is always the TEXT user id. SQLite orders
    // every INTEGER before every TEXT, so this would match EVERY row in SQL
    // while the in-memory evaluator disagrees — the exact divergence #954
    // refuses at save time.
    let (status, body) = put_policy(
        &s.app,
        tid,
        &s.service,
        json!({"prefix": "x/", "select": {"size_bytes": {"$lt": {"$auth": "id"}}}}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error_code"], "FILE_POLICY_OPERAND_UNSUPPORTED");

    // `meta_json` is deliberately NOT in the synthetic file schema — a policy
    // may not reason about caller-supplied JSON.
    let (status, body) = put_policy(
        &s.app,
        tid,
        &s.service,
        json!({"prefix": "x/", "select": {"meta_json": "anything"}}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error_code"], "FILE_POLICY_OPERAND_UNSUPPORTED");

    // The delete clause goes through the same validation.
    let (status, body) = put_policy(
        &s.app,
        tid,
        &s.service,
        json!({"prefix": "x/", "owner_scoped": true,
               "delete": {"size_bytes": {"$gt": {"$auth": "id"}}}}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error_code"], "FILE_POLICY_OPERAND_UNSUPPORTED");

    // A well-typed clause over an allowed column is accepted.
    let (status, body) = put_policy(
        &s.app,
        tid,
        &s.service,
        json!({"prefix": "x/", "select": {"uploader": {"$auth": "id"}}}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "uploader is TEXT like $auth: {body}"
    );
}

// ─── (e) config is service-only on every verb ────────────────────────────────

#[tokio::test]
async fn user_and_anon_cannot_read_or_write_the_registry() {
    let tid = "fp-authz";
    let s = stack(tid).await;
    let user = user_token(&s.app, tid).await;

    for token in [&s.anon, &user] {
        let (status, body) = put_policy(
            &s.app,
            tid,
            token,
            json!({"prefix": "avatars/", "owner_scoped": true}),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "PUT must be service-only");
        assert!(
            body["error_aliases"]
                .as_array()
                .map(|a| a.contains(&json!("SERVICE_REQUIRED")))
                .unwrap_or(false),
            "expected the SERVICE_REQUIRED alias, got {body}"
        );

        let (status, _) = list_policies(&s.app, tid, token).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "LIST leaks the tenant's access map — service-only too"
        );

        let (status, _) = clear_policy(&s.app, tid, token, "avatars/").await;
        assert_eq!(status, StatusCode::FORBIDDEN, "DELETE must be service-only");
    }
}

// ─── (f) the seed: on create, and once-only on boot ──────────────────────────

/// A meta.sqlite with the migrated schema and one owner admin.
fn meta_with_owner() -> (rusqlite::Connection, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let conn = open_meta(&dir.path().join("meta.sqlite")).unwrap();
    drust::db::migrations::run_migrations(&conn, dir.path()).unwrap();
    conn.execute(
        "INSERT INTO admins (id, username, password_hash, role) VALUES (1, 'boss', 'h', 'owner')",
        [],
    )
    .unwrap();
    (conn, dir)
}

#[tokio::test]
async fn a_new_tenant_is_seeded_with_an_open_root_and_stamped_as_seeded() {
    let (mut conn, dir) = meta_with_owner();
    drust::mgmt::tenants::crud::make_tenant_inner(&mut conn, dir.path(), "born", "Born", 500, 1, 1)
        .unwrap();

    assert_eq!(
        policy_rows(dir.path(), "born"),
        vec![(String::new(), 0, 1)],
        "a fresh tenant gets exactly one row: the open root, preserving \
         today's 'a file cap is the only door' behaviour"
    );
    let marker: i64 = conn
        .query_row(
            "SELECT file_policy_seeded FROM tenants WHERE id = 'born'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        marker, 1,
        "a tenant seeded at create must be stamped, or the boot pass re-seeds it \
         after a deliberate clear"
    );
}

#[tokio::test]
async fn the_boot_seed_runs_once_and_never_resurrects_a_cleared_root() {
    let (conn, dir) = meta_with_owner();

    // An UPGRADED tenant: the row predates v1.63, so its marker is 0 and the
    // boot pass owes it a root policy.
    conn.execute("INSERT INTO tenants (id, name) VALUES ('old', 'Old')", [])
        .unwrap();
    drust::storage::tenant_db::open_write(dir.path(), "old").unwrap();
    drust::db::migrations::run_migrations(&conn, dir.path()).unwrap();
    assert_eq!(
        policy_rows(dir.path(), "old"),
        vec![(String::new(), 0, 1)],
        "the boot pass seeds an existing tenant so upgrading changes nothing"
    );

    // The tenant then opts INTO deny-by-default by clearing the root.
    rusqlite::Connection::open(dir.path().join("tenants").join("old").join("data.sqlite"))
        .unwrap()
        .execute("DELETE FROM _system_file_policy WHERE prefix = ''", [])
        .unwrap();

    // Reboot. Twice, because "runs on every boot" is the whole hazard.
    drust::db::migrations::run_migrations(&conn, dir.path()).unwrap();
    drust::db::migrations::run_migrations(&conn, dir.path()).unwrap();
    assert!(
        policy_rows(dir.path(), "old").is_empty(),
        "a deliberately cleared root must stay cleared across restarts — a bare \
         INSERT OR IGNORE with no marker resurrects it on every boot"
    );
}
