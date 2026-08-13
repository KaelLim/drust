//! #950-B T2 / #974 T2 — the four upload stations: route split, uploader
//! stamping, the publish decision, and `path` intake.
//!
//! Every station that creates a `_system_files` row has to make the same three
//! decisions, and until v1.63 two of them were wrong on the data plane:
//!
//! 1. **uploader** — Mode-A stamped the literal `"service"` on every row, so a
//!    user upload was owned by nobody. Per-file RLS defaults to owner-scoped,
//!    which makes the stamp the identity the whole feature keys on.
//! 2. **visibility** — Mode-A defaults to `public`, so before v1.63 a caller
//!    that said nothing silently published. That half is fixed and stays
//!    fixed: a non-service caller who omits the field gets `private`. What an
//!    EXPLICIT `public` from a non-service caller means went through three
//!    shapes, and the third is the one that stands (the first was tagged as
//!    v1.63.0 and reverted; the second was never tagged): v1.63.0 refused it
//!    outright
//!    (`FILE_VISIBILITY_SERVICE_ONLY` — publishing reachable only with the
//!    god-mode service key), v1.63.1 honored it always (no lever between "may
//!    upload" and "may publish"), and **v1.64 (#974) makes it a per-prefix
//!    GRANT**: `_system_file_policy.public_upload_roles` on the longest prefix
//!    rule matching the upload's declared `path` must name the caller's role,
//!    or the station answers 403 `FILE_PUBLIC_UPLOAD_DENIED`. Deny by default;
//!    an upgraded tenant is grandfathered by the boot seed on its ROOT rule,
//!    which is why the Mode-A harness below (a pre-v1.64 tenant, marker unset
//!    at `run_migrations`) starts out able to publish and the tests that pin
//!    the closed side revoke the root grant first.
//! 3. **path** — the caller-declared label a prefix policy attaches to, and —
//!    since v1.64 — the input that decides WHICH rule governs the publish.
//!
//! **The polarity trap this file exists to pin:** tus already defaults to
//! `private` (`uploads/mod.rs`'s `_ => "private"`). "Unifying" the two stations
//! on Mode-A's `public` default would be a real regression, so
//! `tus_service_default_visibility_stays_private` is a deliberate anti-unify
//! lock, and `service_mode_a_default_visibility_stays_public` pins the other
//! side: Mode-A's service default is NOT being tightened either.
//!
//! Route split: the three dual-mounted Mode-A verbs (upload / delete / stream)
//! now have an admin twin. The data-plane handler takes a REQUIRED `AuthCtx`
//! (absent ⇒ 500 `AUTH_CTX_MISSING`, fail-closed) and the admin twin takes
//! none — the admin router mounts behind an admin session and has no bearer,
//! so "extension absent ⇒ treat as service" would be fail-OPEN on a read gate.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::routing::post;
use drust::auth::bearer::{generate_token, hash_token};
use drust::mgmt::tenant_files::TenantFilesState;
use drust::storage::garage::GarageClient;
use drust::storage::meta::open_meta;
use drust::storage::pool::TenantRegistry;
use drust::tenant::events::EventBus;
use drust::tenant::rooms::{RoomBus, RoomsConfig};
use drust::tenant::router::{TenantAuthState, TenantRef, TokenRole};
use drust::tenant::{TenantStack, WebhookDispatcher, build_tenant_router};
use std::sync::Arc;
use tokio::sync::Mutex;
use tower::ServiceExt;

const BOUNDARY: &str = "drustrlsuploadboundary";

fn mem_garage() -> Arc<GarageClient> {
    Arc::new(GarageClient::from_store(
        Arc::new(object_store::memory::InMemory::new()),
        "unused",
    ))
}

/// One multipart body. `parts` is `(field, value, filename?)`; a `Some`
/// filename makes it the `file` part shape.
fn multipart_body(parts: &[(&str, &str, Option<&str>)]) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::new();
    for (name, value, filename) in parts {
        body.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
        match filename {
            Some(f) => {
                body.extend_from_slice(
                    format!(
                        "Content-Disposition: form-data; name=\"{name}\"; filename=\"{f}\"\r\n"
                    )
                    .as_bytes(),
                );
                body.extend_from_slice(b"Content-Type: application/octet-stream\r\n");
            }
            None => body.extend_from_slice(
                format!("Content-Disposition: form-data; name=\"{name}\"\r\n").as_bytes(),
            ),
        }
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(value.as_bytes());
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
    body
}

fn upload_request(
    uri: &str,
    bearer: Option<&str>,
    parts: &[(&str, &str, Option<&str>)],
) -> Request<Body> {
    let mut b = Request::builder().method("POST").uri(uri).header(
        header::CONTENT_TYPE,
        format!("multipart/form-data; boundary={BOUNDARY}"),
    );
    if let Some(t) = bearer {
        b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    b.body(Body::from(multipart_body(parts))).unwrap()
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1_048_576)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

async fn body_text(resp: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), 1_048_576)
        .await
        .unwrap();
    String::from_utf8_lossy(&bytes).to_string()
}

/// `(visibility, uploader, path)` straight out of the tenant db — the row is
/// the deliverable, not the HTTP status.
fn file_row(dir: &tempfile::TempDir, tenant: &str, key: &str) -> (String, String, Option<String>) {
    let db = dir.path().join("tenants").join(tenant).join("data.sqlite");
    let conn = rusqlite::Connection::open(db).unwrap();
    conn.query_row(
        "SELECT visibility, uploader, path FROM _system_files WHERE key = ?1",
        rusqlite::params![key],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )
    .unwrap()
}

// ─── Section 1: Mode-A through the PRODUCTION tenant router ───────────────────

/// The Mode-A harness: a production `build_tenant_router` plus every handle a
/// publish-grant test needs (the Garage client, so "which bucket did the bytes
/// land in" is checkable, and an anon bearer, so the per-ROLE half of the grant
/// is reachable).
struct ModeA {
    app: axum::Router,
    svc: String,
    anon: String,
    dir: tempfile::TempDir,
    garage: Arc<GarageClient>,
}

/// Production `build_tenant_router` with the files plane mounted, a service
/// token, an anon token, self-registration on, and
/// `file_user_caps = file_anon_caps = [upload,read,list]` so both a real
/// `drust_user_*` session and the anon bearer reach the upload handler.
///
/// The tenant row is INSERTed before `run_migrations`, so this is a **pre-v1.64
/// tenant** as far as the boot path is concerned: it gets the grandfather
/// publish grant on its root rule, exactly like a real upgraded tenant. That is
/// deliberate — it makes "an upgrade is a non-event" the harness default and
/// forces every deny-side test to revoke the grant explicitly, which is also
/// the shape a real tenant tightens itself with.
async fn mode_a_stack(tenant: &str) -> ModeA {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let conn = open_meta(&data.join("meta.sqlite")).unwrap();
    conn.execute(
        "INSERT INTO tenants (id, name) VALUES (?1, 'x')",
        rusqlite::params![tenant],
    )
    .unwrap();
    let svc = generate_token();
    conn.execute(
        "INSERT INTO tokens (tenant_id, token_hash, label, role) VALUES (?1, ?2, 'svc', 'service')",
        rusqlite::params![tenant, hash_token(&svc)],
    )
    .unwrap();
    let anon = generate_token();
    conn.execute(
        "INSERT INTO tokens (tenant_id, token_hash, label, role) VALUES (?1, ?2, 'anon', 'anon')",
        rusqlite::params![tenant, hash_token(&anon)],
    )
    .unwrap();
    drust::storage::tenant_db::open_write(&data, tenant).unwrap();
    drust::db::migrations::run_migrations(&conn, &data).unwrap();
    conn.execute(
        "UPDATE tenants SET allow_self_register = 1, file_user_caps_json = ?2, \
                file_anon_caps_json = ?2 WHERE id = ?1",
        rusqlite::params![tenant, r#"["upload","read","list"]"#],
    )
    .unwrap();

    let tenants = Arc::new(TenantRegistry::new(data.clone(), 2));
    let bus = EventBus::new();
    let webhooks = WebhookDispatcher::new(tenants.clone(), None);
    let meta = Arc::new(Mutex::new(conn));
    let auth_state = TenantAuthState::test_default(meta, tenants.clone());
    let garage = mem_garage();
    let mut files_state =
        TenantFilesState::test_default(Some(garage.clone()), data.clone(), tenants.clone());
    // CI disks routinely sit under the 20% default and the guard would 507.
    files_state.disk_min_free_pct = 0;
    let mcp = Arc::new(drust::mcp::http_registry::McpHttpRegistry::new(Arc::new(
        drust::mcp::server::McpRegistry::with_bus(tenants.clone(), bus.clone()),
    )));
    let (functions, functions_exec, fn_cfg) = drust::functions::test_stack_parts(tenants.clone());
    let stack = TenantStack {
        auth: auth_state,
        bus: bus.clone(),
        bus_rooms: RoomBus::new(),
        bucket: RoomsConfig::test_defaults().bucket(),
        rooms_cfg: RoomsConfig::test_defaults(),
        mcp,
        files: Some(files_state),
        webhooks,
        functions,
        functions_exec,
        fn_cfg,
        cron: std::sync::Arc::new(drust::cron::CronState::test_default()),
        cors_origins: Vec::new(),
    };
    ModeA {
        app: build_tenant_router(stack),
        svc,
        anon,
        dir,
        garage,
    }
}

/// Register or replace one prefix rule through the REAL service-only face
/// (`PUT /t/<id>/file-policies`), so the tests exercise the same door an
/// operator uses rather than a hand-INSERT the write face would have refused.
async fn put_policy(app: &axum::Router, tenant: &str, svc: &str, row: serde_json::Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/t/{tenant}/file-policies"))
                .header(header::AUTHORIZATION, format!("Bearer {svc}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(row.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    assert_eq!(
        status,
        StatusCode::OK,
        "policy PUT rejected: {}",
        body_text(resp).await
    );
}

/// `DELETE /t/<id>/file-policies?prefix=<prefix>` — the rule-removal door.
async fn clear_policy(app: &axum::Router, tenant: &str, svc: &str, prefix: &str) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                // `/` is legal unescaped in a query value and every prefix in
                // this file is ASCII, so no percent-encoding is needed.
                .uri(format!("/t/{tenant}/file-policies?prefix={prefix}"))
                .header(header::AUTHORIZATION, format!("Bearer {svc}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    assert_eq!(
        status,
        StatusCode::OK,
        "policy DELETE rejected: {}",
        body_text(resp).await
    );
}

/// The root rule as the boot seed leaves it, MINUS the publish grant — the
/// replace-not-merge revoke a tenant performs to close the grandfather door.
/// `public_read` is kept so reads are untouched: this test file is about the
/// publish dimension only.
fn root_rule_without_grant() -> serde_json::Value {
    serde_json::json!({"prefix": "", "owner_scoped": false, "public_read": true})
}

/// How many `_system_files` rows exist — a refusal must leave none behind.
fn file_count(dir: &tempfile::TempDir, tenant: &str) -> i64 {
    let db = dir.path().join("tenants").join(tenant).join("data.sqlite");
    rusqlite::Connection::open(db)
        .unwrap()
        .query_row("SELECT COUNT(*) FROM _system_files", [], |r| r.get(0))
        .unwrap()
}

/// Register + log in an end user, returning the `drust_user_*` session token
/// and the `u-…` id the uploader stamp must match.
async fn user_token_and_id(app: &axum::Router, tenant: &str, email: &str) -> (String, String) {
    for path in ["register", "login"] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/t/{tenant}/auth/{path}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({"email": email, "password": "longpassword"}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        if path == "login" {
            let v = body_json(resp).await;
            let token = v["token"].as_str().expect("login returns a token").into();
            let id = v["user_id"]
                .as_str()
                .expect("login echoes the user id")
                .to_string();
            return (token, id);
        }
    }
    unreachable!()
}

/// Silence is `private` — and stays `private` even though this tenant's root
/// rule DOES carry the grandfather publish grant. A grant is permission to
/// publish, never an instruction to.
#[tokio::test]
async fn user_mode_a_upload_is_private_and_stamped_with_the_user_id() {
    let tid = "rls-up-user";
    let ModeA { app, dir, .. } = mode_a_stack(tid).await;
    let (user, uid) = user_token_and_id(&app, tid, "alice@x.com").await;

    let resp = app
        .clone()
        .oneshot(upload_request(
            &format!("/t/{tid}/files"),
            Some(&user),
            &[("file", "hello", Some("me.png"))],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "user upload should succeed");
    let key = body_json(resp).await["key"].as_str().unwrap().to_string();

    let (visibility, uploader, _path) = file_row(&dir, tid, &key);
    assert_eq!(
        visibility, "private",
        "a non-service upload with no visibility field must land private, \
         NOT on Mode-A's service default of public"
    );
    assert_eq!(
        uploader, uid,
        "the row must be stamped with the caller's user id, not the literal 'service'"
    );
}

/// v1.64 (#974), the OPEN direction: an explicit `visibility=public` from an
/// end user is honored where the governing rule grants the `user` role — here
/// the ROOT rule, carrying the grandfather grant an upgraded tenant receives at
/// boot. This is the pin that an upgrade is a non-event for a tenant whose
/// frontend already publishes.
///
/// It checks the deliverable end to end, not just the status: the row says
/// `public`, the object is in the `public` bucket (which Caddy serves without
/// drust in the path), and it is NOT in `private`.
#[tokio::test]
async fn user_mode_a_public_is_honored_under_the_grandfathered_root_grant() {
    let tid = "rls-up-pub";
    let ModeA {
        app, dir, garage, ..
    } = mode_a_stack(tid).await;
    let (user, uid) = user_token_and_id(&app, tid, "alice@x.com").await;

    let resp = app
        .clone()
        .oneshot(upload_request(
            &format!("/t/{tid}/files"),
            Some(&user),
            &[
                ("file", "hello", Some("me.png")),
                ("visibility", "public", None),
            ],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let key = body_json(resp).await["key"].as_str().unwrap().to_string();

    let (visibility, uploader, _path) = file_row(&dir, tid, &key);
    assert_eq!(
        visibility, "public",
        "the root grant covers an unfiled upload, so the publish is honored"
    );
    assert_eq!(
        uploader, uid,
        "publishing does not change the uploader stamp — still the caller"
    );
    let object_key = format!("{tid}/{key}");
    assert_eq!(
        garage
            .get_object_bytes_in("public", &object_key)
            .await
            .unwrap()
            .as_ref(),
        b"hello",
        "the bytes must physically be in the public bucket, not merely labelled"
    );
    assert!(
        garage
            .get_object_bytes_in("private", &object_key)
            .await
            .is_err()
    );
}

/// The CLOSED direction, same request, same caller: once the tenant revokes the
/// root grant (a replace-not-merge re-register that omits the field), the
/// publish is refused with `FILE_PUBLIC_UPLOAD_DENIED` — and refused BEFORE any
/// row or object exists, never downgraded silently to `private`.
#[tokio::test]
async fn user_mode_a_public_is_refused_once_the_root_grant_is_revoked() {
    let tid = "rls-up-revoked";
    let ModeA {
        app,
        svc,
        dir,
        garage,
        ..
    } = mode_a_stack(tid).await;
    let (user, _uid) = user_token_and_id(&app, tid, "alice@x.com").await;
    put_policy(&app, tid, &svc, root_rule_without_grant()).await;

    let resp = app
        .clone()
        .oneshot(upload_request(
            &format!("/t/{tid}/files"),
            Some(&user),
            &[
                ("file", "hello", Some("me.png")),
                ("visibility", "public", None),
                ("path", "hr/salaries/me.png", None),
            ],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = body_json(resp).await;
    assert_eq!(body["error_code"], "FILE_PUBLIC_UPLOAD_DENIED");
    let message = body["message"].as_str().unwrap();
    assert!(
        message.contains("PUT /file-policies"),
        "the refusal points at the fix rather than just saying no: {message}"
    );
    assert!(
        !message.contains("hr/") && !message.contains("does not grant"),
        "…but it must not disclose WHICH rule governed the decision — that \
         detail is service-only and belongs in the server log: {message}"
    );
    assert_eq!(
        file_count(&dir, tid),
        0,
        "a refusal must leave no row — and no silently-private file either"
    );
    assert!(
        garage.list_objects().await.unwrap_or_default().is_empty(),
        "…and no object"
    );
}

/// Longest-prefix, at the station: a grant on `avatars/` unlocks exactly that
/// folder and nothing else, with the root explicitly ungranted underneath it.
/// The two uploads differ ONLY in their declared `path`.
#[tokio::test]
async fn mode_a_a_deeper_grant_unlocks_only_its_own_prefix() {
    let tid = "rls-up-prefix";
    let ModeA { app, svc, dir, .. } = mode_a_stack(tid).await;
    let (user, _uid) = user_token_and_id(&app, tid, "alice@x.com").await;
    put_policy(&app, tid, &svc, root_rule_without_grant()).await;
    put_policy(
        &app,
        tid,
        &svc,
        serde_json::json!({
            "prefix": "avatars/",
            "owner_scoped": true,
            "public_upload_roles": ["user"],
        }),
    )
    .await;

    let inside = app
        .clone()
        .oneshot(upload_request(
            &format!("/t/{tid}/files"),
            Some(&user),
            &[
                ("file", "hello", Some("me.png")),
                ("visibility", "public", None),
                ("path", "avatars/alice/me.png", None),
            ],
        ))
        .await
        .unwrap();
    assert_eq!(inside.status(), StatusCode::OK);
    let key = body_json(inside).await["key"].as_str().unwrap().to_string();
    assert_eq!(file_row(&dir, tid, &key).0, "public");

    let outside = app
        .clone()
        .oneshot(upload_request(
            &format!("/t/{tid}/files"),
            Some(&user),
            &[
                ("file", "hello", Some("q3.pdf")),
                ("visibility", "public", None),
                ("path", "docs/q3.pdf", None),
            ],
        ))
        .await
        .unwrap();
    assert_eq!(
        outside.status(),
        StatusCode::FORBIDDEN,
        "a sibling folder inherits the UNGRANTED root, not the avatars grant"
    );
    assert_eq!(
        body_json(outside).await["error_code"],
        "FILE_PUBLIC_UPLOAD_DENIED"
    );
    assert_eq!(file_count(&dir, tid), 1, "only the granted upload landed");
}

/// Clearing the rule takes the right back — the registry is live, not a
/// one-time provisioning step. Same request, `DELETE` in between.
#[tokio::test]
async fn mode_a_clearing_the_rule_takes_the_publish_right_back() {
    let tid = "rls-up-cleared";
    let ModeA { app, svc, dir, .. } = mode_a_stack(tid).await;
    let (user, _uid) = user_token_and_id(&app, tid, "alice@x.com").await;
    put_policy(&app, tid, &svc, root_rule_without_grant()).await;
    put_policy(
        &app,
        tid,
        &svc,
        serde_json::json!({
            "prefix": "avatars/",
            "owner_scoped": true,
            "public_upload_roles": ["user"],
        }),
    )
    .await;
    let publish = |token: String| {
        let app = app.clone();
        async move {
            app.oneshot(upload_request(
                &format!("/t/{tid}/files"),
                Some(&token),
                &[
                    ("file", "hello", Some("me.png")),
                    ("visibility", "public", None),
                    ("path", "avatars/alice/me.png", None),
                ],
            ))
            .await
            .unwrap()
        }
    };
    assert_eq!(publish(user.clone()).await.status(), StatusCode::OK);

    clear_policy(&app, tid, &svc, "avatars/").await;

    let after = publish(user).await;
    assert_eq!(
        after.status(),
        StatusCode::FORBIDDEN,
        "with the rule gone, the upload falls back to the ungranted root"
    );
    assert_eq!(
        body_json(after).await["error_code"],
        "FILE_PUBLIC_UPLOAD_DENIED"
    );
    assert_eq!(file_count(&dir, tid), 1);
}

/// The grant names ROLES, and the two are independent: a rule granting only
/// `anon` lets the anon bearer publish into that prefix while an authenticated
/// user — who holds the very same `upload` file cap — is refused on the very
/// same path.
#[tokio::test]
async fn mode_a_the_grant_is_per_role_anon_and_user_do_not_share_it() {
    let tid = "rls-up-roles";
    let ModeA {
        app,
        svc,
        anon,
        dir,
        ..
    } = mode_a_stack(tid).await;
    let (user, _uid) = user_token_and_id(&app, tid, "alice@x.com").await;
    put_policy(&app, tid, &svc, root_rule_without_grant()).await;
    put_policy(
        &app,
        tid,
        &svc,
        serde_json::json!({
            "prefix": "drop/",
            "owner_scoped": true,
            "public_upload_roles": ["anon"],
        }),
    )
    .await;

    let by_anon = app
        .clone()
        .oneshot(upload_request(
            &format!("/t/{tid}/files"),
            Some(&anon),
            &[
                ("file", "hello", Some("a.png")),
                ("visibility", "public", None),
                ("path", "drop/a.png", None),
            ],
        ))
        .await
        .unwrap();
    assert_eq!(by_anon.status(), StatusCode::OK);
    let key = body_json(by_anon).await["key"]
        .as_str()
        .unwrap()
        .to_string();
    let (visibility, uploader, _p) = file_row(&dir, tid, &key);
    assert_eq!(visibility, "public");
    assert_eq!(uploader, "anon", "the anon sentinel, not a user id");

    let by_user = app
        .clone()
        .oneshot(upload_request(
            &format!("/t/{tid}/files"),
            Some(&user),
            &[
                ("file", "hello", Some("b.png")),
                ("visibility", "public", None),
                ("path", "drop/b.png", None),
            ],
        ))
        .await
        .unwrap();
    assert_eq!(
        by_user.status(),
        StatusCode::FORBIDDEN,
        "an anon-only grant must not cover the user role"
    );
    assert_eq!(
        body_json(by_user).await["error_code"],
        "FILE_PUBLIC_UPLOAD_DENIED"
    );
}

#[tokio::test]
async fn service_mode_a_default_visibility_stays_public() {
    // Regression pin for the OTHER half of the visibility rule: the service
    // default is deliberately untouched by v1.63 — and by v1.64, where service
    // short-circuits before the registry is read at all.
    let tid = "rls-up-svc";
    let ModeA { app, svc, dir, .. } = mode_a_stack(tid).await;
    let resp = app
        .clone()
        .oneshot(upload_request(
            &format!("/t/{tid}/files"),
            Some(&svc),
            &[("file", "hello", Some("logo.png"))],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let key = body_json(resp).await["key"].as_str().unwrap().to_string();
    let (visibility, uploader, path) = file_row(&dir, tid, &key);
    assert_eq!(
        visibility, "public",
        "service Mode-A default must stay public"
    );
    assert_eq!(uploader, "service");
    assert_eq!(path, None, "no path field ⇒ NULL, never an empty string");

    // …and service publishing does not depend on the registry at all: revoke
    // every grant and an explicit service `public` still goes through. This is
    // the recovery path — a broken or empty registry must never lock a tenant
    // out of its own storage.
    put_policy(&app, tid, &svc, root_rule_without_grant()).await;
    let resp = app
        .clone()
        .oneshot(upload_request(
            &format!("/t/{tid}/files"),
            Some(&svc),
            &[
                ("file", "hello", Some("logo2.png")),
                ("visibility", "public", None),
                ("path", "anywhere/logo2.png", None),
            ],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let key = body_json(resp).await["key"].as_str().unwrap().to_string();
    assert_eq!(file_row(&dir, tid, &key).0, "public");
}

#[tokio::test]
async fn mode_a_stores_a_declared_path() {
    let tid = "rls-up-path";
    let ModeA { app, svc, dir, .. } = mode_a_stack(tid).await;
    let resp = app
        .clone()
        .oneshot(upload_request(
            &format!("/t/{tid}/files"),
            Some(&svc),
            &[
                ("file", "hello", Some("x.png")),
                ("path", "avatars/alice/x.png", None),
            ],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let key = body_json(resp).await["key"].as_str().unwrap().to_string();
    let (_v, _u, path) = file_row(&dir, tid, &key);
    assert_eq!(path.as_deref(), Some("avatars/alice/x.png"));
}

#[tokio::test]
async fn mode_a_rejects_an_illegal_path() {
    let tid = "rls-up-badpath";
    let ModeA { app, svc, dir, .. } = mode_a_stack(tid).await;
    let resp = app
        .clone()
        .oneshot(upload_request(
            &format!("/t/{tid}/files"),
            Some(&svc),
            &[("file", "hello", Some("x.png")), ("path", "../x", None)],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(
        body_text(resp).await.contains("FILE_PATH_INVALID"),
        "an illegal path is refused with its own code — never silently trimmed"
    );
    let db = dir.path().join("tenants").join(tid).join("data.sqlite");
    let n: i64 = rusqlite::Connection::open(db)
        .unwrap()
        .query_row("SELECT COUNT(*) FROM _system_files", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 0);
}

// ─── Section 2: gate polarity — the data-plane handler is fail-CLOSED ─────────

/// The data-plane `upload` mounted with NO `AuthCtx` in extensions (i.e. the
/// bearer layer was bypassed or a future refactor dropped it) must refuse, not
/// fall back to service. This is the whole reason the admin mount became a
/// separate handler instead of an `unwrap_or(service)` inside one.
#[tokio::test]
async fn data_plane_upload_fails_closed_without_an_auth_ctx() {
    let dir = tempfile::tempdir().unwrap();
    let tid = "rls-noctx";
    drust::storage::tenant_db::open_write(dir.path(), tid).unwrap();
    let tenants = Arc::new(TenantRegistry::new(dir.path().to_path_buf(), 2));
    let mut state =
        TenantFilesState::test_default(Some(mem_garage()), dir.path().to_path_buf(), tenants);
    state.disk_min_free_pct = 0;
    let app = axum::Router::new()
        .route("/t/{tenant}/files", post(drust::mgmt::tenant_files::upload))
        .with_state(state);
    let resp = app
        .oneshot(upload_request(
            &format!("/t/{tid}/files"),
            None,
            &[("file", "hello", Some("x.png"))],
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "a missing identity must never be read as 'service'"
    );
    assert!(
        body_text(resp).await.contains("AUTH_CTX_MISSING"),
        "the fail-closed refusal names itself"
    );
}

// ─── Section 3: the admin twins still work with no bearer at all ──────────────

/// The three dual-mounted verbs, driven through the REAL mgmt router behind an
/// admin session cookie. If the admin mount ever picks up the data-plane
/// handler again, upload/bytes/delete all 500 with `AUTH_CTX_MISSING` here.
#[tokio::test]
async fn admin_twins_upload_stream_and_delete_without_a_bearer() {
    use drust::mgmt::routes::MgmtState;
    use drust::storage::meta::bootstrap_admin;

    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let tid = "rls-admin-twin";
    let mut conn = open_meta(&data.join("meta.sqlite")).unwrap();
    bootstrap_admin(&mut conn, "root", "hunter2").unwrap();
    conn.execute(
        "INSERT INTO tenants (id, name) VALUES (?1, 'x')",
        rusqlite::params![tid],
    )
    .unwrap();
    drust::storage::tenant_db::open_write(&data, tid).unwrap();
    drust::db::migrations::run_migrations(&conn, &data).unwrap();
    let tenants = Arc::new(TenantRegistry::new(data.clone(), 2));
    let bus = EventBus::new();
    let mcp = Arc::new(drust::mcp::http_registry::McpHttpRegistry::new(Arc::new(
        drust::mcp::server::McpRegistry::with_bus(tenants.clone(), bus.clone()),
    )));
    let mut state = MgmtState::test_default(
        Arc::new(Mutex::new(conn)),
        data.clone(),
        tenants,
        mcp,
        bus,
        RoomBus::new(),
    );
    state.garage = Some(mem_garage());
    state.disk_min_free_pct = 0;
    let app = state.with_data_dir(data);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("username=root&password=hunter2"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "admin login failed");
    let cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();

    // upload (admin twin) — no bearer anywhere on this request.
    let mut req = upload_request(
        &format!("/admin/tenants/{tid}/files/upload"),
        None,
        &[("file", "hello", Some("a.txt"))],
    );
    req.headers_mut()
        .insert(header::COOKIE, cookie.parse().unwrap());
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "admin upload twin must work");
    let key = body_json(resp).await["key"].as_str().unwrap().to_string();

    // bytes (admin twin).
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/admin/tenants/{tid}/files/{key}/bytes"))
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "admin bytes twin must work");

    // delete (admin twin).
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/admin/tenants/{tid}/files/{key}"))
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "admin delete twin must work"
    );
}

// ─── Section 4: tus (Mode B) ──────────────────────────────────────────────────

fn tus_setup(tid: &str) -> (tempfile::TempDir, TenantFilesState, TenantRef) {
    let dir = tempfile::tempdir().unwrap();
    drust::storage::tenant_db::open_write(dir.path(), tid).unwrap();
    let registry = Arc::new(TenantRegistry::new(dir.path().to_path_buf(), 2));
    let pool = registry.get_or_create(tid).unwrap();
    let mut state =
        TenantFilesState::test_default(Some(mem_garage()), dir.path().to_path_buf(), registry);
    state.disk_min_free_pct = 0;
    let tref = TenantRef {
        tenant_id: tid.to_string(),
        token_hint: "svc".into(),
        pool,
        role: TokenRole::Service,
    };
    (dir, state, tref)
}

fn b64(s: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(s)
}

fn tus_headers(len: i64, meta: &[(&str, &str)]) -> axum::http::HeaderMap {
    let mut h = axum::http::HeaderMap::new();
    h.insert("upload-length", len.to_string().parse().unwrap());
    if !meta.is_empty() {
        let joined = meta
            .iter()
            .map(|(k, v)| format!("{k} {}", b64(v)))
            .collect::<Vec<_>>()
            .join(",");
        h.insert("upload-metadata", joined.parse().unwrap());
    }
    h
}

fn anon_upload_caps() -> axum::Extension<drust::tenant::file_caps::TenantFileCaps> {
    let mut caps = drust::tenant::file_caps::TenantFileCaps::default();
    caps.anon.insert(drust::storage::schema::FileVerb::Upload);
    axum::Extension(caps)
}

/// **Anti-unify lock.** tus has ALWAYS defaulted to private (`_ => "private"`).
/// v1.63 tightens Mode-A toward tus, never the other way: if someone
/// "harmonises" the two stations on Mode-A's public default, this fails.
#[tokio::test]
async fn tus_service_default_visibility_stays_private() {
    use axum::extract::{Path, State};
    use axum::response::IntoResponse;
    let (_d, state, tref) = tus_setup("tus-vis");
    let pool = tref.pool.clone();
    let resp = drust::tenant::uploads::create(
        State(state),
        axum::Extension(tref),
        axum::Extension(Default::default()),
        axum::Extension(drust::auth::middleware::AuthCtx::Service { admin_id: None }),
        Path("tus-vis".to_string()),
        tus_headers(5, &[("filename", "a.bin")]),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let vis: String = pool
        .with_reader(|c| {
            c.query_row("SELECT visibility FROM _system_upload_sessions", [], |r| {
                r.get(0)
            })
        })
        .await
        .unwrap();
    assert_eq!(vis, "private", "tus service default must remain private");
}

/// Register one grant directly on the tenant's registry — the tus and edge
/// harnesses have no HTTP config face in reach, so they use the same
/// `upsert_file_policy` kernel the REST face calls.
async fn grant_prefix(pool: &drust::storage::pool::SharedTenantPool, prefix: &str, roles: &[&str]) {
    let row = drust::storage::file_policy::FilePolicyRow {
        prefix: prefix.to_string(),
        owner_scoped: true,
        public_read: false,
        select_policy: None,
        delete_policy: None,
        public_upload_roles: Some(roles.iter().map(|r| r.to_string()).collect()),
    };
    pool.with_writer(move |c| drust::storage::file_policy::upsert_file_policy(c, &row))
        .await
        .unwrap();
}

/// v1.64 (#974), tus half. This harness builds a tenant with NO registry rows
/// at all — the deny-by-default state a post-v1.64 tenant is born in — so the
/// first create is refused, and the SAME create succeeds once a rule granting
/// `anon` on the declared path's prefix exists.
///
/// The decision is made at CREATE and frozen onto the session row; finalize
/// copies it and never re-checks (see the create handler's note on the accepted
/// create→finalize race).
#[tokio::test]
async fn tus_non_service_public_needs_a_grant_on_the_declared_path() {
    use axum::extract::{Path, State};
    use axum::response::IntoResponse;
    let (_d, state, mut tref) = tus_setup("tus-pub");
    tref.role = TokenRole::Anon;
    let pool = tref.pool.clone();
    let create = async |state: TenantFilesState, tref: TenantRef| {
        drust::tenant::uploads::create(
            State(state),
            axum::Extension(tref),
            anon_upload_caps(),
            axum::Extension(drust::auth::middleware::AuthCtx::Anon),
            Path("tus-pub".to_string()),
            tus_headers(
                5,
                &[
                    ("filename", "a.bin"),
                    ("visibility", "public"),
                    ("path", "drop/a.bin"),
                ],
            ),
        )
        .await
        .into_response()
    };

    let refused = create(state.clone(), tref.clone()).await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        body_json(refused).await["error_code"],
        "FILE_PUBLIC_UPLOAD_DENIED"
    );
    let sessions: i64 = pool
        .with_reader(|c| {
            c.query_row("SELECT COUNT(*) FROM _system_upload_sessions", [], |r| {
                r.get(0)
            })
        })
        .await
        .unwrap();
    assert_eq!(
        sessions, 0,
        "the refusal precedes the session row and the spool file"
    );

    grant_prefix(&pool, "drop/", &["anon"]).await;
    let ok = create(state, tref).await;
    assert_eq!(ok.status(), StatusCode::CREATED);
    let vis: String = pool
        .with_reader(|c| {
            c.query_row("SELECT visibility FROM _system_upload_sessions", [], |r| {
                r.get(0)
            })
        })
        .await
        .unwrap();
    assert_eq!(
        vis, "public",
        "with the grant in place the session carries the caller's choice"
    );
}

/// …and the granted choice survives the whole tus lifecycle: what `create`
/// decided is what the `_system_files` row says after finalize, which is where
/// the publish becomes real.
#[tokio::test]
async fn tus_granted_public_survives_create_through_finalize() {
    use axum::extract::{Path, State};
    use axum::response::IntoResponse;
    let (_d, state, mut tref) = tus_setup("tus-fin-pub");
    tref.role = TokenRole::Anon;
    let pool = tref.pool.clone();
    grant_prefix(&pool, "drop/", &["anon"]).await;

    let resp = drust::tenant::uploads::create(
        State(state.clone()),
        axum::Extension(tref.clone()),
        anon_upload_caps(),
        axum::Extension(drust::auth::middleware::AuthCtx::Anon),
        Path("tus-fin-pub".to_string()),
        tus_headers(
            5,
            &[
                ("filename", "a.bin"),
                ("visibility", "public"),
                ("path", "drop/a.bin"),
            ],
        ),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let token = resp
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_string();

    let mut h = axum::http::HeaderMap::new();
    h.insert("upload-offset", "0".parse().unwrap());
    let resp = drust::tenant::uploads::patch(
        State(state),
        axum::Extension(tref),
        anon_upload_caps(),
        axum::Extension(drust::auth::middleware::AuthCtx::Anon),
        Path(("tus-fin-pub".to_string(), token)),
        h,
        axum::body::Bytes::from_static(b"hello"),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let (vis, uploader, path): (String, String, Option<String>) = pool
        .with_reader(|c| {
            c.query_row(
                "SELECT visibility, uploader, path FROM _system_files",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
        })
        .await
        .unwrap();
    assert_eq!(vis, "public", "finalize honors the decision create froze");
    assert_eq!(uploader, "anon");
    assert_eq!(path.as_deref(), Some("drop/a.bin"));
}

/// The half of v1.63 that v1.64 KEEPS: silence from a non-service caller is
/// `private`, decided by the caller-not-service arm rather than by the station
/// default (which happens to agree here — the Mode-A twin above is where the
/// two differ).
#[tokio::test]
async fn tus_non_service_silent_upload_stays_private() {
    use axum::extract::{Path, State};
    use axum::response::IntoResponse;
    let (_d, state, mut tref) = tus_setup("tus-silent");
    tref.role = TokenRole::Anon;
    let pool = tref.pool.clone();
    let resp = drust::tenant::uploads::create(
        State(state),
        axum::Extension(tref),
        anon_upload_caps(),
        axum::Extension(drust::auth::middleware::AuthCtx::Anon),
        Path("tus-silent".to_string()),
        tus_headers(5, &[("filename", "a.bin")]),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let vis: String = pool
        .with_reader(|c| {
            c.query_row("SELECT visibility FROM _system_upload_sessions", [], |r| {
                r.get(0)
            })
        })
        .await
        .unwrap();
    assert_eq!(vis, "private");
}

#[tokio::test]
async fn tus_rejects_an_illegal_path() {
    use axum::extract::{Path, State};
    use axum::response::IntoResponse;
    let (_d, state, tref) = tus_setup("tus-badpath");
    let resp = drust::tenant::uploads::create(
        State(state),
        axum::Extension(tref),
        axum::Extension(Default::default()),
        axum::Extension(drust::auth::middleware::AuthCtx::Service { admin_id: None }),
        Path("tus-badpath".to_string()),
        tus_headers(5, &[("filename", "a.bin"), ("path", "a//b")]),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(resp).await["error_code"], "FILE_PATH_INVALID");
}

/// The path declared at `create` has to survive the session row and land on the
/// `_system_files` row that finalize writes — the whole point of carrying it.
#[tokio::test]
async fn tus_path_survives_create_through_finalize() {
    use axum::extract::{Path, State};
    use axum::response::IntoResponse;
    let (_d, state, tref) = tus_setup("tus-fin");
    let pool = tref.pool.clone();
    let resp = drust::tenant::uploads::create(
        State(state.clone()),
        axum::Extension(tref.clone()),
        axum::Extension(Default::default()),
        axum::Extension(drust::auth::middleware::AuthCtx::Service { admin_id: None }),
        Path("tus-fin".to_string()),
        tus_headers(5, &[("filename", "a.bin"), ("path", "照片/alice/a.bin")]),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let token = resp
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_string();

    let sess_path: Option<String> = pool
        .with_reader(|c| c.query_row("SELECT path FROM _system_upload_sessions", [], |r| r.get(0)))
        .await
        .unwrap();
    assert_eq!(sess_path.as_deref(), Some("照片/alice/a.bin"));

    let mut h = axum::http::HeaderMap::new();
    h.insert("upload-offset", "0".parse().unwrap());
    let resp = drust::tenant::uploads::patch(
        State(state),
        axum::Extension(tref),
        axum::Extension(Default::default()),
        axum::Extension(drust::auth::middleware::AuthCtx::Service { admin_id: None }),
        Path(("tus-fin".to_string(), token)),
        h,
        axum::body::Bytes::from_static(b"hello"),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let (path, uploader): (Option<String>, String) = pool
        .with_reader(|c| {
            c.query_row("SELECT path, uploader FROM _system_files", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
        })
        .await
        .unwrap();
    assert_eq!(path.as_deref(), Some("照片/alice/a.bin"));
    assert_eq!(uploader, "service", "tus uploader stamping is unchanged");
}

// ─── Section 5: edge `put-file` ───────────────────────────────────────────────

async fn edge_mcp(tenant: &str) -> (drust::mcp::server::DrustMcp, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let tenants = Arc::new(TenantRegistry::new(tmp.path().to_path_buf(), 2));
    let rooms_cfg = RoomsConfig::test_defaults();
    let bucket = rooms_cfg.bucket();
    let mcp = drust::mcp::server::DrustMcp::new(
        tenant,
        tenants.get_or_create(tenant).unwrap(),
        EventBus::new(),
        WebhookDispatcher::new(tenants.clone(), None),
        Some(mem_garage()),
        String::new(),
        Arc::new([0u8; 32]),
        None,
        52_428_800,
        1_000_000,
        Arc::new(Mutex::new(
            drust::safety::audit_db::open_audit_db_memory().unwrap(),
        )),
        RoomBus::new(),
        bucket,
        rooms_cfg,
        None,
        None,
    );
    (mcp, tmp)
}

fn upload_caps_for_user() -> drust::tenant::file_caps::TenantFileCaps {
    let mut caps = drust::tenant::file_caps::TenantFileCaps::default();
    caps.user.insert(drust::storage::schema::FileVerb::Upload);
    caps
}

async fn edge_file_row(mcp: &drust::mcp::server::DrustMcp, key: &str) -> (String, String) {
    let key = key.to_string();
    mcp.inner()
        .pool
        .with_reader(move |c| {
            c.query_row(
                "SELECT visibility, uploader FROM _system_files WHERE key = ?1",
                rusqlite::params![key],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
        })
        .await
        .unwrap()
}

/// v1.64 (#974), edge half. The WIT hands the guest's `visibility` straight
/// through but accepts no `path`, so an edge upload is always UNFILED and only
/// the tenant's ROOT rule can grant it — `longest_match` gives a `None` path a
/// `''`-or-nothing answer, exactly as it does for a `path IS NULL` row on the
/// read side. Reaching this door already requires the `upload` file cap; the
/// grant is the second, per-prefix gate on top. The uploader stamp is unchanged
/// — still the caller.
#[tokio::test(flavor = "multi_thread")]
async fn edge_non_privileged_public_put_needs_the_root_grant() {
    let (mcp, _t) = edge_mcp("edge-pub").await;
    let put = async |key: &str| {
        drust::functions::enforce::enforced_put_file(
            &mcp,
            TokenRole::User,
            &upload_caps_for_user(),
            "u-1",
            key,
            b"x".to_vec(),
            "application/octet-stream",
            "public",
            0,
        )
        .await
    };

    let refused = put("p.bin").await.unwrap_err();
    assert!(
        refused.contains("FILE_PUBLIC_UPLOAD_DENIED"),
        "an ungranted tenant refuses the publish: {refused}"
    );

    // A grant on a DEEPER prefix can never cover an unfiled upload…
    grant_prefix(&mcp.inner().pool, "uploads/", &["user"]).await;
    assert!(put("p.bin").await.is_err());

    // …only the root rule can.
    grant_prefix(&mcp.inner().pool, "", &["user"]).await;
    put("p.bin").await.unwrap();
    let (vis, uploader) = edge_file_row(&mcp, "p.bin").await;
    assert_eq!(vis, "public");
    assert_eq!(
        uploader, "u-1",
        "publishing must not revert the stamp to 'function'"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn edge_non_privileged_put_is_private_and_stamped_with_the_caller() {
    let (mcp, _t) = edge_mcp("edge-priv").await;
    drust::functions::enforce::enforced_put_file(
        &mcp,
        TokenRole::User,
        &upload_caps_for_user(),
        "u-alice",
        "q.bin",
        b"x".to_vec(),
        "application/octet-stream",
        "private",
        0,
    )
    .await
    .unwrap();
    let (vis, uploader) = edge_file_row(&mcp, "q.bin").await;
    assert_eq!(vis, "private");
    assert_eq!(
        uploader, "u-alice",
        "a user-invoked upload must be owned by that user, not by 'function'"
    );
}

/// The privileged path is byte-identical and NEEDS NO GRANT: `put_file_raw`
/// still publishes on this same ungranted tenant, and still stamps `function`.
/// Service short-circuits before the registry is read at all.
#[tokio::test(flavor = "multi_thread")]
async fn edge_privileged_put_keeps_public_and_the_function_stamp() {
    let (mcp, _t) = edge_mcp("edge-god").await;
    drust::functions::enforce::put_file_raw(
        &mcp,
        "r.bin",
        b"x".to_vec(),
        "application/octet-stream",
        "public",
        0,
    )
    .await
    .unwrap();
    let (vis, uploader) = edge_file_row(&mcp, "r.bin").await;
    assert_eq!(vis, "public");
    assert_eq!(uploader, "function");
}
