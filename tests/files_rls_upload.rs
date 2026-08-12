//! #950-B T2 — the four upload stations: route split, uploader stamping,
//! visibility forcing, and `path` intake.
//!
//! Every station that creates a `_system_files` row has to make the same three
//! decisions, and until v1.63 two of them were wrong on the data plane:
//!
//! 1. **uploader** — Mode-A stamped the literal `"service"` on every row, so a
//!    user upload was owned by nobody. Per-file RLS defaults to owner-scoped,
//!    which makes the stamp the identity the whole feature keys on.
//! 2. **visibility** — Mode-A defaults to `public`, and a non-service caller
//!    could ask for `public` outright. `public` bytes are served by Caddy
//!    straight from Garage and never reach drust, so a publish decision is a
//!    permanent RLS bypass for that object. Only service may publish.
//! 3. **path** — the caller-declared label a prefix policy attaches to.
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

/// Production `build_tenant_router` with the files plane mounted, a service
/// token, self-registration on, and `file_user_caps = [upload,read,list]` so a
/// real `drust_user_*` session reaches the upload handler.
async fn mode_a_stack(tenant: &str) -> (axum::Router, String, tempfile::TempDir) {
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
    drust::storage::tenant_db::open_write(&data, tenant).unwrap();
    drust::db::migrations::run_migrations(&conn, &data).unwrap();
    conn.execute(
        "UPDATE tenants SET allow_self_register = 1, file_user_caps_json = ?2 WHERE id = ?1",
        rusqlite::params![tenant, r#"["upload","read","list"]"#],
    )
    .unwrap();

    let tenants = Arc::new(TenantRegistry::new(data.clone(), 2));
    let bus = EventBus::new();
    let webhooks = WebhookDispatcher::new(tenants.clone(), None);
    let meta = Arc::new(Mutex::new(conn));
    let auth_state = TenantAuthState::test_default(meta, tenants.clone());
    let mut files_state =
        TenantFilesState::test_default(Some(mem_garage()), data.clone(), tenants.clone());
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
    (build_tenant_router(stack), svc, dir)
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

#[tokio::test]
async fn user_mode_a_upload_is_private_and_stamped_with_the_user_id() {
    let tid = "rls-up-user";
    let (app, _svc, dir) = mode_a_stack(tid).await;
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

#[tokio::test]
async fn user_mode_a_explicit_public_is_refused() {
    let tid = "rls-up-pub";
    let (app, _svc, dir) = mode_a_stack(tid).await;
    let (user, _uid) = user_token_and_id(&app, tid, "alice@x.com").await;

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
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        body_json(resp).await["error_code"],
        "FILE_VISIBILITY_SERVICE_ONLY",
        "publishing is a service decision — /public/* bypasses drust entirely"
    );

    // …and nothing was written: the gate runs before the INSERT.
    let db = dir.path().join("tenants").join(tid).join("data.sqlite");
    let n: i64 = rusqlite::Connection::open(db)
        .unwrap()
        .query_row("SELECT COUNT(*) FROM _system_files", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 0, "a refused upload must not leave a row behind");
}

#[tokio::test]
async fn service_mode_a_default_visibility_stays_public() {
    // Regression pin for the OTHER half of the visibility rule: the service
    // default is deliberately untouched by v1.63.
    let tid = "rls-up-svc";
    let (app, svc, dir) = mode_a_stack(tid).await;
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
}

#[tokio::test]
async fn mode_a_stores_a_declared_path() {
    let tid = "rls-up-path";
    let (app, svc, dir) = mode_a_stack(tid).await;
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
    let (app, svc, dir) = mode_a_stack(tid).await;
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

#[tokio::test]
async fn tus_non_service_explicit_public_is_refused() {
    use axum::extract::{Path, State};
    use axum::response::IntoResponse;
    let (_d, state, mut tref) = tus_setup("tus-pub");
    tref.role = TokenRole::Anon;
    let pool = tref.pool.clone();
    let resp = drust::tenant::uploads::create(
        State(state),
        axum::Extension(tref),
        anon_upload_caps(),
        axum::Extension(drust::auth::middleware::AuthCtx::Anon),
        Path("tus-pub".to_string()),
        tus_headers(5, &[("filename", "a.bin"), ("visibility", "public")]),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        body_json(resp).await["error_code"],
        "FILE_VISIBILITY_SERVICE_ONLY"
    );
    let n: i64 = pool
        .with_reader(|c| {
            c.query_row("SELECT COUNT(*) FROM _system_upload_sessions", [], |r| {
                r.get(0)
            })
        })
        .await
        .unwrap();
    assert_eq!(n, 0, "a refused create must not leave a session row");
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

/// G6: the WIT hands the guest's `visibility` straight through, so a user-invoked
/// function could publish into the public bucket — a permanent RLS bypass. A
/// non-privileged caller asking for `public` is refused outright.
#[tokio::test(flavor = "multi_thread")]
async fn edge_non_privileged_public_put_is_refused() {
    let (mcp, _t) = edge_mcp("edge-pub").await;
    let err = drust::functions::enforce::enforced_put_file(
        &mcp,
        TokenRole::User,
        &upload_caps_for_user(),
        "u-1",
        "p.bin",
        b"x".to_vec(),
        "application/octet-stream",
        "public",
        0,
    )
    .await
    .unwrap_err();
    assert!(
        err.contains("FILE_VISIBILITY_SERVICE_ONLY"),
        "got {err:?} — a host op refuses with a code, not an HTTP status"
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

/// The privileged path is byte-identical: `put_file_raw` still publishes and
/// still stamps `function`.
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
