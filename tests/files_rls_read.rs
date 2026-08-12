//! #950-B T4 — the per-file gate: `authorize_file` behind the single-file REST
//! verbs (`get_one` / `bytes` / `delete_one`) and the edge `get-file` host op.
//!
//! Until v1.63 a file cap was the WHOLE decision: any bearer holding
//! `file.read` could read every object in the tenant. This file pins the inner
//! gate that now sits under it, and in particular the four shapes that are easy
//! to get backwards:
//!
//! 1. **A hidden file answers 404, never 403.** A 403 would confirm the object
//!    exists to a caller who may not see it — the same rule `owner_field` reads
//!    follow.
//! 2. **The longest matching prefix wins**, so `shared/hr/` can tighten what
//!    `shared/` opened.
//! 3. **A clause-less registry row denies everything.** The write face refuses
//!    to create that shape, so the only way in is a legacy or hand-written row
//!    — which must fail CLOSED, not read as "no restriction".
//! 4. **The cap gate is still there.** RLS is the INNER of two gates; passing a
//!    policy does not grant a cap, and the tests below prove both directions.
//!
//! Ordering note (spec §測試計畫): tenant creation seeds `'' → public_read=1`,
//! so any test of the unmatched owner-scoped DEFAULT must `clear` the root
//! policy first, or it is really testing the seed.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::auth::bearer::{generate_token, hash_token};
use drust::mgmt::tenant_files::TenantFilesState;
use drust::storage::garage::GarageClient;
use drust::storage::meta::open_meta;
use drust::storage::pool::TenantRegistry;
use drust::tenant::events::EventBus;
use drust::tenant::rooms::{RoomBus, RoomsConfig};
use drust::tenant::router::{TenantAuthState, TokenRole};
use drust::tenant::{TenantStack, WebhookDispatcher, build_tenant_router};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::Mutex;
use tower::ServiceExt;

const BOUNDARY: &str = "drustrlsreadboundary";

fn mem_garage() -> Arc<GarageClient> {
    Arc::new(GarageClient::from_store(
        Arc::new(object_store::memory::InMemory::new()),
        "unused",
    ))
}

struct Ctx {
    app: axum::Router,
    svc: String,
    anon: String,
    dir: tempfile::TempDir,
    tid: String,
}

/// Production `build_tenant_router` with the files plane mounted and the file
/// caps handed out explicitly, so every refusal below is the RLS gate and not
/// an accidental cap denial.
async fn stack_with_caps(tenant: &str, user_caps: &str, anon_caps: &str) -> Ctx {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let conn = open_meta(&data.join("meta.sqlite")).unwrap();
    conn.execute(
        "INSERT INTO tenants (id, name) VALUES (?1, 'x')",
        rusqlite::params![tenant],
    )
    .unwrap();
    let svc = generate_token();
    let anon = generate_token();
    conn.execute(
        "INSERT INTO tokens (tenant_id, token_hash, label, role) VALUES (?1, ?2, 'svc', 'service')",
        rusqlite::params![tenant, hash_token(&svc)],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO tokens (tenant_id, token_hash, label, role) VALUES (?1, ?2, 'anon', 'anon')",
        rusqlite::params![tenant, hash_token(&anon)],
    )
    .unwrap();
    drust::storage::tenant_db::open_write(&data, tenant).unwrap();
    drust::db::migrations::run_migrations(&conn, &data).unwrap();
    conn.execute(
        "UPDATE tenants SET allow_self_register = 1, file_user_caps_json = ?2, \
         file_anon_caps_json = ?3 WHERE id = ?1",
        rusqlite::params![tenant, user_caps, anon_caps],
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
    let app = build_tenant_router(TenantStack {
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
        cron: Arc::new(drust::cron::CronState::test_default()),
        cors_origins: Vec::new(),
    });
    Ctx {
        app,
        svc,
        anon,
        dir,
        tid: tenant.to_string(),
    }
}

async fn stack(tenant: &str) -> Ctx {
    stack_with_caps(
        tenant,
        r#"["upload","read","list","delete"]"#,
        r#"["read","list"]"#,
    )
    .await
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1_048_576)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

impl Ctx {
    async fn send(&self, method: &str, uri: String, token: &str, body: Option<Value>) -> Response {
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
        self.app
            .clone()
            .oneshot(b.body(body).unwrap())
            .await
            .unwrap()
    }

    /// Register + log in an end user; returns `(session token, u-… id)`.
    async fn user(&self, email: &str) -> (String, String) {
        let tid = &self.tid;
        for path in ["register", "login"] {
            let resp = self
                .app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/t/{tid}/auth/{path}"))
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(
                            json!({"email": email, "password": "longpassword"}).to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            if path == "login" {
                let v = body_json(resp).await;
                return (
                    v["token"].as_str().expect("login returns a token").into(),
                    v["user_id"].as_str().expect("login echoes the id").into(),
                );
            }
        }
        unreachable!()
    }

    /// Mode-A upload; returns the object key. `visibility` is only honoured for
    /// the service token (v1.63 forces every other caller to private).
    async fn upload(
        &self,
        token: &str,
        filename: &str,
        path: Option<&str>,
        visibility: Option<&str>,
    ) -> String {
        let tid = &self.tid;
        let mut parts: Vec<(&str, &str, Option<&str>)> =
            vec![("file", "hello-bytes", Some(filename))];
        if let Some(p) = path {
            parts.push(("path", p, None));
        }
        if let Some(v) = visibility {
            parts.push(("visibility", v, None));
        }
        let mut body: Vec<u8> = Vec::new();
        for (name, value, fname) in &parts {
            body.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
            match fname {
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

        let resp = self
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/t/{tid}/files"))
                    .header(
                        header::CONTENT_TYPE,
                        format!("multipart/form-data; boundary={BOUNDARY}"),
                    )
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "upload should succeed");
        body_json(resp).await["key"].as_str().unwrap().to_string()
    }

    async fn get_one(&self, token: &str, key: &str) -> StatusCode {
        let tid = &self.tid;
        self.send("GET", format!("/t/{tid}/files/{key}"), token, None)
            .await
            .status()
    }

    async fn bytes(&self, token: &str, key: &str) -> StatusCode {
        let tid = &self.tid;
        self.send("GET", format!("/t/{tid}/files/{key}/bytes"), token, None)
            .await
            .status()
    }

    async fn delete(&self, token: &str, key: &str) -> StatusCode {
        let tid = &self.tid;
        self.send("DELETE", format!("/t/{tid}/files/{key}"), token, None)
            .await
            .status()
    }

    async fn put_policy(&self, body: Value) {
        let tid = &self.tid;
        let svc = self.svc.clone();
        let resp = self
            .send("PUT", format!("/t/{tid}/file-policies"), &svc, Some(body))
            .await;
        assert_eq!(resp.status(), StatusCode::OK, "policy registration failed");
    }

    async fn clear_policy(&self, prefix: &str) {
        let tid = &self.tid;
        let svc = self.svc.clone();
        let resp = self
            .send(
                "DELETE",
                format!("/t/{tid}/file-policies?prefix={prefix}"),
                &svc,
                None,
            )
            .await;
        assert_eq!(resp.status(), StatusCode::OK, "policy clear failed");
    }

    /// Hand-write a registry row the public API refuses to create.
    fn raw_policy_insert(&self, sql: &str) {
        let db = self
            .dir
            .path()
            .join("tenants")
            .join(&self.tid)
            .join("data.sqlite");
        rusqlite::Connection::open(db)
            .unwrap()
            .execute(sql, [])
            .unwrap();
    }
}

type Response = axum::response::Response;

// ─── (a) owner-scoped prefix ─────────────────────────────────────────────────

#[tokio::test]
async fn an_owner_scoped_prefix_hides_another_users_file() {
    let c = stack("rls-rd-owner").await;
    let (alice, _aid) = c.user("alice@x.com").await;
    let (bob, _bid) = c.user("bob@x.com").await;
    c.put_policy(json!({"prefix": "avatars/", "owner_scoped": true}))
        .await;

    let akey = c
        .upload(&alice, "a.png", Some("avatars/alice/a.png"), None)
        .await;

    assert_eq!(
        c.get_one(&alice, &akey).await,
        StatusCode::OK,
        "the uploader reads their own file"
    );
    assert_eq!(
        c.bytes(&alice, &akey).await,
        StatusCode::OK,
        "the bytes route runs the same gate, not a looser one"
    );
    assert_eq!(
        c.get_one(&bob, &akey).await,
        StatusCode::NOT_FOUND,
        "a foreign owner-scoped file must be 404 — a 403 would confirm it exists"
    );
    assert_eq!(c.bytes(&bob, &akey).await, StatusCode::NOT_FOUND);
    let svc = c.svc.clone();
    assert_eq!(
        c.get_one(&svc, &akey).await,
        StatusCode::OK,
        "service bypasses the per-file gate, exactly like every other RLS face"
    );
}

// ─── (b) public_read prefix ──────────────────────────────────────────────────

#[tokio::test]
async fn a_public_read_prefix_is_open_to_user_and_anon() {
    let c = stack("rls-rd-shared").await;
    let (alice, _aid) = c.user("alice@x.com").await;
    c.put_policy(json!({"prefix": "shared/", "public_read": true}))
        .await;
    let svc = c.svc.clone();
    let key = c
        .upload(&svc, "s.txt", Some("shared/s.txt"), Some("private"))
        .await;

    assert_eq!(
        c.get_one(&alice, &key).await,
        StatusCode::OK,
        "a user with the read cap reads an explicitly-open prefix"
    );
    let anon = c.anon.clone();
    assert_eq!(
        c.get_one(&anon, &key).await,
        StatusCode::OK,
        "anon too — two gates, and both are open here"
    );
}

// ─── (c) longest-prefix override ─────────────────────────────────────────────

#[tokio::test]
async fn a_deeper_owner_scoped_prefix_overrides_its_open_parent() {
    let c = stack("rls-rd-override").await;
    let (alice, _aid) = c.user("alice@x.com").await;
    c.put_policy(json!({"prefix": "shared/", "public_read": true}))
        .await;
    c.put_policy(json!({"prefix": "shared/hr/", "owner_scoped": true}))
        .await;
    let svc = c.svc.clone();

    let open = c
        .upload(&svc, "o.txt", Some("shared/o.txt"), Some("private"))
        .await;
    let hr = c
        .upload(&svc, "h.txt", Some("shared/hr/h.txt"), Some("private"))
        .await;

    assert_eq!(c.get_one(&alice, &open).await, StatusCode::OK);
    assert_eq!(
        c.get_one(&alice, &hr).await,
        StatusCode::NOT_FOUND,
        "the longest match wins: shared/hr/ is owner-scoped and alice is not the uploader"
    );
}

// ─── (d) the unmatched default ───────────────────────────────────────────────

#[tokio::test]
async fn with_the_root_cleared_an_unfiled_file_is_owner_only() {
    let c = stack("rls-rd-default").await;
    let (alice, _aid) = c.user("alice@x.com").await;
    let (bob, _bid) = c.user("bob@x.com").await;
    // The seeded root is what preserves today's behaviour; clearing it is how a
    // tenant opts into deny-by-default, and it is the ONLY way to reach the
    // unmatched arm.
    c.clear_policy("").await;

    let unfiled = c.upload(&alice, "u.bin", None, None).await;
    let filed = c.upload(&alice, "f.bin", Some("misc/f.bin"), None).await;

    for key in [&unfiled, &filed] {
        assert_eq!(
            c.get_one(&alice, key).await,
            StatusCode::OK,
            "the uploader still reads their own file under the default"
        );
        assert_eq!(
            c.get_one(&bob, key).await,
            StatusCode::NOT_FOUND,
            "with nothing registered the default is owner-scoped, path or no path"
        );
    }
}

// ─── (e) clause-less legacy row ──────────────────────────────────────────────

#[tokio::test]
async fn a_clause_less_registry_row_denies_every_read() {
    let c = stack("rls-rd-clauseless").await;
    let (alice, _aid) = c.user("alice@x.com").await;
    // The write face refuses this shape (FILE_POLICY_OPEN_REQUIRES_FLAG), so a
    // hand-written row is the only source — and it must fail CLOSED.
    c.raw_policy_insert(
        "INSERT INTO \"_system_file_policy\" (prefix, owner_scoped, public_read, \
         select_policy_json, delete_policy_json) VALUES ('x/', 0, 0, NULL, NULL)",
    );
    let key = c.upload(&alice, "x.bin", Some("x/mine.bin"), None).await;

    assert_eq!(
        c.get_one(&alice, &key).await,
        StatusCode::NOT_FOUND,
        "'restricted but unspecified' denies even the uploader — never reads as open"
    );
    let anon = c.anon.clone();
    assert_eq!(c.get_one(&anon, &key).await, StatusCode::NOT_FOUND);
}

// ─── (f) delete semantics ────────────────────────────────────────────────────

#[tokio::test]
async fn delete_inherits_select_and_a_stricter_delete_clause_still_binds() {
    let c = stack("rls-rd-delete").await;
    let (alice, _aid) = c.user("alice@x.com").await;
    let (bob, _bid) = c.user("bob@x.com").await;

    // `pub/` — open to read, no delete clause ⇒ delete inherits select.
    c.put_policy(json!({"prefix": "pub/", "public_read": true}))
        .await;
    // `strict/` — open to read, but only the uploader may delete.
    c.put_policy(json!({
        "prefix": "strict/",
        "public_read": true,
        "delete": {"uploader": {"$auth": "id"}}
    }))
    .await;

    let inherited = c.upload(&alice, "p.bin", Some("pub/p.bin"), None).await;
    let strict = c.upload(&alice, "s.bin", Some("strict/s.bin"), None).await;

    assert_eq!(
        c.get_one(&bob, &strict).await,
        StatusCode::OK,
        "the select side stays open: bob can READ it"
    );
    assert_eq!(
        c.delete(&bob, &strict).await,
        StatusCode::NOT_FOUND,
        "…but the stricter delete clause refuses the delete"
    );
    assert_eq!(
        c.delete(&alice, &strict).await,
        StatusCode::NO_CONTENT,
        "the uploader satisfies the delete clause"
    );
    assert_eq!(
        c.delete(&bob, &inherited).await,
        StatusCode::NO_CONTENT,
        "with no delete clause the select semantics carry over — readable ⇒ deletable \
         (the Delete cap is the other half of the gate)"
    );
}

/// A refused delete must not have destroyed the object first: the gate runs
/// BEFORE the Garage call, so the file is still readable afterwards.
#[tokio::test]
async fn a_refused_delete_leaves_the_row_and_the_object_intact() {
    let c = stack("rls-rd-del-order").await;
    let (alice, _aid) = c.user("alice@x.com").await;
    let (bob, _bid) = c.user("bob@x.com").await;
    c.put_policy(json!({"prefix": "own/", "owner_scoped": true}))
        .await;
    let key = c.upload(&alice, "o.bin", Some("own/o.bin"), None).await;

    assert_eq!(c.delete(&bob, &key).await, StatusCode::NOT_FOUND);
    assert_eq!(
        c.bytes(&alice, &key).await,
        StatusCode::OK,
        "the bytes must survive a refused delete — the gate precedes the S3 delete"
    );
}

// ─── (g) the cap gate is still the outer one ─────────────────────────────────

#[tokio::test]
async fn passing_the_policy_does_not_grant_the_cap() {
    // Root seed leaves every prefix readable, so ONLY the missing cap can deny.
    let c = stack_with_caps("rls-rd-nocap", r#"["upload"]"#, r#"[]"#).await;
    let (alice, _aid) = c.user("alice@x.com").await;
    let key = c.upload(&alice, "a.bin", Some("any/a.bin"), None).await;

    assert_eq!(
        c.get_one(&alice, &key).await,
        StatusCode::FORBIDDEN,
        "the per-verb cap layer is OUTSIDE the RLS gate and still refuses first"
    );
}

// ─── (h) edge `get-file` under the caller's identity ─────────────────────────

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

fn file_caps_all() -> drust::tenant::file_caps::TenantFileCaps {
    use drust::storage::schema::FileVerb;
    let mut caps = drust::tenant::file_caps::TenantFileCaps::default();
    for v in [FileVerb::Read, FileVerb::Upload] {
        caps.user.insert(v);
        caps.anon.insert(v);
    }
    caps
}

#[tokio::test(flavor = "multi_thread")]
async fn edge_get_file_is_policy_gated_under_the_callers_identity() {
    use drust::auth::middleware::AuthCtx;
    let (mcp, _t) = edge_mcp("edge-read").await;
    let caps = file_caps_all();
    // A user-invoked put stamps the caller and leaves `path` NULL; with no root
    // policy registered (this DB was never seeded) the unmatched default is
    // owner-scoped, so only alice may read it back.
    drust::functions::enforce::enforced_put_file(
        &mcp,
        TokenRole::User,
        &caps,
        "u-alice",
        "e.bin",
        b"hello".to_vec(),
        "application/octet-stream",
        "private",
        0,
    )
    .await
    .unwrap();

    let alice = AuthCtx::User {
        user_id: "u-alice".into(),
        token_hash: String::new(),
    };
    let bytes = drust::functions::enforce::enforced_get_file_bytes(
        &mcp,
        &alice,
        &caps,
        "e.bin",
        4 * 1024 * 1024,
    )
    .await
    .expect("the uploader reads their own file");
    assert_eq!(bytes, b"hello");

    let err = drust::functions::enforce::enforced_get_file_bytes(
        &mcp,
        &AuthCtx::Anon,
        &caps,
        "e.bin",
        4 * 1024 * 1024,
    )
    .await
    .unwrap_err();
    assert!(
        err.contains("FILE_NOT_FOUND"),
        "an anon caller must not read another identity's owner-scoped file, and the \
         refusal must not double as an existence oracle — got {err:?}"
    );

    // The privileged path is unchanged: `get_file_bytes_raw` never consults a
    // policy (service-authored code, god mode).
    let raw = drust::functions::enforce::get_file_bytes_raw(&mcp, "e.bin", 4 * 1024 * 1024)
        .await
        .expect("privileged read is byte-identical to pre-v1.63");
    assert_eq!(raw, b"hello");
}

#[tokio::test(flavor = "multi_thread")]
async fn edge_get_file_honours_a_registered_open_prefix() {
    use drust::auth::middleware::AuthCtx;
    use drust::storage::file_policy::{FilePolicyRow, upsert_file_policy};
    let (mcp, _t) = edge_mcp("edge-read-open").await;
    let caps = file_caps_all();
    drust::functions::enforce::enforced_put_file(
        &mcp,
        TokenRole::User,
        &caps,
        "u-alice",
        "o.bin",
        b"hello".to_vec(),
        "application/octet-stream",
        "private",
        0,
    )
    .await
    .unwrap();
    // An unfiled row (`path` NULL) can only ever match the root.
    mcp.inner()
        .pool
        .with_writer(|c| {
            upsert_file_policy(
                c,
                &FilePolicyRow {
                    prefix: String::new(),
                    owner_scoped: false,
                    public_read: true,
                    select_policy: None,
                    delete_policy: None,
                },
            )
        })
        .await
        .unwrap();

    let bytes = drust::functions::enforce::enforced_get_file_bytes(
        &mcp,
        &AuthCtx::Anon,
        &caps,
        "o.bin",
        4 * 1024 * 1024,
    )
    .await
    .expect("an explicitly-open root lets an anon caller read");
    assert_eq!(bytes, b"hello");
}
