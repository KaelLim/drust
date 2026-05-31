//! Shared OAuth test scaffolding factored from `tests/admin_oauth.rs`
//! (v1.11) so the v1.12 per-tenant OAuth integration tests can reuse the
//! fake-provider HTTP servers, cookie helpers, and audit-row pollers.
//!
//! Admin-specific helpers (the MgmtState builder + `spin_up_admin_*`) stay
//! in `tests/admin_oauth.rs`; only the actor-agnostic bits live here.

use axum::body::Body;
use axum::extract::Form;
use axum::http::{Response, StatusCode, header};
use axum::response::Json;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

// ---------- Process-global test audit writer ----------
//
// v1.25.2 retired the JSONL writer; `write_entry` now calls
// `audit_db::try_send`, which is a no-op until the global
// `AuditWriter` is initialised. The tests that assert on audit
// rows must call `ensure_test_audit_writer()` once per process.
//
// Design constraints:
//   (a) AuditWriter::new calls tokio::spawn — it must run on a runtime
//       that outlives individual #[tokio::test] runtimes (each test gets
//       its own runtime that drops at the end of the test).
//   (b) The NamedTempFile must survive the whole test-binary run.
//   (c) Read connections must be openable from any test thread.
//
// Solution: spawn a dedicated long-lived multi-thread Tokio runtime on a
// background std::thread. The LazyLock creates this runtime once, then
// uses `runtime.spawn(...)` to start the writer task inside it.

use std::path::PathBuf;
use std::sync::LazyLock;

static TEST_AUDIT_DB: LazyLock<PathBuf> = LazyLock::new(|| {
    // Persist a NamedTempFile for the whole test-binary run.
    let tmp = tempfile::NamedTempFile::new().expect("audit tmp file");
    let path = tmp.path().to_path_buf();

    // Open the write connection and apply schema.
    let conn = drust::safety::audit_db::open_audit_db_write(&path)
        .expect("open test audit DB");

    // We need the AuditWriter (which calls tokio::spawn internally) to run
    // on a runtime that outlives individual #[tokio::test] runtimes.
    // Solution: spawn a std::thread that owns a dedicated current-thread
    // Tokio runtime. The writer task lives on that runtime's thread and
    // persists after any individual test's runtime drops.
    //
    // A std::sync::mpsc channel synchronises: the thread signals `tx_ready`
    // after init_globals returns, so ensure_test_audit_writer() only returns
    // once the writer is ready to accept try_send() calls.
    let (tx_ready, rx_ready) = std::sync::mpsc::channel::<()>();
    std::thread::Builder::new()
        .name("test-audit-writer".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("build test-audit-writer runtime");
            rt.block_on(async move {
                let writer = drust::safety::audit_db::AuditWriter::new(conn);
                drust::safety::audit_db::init_globals(writer);
                // Signal caller that init is done.
                let _ = tx_ready.send(());
                // Keep this thread's runtime alive forever so the writer
                // task keeps running after individual tests finish.
                std::future::pending::<()>().await;
            });
        })
        .expect("spawn test-audit-writer thread");

    // Block until the writer is ready.
    rx_ready.recv().expect("test-audit-writer init signal");

    // Leak the NamedTempFile so the file is not deleted.
    Box::leak(Box::new(tmp));
    path
});

/// Ensure the global test audit writer is initialised. Call this before
/// any request that may emit an audit row — must be called from inside
/// a tokio context but the writer itself runs on a dedicated runtime.
pub fn ensure_test_audit_writer() {
    let _ = &*TEST_AUDIT_DB;
}

// ---------- Fake provider server ----------

#[derive(Clone)]
pub struct FakeScript {
    pub email: String,
    pub email_verified: bool,
    pub provider_user_id: String,
    /// Avatar URL the fake provider returns. Google emits this in the
    /// id_token `picture` claim; GitHub emits it as `avatar_url` on
    /// `GET /user`.
    pub picture: String,
}

impl Default for FakeScript {
    fn default() -> Self {
        Self {
            email: "kael@example.com".to_string(),
            email_verified: true,
            provider_user_id: "sub-default".to_string(),
            picture: "https://example.test/avatar.png".to_string(),
        }
    }
}

pub struct FakeProvider {
    pub base_url: String,
    pub last_code: Mutex<Option<String>>,
    pub script: Mutex<FakeScript>,
}

/// Spawn a fake Google OIDC provider on 127.0.0.1:0. Returns an Arc whose
/// `base_url` is the live `http://127.0.0.1:<port>` and whose `/token`
/// endpoint returns a synthesized id_token built from the current script.
pub async fn spawn_fake_google() -> Arc<FakeProvider> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{addr}");
    let state = Arc::new(FakeProvider {
        base_url: base_url.clone(),
        last_code: Mutex::new(None),
        script: Mutex::new(FakeScript::default()),
    });

    let st = state.clone();
    let app = axum::Router::new().route(
        "/token",
        axum::routing::post(move |Form(form): Form<HashMap<String, String>>| {
            let st = st.clone();
            async move {
                if let Some(code) = form.get("code") {
                    *st.last_code.lock().await = Some(code.clone());
                }
                let script = st.script.lock().await.clone();
                // v1.32 A2: include iss / aud / exp so decode_id_token passes
                // the OIDC §3.1.3.7 checks. Mirror the `client_id` field from
                // the token request back as `aud` — exactly what a real OIDC
                // provider does, and ensures any GoogleAdapter client_id works.
                let aud = form
                    .get("client_id")
                    .cloned()
                    .unwrap_or_else(|| "test-client-id".into());
                let exp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64
                    + 3600;
                let claims = serde_json::json!({
                    "sub": script.provider_user_id,
                    "email": script.email,
                    "email_verified": script.email_verified,
                    "name": "Kael",
                    "picture": script.picture,
                    "iss": "https://accounts.google.com",
                    "aud": aud,
                    "exp": exp,
                });
                let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
                let id_token = format!("header.{payload}.sig");
                Json(serde_json::json!({ "id_token": id_token }))
            }
        }),
    );
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    state
}

/// Variant of `spawn_fake_google` whose `/token` endpoint returns 400 so
/// `GoogleAdapter::exchange` (which calls `.error_for_status()?`) fails —
/// exercising the `oauth_provider_error` branch in `oauth_callback`.
pub async fn spawn_fake_google_returning_400() -> Arc<FakeProvider> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{addr}");
    let state = Arc::new(FakeProvider {
        base_url: base_url.clone(),
        last_code: Mutex::new(None),
        script: Mutex::new(FakeScript::default()),
    });

    let st = state.clone();
    let app = axum::Router::new().route(
        "/token",
        axum::routing::post(move |Form(form): Form<HashMap<String, String>>| {
            let st = st.clone();
            async move {
                if let Some(code) = form.get("code") {
                    *st.last_code.lock().await = Some(code.clone());
                }
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": "invalid_grant" })),
                )
            }
        }),
    );
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    state
}

/// Spawn a fake GitHub OAuth provider on 127.0.0.1:0. Exposes the three
/// endpoints `GitHubAdapter::exchange` calls.
pub async fn spawn_fake_github() -> Arc<FakeProvider> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{addr}");
    let state = Arc::new(FakeProvider {
        base_url: base_url.clone(),
        last_code: Mutex::new(None),
        script: Mutex::new(FakeScript::default()),
    });

    let st1 = state.clone();
    let st2 = state.clone();
    let st3 = state.clone();
    let app = axum::Router::new()
        .route(
            "/login/oauth/access_token",
            axum::routing::post(move |Form(form): Form<HashMap<String, String>>| {
                let st = st1.clone();
                async move {
                    if let Some(code) = form.get("code") {
                        *st.last_code.lock().await = Some(code.clone());
                    }
                    Json(serde_json::json!({
                        "access_token": "fake-token",
                        "token_type": "bearer",
                        "scope": "read:user user:email",
                    }))
                }
            }),
        )
        .route(
            "/user/emails",
            axum::routing::get(move || {
                let st = st2.clone();
                async move {
                    let script = st.script.lock().await.clone();
                    Json(serde_json::json!([{
                        "email": script.email,
                        "primary": true,
                        "verified": script.email_verified,
                    }]))
                }
            }),
        )
        .route(
            "/user",
            axum::routing::get(move || {
                let st = st3.clone();
                async move {
                    let script = st.script.lock().await.clone();
                    let id: u64 = script.provider_user_id.parse().unwrap_or(0);
                    Json(serde_json::json!({
                        "id": id,
                        "name": "Kael",
                        "avatar_url": script.picture,
                    }))
                }
            }),
        );
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    state
}

// ---------- Response helpers ----------

/// Pull a cookie VALUE (the bit before the first `;`) by name from all
/// `Set-Cookie` headers on a response. Returns `None` if absent.
pub fn extract_set_cookie(resp: &Response<Body>, name: &str) -> Option<String> {
    for v in resp.headers().get_all(header::SET_COOKIE).iter() {
        let raw = v.to_str().ok()?;
        let first = raw.split(';').next().unwrap_or("");
        if let Some((k, val)) = first.split_once('=') {
            if k.trim() == name {
                return Some(val.trim().to_string());
            }
        }
    }
    None
}

pub fn assert_redirect_contains(resp: &Response<Body>, fragment: &str) {
    let status = resp.status();
    assert!(
        status == StatusCode::FOUND || status == StatusCode::SEE_OTHER,
        "expected redirect, got {status}"
    );
    let loc = resp
        .headers()
        .get(header::LOCATION)
        .unwrap_or_else(|| panic!("no Location header on {status} response"))
        .to_str()
        .unwrap();
    assert!(loc.contains(fragment), "expected {fragment:?} in {loc:?}");
}

// ---------- Audit row helpers ----------
//
// v1.25.2 retired the JSONL writer; audit rows now live in the
// SQLite DB managed by the global AuditWriter. Touch TEST_AUDIT_DB
// to ensure the LazyLock initialises the writer before polling.

/// Poll the global test audit DB for a row matching `auth_method`.
/// `_log_dir` is accepted but ignored — kept for call-site compatibility
/// (callers pass the test's log_dir which is no longer written to).
pub async fn poll_for_audit_row(
    _log_dir: &std::path::Path,
    auth_method: &str,
    max_ms: u64,
) -> serde_json::Value {
    // Force LazyLock init so the global writer is running.
    let _ = &*TEST_AUDIT_DB;
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(max_ms);
    loop {
        if let Some(row) = try_find_audit_row_db(auth_method) {
            return row;
        }
        if std::time::Instant::now() >= deadline {
            panic!("audit row with auth_method={auth_method} not written within {max_ms}ms");
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

/// Query the global test audit DB for a row matching `auth_method`.
/// Returns a flattened JSON object that merges top-level DB columns
/// with any fields stored in the `extra` JSON blob, so test assertions
/// on `row["admin_id"]`, `row["auth_kind"]`, etc. work directly.
fn try_find_audit_row_db(auth_method: &str) -> Option<serde_json::Value> {
    let db_path = TEST_AUDIT_DB.as_path();
    let conn = drust::safety::audit_db::open_audit_db_read(db_path).ok()?;
    // The async writer flushes every 100 ms; a single checkpoint call
    // before reading ensures WAL frames are visible in the read conn.
    let _ = conn.execute_batch("PRAGMA wal_checkpoint(PASSIVE);");
    // Filter to success rows only; failure rows lack admin_id in extra.
    // ORDER BY id DESC picks the most-recently-inserted success row when
    // multiple tests write in parallel (parallel tests share this DB).
    let mut stmt = conn
        .prepare(
            "SELECT status, auth_method, oauth_email, extra, \
                    actor_admin_id, tenant \
             FROM audit WHERE auth_method = ?1 AND status = 'ok' \
             ORDER BY id DESC LIMIT 1",
        )
        .ok()?;
    stmt.query_row([auth_method], |r| {
        let status: Option<String> = r.get(0)?;
        let auth_method_col: Option<String> = r.get(1)?;
        let oauth_email: Option<String> = r.get(2)?;
        let extra_json: Option<String> = r.get(3)?;
        let actor_admin_id: Option<i64> = r.get(4)?;
        let tenant: Option<String> = r.get(5)?;
        // Build a base object with the direct columns.
        let mut map = serde_json::Map::new();
        if let Some(s) = status {
            map.insert("status".into(), serde_json::Value::String(s));
        }
        if let Some(m) = auth_method_col {
            map.insert("auth_method".into(), serde_json::Value::String(m));
        }
        if let Some(e) = oauth_email {
            map.insert("oauth_email".into(), serde_json::Value::String(e));
        }
        if let Some(id) = actor_admin_id {
            map.insert("admin_id".into(), serde_json::Value::Number(id.into()));
        }
        if let Some(t) = tenant {
            map.insert("tenant".into(), serde_json::Value::String(t));
        }
        // Merge fields from the `extra` JSON blob (auth_kind, admin_id,
        // auth_user_id, etc.) — direct columns win over extra.
        if let Some(extra_str) = extra_json {
            if let Ok(serde_json::Value::Object(extra_map)) =
                serde_json::from_str::<serde_json::Value>(&extra_str)
            {
                for (k, v) in extra_map {
                    map.entry(k).or_insert(v);
                }
            }
        }
        Ok(serde_json::Value::Object(map))
    })
    .ok()
}

/// Legacy JSONL-based helper kept so any callers that still compile
/// against the old signature get a no-op result (returns None always).
/// New code should use `try_find_audit_row_db` directly.
pub fn try_find_audit_row(
    _log_dir: &std::path::Path,
    _auth_method: &str,
) -> Option<serde_json::Value> {
    None
}
