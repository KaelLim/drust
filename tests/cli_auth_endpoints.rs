//! T6/T7 (CLI Phase 2 §S4) — CLI-PAT lifecycle endpoints + admin-UI management.
//!
//! Covers the three public self-authenticating endpoints
//!   GET    /auth/cli/whoami
//!   POST   /auth/cli/token/refresh
//!   DELETE /auth/cli/token
//! plus the cookie-gated admin-UI revoke route + settings-page listing.
//!
//! Helper shape modeled on `tests/admin_pat_reroll.rs` (spin_up / insert_admin /
//! body_json / OnceLock audit writer) and the labeled-CLI-PAT seeding from T4.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use drust::auth::admin_token::{generate_cli_token, hash_token};
use drust::mgmt::routes::MgmtState;
use drust::safety::audit_db::{AuditWriter, open_audit_db_read, open_audit_db_write};
use drust::storage::meta::{bootstrap_admin, open_meta};
use drust::tenant::rooms::RoomBus;
use rusqlite::{Connection, params};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering::SeqCst;
use tempfile::{TempDir, tempdir};
use tokio::sync::Mutex;
use tower::ServiceExt;

// ─── harness ────────────────────────────────────────────────────────────────

fn build_state(conn: rusqlite::Connection, data_dir: PathBuf, log_dir: PathBuf) -> MgmtState {
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
        data_dir,
        tenants,
        mcp,
        bus,
        drust::tenant::rooms::RoomBus::new(),
    );
    state.log_dir = log_dir;
    state
}

/// Spin up a mgmt router with one bootstrapped owner admin (id=1).
///
/// Production order (bootstrap_admin → run_migrations) so the backfill loop
/// mints admin 1's unlabeled UI PAT (with plaintext) — `ui_pat_of` reads it.
async fn spin_up() -> (axum::Router, TempDir) {
    let (app, dir, _bus) = spin_up_with_bus().await;
    (app, dir)
}

/// #975 — same router, plus the SHARED `RoomBus` the CLI-PAT lifecycle
/// handlers evict through, so a test can observe a tenant's eviction epoch
/// across a REST call.
async fn spin_up_with_bus() -> (axum::Router, TempDir, RoomBus) {
    let dir = tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let log_dir = data_dir.join("audit");
    std::fs::create_dir_all(&log_dir).unwrap();
    let mut conn = open_meta(&data_dir.join("meta.sqlite")).unwrap();
    bootstrap_admin(&mut conn, "root", "hunter2").unwrap();
    drust::db::migrations::run_migrations(&conn, &data_dir).unwrap();
    let state = build_state(conn, data_dir.clone(), log_dir);
    let bus_rooms = state.bus_rooms.clone();
    let app = state.with_data_dir(data_dir);
    (app, dir, bus_rooms)
}

fn open_meta_ro(dir: &TempDir) -> Connection {
    Connection::open(dir.path().join("meta.sqlite")).unwrap()
}

/// Insert a labeled CLI PAT for `admin_id`; return `(row_id, plaintext)`.
/// Labeled rows do not collide with the unlabeled UI PAT under the relaxed
/// `uniq_admin_tokens_active` index.
fn insert_cli_pat(dir: &TempDir, admin_id: i64, label: &str) -> (i64, String) {
    let pt = generate_cli_token();
    let h = hash_token(&pt);
    let conn = open_meta_ro(dir);
    conn.execute(
        "INSERT INTO _admin_tokens (admin_id, token_hash, plaintext, label, expires_at) \
         VALUES (?1, ?2, ?3, ?4, datetime('now','+1 day'))",
        params![admin_id, h, pt, label],
    )
    .unwrap();
    (conn.last_insert_rowid(), pt)
}

/// #975 T2 review — a tenant row with an explicit owner, so the reach-scoped
/// eviction set (`SELECT id FROM tenants WHERE owner_admin_id = ?`) has
/// something to select.
fn insert_tenant(dir: &TempDir, id: &str, owner: i64) {
    let conn = open_meta_ro(dir);
    conn.execute(
        "INSERT INTO tenants (id, name, owner_admin_id) VALUES (?1, ?2, ?3)",
        params![id, id, owner],
    )
    .unwrap();
}

/// Seed a labeled CLI PAT for the bootstrapped admin (id=1). Returns
/// `(admin_id, plaintext)`.
///
/// That admin is bootstrapped BEFORE `run_migrations`, so the v1.29 role
/// backfill makes it an `owner` — i.e. `sees_all_tenants`, whose PAT really
/// does reach every tenant. Tests that need the NARROW reach must make their
/// own `member` (see `insert_admin`).
fn seed_cli_pat(dir: &TempDir, label: &str) -> (i64, String) {
    let (_, pt) = insert_cli_pat(dir, 1, label);
    (1, pt)
}

async fn body_json(resp: axum::http::Response<Body>) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 65_536)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

// ─── T6 §4.3 — GET /auth/cli/whoami ──────────────────────────────────────────

#[tokio::test]
async fn whoami_returns_admin_consoles_and_tenants_endpoint() {
    let (app, dir) = spin_up().await;
    let (admin_id, pat) = seed_cli_pat(&dir, "cli:laptop");
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/auth/cli/whoami")
                .header(header::AUTHORIZATION, format!("Bearer {pat}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let b = body_json(resp).await;
    assert_eq!(b["admin"]["id"], serde_json::json!(admin_id));
    assert_eq!(b["consoles"][0]["id"], "default");
    assert_eq!(b["tenants_endpoint"], "/admin/api/cmdk/tenants");
    assert!(b["consoles"].as_array().unwrap().len() == 1); // OSS cardinality 1
}

#[tokio::test]
async fn whoami_rejects_missing_bearer_with_json_401_not_redirect() {
    let (app, _dir) = spin_up().await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/auth/cli/whoami")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED); // JSON, never 303
    assert_eq!(body_json(resp).await["error_code"], "CLI_AUTH_REQUIRED");
}

// ─── read helpers (T6 refresh / logout / UI revoke) ───────────────────────────

fn hash_of(t: &str) -> String {
    hash_token(t)
}

fn post_bearer(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

/// The bootstrapped admin's backfilled unlabeled UI PAT: `(admin_id, plaintext)`.
fn ui_pat_of(dir: &TempDir) -> (i64, String) {
    let conn = open_meta_ro(dir);
    conn.query_row(
        "SELECT admin_id, plaintext FROM _admin_tokens \
         WHERE revoked_at IS NULL AND label IS NULL",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .unwrap()
}

fn is_revoked(conn: &Connection, hash: &str) -> bool {
    let revoked: Option<String> = conn
        .query_row(
            "SELECT revoked_at FROM _admin_tokens WHERE token_hash = ?1",
            params![hash],
            |r| r.get(0),
        )
        .unwrap();
    revoked.is_some()
}

fn active_labeled_count(conn: &Connection, admin_id: i64) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM _admin_tokens \
         WHERE admin_id = ?1 AND label IS NOT NULL AND revoked_at IS NULL",
        params![admin_id],
        |r| r.get(0),
    )
    .unwrap()
}

// ─── T6 — POST /auth/cli/token/refresh ────────────────────────────────────────

#[tokio::test]
async fn refresh_mints_labeled_pat_and_revokes_only_the_old_one() {
    let (app, dir) = spin_up().await;
    let (admin_id, ui_pat) = ui_pat_of(&dir); // the backfilled unlabeled UI PAT
    let (_, old_cli) = seed_cli_pat(&dir, "cli:laptop");
    let old_hash = hash_of(&old_cli);
    let resp = app
        .oneshot(post_bearer("/auth/cli/token/refresh", &old_cli))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let b = body_json(resp).await;
    let new_tok = b["access_token"].as_str().unwrap();
    assert!(new_tok.starts_with("drust_pat_cli_")); // T4 generate_cli_token
    assert!(b["expires_at"].is_string());
    // old CLI PAT now revoked, new one active+labeled, UI PAT untouched
    let c = open_meta_ro(&dir);
    assert!(is_revoked(&c, &old_hash));
    assert_eq!(active_labeled_count(&c, admin_id), 1);
    assert!(!is_revoked(&c, &hash_of(&ui_pat))); // UI PAT survives
}

/// v1.45.1 (F2) — two concurrent refreshes of the SAME CLI PAT must never leave
/// two active successors. The meta mutex is released between `resolve_cli_caller`
/// and the mint/revoke tx, so both requests can resolve the token as active; the
/// fix revokes-conditional FIRST inside the tx and aborts (409) the loser instead
/// of minting a second successor. Shared router (one meta connection, as in prod)
/// on a 2-worker runtime: tokio Mutex FIFO fairness forces both resolves ahead of
/// the tx phase, so pre-fix this reliably leaves 2 active labeled PATs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_refresh_replay_never_mints_a_second_active_pat() {
    let (app, dir) = spin_up().await;
    let (admin_id, _ui) = ui_pat_of(&dir);
    let (_, old_cli) = seed_cli_pat(&dir, "cli:laptop");
    let (a, b) = (app.clone(), app.clone());
    let (t1, t2) = (old_cli.clone(), old_cli.clone());
    let h1 =
        tokio::spawn(async move { a.oneshot(post_bearer("/auth/cli/token/refresh", &t1)).await });
    let h2 =
        tokio::spawn(async move { b.oneshot(post_bearer("/auth/cli/token/refresh", &t2)).await });
    let s1 = h1.await.unwrap().unwrap().status();
    let s2 = h2.await.unwrap().unwrap().status();
    let c = open_meta_ro(&dir);
    assert_eq!(
        active_labeled_count(&c, admin_id),
        1,
        "a replayed refresh minted a second active PAT (statuses={s1:?}, {s2:?})"
    );
}

/// #975 — refresh soft-revokes the OLD CLI PAT, which resolves to
/// `AuthCtx::Service` on every tenant its admin can see and may be holding
/// live rooms WS sockets there. The seeded admin is an `owner`
/// (`sees_all_tenants`), so "every tenant it can see" is the whole host.
#[tokio::test]
async fn refresh_by_a_sees_all_admin_evicts_host_wide() {
    let (app, dir, bus) = spin_up_with_bus().await;
    let (_, old_cli) = seed_cli_pat(&dir, "cli:laptop");
    let ha = bus.tenant_epoch_handle("t-a");
    let hb = bus.tenant_epoch_handle("t-b");

    let resp = app
        .oneshot(post_bearer("/auth/cli/token/refresh", &old_cli))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    assert_eq!(ha.load(SeqCst), 1, "refresh must evict (tenant t-a)");
    assert_eq!(hb.load(SeqCst), 1, "evict must be host-wide (tenant t-b)");
}

/// #975 T2 review (MED), the narrow direction — and the one that exercises the
/// PUBLIC-router shape: `/auth/cli/token/refresh` self-authenticates against
/// the bearer being rotated, so there is no admin session and no
/// `AdminProfileExt` here. The reach still has to come out right, which is why
/// `mgmt::pat_evict` re-reads `admins.role` from `meta` rather than taking the
/// extension. A `member`'s CLI must not be able to disconnect a tenant that
/// member cannot even see.
#[tokio::test]
async fn refresh_by_a_member_evicts_only_the_tenants_that_member_owns() {
    let (app, dir, bus) = spin_up_with_bus().await;
    let (member_id, _) = insert_admin(&dir, "cli-member@x", "member");
    let (_, old_cli) = insert_cli_pat(&dir, member_id, "cli:laptop");
    insert_tenant(&dir, "t-mine", member_id);
    insert_tenant(&dir, "t-theirs", 1); // the bootstrapped owner's tenant
    let h_mine = bus.tenant_epoch_handle("t-mine");
    let h_theirs = bus.tenant_epoch_handle("t-theirs");

    let resp = app
        .oneshot(post_bearer("/auth/cli/token/refresh", &old_cli))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    assert_eq!(h_mine.load(SeqCst), 1, "the member's own tenant is evicted");
    assert_eq!(
        h_theirs.load(SeqCst),
        0,
        "a member refreshing their own CLI token must not kick another \
         admin's tenant — the bearer CTE would have refused their PAT there \
         (PAT_TENANT_DENIED), so no socket there is theirs"
    );
}

#[tokio::test]
async fn refresh_refuses_the_unlabeled_ui_pat() {
    let (app, dir) = spin_up().await;
    let (_, ui_pat) = ui_pat_of(&dir);
    let resp = app
        .oneshot(post_bearer("/auth/cli/token/refresh", &ui_pat))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_json(resp).await["error_code"], "NOT_A_CLI_TOKEN");
}

// ─── audit + second-router helpers (T6 logout) ────────────────────────────────

/// Build a fresh mgmt router over an EXISTING meta.sqlite (no bootstrap /
/// migrate) — `oneshot` consumes a router, so a second probe needs a new one.
fn app2(dir: &TempDir) -> axum::Router {
    let data_dir = dir.path().to_path_buf();
    let log_dir = data_dir.join("audit");
    let conn = open_meta(&data_dir.join("meta.sqlite")).unwrap();
    let state = build_state(conn, data_dir.clone(), log_dir);
    state.with_data_dir(data_dir)
}

/// Initialize the process-global audit writer once per test binary (OnceLock,
/// modeled on `tests/admin_pat_reroll.rs::reroll_emits_revoke_and_mint_audit_rows`).
///
/// Unlike that single-audit-test oracle, this binary has TWO audit-asserting
/// tests (logout + UI-revoke). `AuditWriter::new` spawns its drain task via
/// `tokio::spawn`, which binds to the CURRENT runtime — so if the first
/// `#[tokio::test]` to init the writer finishes before a later test reads, its
/// runtime (and the drain task) is gone and the later test's rows never persist.
/// Host the writer on a dedicated LEAKED multi-thread runtime so the drain task
/// outlives every per-test runtime.
static AUDIT_PATH: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
fn init_global_audit() {
    AUDIT_PATH.get_or_init(|| {
        let dir = Box::new(tempdir().unwrap());
        let path = dir.path().join("test_global_audit_cli_auth.sqlite");
        let conn = open_audit_db_write(&path).unwrap();
        let rt = Box::leak(Box::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .unwrap(),
        ));
        let _guard = rt.enter(); // AuditWriter::new's tokio::spawn lands on `rt`
        let writer = AuditWriter::new(conn);
        drust::safety::audit_db::init_globals(writer);
        Box::leak(dir); // keep the directory alive for the process
        path
    });
}

/// True if an audit row with `op` + `actor_admin_id == Some(admin_id)` landed.
fn audit_has(op: &str, admin_id: i64) -> bool {
    let path = AUDIT_PATH.get().expect("init_global_audit must run first");
    let r = open_audit_db_read(path).unwrap();
    let mut stmt = r
        .prepare("SELECT actor_admin_id FROM audit WHERE op = ?1 ORDER BY id DESC LIMIT 50")
        .unwrap();
    let rows: Vec<Option<i64>> = stmt
        .query_map(params![op], |row| row.get::<_, Option<i64>>(0))
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();
    rows.contains(&Some(admin_id))
}

// ─── T6 — DELETE /auth/cli/token (logout self-revoke) ─────────────────────────

#[tokio::test]
async fn logout_revokes_the_authenticating_cli_token_and_fires_audit() {
    init_global_audit(); // OnceLock pattern from admin_pat_reroll.rs
    let (app, dir) = spin_up().await;
    let (admin_id, cli) = seed_cli_pat(&dir, "cli:laptop");
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/auth/cli/token")
                .header(header::AUTHORIZATION, format!("Bearer {cli}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["revoked"], serde_json::json!(true));
    assert!(is_revoked(&open_meta_ro(&dir), &hash_of(&cli)));
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    assert!(audit_has("admin.token.revoke", admin_id)); // reads meta_logs
    // same token no longer authenticates
    let r2 = app2(&dir)
        .oneshot(post_bearer("/auth/cli/token/refresh", &cli))
        .await
        .unwrap();
    assert_eq!(r2.status(), StatusCode::UNAUTHORIZED);
}

/// v1.45.1 (F6) — logout with the unlabeled UI PAT must report `{"revoked":false}`
/// (the `label IS NOT NULL` scope correctly leaves the UI PAT alone; only the
/// response used to lie). The UI PAT still resolves afterward.
#[tokio::test]
async fn logout_with_ui_pat_reports_not_revoked_and_leaves_it_active() {
    let (app, dir) = spin_up().await;
    let (_admin_id, ui_pat) = ui_pat_of(&dir);
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/auth/cli/token")
                .header(header::AUTHORIZATION, format!("Bearer {ui_pat}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["revoked"], serde_json::json!(false));
    // UI PAT untouched → still resolves.
    assert!(!is_revoked(&open_meta_ro(&dir), &hash_of(&ui_pat)));
}

/// #975 — a logout that actually revoked something (`n > 0`) must close the
/// revoked PAT's live rooms sockets. The seeded admin is an `owner`, so the
/// reach is the whole host.
#[tokio::test]
async fn logout_by_a_sees_all_admin_evicts_host_wide() {
    let (app, dir, bus) = spin_up_with_bus().await;
    let (_admin_id, cli) = seed_cli_pat(&dir, "cli:laptop");
    let ha = bus.tenant_epoch_handle("t-a");
    let hb = bus.tenant_epoch_handle("t-b");

    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/auth/cli/token")
                .header(header::AUTHORIZATION, format!("Bearer {cli}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    assert_eq!(ha.load(SeqCst), 1, "logout must evict (tenant t-a)");
    assert_eq!(hb.load(SeqCst), 1, "evict must be host-wide (tenant t-b)");
}

/// #975 T2 review (MED), narrow direction — a `member`'s CLI logout closes
/// only that member's own tenants.
#[tokio::test]
async fn logout_by_a_member_evicts_only_the_tenants_that_member_owns() {
    let (app, dir, bus) = spin_up_with_bus().await;
    let (member_id, _) = insert_admin(&dir, "cli-logout-member@x", "member");
    let (_, cli) = insert_cli_pat(&dir, member_id, "cli:laptop");
    insert_tenant(&dir, "t-mine", member_id);
    insert_tenant(&dir, "t-theirs", 1);
    let h_mine = bus.tenant_epoch_handle("t-mine");
    let h_theirs = bus.tenant_epoch_handle("t-theirs");

    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/auth/cli/token")
                .header(header::AUTHORIZATION, format!("Bearer {cli}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    assert_eq!(h_mine.load(SeqCst), 1, "the member's own tenant is evicted");
    assert_eq!(
        h_theirs.load(SeqCst),
        0,
        "a member logging out must not kick another admin's tenant"
    );
}

/// #975, the other direction — a logout that revoked NOTHING (`n == 0`; here
/// the unlabeled UI PAT, which the `label IS NOT NULL` scope excludes) must
/// NOT evict. Nothing was revoked, so there is no stale credential to close,
/// and evicting anyway would kick live subscribers for a no-op (spec
/// §隔離與資安不變量 4, the "真變才 evict" rule) — and for a `sees_all_tenants`
/// caller that no-op reaches every tenant on the host.
#[tokio::test]
async fn logout_with_nothing_to_revoke_does_not_evict() {
    let (app, dir, bus) = spin_up_with_bus().await;
    let (_admin_id, ui_pat) = ui_pat_of(&dir);
    let ha = bus.tenant_epoch_handle("t-a");

    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/auth/cli/token")
                .header(header::AUTHORIZATION, format!("Bearer {ui_pat}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["revoked"], serde_json::json!(false));

    assert_eq!(
        ha.load(SeqCst),
        0,
        "a no-op logout must not kick anyone's sockets"
    );
}

// ─── T7 helpers (cookie-gated admin-UI revoke) ────────────────────────────────

/// Insert an admin directly + create a session. Returns `(admin_id, cookie)`.
/// Modeled on `tests/admin_pat_reroll.rs::insert_admin`.
fn insert_admin(dir: &TempDir, email: &str, role: &str) -> (i64, String) {
    let conn = open_meta_ro(dir);
    let username = email.split('@').next().unwrap_or("admin").to_string();
    conn.execute(
        "INSERT INTO admins (username, password_hash, email, role) VALUES (?1, '$oauth-only$', ?2, ?3)",
        params![username, email, role],
    )
    .unwrap();
    let admin_id = conn.last_insert_rowid();
    let session_token = {
        use base64::Engine;
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    };
    let expires_at = chrono::Utc::now() + chrono::Duration::days(7);
    conn.execute(
        "INSERT INTO sessions (token, admin_id, expires_at) VALUES (?1, ?2, ?3)",
        params![session_token, admin_id, expires_at.to_rfc3339()],
    )
    .unwrap();
    (admin_id, format!("drust_session={session_token}"))
}

/// Seed a labeled CLI PAT for `admin_id`; return the new row id.
fn seed_cli_pat_for(dir: &TempDir, admin_id: i64, label: &str) -> i64 {
    insert_cli_pat(dir, admin_id, label).0
}

fn row_is_revoked(conn: &Connection, id: i64) -> bool {
    let revoked: Option<String> = conn
        .query_row(
            "SELECT revoked_at FROM _admin_tokens WHERE id = ?1",
            params![id],
            |r| r.get(0),
        )
        .unwrap();
    revoked.is_some()
}

// ─── T7 — POST /admin/settings/cli-tokens/{id}/revoke ─────────────────────────

#[tokio::test]
async fn ui_revoke_soft_revokes_scoped_to_caller_and_fires_clear_and_audit() {
    init_global_audit();
    let (app, dir) = spin_up().await;
    let (admin_id, session) = insert_admin(&dir, "kael@x", "owner");
    let id = seed_cli_pat_for(&dir, admin_id, "cli:laptop"); // returns row id
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/admin/settings/cli-tokens/{id}/revoke"))
                .header(header::COOKIE, &session)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER); // 303 → /admin/settings
    assert!(row_is_revoked(&open_meta_ro(&dir), id));
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    assert!(audit_has("admin.token.revoke", admin_id));
}

#[tokio::test]
async fn ui_revoke_cannot_touch_another_admins_token_or_the_ui_pat() {
    let (app, dir) = spin_up().await;
    let (_a, session) = insert_admin(&dir, "a@x", "owner");
    let (b_id, _) = insert_admin(&dir, "b@x", "member");
    let other = seed_cli_pat_for(&dir, b_id, "cli:other"); // belongs to admin B
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/admin/settings/cli-tokens/{other}/revoke"))
                .header(header::COOKIE, &session)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND); // CLI_TOKEN_NOT_FOUND, fail-closed
    assert!(!row_is_revoked(&open_meta_ro(&dir), other));
}

/// #975 — the admin-UI per-row revoke kills a CLI PAT that may hold live rooms
/// sockets on any tenant its admin reaches; for an `owner` that is the host.
#[tokio::test]
async fn ui_revoke_by_a_sees_all_admin_evicts_host_wide() {
    let (app, dir, bus) = spin_up_with_bus().await;
    let (admin_id, session) = insert_admin(&dir, "kael-evict@x", "owner");
    let id = seed_cli_pat_for(&dir, admin_id, "cli:laptop");
    let ha = bus.tenant_epoch_handle("t-a");
    let hb = bus.tenant_epoch_handle("t-b");

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/admin/settings/cli-tokens/{id}/revoke"))
                .header(header::COOKIE, &session)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    assert_eq!(ha.load(SeqCst), 1, "ui revoke must evict (tenant t-a)");
    assert_eq!(hb.load(SeqCst), 1, "evict must be host-wide (tenant t-b)");
}

/// #975 T2 review (MED), narrow direction — this route is the second one on
/// `settings_router` (no `require_owner_layer`), so a `member` reaches it with
/// nothing but a session and a CLI token of their own. Their revoke must stop
/// at the tenants they own.
#[tokio::test]
async fn ui_revoke_by_a_member_evicts_only_the_tenants_that_member_owns() {
    let (app, dir, bus) = spin_up_with_bus().await;
    let (member_id, session) = insert_admin(&dir, "kael-member-evict@x", "member");
    let id = seed_cli_pat_for(&dir, member_id, "cli:laptop");
    insert_tenant(&dir, "t-mine", member_id);
    insert_tenant(&dir, "t-theirs", 1);
    let h_mine = bus.tenant_epoch_handle("t-mine");
    let h_theirs = bus.tenant_epoch_handle("t-theirs");

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/admin/settings/cli-tokens/{id}/revoke"))
                .header(header::COOKIE, &session)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    assert_eq!(h_mine.load(SeqCst), 1, "the member's own tenant is evicted");
    assert_eq!(
        h_theirs.load(SeqCst),
        0,
        "a member revoking their own CLI token must not kick another admin's \
         tenant"
    );
}

/// #975, the other direction — a revoke that matched no row 404s before the
/// clear/evict pair, so it must not bump anything. Otherwise a guessed token
/// id becomes a disconnect button — host-wide in the hands of the `owner` this
/// test uses.
#[tokio::test]
async fn ui_revoke_that_matches_no_row_does_not_evict() {
    let (app, dir, bus) = spin_up_with_bus().await;
    let (_a, session) = insert_admin(&dir, "a-evict@x", "owner");
    let (b_id, _) = insert_admin(&dir, "b-evict@x", "member");
    let other = seed_cli_pat_for(&dir, b_id, "cli:other"); // belongs to admin B
    let ha = bus.tenant_epoch_handle("t-a");

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/admin/settings/cli-tokens/{other}/revoke"))
                .header(header::COOKIE, &session)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    assert_eq!(
        ha.load(SeqCst),
        0,
        "a revoke that changed nothing must not kick anyone's sockets"
    );
}

// ─── T7 — settings page lists labeled CLI tokens ──────────────────────────────

#[tokio::test]
async fn settings_page_lists_labeled_cli_tokens() {
    let (app, dir) = spin_up().await;
    let (admin_id, session) = insert_admin(&dir, "kael@x", "owner");
    seed_cli_pat_for(&dir, admin_id, "cli:macbook");
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/settings")
                .header(header::COOKIE, &session)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let html = String::from_utf8(
        axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(html.contains("cli:macbook"));
    assert!(html.contains("/admin/settings/cli-tokens/")); // a revoke form action
}
