//! #976 T1 — the PRODUCING side of the two request extensions the realtime
//! faces consume: `PatDeadline` (inserted at BOTH admin-PAT resolution arms of
//! `bearer_auth_layer` — the cache-hit arm and the DB/CTE arm) and
//! `WsBaselineMeta` (inserted by the `ws_baseline_capture` layer that
//! `ws_router` mounts INSIDE bearer auth).
//!
//! The probe router mirrors the production `ws_router` layer order — capture
//! applied first = innermost — but swaps the WS/SSE routes for a plain handler
//! that reports what the extensions hold. No socket, so unlike `rooms_ws.rs`
//! these run in every gate.

use axum::body::Body;
use axum::extract::Extension;
use axum::http::{Request, StatusCode, header};
use axum::routing::get;
use axum::{Json, Router};
use drust::auth::admin_token;
use drust::storage::meta::open_meta;
use drust::storage::pool::TenantRegistry;
use drust::tenant::rooms::RoomBus;
use drust::tenant::rooms::ws_auth::{PatDeadline, WsBaselineMeta};
use drust::tenant::router::{TenantAuthState, bearer_auth_layer};
use rusqlite::params;
use std::sync::Arc;
use tokio::sync::Mutex;
use tower::ServiceExt;

const TENANT: &str = "t-cap";

/// Reports both extensions: `epoch0` is null when no baseline was captured,
/// `deadline` is null when the credential carries no hard expiry.
async fn probe(
    baseline: Option<Extension<WsBaselineMeta>>,
    deadline: Option<Extension<PatDeadline>>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "epoch0": baseline.map(|Extension(m)| m.epoch0),
        "deadline": deadline
            .map(|Extension(PatDeadline(exp))| exp.format("%Y-%m-%d %H:%M:%S").to_string()),
    }))
}

struct Fixture {
    /// Production shape: bearer auth OUTER, capture INNER.
    app: Router,
    /// Same routes with the capture layer left off — the fallback contract.
    app_no_capture: Router,
    /// Capture layer with NO auth in front of it: `TenantRef` never appears.
    app_capture_unauthed: Router,
    bus: RoomBus,
    /// PAT whose `_admin_tokens.expires_at` is non-NULL, plus that raw value.
    pat_expiring: String,
    pat_expires_at: String,
    /// PAT with `expires_at IS NULL`.
    pat_forever: String,
    /// Plain tenant service bearer.
    service_token: String,
    _dir: tempfile::TempDir,
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let conn = open_meta(&data.join("meta.sqlite")).unwrap();
    conn.execute(
        "INSERT INTO admins (username, password_hash, email) \
         VALUES ('a-exp', '$argon2id$v=19$m=19456,t=2,p=1$x$x', 'a-exp@example.com')",
        [],
    )
    .unwrap();
    let admin_expiring: i64 = conn.last_insert_rowid();
    conn.execute(
        "INSERT INTO admins (username, password_hash, email) \
         VALUES ('a-forever', '$argon2id$v=19$m=19456,t=2,p=1$x$x', 'a-forever@example.com')",
        [],
    )
    .unwrap();
    let admin_forever: i64 = conn.last_insert_rowid();
    conn.execute(
        "INSERT INTO tenants (id, name) VALUES (?1, 'cap')",
        params![TENANT],
    )
    .unwrap();
    let service_token = drust::auth::bearer::generate_token();
    conn.execute(
        "INSERT INTO tokens (tenant_id, token_hash, role) VALUES (?1, ?2, 'service')",
        params![TENANT, drust::auth::bearer::hash_token(&service_token)],
    )
    .unwrap();
    let _ = drust::storage::tenant_db::open_write(&data, TENANT).unwrap();
    drust::db::migrations::run_migrations(&conn, &data).unwrap();

    // Both PATs must reach this tenant, and `uniq_admin_tokens_active` allows
    // one active row per admin — so revoke whatever the migration backfill
    // minted before inserting the known plaintexts.
    conn.execute("UPDATE admins SET role='owner'", []).unwrap();
    conn.execute(
        "UPDATE _admin_tokens SET revoked_at = datetime('now') WHERE revoked_at IS NULL",
        [],
    )
    .unwrap();
    let pat_expiring = admin_token::generate_token();
    conn.execute(
        "INSERT INTO _admin_tokens (admin_id, token_hash, expires_at) \
         VALUES (?1, ?2, datetime('now', '+1 hour'))",
        params![admin_expiring, admin_token::hash_token(&pat_expiring)],
    )
    .unwrap();
    let pat_expires_at: String = conn
        .query_row(
            "SELECT expires_at FROM _admin_tokens WHERE admin_id = ?1 AND revoked_at IS NULL",
            params![admin_expiring],
            |r| r.get(0),
        )
        .unwrap();
    let pat_forever = admin_token::generate_token();
    conn.execute(
        "INSERT INTO _admin_tokens (admin_id, token_hash) VALUES (?1, ?2)",
        params![admin_forever, admin_token::hash_token(&pat_forever)],
    )
    .unwrap();

    let registry = Arc::new(TenantRegistry::new(data.clone(), 2));
    let state = TenantAuthState::test_default(Arc::new(Mutex::new(conn)), registry);
    let bus = state.bus_rooms.clone();

    // Layer order copies `ws_router` in src/tenant/mod.rs: `.layer()` applied
    // later is OUTER, so capture-then-bearer means capture runs INSIDE auth.
    let app = Router::new()
        .route("/t/{tenant}/probe", get(probe))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            drust::tenant::rooms::ws_auth::ws_baseline_capture,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            bearer_auth_layer,
        ))
        .with_state(state.clone());
    let app_no_capture = Router::new()
        .route("/t/{tenant}/probe", get(probe))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            bearer_auth_layer,
        ))
        .with_state(state.clone());
    let app_capture_unauthed = Router::new()
        .route("/t/{tenant}/probe", get(probe))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            drust::tenant::rooms::ws_auth::ws_baseline_capture,
        ))
        .with_state(state);

    Fixture {
        app,
        app_no_capture,
        app_capture_unauthed,
        bus,
        pat_expiring,
        pat_expires_at,
        pat_forever,
        service_token,
        _dir: dir,
    }
}

async fn probe_with(app: &Router, bearer: Option<&str>) -> serde_json::Value {
    let mut b = Request::builder().uri(format!("/t/{TENANT}/probe"));
    if let Some(tok) = bearer {
        b = b.header(header::AUTHORIZATION, format!("Bearer {tok}"));
    }
    let resp = app
        .clone()
        .oneshot(b.body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "probe request rejected");
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 16)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// The two arms are separate code paths: request 1 resolves through the meta
/// CTE and fills the auth cache, request 2 is served from that cache. Both
/// must carry the SAME deadline, or a PAT socket opened on a cache hit would
/// live forever.
#[tokio::test]
async fn pat_expiry_reaches_both_the_db_arm_and_the_cache_hit_arm() {
    let f = fixture().await;
    let first = probe_with(&f.app, Some(&f.pat_expiring)).await;
    assert_eq!(
        first["deadline"], f.pat_expires_at,
        "DB arm must insert PatDeadline: {first}"
    );
    let second = probe_with(&f.app, Some(&f.pat_expiring)).await;
    assert_eq!(
        second["deadline"], f.pat_expires_at,
        "cache-hit arm must insert the same PatDeadline: {second}"
    );
}

/// Credential-family rule: only an admin PAT carrying `expires_at` gets one.
#[tokio::test]
async fn no_deadline_for_a_never_expiring_pat_or_a_tenant_bearer() {
    let f = fixture().await;
    for (label, tok) in [
        ("PAT with expires_at IS NULL", &f.pat_forever),
        ("tenant service bearer", &f.service_token),
    ] {
        // Both arms again: DB first, then the cache hit.
        for pass in 1..=2 {
            let v = probe_with(&f.app, Some(tok)).await;
            assert!(
                v["deadline"].is_null(),
                "{label} must carry no deadline (pass {pass}): {v}"
            );
        }
    }
}

/// The baseline is the tenant's CURRENT epoch, read from the same handle
/// `evict_tenant` bumps — a capture that read a private atomic would keep
/// answering 0 here and never close an evicted socket.
#[tokio::test]
async fn baseline_is_captured_and_tracks_the_tenant_epoch() {
    let f = fixture().await;
    let before = probe_with(&f.app, Some(&f.service_token)).await;
    assert_eq!(before["epoch0"], 0, "fresh tenant epoch: {before}");
    f.bus.evict_tenant(TENANT);
    let after = probe_with(&f.app, Some(&f.service_token)).await;
    assert_eq!(
        after["epoch0"],
        f.bus
            .tenant_epoch_handle(TENANT)
            .load(std::sync::atomic::Ordering::SeqCst),
        "capture must read the live tenant epoch: {after}"
    );
    assert_eq!(
        after["epoch0"], 1,
        "evict_tenant bumps the baseline: {after}"
    );
}

/// Fallback contract: a mount without the layer produces no extension, which
/// is what sends the consumer to its inline capture (today's behavior).
#[tokio::test]
async fn no_capture_layer_means_no_baseline_extension() {
    let f = fixture().await;
    let v = probe_with(&f.app_no_capture, Some(&f.service_token)).await;
    assert!(v["epoch0"].is_null(), "unlayered mount captured: {v}");
}

/// `epochs` is an INSERTING keyspace, so the capture must fire only on a
/// VALIDATED tenant id — i.e. only when bearer auth already inserted
/// `TenantRef`. Skipping the capture IS skipping the `tenant_epoch_handle`
/// insert (one branch, both effects), so an unauthenticated request reaching
/// the layer must come back with no baseline at all.
#[tokio::test]
async fn capture_skips_when_tenant_ref_is_absent() {
    let f = fixture().await;
    let v = probe_with(&f.app_capture_unauthed, None).await;
    assert!(
        v["epoch0"].is_null(),
        "captured a baseline without a validated tenant: {v}"
    );
}
