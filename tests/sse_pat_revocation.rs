//! E2′ — revoking an admin PAT ends the SSE streams that admin's PATs opened.
//!
//! An SSE stream opened with an admin PAT resolves to `AuthCtx::Service`, so
//! it is unfiltered, and a UI PAT carries no `expires_at`, so #976's deadline
//! never ends it. The PAT-revocation sites now send a per-ADMIN signal after
//! their auth-cache clear; these tests drive the real revocation handlers
//! against the SAME meta, auth cache and `RoomBus` the data plane serves from
//! (one `spin_up_tenant_rooms` harness), and watch real streams.
//!
//! The two probe-router tests at the end pin WHY `ws_router` reads the
//! revocation generation outside bearer auth.

mod helpers;

use axum::Router;
use axum::body::Body;
use axum::extract::{Extension, Path, State};
use axum::http::{Request, StatusCode, header};
use axum::routing::get;
use drust::auth::middleware::AdminId;
use drust::mgmt::routes::MgmtState;
use drust::tenant::rooms::RoomsConfig;
use eventsource_stream::Eventsource;
use futures::StreamExt;
use rusqlite::params;
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

const TENANT: &str = "t-sse-pat";

type Events = std::pin::Pin<
    Box<
        dyn futures::Stream<
                Item = Result<
                    eventsource_stream::Event,
                    eventsource_stream::EventStreamError<std::io::Error>,
                >,
            > + Send,
    >,
>;

struct Fx {
    h: helpers::RoomsHarness,
    mgmt: MgmtState,
    service: String,
    a_id: i64,
    a_pat: String,
    a_cli_id: i64,
    a_cli: String,
    b_id: i64,
    b_pat: String,
}

async fn fixture() -> Fx {
    let h = helpers::spin_up_tenant_rooms(TENANT, "anon", RoomsConfig::test_defaults()).await;

    let service = drust::auth::bearer::generate_token();
    let a_pat = drust::auth::admin_token::generate_token();
    let b_pat = drust::auth::admin_token::generate_token();
    let a_cli = drust::auth::admin_token::generate_cli_token();
    let (a_id, b_id, a_cli_id) = {
        let conn = h.meta.lock().await;
        conn.execute(
            "INSERT INTO tokens (tenant_id, token_hash, role) VALUES (?1, ?2, 'service')",
            params![TENANT, drust::auth::bearer::hash_token(&service)],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO admins (username, password_hash, email, role) \
             VALUES ('sse-a', '$argon2id$v=19$m=19456,t=2,p=1$x$x', 'sse-a@example.com', 'owner')",
            [],
        )
        .unwrap();
        let a_id = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO admins (username, password_hash, email, role) \
             VALUES ('sse-b', '$argon2id$v=19$m=19456,t=2,p=1$x$x', 'sse-b@example.com', 'owner')",
            [],
        )
        .unwrap();
        let b_id = conn.last_insert_rowid();
        // A no-op today (the admins are inserted after `run_migrations`, and a
        // plain INSERT mints nothing); kept so a helper change that inserts
        // admins earlier cannot collide with `uniq_admin_tokens_active`.
        conn.execute(
            "UPDATE _admin_tokens SET revoked_at = datetime('now') \
             WHERE revoked_at IS NULL AND admin_id IN (?1, ?2)",
            params![a_id, b_id],
        )
        .unwrap();
        for (id, pat) in [(a_id, &a_pat), (b_id, &b_pat)] {
            conn.execute(
                "INSERT INTO _admin_tokens (admin_id, token_hash) VALUES (?1, ?2)",
                params![id, drust::auth::admin_token::hash_token(pat)],
            )
            .unwrap();
        }
        conn.execute(
            "INSERT INTO _admin_tokens (admin_id, token_hash, label, expires_at) \
             VALUES (?1, ?2, 'cli', datetime('now', '+1 hour'))",
            params![a_id, drust::auth::admin_token::hash_token(&a_cli)],
        )
        .unwrap();
        (a_id, b_id, conn.last_insert_rowid())
    };

    let pool = h.tenants.get_or_create(TENANT).unwrap();
    pool.with_writer(|c| {
        c.execute_batch("CREATE TABLE posts (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT);")?;
        drust::storage::schema::write_realtime_enabled(c, "posts", true)?;
        Ok::<_, rusqlite::Error>(())
    })
    .await
    .unwrap();

    // meta, auth cache and RoomBus are the data plane's own instances — a
    // revocation driven through a state built on copies would prove nothing.
    let mut mgmt = MgmtState::test_default(
        h.meta.clone(),
        h.data_dir.clone(),
        h.tenants.clone(),
        Arc::new(drust::mcp::http_registry::McpHttpRegistry::new(
            h.mcp.clone(),
        )),
        drust::tenant::events::EventBus::new(),
        h.bus_rooms.clone(),
    );
    mgmt.auth_cache = h.auth_cache.clone();

    Fx {
        h,
        mgmt,
        service,
        a_id,
        a_pat,
        a_cli_id,
        a_cli,
        b_id,
        b_pat,
    }
}

fn owner_profile() -> drust::mgmt::admin_profile::AdminProfileExt {
    drust::mgmt::admin_profile::AdminProfileExt {
        display_name: Some("sse-a".into()),
        email: None,
        picture_url: None,
        initials: "S".into(),
        role: "owner".into(),
        is_owner: true,
        is_admin: false,
        sees_all_tenants: true,
        sees_team: true,
    }
}

async fn subscribe(app: &Router, bearer: &str) -> axum::http::Response<Body> {
    app.clone()
        .oneshot(
            Request::builder()
                .uri(format!("/t/{TENANT}/records/posts/subscribe"))
                .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                .header(header::ACCEPT, "text/event-stream")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

fn into_events(resp: axum::http::Response<Body>) -> Events {
    let (tx, rx) = tokio::sync::mpsc::channel(8);
    let mut body = resp.into_body().into_data_stream();
    tokio::spawn(async move {
        while let Some(chunk) = body.next().await {
            match chunk {
                Ok(b) => {
                    if tx.send(Ok::<_, std::io::Error>(b)).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    Box::pin(tokio_stream::wrappers::ReceiverStream::new(rx).eventsource())
}

/// Open a stream and assert the subscription itself was admitted.
async fn open_sse(app: &Router, bearer: &str) -> Events {
    let resp = subscribe(app, bearer).await;
    assert_eq!(resp.status(), StatusCode::OK, "subscribe rejected");
    into_events(resp)
}

/// True when the stream ENDS (reads to `None`) within `d`.
async fn ends_within(ev: &mut Events, d: Duration) -> bool {
    tokio::time::timeout(d, async { while ev.next().await.is_some() {} })
        .await
        .is_ok()
}

/// The name of the next event, if one arrives within `d`.
async fn next_event_within(ev: &mut Events, d: Duration) -> Option<String> {
    match tokio::time::timeout(d, ev.next()).await {
        Ok(Some(Ok(e))) => Some(e.event),
        _ => None,
    }
}

async fn post_record(fx: &Fx) {
    let resp =
        fx.h.app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/t/{TENANT}/records/posts"))
                    .header(header::AUTHORIZATION, format!("Bearer {}", fx.service))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"data":{"title":"hi"}}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
    assert!(
        resp.status().is_success(),
        "insert failed: {}",
        resp.status()
    );
}

async fn reroll(fx: &Fx, admin_id: i64) {
    let resp =
        drust::mgmt::admin_pat::reroll(State(fx.mgmt.clone()), Extension(AdminId(admin_id))).await;
    assert_eq!(resp.status(), StatusCode::OK, "reroll failed");
}

const ENDS: Duration = Duration::from_secs(2);
const STAYS: Duration = Duration::from_millis(800);

#[tokio::test]
async fn reroll_ends_the_callers_pat_stream_but_not_an_anon_stream() {
    let fx = fixture().await;
    let mut a = open_sse(&fx.h.app, &fx.a_pat).await;
    let mut anon = open_sse(&fx.h.app, &fx.h.token).await;

    reroll(&fx, fx.a_id).await;

    assert!(
        ends_within(&mut a, ENDS).await,
        "the rerolled admin's PAT stream is still open — a revoked PAT keeps an \
         unfiltered Service stream"
    );
    post_record(&fx).await;
    assert_eq!(
        next_event_within(&mut anon, ENDS).await.as_deref(),
        Some("created"),
        "an anon stream must be untouched by a PAT revocation"
    );
    assert_eq!(
        subscribe(&fx.h.app, &fx.a_pat).await.status(),
        StatusCode::UNAUTHORIZED,
        "the rerolled PAT must not reconnect"
    );
}

#[tokio::test]
async fn a_service_key_stream_survives_a_pat_revocation() {
    let fx = fixture().await;
    let mut svc = open_sse(&fx.h.app, &fx.service).await;

    reroll(&fx, fx.a_id).await;

    assert!(
        !ends_within(&mut svc, STAYS).await,
        "a tenant service-key stream carries no admin identity and must not end"
    );
    post_record(&fx).await;
    assert_eq!(
        next_event_within(&mut svc, ENDS).await.as_deref(),
        Some("created")
    );
}

/// Also the control arm for the reroll test: without a revocation of THIS
/// admin, the stream stays — so the stream ending there is the signal's doing.
#[tokio::test]
async fn another_admins_revocation_does_not_end_this_pat_stream() {
    let fx = fixture().await;
    let mut a = open_sse(&fx.h.app, &fx.a_pat).await;

    reroll(&fx, fx.b_id).await;

    assert!(
        !ends_within(&mut a, STAYS).await,
        "admin B's reroll ended admin A's stream"
    );
    post_record(&fx).await;
    assert_eq!(
        next_event_within(&mut a, ENDS).await.as_deref(),
        Some("created")
    );
}

/// Both a `PatDeadline` (+1 h) and a `PatRevocation` ride on this stream; the
/// revocation must win long before the deadline.
#[tokio::test]
async fn cli_revoke_ends_a_cli_pat_stream_long_before_its_deadline() {
    let fx = fixture().await;
    let mut cli = open_sse(&fx.h.app, &fx.a_cli).await;

    let resp = drust::mgmt::admin_pat::cli_token_revoke(
        State(fx.mgmt.clone()),
        Extension(AdminId(fx.a_id)),
        Path(fx.a_cli_id),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "cli revoke failed");

    assert!(
        ends_within(&mut cli, ENDS).await,
        "a revoked CLI PAT's stream is still open an hour before its deadline"
    );
}

/// Deliberate (the signal is per ADMIN, not per token): revoking one CLI PAT
/// restarts the same admin's UI-PAT stream once, and the still-valid UI PAT
/// reconnects.
#[tokio::test]
async fn cli_revoke_also_restarts_the_same_admins_ui_pat_stream() {
    let fx = fixture().await;
    let mut ui = open_sse(&fx.h.app, &fx.a_pat).await;

    let resp = drust::mgmt::admin_pat::cli_token_revoke(
        State(fx.mgmt.clone()),
        Extension(AdminId(fx.a_id)),
        Path(fx.a_cli_id),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "cli revoke failed");

    assert!(ends_within(&mut ui, ENDS).await);
    assert_eq!(
        subscribe(&fx.h.app, &fx.a_pat).await.status(),
        StatusCode::OK,
        "the UI PAT was not revoked and must reconnect"
    );
}

#[tokio::test]
async fn remove_admin_ends_the_removed_admins_stream_only() {
    let fx = fixture().await;
    let mut b = open_sse(&fx.h.app, &fx.b_pat).await;
    let mut a = open_sse(&fx.h.app, &fx.a_pat).await;
    let mut anon = open_sse(&fx.h.app, &fx.h.token).await;

    let resp = drust::mgmt::admin_team::remove_admin(
        State(fx.mgmt.clone()),
        Path(fx.b_id),
        Extension(AdminId(fx.a_id)),
        Extension(owner_profile()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "remove_admin failed");

    assert!(
        ends_within(&mut b, ENDS).await,
        "the removed admin's PAT stream is still open"
    );
    post_record(&fx).await;
    assert_eq!(
        next_event_within(&mut a, ENDS).await.as_deref(),
        Some("created"),
        "the CALLER's stream must not end — the signal goes to the removed admin"
    );
    assert_eq!(
        next_event_within(&mut anon, ENDS).await.as_deref(),
        Some("created")
    );
    assert_eq!(
        subscribe(&fx.h.app, &fx.b_pat).await.status(),
        StatusCode::UNAUTHORIZED,
        "the removed admin's PAT went with the row"
    );
}

/// The one site that signals through `revoke_admin(` directly rather than
/// through `evict_reach`.
#[tokio::test]
async fn role_demotion_ends_the_demoted_admins_stream() {
    let fx = fixture().await;
    let mut b = open_sse(&fx.h.app, &fx.b_pat).await;
    let mut anon = open_sse(&fx.h.app, &fx.h.token).await;

    let resp = drust::mgmt::admin_team::change_role(
        State(fx.mgmt.clone()),
        Path(fx.b_id),
        Extension(AdminId(fx.a_id)),
        Extension(owner_profile()),
        axum::Json(drust::mgmt::admin_team::RoleBody {
            role: "member".into(),
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "change_role failed");

    assert!(
        ends_within(&mut b, ENDS).await,
        "the demoted admin's PAT stream is still open"
    );
    post_record(&fx).await;
    assert_eq!(
        next_event_within(&mut anon, ENDS).await.as_deref(),
        Some("created")
    );
    let resp = subscribe(&fx.h.app, &fx.b_pat).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 16)
        .await
        .unwrap();
    assert!(
        String::from_utf8_lossy(&bytes).contains("PAT_TENANT_DENIED"),
        "a member who does not own the tenant is denied there"
    );
}

/// Probe router over the real SSE handler with a middleware that revokes
/// admin A at a chosen point in the layer stack. `with_gen_layer` mounts
/// `pat_gen_capture` outermost (the production shape); without it the capture
/// falls back inline.
fn probe_router(fx: &Fx, with_gen_layer: bool) -> Router {
    let mut state = drust::tenant::router::TenantAuthState::test_default(
        fx.h.meta.clone(),
        fx.h.tenants.clone(),
    );
    state.bus_rooms = fx.h.bus_rooms.clone();
    state.auth_cache = fx.h.auth_cache.clone();

    let bus = fx.h.bus_rooms.clone();
    let a_id = fx.a_id;
    let inject =
        axum::middleware::from_fn(move |req: Request<Body>, next: axum::middleware::Next| {
            let bus = bus.clone();
            async move {
                bus.cred().revoke_admin(a_id);
                next.run(req).await
            }
        });
    let events = drust::tenant::events::EventBus::new();
    let route = Router::new().route(
        "/t/{tenant}/records/{coll}/subscribe",
        get(move |ext, ctx, pat_deadline, pat_revocation, path| {
            drust::tenant::sse::subscribe_handler(
                events.clone(),
                ext,
                ctx,
                pat_deadline,
                pat_revocation,
                path,
            )
        }),
    );
    let capture = axum::middleware::from_fn_with_state(
        state.clone(),
        drust::tenant::rooms::ws_auth::ws_baseline_capture,
    );
    let bearer = axum::middleware::from_fn_with_state(
        state.clone(),
        drust::tenant::router::bearer_auth_layer,
    );
    // `.layer()` applied later is OUTER (runs first).
    let route = if with_gen_layer {
        // Runs: pat_gen_capture → inject → bearer → capture → handler.
        route.layer(capture).layer(bearer).layer(inject).layer(
            axum::middleware::from_fn_with_state(
                state.clone(),
                drust::tenant::rooms::ws_auth::pat_gen_capture,
            ),
        )
    } else {
        // Runs: bearer → inject → capture → handler.
        route.layer(capture).layer(inject).layer(bearer)
    };
    route.with_state(state)
}

/// A revocation landing after `g0` was read but before auth resolves the PAT
/// (auth still admits it — only the bus moved) is NOT missed: the stream ends
/// at once. This is the behavioural reason `pat_gen_capture` is outside bearer.
#[tokio::test]
async fn a_revocation_after_gen_capture_but_before_auth_ends_the_stream_at_once() {
    let fx = fixture().await;
    let app = probe_router(&fx, true);
    let mut a = open_sse(&app, &fx.a_pat).await;
    assert!(
        ends_within(&mut a, Duration::from_secs(1)).await,
        "a revocation between the generation read and the auth read was missed"
    );
}

/// The fallback's limit, recorded: with no `pat_gen_capture`, `g0` is read
/// inline after auth, so a revocation landing between auth and that read is
/// adopted as the baseline and the stream does NOT end. That is the window the
/// production layer order closes (pinned structurally in `ws_auth.rs`).
#[tokio::test]
async fn without_the_gen_layer_the_capture_falls_back_inline() {
    let fx = fixture().await;
    let app = probe_router(&fx, false);
    let mut a = open_sse(&app, &fx.a_pat).await;
    assert!(
        !ends_within(&mut a, STAYS).await,
        "the inline fallback unexpectedly saw a revocation older than its g0"
    );
}
