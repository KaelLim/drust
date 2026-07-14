//! v1.49 Task 4 — webhook egress third gate.
//!
//! The per-tenant egress allowlist (`tenants.egress_allowlist_json`, tagged
//! `{system,uri}` JSON, deny-all default) gates webhook DELIVERY as a THIRD
//! gate, ADDED alongside the existing two: `check_url` (registration-time
//! private-IP block) and the `PinnedPublicResolver` (per-attempt DNS filter).
//! Never a replacement — dropping any one reopens SSRF.
//!
//! Three end-to-end assertions against the real tenant router + dispatch path:
//!   (a) registering a webhook whose target origin is NOT on the allowlist is
//!       rejected `400 EGRESS_NOT_ALLOWLISTED`;
//!   (b) after the origin is added (`system=webhook`) the same registration
//!       succeeds (`201`);
//!   (c) a subscription whose origin was later removed from the allowlist is
//!       denied at dispatch — a delivery failure is recorded and NO POST is
//!       attempted (the recorded reason names the egress gate, not the
//!       resolver, proving the gate short-circuits before any DNS/HTTP).
//!
//! Non-loopback origins are used deliberately so the egress gate actually
//! applies (loopback dev targets keep the same carve-out the resolver has).
//! A denied dispatch short-circuits before any network I/O, so the suite
//! stays hermetic.

mod helpers;

use axum::body::Body;
use axum::http::{Request, header};
use helpers::spin_up_tenant_with_role;
use tower::ServiceExt;

/// RFC 5737 TEST-NET-1 literal: `is_private_ip` treats it as public (so
/// `check_url`'s registration DNS gate and the dispatch `PinnedPublicResolver`
/// both PASS — leaving the egress gate as the sole decider), it needs no DNS
/// (an IP literal resolves locally), and it is non-routable so no test ever
/// actually reaches it. The egress gate denies (a) and (c) before any POST,
/// and (b) only registers (never dispatches).
const ORIGIN: &str = "https://192.0.2.1";
const URL: &str = "https://192.0.2.1/hook";

/// PUT the tenant's egress allowlist (service-only whole-list replace).
async fn put_allowlist(
    app: &axum::Router,
    tid: &str,
    svc: &str,
    entries: serde_json::Value,
) -> u16 {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/t/{tid}/egress-allowlist"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {svc}"))
                .body(Body::from(
                    serde_json::json!({ "entries": entries }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    resp.status().as_u16()
}

/// Register a webhook via the service-only REST create route.
async fn create_webhook(
    app: &axum::Router,
    tid: &str,
    svc: &str,
    url: &str,
) -> (u16, serde_json::Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{tid}/admin/webhooks"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {svc}"))
                .body(Body::from(
                    serde_json::json!({
                        "collection": "notes",
                        "events": ["created"],
                        "url": url,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, v)
}

// ─── (a) registration denied when origin not allowlisted ────────────────────

#[tokio::test]
async fn register_denied_when_origin_not_allowlisted() {
    let tid = "t-egress-reg-deny";
    let (app, svc, _dir) = spin_up_tenant_with_role(tid, "service").await;

    // Fresh tenant → empty allowlist → deny-all.
    let (status, v) = create_webhook(&app, tid, &svc, URL).await;
    assert_eq!(status, 400, "expected 400, got {status}: {v}");
    assert_eq!(
        v["error_code"].as_str(),
        Some("EGRESS_NOT_ALLOWLISTED"),
        "wrong error_code: {v}"
    );
}

// ─── (b) registration allowed after origin added ────────────────────────────

#[tokio::test]
async fn register_allowed_after_origin_added() {
    let tid = "t-egress-reg-allow";
    let (app, svc, _dir) = spin_up_tenant_with_role(tid, "service").await;

    // Add the origin as a system=webhook entry.
    let put = put_allowlist(
        &app,
        tid,
        &svc,
        serde_json::json!([{ "system": "webhook", "uri": ORIGIN }]),
    )
    .await;
    assert_eq!(put, 200, "allowlist PUT should succeed");

    let (status, v) = create_webhook(&app, tid, &svc, URL).await;
    assert_eq!(
        status, 201,
        "expected 201 after allowlisting, got {status}: {v}"
    );
}

// ─── (c) dispatch denied when origin later removed from the allowlist ────────

#[tokio::test]
async fn dispatch_denied_when_origin_removed_records_failure_no_delivery() {
    let tid = "t-egress-dispatch-deny";
    let (app, svc, dir) = spin_up_tenant_with_role(tid, "service").await;

    // 1. Allowlist the origin so registration succeeds.
    assert_eq!(
        put_allowlist(
            &app,
            tid,
            &svc,
            serde_json::json!([{ "system": "webhook", "uri": ORIGIN }]),
        )
        .await,
        200
    );

    // 2. Create the `notes` collection + a subscription pointing at the origin.
    let pool = helpers::grab_pool(tid, &dir).await;
    pool.with_writer(|c| {
        c.execute_batch(
            "CREATE TABLE notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                note TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );",
        )
    })
    .await
    .unwrap();
    pool.with_writer(|c| {
        c.execute(
            "INSERT INTO _system_webhooks(collection,events,url,secret,active,created_at)
             VALUES('notes','[\"created\"]',?1,'topsecret',1,'2026-01-01T00:00:00Z')",
            rusqlite::params![URL],
        )?;
        Ok(())
    })
    .await
    .unwrap();

    // 3. REMOVE the origin from the allowlist (whole-list replace with empty).
    assert_eq!(
        put_allowlist(&app, tid, &svc, serde_json::json!([])).await,
        200
    );

    // 4. POST a record → triggers dispatch. The egress gate reads the FRESH
    //    (now-empty) allowlist and denies before any resolve/POST.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/t/{tid}/records/notes"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {svc}"))
                .body(Body::from(
                    serde_json::json!({"data": {"note": "hi"}}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 201, "record insert must succeed");

    // 5. Poll for the recorded failure (up to ~2s). The reason must name the
    //    egress gate — NOT "host_now_private_or_unresolvable", which is what a
    //    fall-through to the resolver would have produced for this bogus host.
    let mut reason: Option<String> = None;
    for _ in 0..40 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let r = pool
            .with_reader(|c| {
                c.query_row(
                    "SELECT last_failure_reason FROM _system_webhooks WHERE id = 1",
                    [],
                    |row| row.get::<_, Option<String>>(0),
                )
            })
            .await
            .ok()
            .flatten();
        if r.is_some() {
            reason = r;
            break;
        }
    }
    let reason = reason.expect("egress-denied dispatch must record last_failure_reason");
    assert!(
        reason.contains("egress"),
        "failure reason should name the egress gate (not the resolver), got: {reason}"
    );
}
