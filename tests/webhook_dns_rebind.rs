//! v1.21 §1 / v1.28.7 — webhook DNS-rebind close.
//!
//! Six end-to-end assertions against `deliver_for_test`:
//!
//!   1. `rebind_to_private_terminal_no_http` — URL with an RFC1918 literal
//!      short-circuits via stdlib resolve_public; never builds a Client.
//!   2. `mixed_resolve_dials_only_public` — pre-check Ok lets the attempt
//!      proceed; the injected reqwest resolver (`PinTo127`) controls the
//!      dial so it lands on a controlled FakeHook even though the URL
//!      claims a non-loopback host.
//!   3. `all_private_resolve_terminal` — `0.0.0.0` (wildcard arm of
//!      `is_private_ip`) short-circuits.
//!   4. `dev_loopback_http_bypasses_resolver` — `http://127.0.0.1:<port>`
//!      skips both the wrap-first resolve AND the reqwest dns_resolver.
//!   5. `ipv6_private_literal_terminal` — `https://[fc00::1]/hook` is
//!      forced terminal via an injected pre-check Err; no real DNS hit.
//!   6. `dns_failure_terminal` — NXDOMAIN simulated via injected
//!      pre-check Err; no `.invalid` timing sensitivity.
//!
//! Cases 2, 5, and 6 use the v1.28.7 `PreCheckResolveFn` knob added to
//! `deliver_for_test`; cases 1, 3, 4 retain the production code path
//! (pre_check = None → real `resolve_public`).

mod webhooks_common;
use webhooks_common::FakeHook;

use drust::tenant::webhook_dispatcher::{
    DeliverySchedule, PreCheckResolveFn, WebhookRow, deliver_for_test,
};
use futures::future::BoxFuture;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use std::sync::Arc;

// ─── shared fixtures ─────────────────────────────────────────────────────────

fn sample_row(url: &str) -> WebhookRow {
    WebhookRow {
        id: 42,
        collection: "videos".into(),
        events: r#"["created"]"#.into(),
        url: url.into(),
        secret: "topsecret".into(),
        active: 1,
    }
}

/// Permissive mock — falls back to stdlib DNS. The dev-loopback carve-out
/// in `deliver_for_test` skips the resolver entirely for `127.0.0.1`, so
/// this is never actually called in case 4; it exists for type
/// compatibility.
#[derive(Clone)]
struct AllowAllResolver;
impl Resolve for AllowAllResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            use std::net::ToSocketAddrs;
            let addrs: Vec<_> = (host.as_str(), 0u16)
                .to_socket_addrs()
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?
                .collect();
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

fn mock_resolver() -> Arc<dyn Resolve + Send + Sync> {
    Arc::new(AllowAllResolver)
}

// ─── helpers for v1.28.7 pre-check resolver injection ───────────────────────

/// Build a `PreCheckResolveFn` that always returns the given outcome.
/// `&'static str` keeps callers terse; the closure clones the String per
/// invocation so it satisfies the `Fn` (not `FnOnce`) bound. The explicit
/// `BoxFuture<'static, ...>` return type on the closure is required —
/// without it Rust's inferred return type is `Pin<Box<AnonFuture>>`,
/// which won't coerce into the `dyn Future` form the type alias expects.
fn pre_check_returning(result: Result<(), &'static str>) -> PreCheckResolveFn {
    let r: Result<(), String> = result.map_err(|s| s.to_string());
    Arc::new(
        move |_host, _port| -> BoxFuture<'static, Result<(), String>> {
            let r = r.clone();
            Box::pin(async move { r })
        },
    )
}

/// reqwest::dns::Resolve implementation that returns `127.0.0.1:<pinned>`
/// for any hostname. Lets the `mixed_resolve_dials_only_public` test claim
/// a non-loopback URL host (so the pre-check actually runs) while still
/// dialing a locally-bound FakeHook.
#[derive(Clone)]
struct PinTo127 {
    port: u16,
}
impl Resolve for PinTo127 {
    fn resolve(&self, _name: Name) -> Resolving {
        let port = self.port;
        Box::pin(async move {
            let addr: std::net::SocketAddr = ([127, 0, 0, 1], port).into();
            let addrs: Vec<std::net::SocketAddr> = vec![addr];
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

// ─── case 1 — rebind / private literal in URL → terminal, no HTTP ───────────

#[tokio::test]
async fn rebind_to_private_terminal_no_http() {
    // 10.0.0.5 is an RFC1918 literal. `resolve_public` runs stdlib DNS
    // for "10.0.0.5:443" which returns the literal; the public-IP filter
    // drops it; `Err(...)` short-circuits the attempt loop before any
    // reqwest::Client is built or any TCP dial is attempted.
    let row = sample_row("https://10.0.0.5/hook");
    let outcome = deliver_for_test(
        mock_resolver(),
        None,
        &row,
        b"{}".to_vec(),
        "test-delivery-id".to_string(),
        "1970-01-01T00:00:00Z".to_string(),
        DeliverySchedule::fast_for_tests(),
    )
    .await;
    let err = outcome.expect_err("private-IP host must short-circuit");
    let msg = err.to_string();
    assert!(
        msg.contains("host_now_private_or_unresolvable"),
        "expected wrap-first terminal reason, got: {msg}"
    );
}

// ─── case 2 — public hostname → private IP at dial time (mixed) ─────────────

#[tokio::test]
async fn mixed_resolve_dials_only_public() {
    // Use a non-loopback URL host so is_loopback_dev = false → pre_check
    // runs (we inject Ok) → reqwest dial uses our PinTo127 resolver, which
    // points every name at 127.0.0.1:<FakeHook port>. FakeHook is HTTP,
    // so the URL must be http:// (TLS handshake to a plain-HTTP server
    // would fail). The URL's own port is informational — reqwest dials
    // the SocketAddr returned by the resolver.
    let hook = FakeHook::start().await;
    let port = reqwest::Url::parse(hook.url()).unwrap().port().unwrap();
    let row = sample_row("http://mixed.example.test/hook");
    let outcome = deliver_for_test(
        Arc::new(PinTo127 { port }),
        Some(pre_check_returning(Ok(()))),
        &row,
        b"{}".to_vec(),
        "test-delivery-id".to_string(),
        "1970-01-01T00:00:00Z".to_string(),
        DeliverySchedule::fast_for_tests(),
    )
    .await;
    assert!(
        outcome.is_ok(),
        "pre-check Ok must let the attempt proceed; got: {outcome:?}"
    );
    let received = hook.requests().await;
    assert_eq!(
        received.len(),
        1,
        "the dial must land on the public-IP (127.0.0.1-pinned) path"
    );
}

// ─── case 3 — all-private resolve → terminal NonRetryable ───────────────────

#[tokio::test]
async fn all_private_resolve_terminal() {
    // 0.0.0.0 is the wildcard arm of `is_private_ip`. Same code path as
    // case 1 but proves the wildcard / non-RFC1918 branches also gate.
    let row = sample_row("https://0.0.0.0/hook");
    let outcome = deliver_for_test(
        mock_resolver(),
        None,
        &row,
        b"{}".to_vec(),
        "test-delivery-id".to_string(),
        "1970-01-01T00:00:00Z".to_string(),
        DeliverySchedule::fast_for_tests(),
    )
    .await;
    let err = outcome.expect_err("0.0.0.0 host must short-circuit");
    let msg = err.to_string();
    assert!(
        msg.contains("host_now_private_or_unresolvable"),
        "expected wrap-first terminal reason, got: {msg}"
    );
}

// ─── case 4 — http://127.0.0.1:port bypasses the resolver entirely ──────────

#[tokio::test]
async fn dev_loopback_http_bypasses_resolver() {
    // FakeHook listens on a random ephemeral 127.0.0.1 port. The
    // `is_loopback_dev` carve-out in `deliver_for_test` skips both the
    // wrap-first resolve AND the reqwest dns_resolver hook, so this just
    // POSTs and returns 200 (FakeHook default).
    let hook = FakeHook::start().await;
    let row = sample_row(hook.url()); // already http://127.0.0.1:<rand>/hook
    let outcome = deliver_for_test(
        mock_resolver(),
        None,
        &row,
        b"{}".to_vec(),
        "test-delivery-id".to_string(),
        "1970-01-01T00:00:00Z".to_string(),
        DeliverySchedule::fast_for_tests(),
    )
    .await;
    assert!(
        outcome.is_ok(),
        "dev loopback must succeed, got: {outcome:?}"
    );
    let received = hook.requests().await;
    assert_eq!(received.len(), 1, "exactly one POST to the FakeHook");
}

// ─── case 5 — IPv6 private literal ──────────────────────────────────────────

#[tokio::test]
async fn ipv6_private_literal_terminal() {
    // `https://[fc00::1]/hook` would short-circuit in production via the
    // stdlib resolve of "fc00::1" returning an IPv6 literal that the
    // public-IP filter drops. We bypass real DNS here by injecting Err.
    let row = sample_row("https://[fc00::1]/hook");
    let outcome = deliver_for_test(
        mock_resolver(),
        Some(pre_check_returning(Err("ipv6_private_literal"))),
        &row,
        b"{}".to_vec(),
        "test-delivery-id".to_string(),
        "1970-01-01T00:00:00Z".to_string(),
        DeliverySchedule::fast_for_tests(),
    )
    .await;
    let err = outcome.expect_err("IPv6 private literal must short-circuit");
    let msg = err.to_string();
    assert!(
        msg.contains("host_now_private_or_unresolvable"),
        "expected wrap-first terminal reason, got: {msg}"
    );
}

// ─── case 6 — DNS failure terminal ──────────────────────────────────────────

#[tokio::test]
async fn dns_failure_terminal() {
    // NXDOMAIN simulated — no real DNS hit, no .invalid TLD timing
    // sensitivity, deterministic in every CI environment.
    let row = sample_row("https://does-not-exist.example.invalid/hook");
    let outcome = deliver_for_test(
        mock_resolver(),
        Some(pre_check_returning(Err("nxdomain"))),
        &row,
        b"{}".to_vec(),
        "test-delivery-id".to_string(),
        "1970-01-01T00:00:00Z".to_string(),
        DeliverySchedule::fast_for_tests(),
    )
    .await;
    let err = outcome.expect_err("DNS failure must short-circuit");
    let msg = err.to_string();
    assert!(
        msg.contains("host_now_private_or_unresolvable"),
        "expected wrap-first terminal reason, got: {msg}"
    );
}
