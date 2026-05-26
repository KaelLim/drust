//! v1.21 §1 — webhook DNS-rebind close.
//!
//! Three end-to-end assertions against `deliver_for_test`:
//!
//!   1. `rebind_to_private_terminal_no_http` — a URL whose host already
//!      sits in a private/loopback/link-local range never reaches the
//!      attempt loop; the wrap-first `resolve_public` short-circuits with
//!      a terminal `NonRetryable`.
//!   3. `all_private_resolve_terminal` — same shape, exercised through a
//!      different sentinel (`0.0.0.0`) so we cover both the RFC1918 and
//!      the wildcard arms of `is_private_ip`.
//!   4. `dev_loopback_http_bypasses_resolver` — `http://127.0.0.1:port`
//!      keeps working against a FakeHook; the dev-mode carve-out skips
//!      both the wrap-first resolve AND the reqwest-level resolver.
//!
//! Cases 2/5/6 from the plan are ignored — they require injecting a
//! resolver into the wrap-first `resolve_public` step (not just into
//! reqwest's dial step), which is intentionally out of Theme A scope.
//! See the `#[ignore = ...]` strings for the rationale; the v1.22
//! follow-up will refactor `deliver_for_test` to take an injected
//! pre-check resolver function.

mod webhooks_common;
use webhooks_common::FakeHook;

use drust::tenant::webhook_dispatcher::{
    deliver_for_test, DeliverySchedule, WebhookRow,
};
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
//
// Requires a second injection point: the wrap-first standalone resolve
// uses real stdlib DNS, NOT the injected resolver. Faking a hostname
// that "resolves to one public + one private IP at dispatch time" needs
// either a control of /etc/hosts (CI-hostile) or a function-typed
// resolver knob on `deliver_for_test`. Queued for v1.22.
#[tokio::test]
#[ignore = "needs pre-check resolver injection — see plan §A4 IMPORTANT note; v1.22 follow-up"]
async fn mixed_resolve_dials_only_public() {
    // TODO(v1.22): once `deliver_for_test` accepts an injected pre-check
    // resolver function, drive a mock that returns [public, private] for
    // the same Name and assert the reqwest dial lands on the public IP
    // exclusively. Today the only knob is reqwest's `dns_resolver`, which
    // fires AFTER the wrap-first resolve has already vetted the host.
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
//
// Needs `https://[fc00::1]/x` to flow through stdlib DNS deterministically.
// stdlib `to_socket_addrs` on IPv6-literal hosts requires brackets in the
// raw string AND careful handling of `reqwest::Url::host_str()`, which
// strips brackets for IPv6 literals. The plan's case 5 is functionally
// covered by case 1 + the `rejects_loopback_and_link_local` unit test in
// `webhook_resolver::tests`; we leave the integration-level assertion
// queued behind the same pre-check resolver knob as case 2.
#[tokio::test]
#[ignore = "IPv6 literal stdlib resolution is brittle without bracket-aware test scaffold; v1.22 follow-up"]
async fn ipv6_private_literal_terminal() {
    // TODO(v1.22): exercise `https://[fc00::1]/hook` end-to-end once the
    // pre-check resolver knob exists.
}

// ─── case 6 — DNS failure terminal ──────────────────────────────────────────
//
// Needs a hostname that deterministically fails resolution under any DNS
// configuration. RFC2606 reserves `.invalid` for this purpose, BUT on
// hosts with a DNS search domain set, `something.invalid` can incur a
// 5-30 s blocking lookup (and may even resolve through a captive DNS).
// Skipping until the pre-check resolver knob exists.
#[tokio::test]
#[ignore = "needs pre-check resolver injection to bypass real DNS; v1.22 follow-up"]
async fn dns_failure_terminal() {
    // TODO(v1.22): inject a pre-check resolver that returns
    // `Err("nxdomain")` for the test hostname, then assert
    // NonRetryable + `host_now_private_or_unresolvable`.
}
