//! v1.32.3 D9 pre-work — stress test pinning bearer_auth correctness
//! under 1000 concurrent requests with mixed bearer shapes against a
//! single tenant. The whole point of D9 is to collapse 3-4 separate
//! `meta.lock().await` round-trips per request into ONE CTE — the
//! correctness invariant this test pins is that the collapse doesn't
//! produce false-allow (accepting a bearer that should be denied) or
//! false-deny (denying a bearer that should be accepted) under load.
//!
//! Single-tenant + mixed-bearer is sufficient: every bearer_auth
//! request acquires the SAME meta-mutex regardless of which tenant it
//! targets (meta.sqlite is global). 10-tenant variant was in the plan
//! draft but adds no contention coverage that single-tenant doesn't
//! already provide.
//!
//! Must pass BOTH before AND after the D9 CTE refactor.
//!
//! Run: cargo test --test meta_lock_contention -- --nocapture

use axum::body::Body;
use axum::http::Request;
use std::sync::Arc;
use tokio::task::JoinSet;
use tower::ServiceExt;

mod helpers;

const TENANT: &str = "ba10b1a4-0000-0000-0000-000000000099";
const INVALID_TENANT: &str = "00000000-0000-0000-0000-000000000000";
const N_REQUESTS: usize = 1000;

#[derive(Clone, Copy, Debug)]
enum Expect {
    /// Auth layer must accept (status is anything but 401 / 404; the
    /// downstream handler may still 403 etc., that's not bearer_auth's
    /// concern).
    AuthOk,
    /// Auth layer must reject as unauthorized.
    Status401,
    /// Auth layer must reject as tenant-not-found.
    Status404,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bearer_auth_under_concurrent_load_preserves_correctness() {
    let (app, tid, svc_tok, anon_tok, _dir) =
        helpers::spin_up_dual_role_self_register(TENANT).await;
    let tid = Arc::new(tid);
    let svc = Arc::new(svc_tok);
    let anon = Arc::new(anon_tok);

    let mut set: JoinSet<(u16, Expect, &'static str)> = JoinSet::new();
    for i in 0..N_REQUESTS {
        let app = app.clone();
        let tid_c = tid.clone();
        let svc_c = svc.clone();
        let anon_c = anon.clone();
        set.spawn(async move {
            let (target_tid, bearer, expected, label) = match i % 4 {
                0 => ((*tid_c).clone(), (*svc_c).clone(), Expect::AuthOk, "service"),
                1 => ((*tid_c).clone(), (*anon_c).clone(), Expect::AuthOk, "anon"),
                2 => (
                    (*tid_c).clone(),
                    "drust_invalid_token_xxx_yyy".to_string(),
                    Expect::Status401,
                    "bad-bearer",
                ),
                _ => (
                    INVALID_TENANT.to_string(),
                    (*svc_c).clone(),
                    Expect::Status404,
                    "bad-tenant",
                ),
            };
            let req = Request::builder()
                .method("GET")
                .uri(format!("/t/{target_tid}/collections"))
                .header("Authorization", format!("Bearer {bearer}"))
                .body(Body::empty())
                .unwrap();
            let resp = app.oneshot(req).await.unwrap();
            (resp.status().as_u16(), expected, label)
        });
    }

    let mut false_allow = 0usize;
    let mut false_deny = 0usize;
    let mut mismatch_samples: Vec<(u16, Expect, &'static str)> = Vec::new();
    while let Some(res) = set.join_next().await {
        let (got, expected, label) = res.unwrap();
        let ok = match expected {
            Expect::AuthOk => !(got == 401 || got == 404),
            Expect::Status401 => got == 401,
            Expect::Status404 => got == 404,
        };
        if !ok {
            match expected {
                Expect::Status401 | Expect::Status404 => false_allow += 1,
                Expect::AuthOk => false_deny += 1,
            }
            if mismatch_samples.len() < 10 {
                mismatch_samples.push((got, expected, label));
            }
        }
    }

    assert_eq!(
        false_allow, 0,
        "false-allow under load: {false_allow} requests accepted that should have been denied. \
         samples (first 10): {mismatch_samples:?}"
    );
    assert_eq!(
        false_deny, 0,
        "false-deny under load: {false_deny} requests denied that should have been accepted. \
         samples (first 10): {mismatch_samples:?}"
    );
}
