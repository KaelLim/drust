// tests/functions_isolation.rs — spec §7 invariants:
//   1. host API cannot touch _system_* (inherited PROTECTED_COLLECTION).
//   2. a function-initiated write fires SSE + webhooks (inherited emission)
//      but NEVER re-triggers functions (depth=1: executor host state has
//      functions: None by construction — see HostStateSeed::build_mcp).
//   3. (carried from the Task 11 review fix, c73c4ec) the artifact GC the
//      unit test could only cover at the primitive level, now proven through
//      the real create route with a real component fixture: a create rejected
//      at the per-tenant cap leaves NO orphaned {sha}.wasm, and a same-name
//      replace with different bytes deletes the displaced {sha}.wasm.
mod helpers;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use drust::functions::executor::{FunctionRunner, RunOutcome, RunStatus};
use drust::functions::runtime::HostStateSeed;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tower::ServiceExt;

/// Runner that writes through the host-state DrustMcp exactly like a guest
/// would — this exercises HostStateSeed::build_mcp's None wiring without
/// needing a wasm toolchain in this test file. Bumps `counter` once per run so
/// a (forbidden) re-trigger would be observable as counter > 1.
struct WritingRunner {
    seed: HostStateSeed,
    counter: Arc<AtomicUsize>,
}
#[async_trait::async_trait]
impl FunctionRunner for WritingRunner {
    async fn run(&self, tenant: &str, _p: &std::path::Path, _e: &str) -> RunOutcome {
        let mcp = self.seed.build_mcp(tenant).unwrap();
        // (1) _system_* write must bail PROTECTED_COLLECTION.
        let denied = drust::mcp::tools::write::insert_record(
            &mcp,
            "_system_functions",
            serde_json::json!({"name":"evil"}),
        )
        .await;
        assert!(
            denied
                .unwrap_err()
                .to_string()
                .starts_with("PROTECTED_COLLECTION"),
            "host API must inherit the _system_* write bail"
        );
        // (2) ordinary write — succeeds and fires bus+webhooks (but with
        // functions: None it can never enqueue another invocation).
        drust::mcp::tools::write::insert_record(
            &mcp,
            "fn_out",
            serde_json::json!({"payload":"from-fn"}),
        )
        .await
        .unwrap();
        self.counter.fetch_add(1, Ordering::SeqCst);
        RunOutcome {
            status: RunStatus::Ok,
            result: "{}".into(),
            log_text: String::new(),
        }
    }
}

#[tokio::test]
async fn function_write_cannot_retrigger_and_inherits_protection() {
    // Full stack: dispatcher + executor share a queue; the dispatcher's
    // binding cache holds a function bound to fn_out/created — IF a function
    // write could re-trigger, this binding would fire again and the counter
    // would exceed 1. The stack ALSO wires a bus subscriber on (tenant,
    // fn_out) so the function's own insert is observable as SSE reach.
    let (stack, counter) = helpers::spin_up_isolation_stack("t-iso", |seed, counter| {
        Arc::new(WritingRunner { seed, counter })
    })
    .await;

    // trigger once via record write on the BOUND collection
    stack.dispatcher.dispatch(
        "t-iso",
        "fn_out",
        &drust::tenant::events::Event::Created {
            record: serde_json::json!({"seed":1}),
        },
    );

    // wait for exactly ONE completion, then a quiet period proves no cascade
    for _ in 0..150 {
        if counter.load(Ordering::SeqCst) >= 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(counter.load(Ordering::SeqCst), 1);
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "depth=1: the function's own insert into the BOUND collection must not re-trigger"
    );

    // SSE: the function's insert was published on the bus.
    assert!(
        stack.sse_events_seen.load(Ordering::SeqCst) >= 1,
        "function write reaches SSE"
    );
}

/// Multipart body carrying name + triggers + a wasm part with the given bytes.
fn create_body(name: &str, triggers: &str, wasm: &[u8]) -> (String, Vec<u8>) {
    let b = "drustisoboundary42";
    let mut body: Vec<u8> = Vec::new();
    for (field, value) in [("name", name), ("triggers", triggers)] {
        body.extend_from_slice(format!("--{b}\r\n").as_bytes());
        body.extend_from_slice(
            format!("Content-Disposition: form-data; name=\"{field}\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(value.as_bytes());
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{b}\r\n").as_bytes());
    body.extend_from_slice(
        b"Content-Disposition: form-data; name=\"wasm\"; filename=\"f.wasm\"\r\n",
    );
    body.extend_from_slice(b"Content-Type: application/wasm\r\n\r\n");
    body.extend_from_slice(wasm);
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(format!("--{b}--\r\n").as_bytes());
    (format!("multipart/form-data; boundary={b}"), body)
}

fn fixture(name: &str) -> Vec<u8> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/functions")
        .join(format!("{name}.wasm"));
    std::fs::read(&p).unwrap_or_else(|e| panic!("read fixture {}: {e}", p.display()))
}

fn sha_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    let mut s = String::with_capacity(64);
    for b in digest {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Route-level proof of the c73c4ec artifact-GC fix, which the unit test could
/// only cover at the primitive level (no real component to clear
/// `validate_component`). Two cases, asserted on real on-disk `{sha}.wasm`:
///   (a) a create REJECTED at the per-tenant cap (FN_LIMIT) leaves NO orphan;
///   (b) a same-name replace with DIFFERENT bytes deletes the displaced sha
///       and keeps the new one.
#[tokio::test]
async fn create_route_leaves_no_orphan_artifacts() {
    // cap = 1 so a second distinct-name create rejects with FN_LIMIT.
    let (router, service, dir) =
        helpers::spin_up_functions_route_stack("t-isogc", 1).await;
    let auth = format!("Bearer {service}");
    let fn_dir = dir
        .path()
        .join("tenants")
        .join("t-isogc")
        .join("_functions");

    let happy = fixture("happy");
    let loop_wasm = fixture("loop");
    let happy_sha = sha_hex(&happy);
    let loop_sha = sha_hex(&loop_wasm);
    assert_ne!(happy_sha, loop_sha, "fixtures must have distinct bytes");

    // ---- first create succeeds (fills the cap) -------------------------
    let (ct, body) = create_body("a", "[]", &happy);
    let resp = router
        .clone()
        .oneshot(
            Request::post("/t/t-isogc/functions")
                .header("authorization", &auth)
                .header("content-type", ct)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED, "first create");
    assert!(
        fn_dir.join(format!("{happy_sha}.wasm")).exists(),
        "created function's artifact present"
    );

    // ---- (a) create at the cap rejects 409 FN_LIMIT, no orphan ---------
    let (ct, body) = create_body("b", "[]", &loop_wasm);
    let resp = router
        .clone()
        .oneshot(
            Request::post("/t/t-isogc/functions")
                .header("authorization", &auth)
                .header("content-type", ct)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT, "second create over cap");
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["error_code"], "FN_LIMIT");
    assert!(
        !fn_dir.join(format!("{loop_sha}.wasm")).exists(),
        "rejected create must NOT leave an orphaned {{sha}}.wasm on disk"
    );
    assert!(
        fn_dir.join(format!("{happy_sha}.wasm")).exists(),
        "the live function's artifact must survive the rejected create"
    );

    // ---- (b) replace "a" with different bytes: old sha GC'd, new kept ---
    let (ct, body) = create_body("a", "[]", &loop_wasm);
    let resp = router
        .clone()
        .oneshot(
            Request::post("/t/t-isogc/functions")
                .header("authorization", &auth)
                .header("content-type", ct)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED, "replace same name");
    assert!(
        fn_dir.join(format!("{loop_sha}.wasm")).exists(),
        "replacement artifact kept"
    );
    assert!(
        !fn_dir.join(format!("{happy_sha}.wasm")).exists(),
        "replace must GC the displaced {{sha}}.wasm"
    );
}
