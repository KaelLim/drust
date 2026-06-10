// tests/functions_dispatch.rs — REST record write → function invoked
// (mock runner via helpers' NoopRunner is not observable, so this test
// registers its own recording runner through a purpose-built stack).
mod helpers;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use drust::functions::executor::{FunctionRunner, RunOutcome, RunStatus};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tower::ServiceExt;

struct CountRunner(Arc<AtomicUsize>);
#[async_trait::async_trait]
impl FunctionRunner for CountRunner {
    async fn run(&self, _t: &str, _p: &std::path::Path, ev: &str) -> RunOutcome {
        assert!(ev.contains("record.created"), "payload shape");
        self.0.fetch_add(1, Ordering::SeqCst);
        RunOutcome { status: RunStatus::Ok, result: "{}".into(), log_text: String::new() }
    }
}

#[tokio::test]
async fn rest_insert_triggers_bound_function() {
    let counter = Arc::new(AtomicUsize::new(0));
    let (router, service_token, _tmp) = helpers::spin_up_tenant_with_fn_runner(
        "t-fdisp",
        Arc::new(CountRunner(counter.clone())),
        r#"[{"collection":"posts","events":["created"]}]"#,
    )
    .await;

    let resp = router
        .clone()
        .oneshot(
            Request::post("/t/t-fdisp/records/posts")
                .header("authorization", format!("Bearer {service_token}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"data":{"title":"hello"}}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    for _ in 0..150 {
        if counter.load(Ordering::SeqCst) == 1 {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("function was not invoked within 3s of the REST insert");
}
