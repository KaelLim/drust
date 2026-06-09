//! Body-size limit for record create/update routes.
//!
//! Records are buffered fully in memory, so the limit is bounded —
//! `DRUST_MAX_RECORD_BODY_BYTES`, default 8 MiB — but it must sit ABOVE axum's
//! 2 MiB built-in default so legitimate large document records (e.g. a `docs`
//! collection) can be saved. Regression for the production
//! `PATCH /records/docs/16 -> 413 length limit exceeded` report.

mod helpers;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

/// A JSON object `{"content":"xxx…"}` whose total size is ~`n` bytes.
fn json_body(n: usize) -> String {
    let filler = "x".repeat(n);
    format!("{{\"content\":\"{filler}\"}}")
}

/// A ~3 MiB record body — over axum's old 2 MiB default, under the 8 MiB limit —
/// must clear the body-buffer stage. The `docs` collection doesn't exist, so the
/// handler returns 404/4xx; the point is the status is NOT 413.
#[tokio::test]
async fn records_post_3mib_body_is_not_413() {
    let (app, tok, _dir) = helpers::spin_up_tenant_with_role("rec-big", "service").await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/t/rec-big/records/docs")
                .header("authorization", format!("Bearer {tok}"))
                .header("content-type", "application/json")
                .body(Body::from(json_body(3 * 1024 * 1024)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(
        resp.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "3 MiB body must clear the records limit (was 413 at the 2 MiB axum default)"
    );
}

/// A ~9 MiB record body — over the 8 MiB limit — must be rejected at the body
/// buffer with 413, never reaching the handler.
#[tokio::test]
async fn records_post_9mib_body_is_413() {
    let (app, tok, _dir) = helpers::spin_up_tenant_with_role("rec-huge", "service").await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/t/rec-huge/records/docs")
                .header("authorization", format!("Bearer {tok}"))
                .header("content-type", "application/json")
                .body(Body::from(json_body(9 * 1024 * 1024)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "9 MiB body must hit the 8 MiB records limit"
    );
}
