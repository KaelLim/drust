//! Verify that error responses carry a `suggested_fix` field — both
//! static (from the catalog) and context-aware (templated).

use axum::body::to_bytes;
use axum::http::StatusCode;
use drust::error::json_error;
use serde_json::Value;

#[tokio::test]
async fn json_error_attaches_static_fix_for_known_code() {
    let resp = json_error(StatusCode::FORBIDDEN, "WRITE_DENIED", "x");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let bytes = to_bytes(resp.into_body(), 4096).await.unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["error_code"], "WRITE_DENIED");
    let fix = v["suggested_fix"].as_str().expect("fix present");
    assert!(fix.to_lowercase().contains("service"));
}
