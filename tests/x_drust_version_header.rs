//! Verifies tower_http SetResponseHeaderLayer correctly attaches
//! X-Drust-Version to every response.
//!
//! NOTE: This test verifies the layer behavior in isolation. The actual
//! production wiring (where the layer is added to the main app in
//! src/main.rs) is validated manually via:
//!
//!   curl -s -i http://127.0.0.1:47826/health | grep -i x-drust-version
//!
//! after `cargo build --release` and `sudo systemctl restart drust`.

use axum::body::Body;
use axum::http::{HeaderName, HeaderValue, Request};
use axum::routing::get;
use axum::Router;
use tower::ServiceExt;
use tower_http::set_header::SetResponseHeaderLayer;

#[tokio::test]
async fn version_header_layer_attaches_to_responses() {
    let app = Router::new()
        .route("/test", get(|| async { "ok" }))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("x-drust-version"),
            HeaderValue::from_static(env!("CARGO_PKG_VERSION")),
        ));

    let resp = app
        .oneshot(Request::builder().uri("/test").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(
        resp.headers()
            .get("x-drust-version")
            .unwrap()
            .to_str()
            .unwrap(),
        env!("CARGO_PKG_VERSION")
    );
}
