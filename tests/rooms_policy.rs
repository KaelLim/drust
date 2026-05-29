//! Smoke test that the public re-exports from `crate::tenant::rooms`
//! are reachable + behave as documented. Unit-test details live in
//! `src/tenant/rooms/{bus,envelope,policy}.rs`.

use drust::tenant::rooms::{PublishBucket, RoomBus, RoomMessage, validate_room_name};
use std::sync::Arc;

#[tokio::test]
async fn cross_module_publish_subscribe_roundtrip() {
    let bus = RoomBus::new();
    let mut rx = bus.subscribe("t", "chat");
    let n = bus.publish(
        "t",
        "chat",
        RoomMessage {
            payload: Arc::new(serde_json::json!({"hi": 1})),
            ts_ms: 1_000,
        },
    );
    assert_eq!(n, 1);
    let got = rx.recv().await.unwrap();
    assert_eq!(got.payload["hi"], 1);
    assert_eq!(got.ts_ms, 1_000);
}

#[test]
fn cross_module_room_name_validation() {
    assert!(validate_room_name("chat:42").is_ok());
    assert!(validate_room_name("_system_x").is_err());
}

#[test]
fn cross_module_publish_bucket_basic() {
    let b = PublishBucket::new(5);
    for _ in 0..5 {
        assert!(b.try_consume("t").is_ok());
    }
    assert!(b.try_consume("t").is_err());
}
