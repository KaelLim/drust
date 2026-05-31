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
            frame_bytes: bytes::Bytes::new(),
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

/// v1.31.2 F8 — A Lagged error on room A must NOT close the connection's
/// channel for room B. Tested at bus level: a slow Receiver on room A
/// gets Lagged, but a different Receiver on room B keeps delivering.
/// (The WS handler change wires this guarantee into the per-room
/// cleanup; this test pins the bus invariant the handler relies on.)
#[tokio::test]
async fn bus_lagged_on_one_room_does_not_affect_another_room() {
    use drust::tenant::rooms::{RoomBus, RoomMessage};
    use std::sync::Arc;

    let bus = RoomBus::new();
    let mut rx_a = bus.subscribe("t1", "noisy");
    let mut rx_b = bus.subscribe("t1", "quiet");

    // Overflow noisy's 256-buffer.
    for i in 0..300 {
        bus.publish(
            "t1",
            "noisy",
            RoomMessage {
                payload: Arc::new(serde_json::json!({ "n": i })),
                ts_ms: 0,
                frame_bytes: bytes::Bytes::new(),
            },
        );
    }
    // Publish to quiet — should be delivered.
    bus.publish(
        "t1",
        "quiet",
        RoomMessage {
            payload: Arc::new(serde_json::json!({ "body": "hello" })),
            ts_ms: 1,
            frame_bytes: bytes::Bytes::new(),
        },
    );

    // rx_a is lagged (>256 messages, never recv'd) — first recv returns Lagged.
    let r = rx_a.recv().await;
    assert!(
        matches!(r, Err(tokio::sync::broadcast::error::RecvError::Lagged(_))),
        "expected Lagged, got {r:?}"
    );

    // rx_b on the OTHER room must still deliver. Pre-handler-fix the WS
    // handler would close on rx_a's Lagged and the client would lose rx_b
    // too. Post-fix the handler removes only the lagging room.
    let got = rx_b.recv().await.unwrap();
    assert_eq!(got.payload["body"], "hello");
}
