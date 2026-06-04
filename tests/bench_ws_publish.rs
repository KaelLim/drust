//! v1.32.2 D8 benchmark — measures `RoomBus`-fan-out wall-clock.
//!
//! Synthetic at the RoomBus + send-equivalent layer. Bypasses WS framing
//! entirely — the work being measured is the (deep-clone Arc<Value> +
//! serde_json::to_string) that pre-D8 was paid PER SUBSCRIBER on send,
//! vs post-D8 a SINGLE serialization at publish + cheap `Bytes` clones
//! on each subscriber. WS-level bench is impossible: `tests/rooms_ws.rs`
//! is all `#[ignore]`'d due to tokio-rs/tokio#2374 (per-test runtime
//! starvation at <10 concurrent clients).
//!
//! Run: cargo test --test bench_ws_publish -- --ignored --nocapture
//! NEVER --release (Cargo.toml LTO hangs 40+ min).
//!
//! 1000×64KB scenario intentionally omitted: per-iteration alloc is
//! ~64MB (1000 deep-clones of a 64KB Value in the pre-D8 path); 100
//! iterations push the allocator into severe pressure and the wall-clock
//! balloons past useful bench territory. 1000×16KB + 100×64KB give the
//! same signal.
//!
//! Two #[ignore]'d test cases:
//!   * `bench_ws_publish_baseline` — pre-D8 shape (receivers do the
//!     serialize work). Was used to capture the v1.32.2 baseline.
//!   * `bench_ws_publish_d8` — post-D8 shape (publisher serializes,
//!     receivers forward bytes). Use to compare.

use drust::tenant::rooms::{RoomBus, RoomMessage, ServerMessage};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{broadcast, mpsc};

const TENANT: &str = "bench-tenant";
const ROOM: &str = "bench-room";
const ITERATIONS: usize = 100;

const SCENARIOS: &[(usize, usize)] = &[
    (10, 1),
    (10, 16),
    (10, 64),
    (100, 1),
    (100, 16),
    (100, 64),
    (1000, 1),
    (1000, 16),
];

/// Pre-D8 shape — receivers deep-clone the payload and serialize the
/// full envelope per recv. Publisher just stamps ts and calls
/// `bus.publish`. The frame_bytes field on `RoomMessage` is set to
/// `Bytes::new()` since this baseline path never consumes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "benchmark — run with --ignored --nocapture; pre-D8 shape"]
async fn bench_ws_publish_baseline() {
    println!("\n=== D8 WS publish — BASELINE (pre-refactor shape) ===");
    println!("subs × payload_kb | per_publish_us | total_ms");
    for &(n_subs, payload_kb) in SCENARIOS {
        let bus = RoomBus::new();
        let payload = serde_json::json!({"data": "x".repeat(payload_kb * 1024)});
        let (tx, mut rx) = mpsc::unbounded_channel::<()>();

        let mut handles = Vec::with_capacity(n_subs);
        for _ in 0..n_subs {
            let mut sub = bus.subscribe(TENANT, ROOM);
            let tx = tx.clone();
            let room_name = ROOM.to_string();
            handles.push(tokio::spawn(async move {
                loop {
                    match sub.recv().await {
                        Ok(rmsg) => {
                            // Pre-D8 send_json work, reproduced exactly:
                            let env = ServerMessage::Message {
                                room: room_name.clone(),
                                payload: (*rmsg.payload).clone(),
                                ts: rmsg.ts_ms,
                            };
                            let s = serde_json::to_string(&env).unwrap();
                            std::hint::black_box(s);
                            if tx.send(()).is_err() {
                                break;
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
            }));
        }
        drop(tx);

        // Warm-up: one publish + drain N acks
        let warm = RoomMessage {
            payload: Arc::new(payload.clone()),
            ts_ms: 1_700_000_000_000,
            frame_bytes: bytes::Bytes::new(),
        };
        assert_eq!(bus.publish(TENANT, ROOM, warm), n_subs);
        for _ in 0..n_subs {
            rx.recv().await.expect("warm recv");
        }

        let start = Instant::now();
        for i in 0..ITERATIONS {
            let msg = RoomMessage {
                payload: Arc::new(payload.clone()),
                ts_ms: 1_700_000_000_000 + i as i64,
                frame_bytes: bytes::Bytes::new(),
            };
            let delivered = bus.publish(TENANT, ROOM, msg);
            assert_eq!(delivered, n_subs);
            for _ in 0..n_subs {
                rx.recv().await.expect("bench recv");
            }
        }
        let elapsed = start.elapsed();
        let per_publish_us = elapsed.as_micros() / ITERATIONS as u128;
        println!(
            "  {n_subs:>4} × {payload_kb:>2}KB        | {per_publish_us:>10}    | {:>7}",
            elapsed.as_millis()
        );

        drop(bus);
        for h in handles {
            let _ = h.await;
        }
    }
}

/// Post-D8 shape — publisher serializes the envelope ONCE into
/// `frame_bytes`; receivers just `Bytes::clone()` and forward. Mirrors
/// `publish_into_bus` + `ws.rs::send_json` (Message branch).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "benchmark — run with --ignored --nocapture; post-D8 shape"]
async fn bench_ws_publish_d8() {
    println!("\n=== D8 WS publish — D8 (post-refactor shape) ===");
    println!("subs × payload_kb | per_publish_us | total_ms");
    for &(n_subs, payload_kb) in SCENARIOS {
        let bus = RoomBus::new();
        let payload = serde_json::json!({"data": "x".repeat(payload_kb * 1024)});
        let (tx, mut rx) = mpsc::unbounded_channel::<()>();

        let mut handles = Vec::with_capacity(n_subs);
        for _ in 0..n_subs {
            let mut sub = bus.subscribe(TENANT, ROOM);
            let tx = tx.clone();
            handles.push(tokio::spawn(async move {
                loop {
                    match sub.recv().await {
                        Ok(rmsg) => {
                            // Post-D8 send_json work: just forward bytes.
                            let frame = rmsg.frame_bytes.clone();
                            std::hint::black_box(frame);
                            if tx.send(()).is_err() {
                                break;
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
            }));
        }
        drop(tx);

        // Build a frame_bytes the same way publish_into_bus does.
        let build_msg = |ts_ms: i64, p: serde_json::Value| {
            let frame = ServerMessage::Message {
                room: ROOM.to_string(),
                payload: p,
                ts: ts_ms,
            };
            let frame_bytes = bytes::Bytes::from(serde_json::to_vec(&frame).unwrap());
            let ServerMessage::Message { payload, .. } = frame else {
                unreachable!()
            };
            RoomMessage {
                payload: Arc::new(payload),
                ts_ms,
                frame_bytes,
            }
        };

        // Warm-up
        let warm = build_msg(1_700_000_000_000, payload.clone());
        assert_eq!(bus.publish(TENANT, ROOM, warm), n_subs);
        for _ in 0..n_subs {
            rx.recv().await.expect("warm recv");
        }

        let start = Instant::now();
        for i in 0..ITERATIONS {
            let msg = build_msg(1_700_000_000_000 + i as i64, payload.clone());
            let delivered = bus.publish(TENANT, ROOM, msg);
            assert_eq!(delivered, n_subs);
            for _ in 0..n_subs {
                rx.recv().await.expect("bench recv");
            }
        }
        let elapsed = start.elapsed();
        let per_publish_us = elapsed.as_micros() / ITERATIONS as u128;
        println!(
            "  {n_subs:>4} × {payload_kb:>2}KB        | {per_publish_us:>10}    | {:>7}",
            elapsed.as_millis()
        );

        drop(bus);
        for h in handles {
            let _ = h.await;
        }
    }
}
