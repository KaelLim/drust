//! v1.32.2 D8 benchmark — pre-refactor baseline.
//!
//! Synthetic bench at the RoomBus + send_json-equivalent layer. Bypasses
//! WS framing entirely — measures only the work that disappears after
//! the D8 refactor (deep-clone Arc<Value> + serde_json::to_string per
//! subscriber). WS-based bench is impossible: tests/rooms_ws.rs is all
//! `#[ignore]`'d due to tokio-rs/tokio#2374 (per-test runtime starvation
//! at <10 concurrent clients).
//!
//! Run: cargo test --test bench_ws_publish -- --ignored --nocapture
//! NEVER --release (Cargo.toml LTO hangs 40+ min).
//!
//! 1000×64KB scenario intentionally omitted: per-iteration alloc is
//! ~64MB (1000 deep-clones of a 64KB Value); 100 iterations push the
//! allocator into severe pressure and the wall-clock balloons past
//! useful bench territory. 1000×16KB + 100×64KB give the same signal.

use drust::tenant::rooms::{RoomBus, RoomMessage, ServerMessage};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{broadcast, mpsc};

const TENANT: &str = "bench-tenant";
const ROOM: &str = "bench-room";
const ITERATIONS: usize = 100;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "benchmark — run with --ignored --nocapture for D8 baseline"]
async fn bench_ws_publish_baseline() {
    println!("\n=== D8 WS publish baseline ===");
    println!("subs × payload_kb | per_publish_us | total_ms");

    // (subs, payload_kb) — 1000×64KB omitted (see file header).
    let scenarios: &[(usize, usize)] = &[
        (10, 1), (10, 16), (10, 64),
        (100, 1), (100, 16), (100, 64),
        (1000, 1), (1000, 16),
    ];

    for &(n_subs, payload_kb) in scenarios {
        {
            let bus = RoomBus::new();
            let payload = serde_json::json!({"data": "x".repeat(payload_kb * 1024)});

            let (tx, mut rx) = mpsc::unbounded_channel::<()>();

            // Spawn N receivers
            let mut handles = Vec::with_capacity(n_subs);
            for _ in 0..n_subs {
                let mut sub = bus.subscribe(TENANT, ROOM);
                let tx = tx.clone();
                let room_name = ROOM.to_string();
                handles.push(tokio::spawn(async move {
                    loop {
                        match sub.recv().await {
                            Ok(rmsg) => {
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
            drop(tx); // close extra producer

            // Warm-up: one publish + drain N acks
            let warm = RoomMessage {
                payload: Arc::new(payload.clone()),
                ts_ms: 1_700_000_000_000,
            };
            assert_eq!(bus.publish(TENANT, ROOM, warm), n_subs);
            for _ in 0..n_subs {
                rx.recv().await.expect("warm recv");
            }

            // Measure ITERATIONS publishes
            let start = Instant::now();
            for i in 0..ITERATIONS {
                let msg = RoomMessage {
                    payload: Arc::new(payload.clone()),
                    ts_ms: 1_700_000_000_000 + i as i64,
                };
                let delivered = bus.publish(TENANT, ROOM, msg);
                assert_eq!(delivered, n_subs);
                for _ in 0..n_subs {
                    rx.recv().await.expect("bench recv");
                }
            }
            let elapsed = start.elapsed();
            let per_publish_us = elapsed.as_micros() / ITERATIONS as u128;
            let total_ms = elapsed.as_millis();
            println!(
                "  {n_subs:>4} × {payload_kb:>2}KB        | {per_publish_us:>10}    | {total_ms:>7}"
            );

            // Cleanup: drop bus → receivers exit on RecvError::Closed
            drop(bus);
            for h in handles {
                let _ = h.await;
            }
        }
    }
}
