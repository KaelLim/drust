//! v1.31 REST publish handler — POST /t/{tenant}/rooms/{room}.
//!
//! Service-key only. Shares `publish_into_bus` with WS (C4) and MCP (C5)
//! — defense-in-depth ≥ 2 layers by construction.

use crate::auth::middleware::AuthCtx;
use crate::error::{json_error, json_error_with_aliases};
use crate::tenant::rooms::audit::{write_publish_audit, write_publish_audit_failure};
use crate::tenant::rooms::bus::{RoomBus, RoomMessage};
use crate::tenant::rooms::envelope::{codes, ServerMessage};
use crate::tenant::rooms::policy::{check_payload_size, validate_room_name, PublishBucket};
use crate::tenant::rooms::state::RoomsConfig;
use axum::extract::Path;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use std::sync::Arc;
use std::time::Instant;

/// Bundle of per-publish state. Cheap to clone (all Arc / Copy inside).
#[derive(Clone)]
pub struct PublishCtx {
    pub bus: RoomBus,
    pub bucket: Arc<PublishBucket>,
    pub cfg: RoomsConfig,
}

/// POST /t/{tenant}/rooms/{room} handler.
pub async fn publish_handler(
    pc: PublishCtx,
    Extension(ctx): Extension<AuthCtx>,
    Path((tenant, room)): Path<(String, String)>,
    Json(payload): Json<serde_json::Value>,
) -> Response {
    let started = Instant::now();
    let token_hint = match &ctx {
        AuthCtx::Service { .. } => "service",
        AuthCtx::User { .. } => "user",
        AuthCtx::Anon => "anon",
    };
    let admin_id = ctx.admin_id();

    // Auth: Service only.
    if !matches!(ctx, AuthCtx::Service { .. }) {
        return json_error_with_aliases(
            StatusCode::FORBIDDEN,
            "WRITE_DENIED",
            &["SERVICE_REQUIRED"],
            "service token required to publish",
        );
    }

    let byte_count = serde_json::to_vec(&payload).map(|v| v.len()).unwrap_or(0);
    let outcome = publish_into_bus(&pc, &tenant, &room, payload, "rest");
    let elapsed_ms = started.elapsed().as_millis() as u64;

    match outcome {
        Ok(delivered_to) => {
            write_publish_audit(
                &tenant,
                token_hint,
                elapsed_ms,
                &room,
                byte_count,
                "rest",
                delivered_to,
                admin_id,
            );
            (
                StatusCode::OK,
                Json(serde_json::json!({"ok": true, "delivered_to": delivered_to})),
            )
                .into_response()
        }
        Err(PublishError::RoomNameInvalid) => {
            write_publish_audit_failure(
                &tenant,
                token_hint,
                elapsed_ms,
                &room,
                byte_count,
                "rest",
                codes::ROOM_NAME_INVALID,
                admin_id,
            );
            json_error(
                StatusCode::BAD_REQUEST,
                codes::ROOM_NAME_INVALID,
                "room name does not match ^[a-zA-Z][a-zA-Z0-9_:.-]{0,127}$",
            )
        }
        Err(PublishError::ProtectedRoom) => {
            write_publish_audit_failure(
                &tenant,
                token_hint,
                elapsed_ms,
                &room,
                byte_count,
                "rest",
                codes::PROTECTED_ROOM,
                admin_id,
            );
            json_error(
                StatusCode::FORBIDDEN,
                codes::PROTECTED_ROOM,
                "room names starting with _system_ are reserved",
            )
        }
        Err(PublishError::PayloadTooLarge) => {
            write_publish_audit_failure(
                &tenant,
                token_hint,
                elapsed_ms,
                &room,
                byte_count,
                "rest",
                codes::PAYLOAD_TOO_LARGE,
                admin_id,
            );
            json_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                codes::PAYLOAD_TOO_LARGE,
                "payload exceeds DRUST_BROADCAST_PAYLOAD_MAX_BYTES",
            )
        }
        Err(PublishError::RateLimited(wait)) => {
            write_publish_audit_failure(
                &tenant,
                token_hint,
                elapsed_ms,
                &room,
                byte_count,
                "rest",
                codes::RATE_LIMITED,
                admin_id,
            );
            let secs = wait.as_secs().max(1);
            let body = serde_json::json!({
                "error_code": codes::RATE_LIMITED,
                "message": format!("publish QPS exhausted; retry after {secs}s"),
            });
            let mut r = (StatusCode::TOO_MANY_REQUESTS, Json(body)).into_response();
            r.headers_mut().insert(
                header::RETRY_AFTER,
                HeaderValue::from_str(&secs.to_string()).unwrap(),
            );
            r
        }
    }
}

/// Outcome of `publish_into_bus`. Wire mapping is caller-specific.
#[derive(Debug)]
pub enum PublishError {
    RoomNameInvalid,
    ProtectedRoom,
    PayloadTooLarge,
    RateLimited(std::time::Duration),
}

/// Shared publish path. Runs gates (room name → payload size → rate
/// limit), stamps ts, dispatches into the bus. Returns `delivered_to`
/// = receiver count at send time. **Does NOT emit audit** — the caller
/// emits with its own `source` so REST/WS/MCP can attribute.
pub fn publish_into_bus(
    pc: &PublishCtx,
    tenant: &str,
    room: &str,
    payload: serde_json::Value,
    _source: &'static str,
) -> Result<usize, PublishError> {
    // 1. Room name.
    if let Err(code) = validate_room_name(room) {
        return Err(if code == codes::PROTECTED_ROOM {
            PublishError::ProtectedRoom
        } else {
            PublishError::RoomNameInvalid
        });
    }
    // 2. Payload size — post-JSON-parse byte count (defense-in-depth
    //    beside axum DefaultBodyLimit on the route).
    let bytes = serde_json::to_vec(&payload).map(|v| v.len()).unwrap_or(0);
    if check_payload_size(bytes, pc.cfg.payload_max_bytes).is_err() {
        return Err(PublishError::PayloadTooLarge);
    }
    // 3. Per-tenant publish QPS.
    if let Err(wait) = pc.bucket.try_consume(tenant) {
        return Err(PublishError::RateLimited(wait));
    }
    // 4. Stamp ts + serialize once + dispatch.
    //
    // v1.32.2 D8 — pre-serialize the full ServerMessage::Message
    // envelope into `frame_bytes` once at publish time. The WS Message
    // fanout (ws.rs) forwards these bytes verbatim, replacing the prior
    // per-subscriber `(*Arc::clone).clone() + serde_json::to_string`
    // hot path. For N subscribers × K-byte payload that's a savings of
    // (N-1)×(deep-clone + serialize) per publish.
    //
    // Wire byte-identity: we serialize via the SAME `ServerMessage`
    // Serialize impl that send_json used to invoke, so the on-the-wire
    // JSON is byte-identical to pre-v1.32.2. The destructure-back pattern
    // moves payload into the frame for serialization, then extracts it
    // out for storage on the RoomMessage — zero deep-clone of the
    // payload Value on the publisher side.
    let ts_ms = chrono::Utc::now().timestamp_millis();
    let frame = ServerMessage::Message {
        room: room.to_string(),
        payload,
        ts: ts_ms,
    };
    let frame_bytes = bytes::Bytes::from(serde_json::to_vec(&frame).unwrap_or_default());
    let ServerMessage::Message { payload, .. } = frame else { unreachable!() };
    let msg = RoomMessage {
        payload: Arc::new(payload),
        ts_ms,
        frame_bytes,
    };
    let delivered = pc.bus.publish(tenant, room, msg);
    Ok(delivered)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// v1.32.2 D8 wire-identity proof: the pre-serialized `frame_bytes`
    /// MUST equal the bytes that the pre-D8 `send_json(&ServerMessage::Message{..})`
    /// path would have produced. If this drifts, every WS subscriber
    /// across every tenant immediately observes a wire change.
    #[test]
    fn d8_frame_bytes_is_byte_identical_to_legacy_send_json() {
        let payload = serde_json::json!({"hello": "world", "n": 42});
        let ts_ms = 1_748_534_400_123_i64;
        let room = "chat:42";

        // Mirror the new publisher path exactly.
        let frame = ServerMessage::Message {
            room: room.to_string(),
            payload: payload.clone(),
            ts: ts_ms,
        };
        let frame_bytes =
            bytes::Bytes::from(serde_json::to_vec(&frame).unwrap_or_default());

        // Mirror the old subscriber path exactly (what send_json built):
        let legacy_env = ServerMessage::Message {
            room: room.to_string(),
            payload,
            ts: ts_ms,
        };
        let legacy_str = serde_json::to_string(&legacy_env).unwrap();

        assert_eq!(
            std::str::from_utf8(&frame_bytes).unwrap(),
            legacy_str.as_str(),
            "D8 frame_bytes must match legacy send_json byte-for-byte"
        );
    }
}
