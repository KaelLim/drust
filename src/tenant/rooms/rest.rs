//! v1.31 REST publish handler — POST /t/{tenant}/rooms/{room}.
//!
//! Service-key only. Shares `publish_into_bus` with WS (C4) and MCP (C5)
//! — defense-in-depth ≥ 2 layers by construction.

use crate::auth::middleware::AuthCtx;
use crate::error::{json_error, json_error_with_aliases};
use crate::tenant::rooms::audit::{write_publish_audit, write_publish_audit_failure};
use crate::tenant::rooms::bus::{RoomBus, RoomMessage};
use crate::tenant::rooms::envelope::codes;
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
    // 4. Stamp ts + dispatch.
    let ts_ms = chrono::Utc::now().timestamp_millis();
    let msg = RoomMessage {
        payload: Arc::new(payload),
        ts_ms,
    };
    let delivered = pc.bus.publish(tenant, room, msg);
    Ok(delivered)
}
