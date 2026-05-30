//! v1.31 — admin-side broadcast room operations.
//!
//! Two service-only (admin-session-gated by `routes::admin_session_layer`)
//! endpoints let operators drop hung subscribers without touching the
//! systemd unit:
//!
//!   POST /admin/tenants/{id}/realtime/evict-all
//!     -> { rooms_evicted, subscribers_dropped }
//!   POST /admin/tenants/{id}/realtime/rooms/{room}/evict
//!     -> { room, subscribers_dropped }
//!
//! Eviction drops the broadcast channel sender; every subscriber's
//! `BroadcastStream` yields `None` on the next poll and the WS handler's
//! select loop terminates the connection cleanly.

use crate::mgmt::tenants::TenantsState;
use crate::tenant::rooms::policy::validate_room_name;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

/// `POST /admin/tenants/{id}/realtime/evict-all` — drop every broadcast
/// channel currently owned by this tenant. Returns the channel + subscriber
/// counts at eviction time. Idempotent: a tenant with no active rooms
/// returns zero/zero.
pub async fn evict_all_rooms_handler(
    State(s): State<TenantsState>,
    Path(tenant_id): Path<String>,
) -> Response {
    let subscribers_dropped = s.bus_rooms.tenant_subscriber_count(&tenant_id);
    let rooms_evicted = s.bus_rooms.evict_tenant(&tenant_id);
    Json(json!({
        "tenant_id": tenant_id,
        "rooms_evicted": rooms_evicted,
        "subscribers_dropped": subscribers_dropped,
    }))
    .into_response()
}

/// `POST /admin/tenants/{id}/realtime/rooms/{room}/evict` — drop a single
/// broadcast channel. Returns the subscriber count at eviction time. A
/// non-existent room returns `subscribers_dropped: 0` (idempotent).
/// Refuses invalid room names with the same `ROOM_NAME_INVALID` /
/// `PROTECTED_ROOM` shape as the publish surface for consistency.
pub async fn evict_room_handler(
    State(s): State<TenantsState>,
    Path((tenant_id, room)): Path<(String, String)>,
) -> Response {
    if let Err(code) = validate_room_name(&room) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error_code": code,
                "message": "room name rejected by publish-surface policy",
            })),
        )
            .into_response();
    }
    let subscribers_dropped = s.bus_rooms.current_subscriber_count(&tenant_id, &room);
    let evicted = s.bus_rooms.evict_room(&tenant_id, &room);
    Json(json!({
        "tenant_id": tenant_id,
        "room": room,
        "evicted": evicted,
        "subscribers_dropped": subscribers_dropped,
    }))
    .into_response()
}
