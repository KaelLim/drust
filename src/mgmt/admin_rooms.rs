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
//! select loop drops that room's fan-in arm.
//!
//! #955 — the two endpoints are no longer the same kind of operation, and
//! the difference is deliberate:
//!
//! * `evict-all` calls `RoomBus::evict_tenant`, which **also bumps the
//!   tenant's eviction epoch**. Every live WS connection compares its
//!   connect-time baseline before each inbound frame and on each keepalive
//!   tick, so the sockets themselves are closed (`CONN_EVICTED` + Close
//!   1008) within one tick — the admin now truly KICKS subscribers. Before
//!   #955 the connection survived with the `AuthCtx` and publish policy it
//!   captured at upgrade and could simply re-subscribe, so this endpoint
//!   amounted to "force a re-subscribe" rather than "drop them".
//! * `…/rooms/{room}/evict` calls `evict_room`, which does **not** bump.
//!   Per-room eviction is a data-plane operation (same family as a LAGGED
//!   recovery), not an identity event, so its semantics are unchanged:
//!   that room's subscribers lose the channel and may re-subscribe on the
//!   same connection.
//!
//! v1.31.3 — F14 validate_tenant_id at handler entry (400 on malformed
//! id rather than silent zero-count). F15 emit admin.broadcast.evict_*
//! audit rows with actor_admin_id for attribution.

use crate::auth::middleware::AdminId;
use crate::mgmt::tenants::TenantsState;
use crate::safety::audit::AuditEntry;
use crate::storage::tenant_db::validate_tenant_id;
use crate::tenant::rooms::policy::validate_room_name;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde_json::json;

/// `POST /admin/tenants/{id}/realtime/evict-all` — drop every broadcast
/// channel currently owned by this tenant AND close every live WS
/// connection on it. Returns the channel + subscriber counts at eviction
/// time. Idempotent: a tenant with no active rooms returns zero/zero.
///
/// #955 — the close is lazy, not immediate: `evict_tenant` bumps the
/// tenant's eviction epoch and each connection acts on the mismatch at its
/// next inbound frame or keepalive tick (`DRUST_BROADCAST_KEEPALIVE_SECS`,
/// default 30 s), sending `CONN_EVICTED` and then Close 1008. So the
/// returned `subscribers_dropped` is the count at eviction time, and the
/// sockets behind it are gone within ≤1 keepalive period rather than
/// synchronously with this response. Clients are expected to reconnect,
/// which re-runs the full bearer authentication — a revoked holder gets
/// 401 there and cannot come back.
///
/// The counts are read BEFORE the evict on purpose: afterwards the
/// channels are gone and both would report zero.
pub async fn evict_all_rooms_handler(
    State(s): State<TenantsState>,
    Extension(AdminId(caller_id)): Extension<AdminId>,
    Path(tenant_id): Path<String>,
) -> Response {
    // v1.31.3 F14 — reject malformed tenant ids at the door instead of
    // silently inserting them into the DashMap key space.
    if let Err(e) = validate_tenant_id(&tenant_id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error_code": "INVALID_TENANT_ID",
                "message": e.to_string(),
            })),
        )
            .into_response();
    }

    let subscribers_dropped = s.bus_rooms.tenant_subscriber_count(&tenant_id);
    let rooms_evicted = s.bus_rooms.tenant_channel_count(&tenant_id);
    s.bus_rooms.evict_tenant(&tenant_id);

    // v1.31.3 F15 — admin audit row with actor_admin_id attribution.
    let mut e = AuditEntry::success(&tenant_id, "admin", "admin.broadcast.evict_all", 0);
    e.actor_admin_id = Some(caller_id);
    e.extra.insert(
        "rooms_evicted".into(),
        serde_json::Value::Number(rooms_evicted.into()),
    );
    e.extra.insert(
        "subscribers_dropped".into(),
        serde_json::Value::Number(subscribers_dropped.into()),
    );
    crate::safety::audit_db::try_send(&e);

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
///
/// #955 — unlike `evict-all`, this does **not** touch the tenant's
/// eviction epoch and therefore does not close any connection: a socket
/// subscribed to other rooms keeps them, and a client may re-subscribe to
/// this room immediately. That is the intended semantic — per-room
/// eviction is a data-plane operation, not an identity event. Use
/// `evict-all` when the point is to kick the holders.
pub async fn evict_room_handler(
    State(s): State<TenantsState>,
    Extension(AdminId(caller_id)): Extension<AdminId>,
    Path((tenant_id, room)): Path<(String, String)>,
) -> Response {
    if let Err(e) = validate_tenant_id(&tenant_id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error_code": "INVALID_TENANT_ID",
                "message": e.to_string(),
            })),
        )
            .into_response();
    }
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

    let mut e = AuditEntry::success(&tenant_id, "admin", "admin.broadcast.evict_room", 0);
    e.actor_admin_id = Some(caller_id);
    e.extra
        .insert("room".into(), serde_json::Value::String(room.clone()));
    e.extra
        .insert("evicted".into(), serde_json::Value::Bool(evicted));
    e.extra.insert(
        "subscribers_dropped".into(),
        serde_json::Value::Number(subscribers_dropped.into()),
    );
    crate::safety::audit_db::try_send(&e);

    Json(json!({
        "tenant_id": tenant_id,
        "room": room,
        "evicted": evicted,
        "subscribers_dropped": subscribers_dropped,
    }))
    .into_response()
}

#[cfg(test)]
mod tests {
    use crate::tenant::rooms::RoomBus;

    /// Carried forward from v1.31.1 F2 regression — `rooms_evicted` MUST
    /// be the count of rooms dropped, not `null`.
    #[test]
    fn evict_tenant_count_snapshot_returns_real_count() {
        let bus = RoomBus::new();
        let _a = bus.subscribe("t-alpha", "chat");
        let _b = bus.subscribe("t-alpha", "presence");
        let _c = bus.subscribe("t-alpha", "metrics");
        let _x = bus.subscribe("t-beta", "chat");

        let rooms_evicted = bus.tenant_channel_count("t-alpha");
        bus.evict_tenant("t-alpha");

        assert_eq!(rooms_evicted, 3, "must report 3 rooms dropped");
        assert_eq!(bus.tenant_channel_count("t-alpha"), 0);
        assert_eq!(bus.tenant_channel_count("t-beta"), 1);
    }
}
