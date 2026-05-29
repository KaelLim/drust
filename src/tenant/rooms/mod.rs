//! v1.31 — broadcast rooms (WebSocket multiplex).
//!
//! Per-tenant in-memory channel keyed by `(tenant_id, room)`. Mirrors
//! the shape of `crate::tenant::events::EventBus` but carries
//! application-defined JSON payload instead of CRUD events.
//!
//! Subscribe: any AuthCtx (Anon/User/Service).
//! Publish: AuthCtx::Service only — enforced at three independent
//! sites (WS handler / REST publish / MCP `broadcast` tool).
//!
//! No DB schema, no replay, no per-room ACL. See spec
//! `docs/superpowers/specs/2026-05-29-drust-v131-broadcast-rooms-design.md`.

pub mod audit;
pub mod bus;
pub mod envelope;
pub mod policy;
pub mod rest;
pub mod state;
pub mod ws_auth;

pub use bus::{RoomBus, RoomMessage};
pub use envelope::{ClientOp, ServerMessage, codes};
pub use policy::{PublishBucket, validate_room_name};
pub use rest::{publish_handler, publish_into_bus, PublishCtx, PublishError};
pub use state::RoomsConfig;
