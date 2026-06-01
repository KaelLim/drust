//! v1.31 wire envelope. Client → Server uses `op`-tagged objects;
//! Server → Client uses `kind`-tagged objects. Unknown fields are
//! ignored on deserialize (forward compatibility).

use serde::{Deserialize, Serialize};

/// Upstream message from WS client. `ref` is optional; if present
/// server echoes it on the resulting `ack` / `error`.
#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ClientOp {
    Subscribe {
        room: String,
        #[serde(default, rename = "ref")]
        client_ref: Option<String>,
    },
    Unsubscribe {
        room: String,
        #[serde(default, rename = "ref")]
        client_ref: Option<String>,
    },
    Publish {
        room: String,
        payload: serde_json::Value,
        #[serde(default, rename = "ref")]
        client_ref: Option<String>,
    },
    Ping {
        #[serde(default, rename = "ref")]
        client_ref: Option<String>,
    },
}

/// Downstream message to WS client.
#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ServerMessage {
    /// Fan-out from publish — all subscribers receive.
    Message {
        room: String,
        payload: serde_json::Value,
        ts: i64,
    },
    /// Confirmation of a client op (when client supplied `ref`).
    Ack {
        #[serde(rename = "ref", skip_serializing_if = "Option::is_none")]
        client_ref: Option<String>,
        op: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        room: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        delivered_to: Option<usize>,
    },
    /// Typed error response.
    Error {
        #[serde(rename = "ref", skip_serializing_if = "Option::is_none")]
        client_ref: Option<String>,
        code: &'static str,
        msg: String,
        /// Optional context (e.g. room name for ROOM_NAME_INVALID).
        #[serde(skip_serializing_if = "Option::is_none")]
        room: Option<String>,
    },
    /// Response to client `op:ping` (NOT WS PING frame).
    Pong {
        #[serde(rename = "ref", skip_serializing_if = "Option::is_none")]
        client_ref: Option<String>,
    },
}

/// Error codes for `ServerMessage::Error.code`.
pub mod codes {
    pub const WS_PUBLISH_DENIED: &str = "WS_PUBLISH_DENIED";
    /// v1.32.5 — emitted when a user token tries `op:publish` on a tenant
    /// whose `allow_user_publish` flag is still off (default).
    pub const WS_PUBLISH_USER_DENIED: &str = "WS_PUBLISH_USER_DENIED";
    /// v1.32.5 — emitted when an anon token tries `op:publish` on a tenant
    /// whose `allow_anon_publish` flag is still off (default).
    pub const WS_PUBLISH_ANON_DENIED: &str = "WS_PUBLISH_ANON_DENIED";
    pub const ROOM_NAME_INVALID: &str = "ROOM_NAME_INVALID";
    pub const PROTECTED_ROOM: &str = "PROTECTED_ROOM";
    pub const PAYLOAD_TOO_LARGE: &str = "PAYLOAD_TOO_LARGE";
    pub const RATE_LIMITED: &str = "RATE_LIMITED";
    pub const ROOM_FULL: &str = "ROOM_FULL";
    pub const CLIENT_ROOM_MAX: &str = "CLIENT_ROOM_MAX";
    pub const UNKNOWN_OP: &str = "UNKNOWN_OP";
    pub const MALFORMED_FRAME: &str = "MALFORMED_FRAME";
    pub const LAGGED: &str = "LAGGED";
    pub const ROOM_EVICTED: &str = "ROOM_EVICTED";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscribe_op_deserializes_with_and_without_ref() {
        let with: ClientOp =
            serde_json::from_str(r#"{"op":"subscribe","room":"chat","ref":"c-1"}"#).unwrap();
        assert!(
            matches!(with, ClientOp::Subscribe { ref client_ref, .. } if client_ref.as_deref() == Some("c-1"))
        );
        let without: ClientOp =
            serde_json::from_str(r#"{"op":"subscribe","room":"chat"}"#).unwrap();
        assert!(
            matches!(without, ClientOp::Subscribe { ref client_ref, .. } if client_ref.is_none())
        );
    }

    #[test]
    fn publish_op_carries_payload() {
        let m: ClientOp =
            serde_json::from_str(r#"{"op":"publish","room":"chat","payload":{"x":1}}"#).unwrap();
        match m {
            ClientOp::Publish { room, payload, .. } => {
                assert_eq!(room, "chat");
                assert_eq!(payload, serde_json::json!({"x": 1}));
            }
            _ => panic!("expected Publish"),
        }
    }

    #[test]
    fn unknown_op_fails_to_parse_so_handler_emits_unknown_op() {
        let r: Result<ClientOp, _> = serde_json::from_str(r#"{"op":"wat","room":"chat"}"#);
        assert!(r.is_err());
    }

    #[test]
    fn server_message_serializes_with_kind_tag() {
        let m = ServerMessage::Message {
            room: "chat".into(),
            payload: serde_json::json!({"hi": true}),
            ts: 1748534400123,
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains(r#""kind":"message""#));
        assert!(s.contains(r#""ts":1748534400123"#));
    }

    #[test]
    fn server_message_ack_drops_ref_when_none() {
        let m = ServerMessage::Ack {
            client_ref: None,
            op: "subscribe",
            room: Some("chat".into()),
            delivered_to: None,
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(!s.contains(r#""ref""#));
        assert!(s.contains(r#""op":"subscribe""#));
    }

    #[test]
    fn unknown_extra_field_is_ignored_on_deserialize() {
        // Forward compatibility: clients on v1.32 may add fields.
        let r: ClientOp = serde_json::from_str(
            r#"{"op":"subscribe","room":"chat","future_field":42}"#,
        )
        .unwrap();
        assert!(matches!(r, ClientOp::Subscribe { .. }));
    }
}
