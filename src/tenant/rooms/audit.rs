//! v1.31 audit emit for broadcast.publish.
//!
//! One row per publish (regardless of WS / REST / MCP origin). Subscribe
//! / unsubscribe are NOT audited (would flood meta_logs.sqlite per spec
//! §Observability rationale).

use crate::safety::audit::AuditEntry;

/// Emit a successful publish audit row.
/// `source` ∈ {"ws", "rest", "mcp"}.
pub fn write_publish_audit(
    tenant: &str,
    token_hint: &str,
    duration_ms: u64,
    room: &str,
    byte_count: usize,
    source: &'static str,
    delivered_to: usize,
) {
    let mut e = AuditEntry::success(tenant, token_hint, "broadcast.publish", duration_ms);
    e.extra
        .insert("room".into(), serde_json::Value::String(room.into()));
    e.extra.insert(
        "byte_count".into(),
        serde_json::Value::Number(byte_count.into()),
    );
    e.extra.insert(
        "source".into(),
        serde_json::Value::String(source.into()),
    );
    e.extra.insert(
        "delivered_to".into(),
        serde_json::Value::Number(delivered_to.into()),
    );
    crate::safety::audit_db::try_send(&e);
}

/// Emit a failed publish audit row (rate-limited / payload-too-large / etc).
pub fn write_publish_audit_failure(
    tenant: &str,
    token_hint: &str,
    duration_ms: u64,
    room: &str,
    byte_count: usize,
    source: &'static str,
    code: &str,
) {
    let mut e =
        AuditEntry::failure(tenant, token_hint, "broadcast.publish", duration_ms, code, "");
    e.extra
        .insert("room".into(), serde_json::Value::String(room.into()));
    e.extra.insert(
        "byte_count".into(),
        serde_json::Value::Number(byte_count.into()),
    );
    e.extra.insert(
        "source".into(),
        serde_json::Value::String(source.into()),
    );
    crate::safety::audit_db::try_send(&e);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_helpers_compile_with_current_audit_entry_shape() {
        write_publish_audit("t", "abc", 1, "chat", 100, "rest", 5);
        write_publish_audit_failure("t", "abc", 1, "chat", 100, "rest", "RATE_LIMITED");
    }
}
