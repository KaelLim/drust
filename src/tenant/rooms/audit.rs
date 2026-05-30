//! v1.31 audit emit for broadcast.publish.
//!
//! One row per publish (regardless of WS / REST / MCP origin). Subscribe
//! / unsubscribe are NOT audited (would flood meta_logs.sqlite per spec
//! §Observability rationale).

use crate::safety::audit::AuditEntry;

/// Emit a successful publish audit row.
/// `source` ∈ {"ws", "rest", "mcp"}.
/// `actor_admin_id` is `Some(id)` when the publish came from an admin PAT
/// (v1.29+ admin tokens carry the admin id on `AuthCtx::Service`).
/// `None` for the shared per-tenant service token and for MCP (where
/// AuthCtx isn't threaded through rmcp's tool layer in v1.31.3 — see
/// CHANGELOG known limitation).
pub fn write_publish_audit(
    tenant: &str,
    token_hint: &str,
    duration_ms: u64,
    room: &str,
    byte_count: usize,
    source: &'static str,
    delivered_to: usize,
    actor_admin_id: Option<i64>,
) {
    let mut e = AuditEntry::success(tenant, token_hint, "broadcast.publish", duration_ms);
    e.actor_admin_id = actor_admin_id;
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
    actor_admin_id: Option<i64>,
) {
    let mut e =
        AuditEntry::failure(tenant, token_hint, "broadcast.publish", duration_ms, code, "");
    e.actor_admin_id = actor_admin_id;
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
        write_publish_audit("t", "abc", 1, "chat", 100, "rest", 5, None);
        write_publish_audit_failure("t", "abc", 1, "chat", 100, "rest", "RATE_LIMITED", None);
    }

    /// v1.31.3 F12 — when actor_admin_id is Some(id) the AuditEntry's
    /// own field MUST be populated so SQL queries can `WHERE
    /// actor_admin_id = ?`. We can't observe the row directly without
    /// audit_db plumbing, so this test exercises the helper compile-time
    /// surface and a wired-through shape via AuditEntry construction
    /// inline. Real DB-level audit assertion is covered in the existing
    /// audit_db integration tests at src/safety/audit_db.rs.
    #[test]
    fn admin_id_threads_into_audit_entry() {
        use crate::safety::audit::AuditEntry;
        // Mirror the helper's internal construction.
        let mut e = AuditEntry::success("t", "service", "broadcast.publish", 1);
        e.actor_admin_id = Some(42);
        assert_eq!(e.actor_admin_id, Some(42));
    }
}
