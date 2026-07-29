//! MCP Resources (v1.56, M2) — the URI parser + a thin router that projects
//! tenant knowledge into `drust://<tenant>/<path>` resources by calling the SAME
//! `src/mcp/tools/*` reader functions the tools use (zero new SQL, zero new
//! enforcement). MCP is service-only (gated in `mcp_dispatch` before the
//! handler), so every read runs at `AuthCtx::Service` via `&DrustMcp`.
//!
//! The router logic lives in pure helpers (`parse_resource_uri`,
//! `render_resource`, `static_resource_list`) tested directly; the thin
//! `ServerHandler` methods in `handler.rs` wrap them (constructing a
//! `RequestContext` in a unit test is impractical).

use crate::mcp::server::DrustMcp;
use crate::mcp::tools::exploration;
use rmcp::ErrorData as McpError;
use rmcp::model::{AnnotateAble, RawResource, Resource};

/// Per-resource body byte cap. Over-cap bodies are truncated with a marker so an
/// unbounded page never streams into model context. `DRUST_MCP_RESOURCE_MAX_BYTES`
/// (default 256 KiB; non-positive/garbage → default).
pub fn resource_max_bytes() -> usize {
    std::env::var("DRUST_MCP_RESOURCE_MAX_BYTES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(262_144)
}

/// The parsed, tenant-checked resource identity. Static entries only in M2 Task 1;
/// Task 2 adds the remaining static resources, Task 3 the record/history templates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceUri {
    /// `drust://<t>/schema` — the `get_schema_overview` payload (bootstrap first stop).
    Schema,
}

fn not_found(uri: &str) -> McpError {
    McpError::resource_not_found(format!("no such resource: {uri}"), None)
}

fn internal(e: impl std::fmt::Display) -> McpError {
    McpError::internal_error(e.to_string(), None)
}

/// Parse + tenant-authorize a `drust://<tenant>/<path>` URI. Deny-by-default:
/// any non-canonical shape or unknown path → `-32002` (`resource_not_found`).
///
/// Hardened per the v1.49.4 parser-differential lesson (spec §6) + the Task-1
/// codex cross-check: a SINGLE `url::Url` parse, then reject every decorated /
/// normalized authority form so `url`'s own path normalization (it resolves
/// `%2e%2e` before `path()`) cannot slip a malformed URI past the segment match.
/// The **cross-tenant guard is `host_str() == tenant_id`** — the path can never
/// change the host, so traversal cannot cross tenants (DiD layer 2; layer 1 is
/// the per-tenant service instance). `as_str() == raw` is the key backstop: if
/// `url` rewrote the input at all (dot-segments, an alias scheme case), it was
/// not canonical → reject.
pub fn parse_resource_uri(raw: &str, tenant_id: &str) -> Result<ResourceUri, McpError> {
    let u = url::Url::parse(raw).map_err(|_| not_found(raw))?;
    if u.scheme() != "drust"
        || !u.username().is_empty()
        || u.password().is_some()
        || u.port().is_some()
        || u.fragment().is_some()
        || u.query().is_some() // no static resource takes a query (templates relax this in Task 3)
        || u.cannot_be_a_base()
        || u.host_str() != Some(tenant_id)
        || u.as_str() != raw
    {
        return Err(not_found(raw));
    }
    let segs: Vec<&str> = match u.path_segments() {
        Some(it) => it.collect(),
        None => return Err(not_found(raw)),
    };
    // Reject empty segments (`//`, trailing `/`) — no valid resource has them.
    if segs.iter().any(|s| s.is_empty()) {
        return Err(not_found(raw));
    }
    match segs.as_slice() {
        ["schema"] => Ok(ResourceUri::Schema),
        _ => Err(not_found(raw)),
    }
}

/// The resources advertised in `resources/list`. Task 2 extends this.
pub fn static_resource_list(tenant_id: &str) -> Vec<Resource> {
    vec![
        RawResource::new(format!("drust://{tenant_id}/schema"), "schema")
            .with_description("Full tenant schema overview (collections, fields, indexes, caps) — the bootstrap first stop.")
            .with_mime_type("application/json")
            .no_annotation(),
    ]
}

/// Render a parsed resource to `(body, mime)` by calling the existing reader fn —
/// same path, same `_system_*` protection as the corresponding tool.
///
/// Read-size note (codex Task-1 review): `cap_body` bounds the returned BODY, not
/// the pre-serialization read. That is acceptable here because every resource is
/// bounded at the source: `schema`/codegen resources read the tenant's OWN config
/// (identical to the existing `get_schema_overview`/codegen tools — service-only,
/// no new amplification), and the record/history templates (Task 3) are
/// page-bounded (`per_page` ≤ 200). No resource reads attacker-unbounded data
/// before the cap.
pub async fn render_resource(
    s: &DrustMcp,
    uri: &ResourceUri,
) -> Result<(String, &'static str), McpError> {
    match uri {
        ResourceUri::Schema => {
            let v = exploration::get_schema_overview(s)
                .await
                .map_err(internal)?;
            Ok((
                serde_json::to_string(&v).map_err(internal)?,
                "application/json",
            ))
        }
    }
}

/// Truncate an over-cap body to a UTF-8 boundary + append a machine-readable
/// marker, so a caller can detect the cut. Under the cap the body is returned
/// unchanged.
pub fn cap_body(body: String) -> String {
    let max = resource_max_bytes();
    if body.len() <= max {
        return body;
    }
    // Find the largest char boundary <= max.
    let mut cut = max;
    while cut > 0 && !body.is_char_boundary(cut) {
        cut -= 1;
    }
    format!(
        "{}\n\n[[truncated: DRUST_MCP_RESOURCE_MAX_BYTES={max}; {} bytes omitted]]",
        &body[..cut],
        body.len() - cut
    )
}

/// One `mcp.resource.read` audit row (URI in the `collection` field, mirroring
/// how `functions::routes::audit_fn` names the entity). No `token_hint` on the
/// MCP handler → empty.
pub(crate) fn audit_resource_read(s: &DrustMcp, uri: &str) {
    let e = crate::safety::audit::AuditEntry::success(s.tenant_id(), "", "mcp.resource.read", 0)
        .with_collection(uri);
    crate::safety::audit_db::try_send(&e);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_schema_uri_for_own_tenant() {
        assert_eq!(
            parse_resource_uri("drust://t-abc/schema", "t-abc").unwrap(),
            ResourceUri::Schema
        );
    }

    #[test]
    fn rejects_cross_tenant_uri() {
        let e = parse_resource_uri("drust://t-other/schema", "t-abc").unwrap_err();
        assert_eq!(e.code.0, -32002);
    }

    #[test]
    fn rejects_traversal_normalization_and_unknown() {
        // url resolves %2e%2e before path(); the as_str()==raw backstop catches it.
        for bad in [
            "drust://t-abc/../secret",
            "drust://t-abc/schema/../x",
            "drust://t-abc/x/%2e%2e/schema",
            "drust://t-abc/nope",
            "drust://t-abc//schema",
            "drust://t-abc/schema/",
        ] {
            assert_eq!(
                parse_resource_uri(bad, "t-abc").unwrap_err().code.0,
                -32002,
                "{bad}"
            );
        }
    }

    #[test]
    fn rejects_decorated_authority() {
        for bad in [
            "drust://user@t-abc/schema", // userinfo
            "drust://t-abc:99/schema",   // port
            "drust://t-abc/schema#frag", // fragment
            "drust://t-abc/schema?x=1",  // query (static resources take none)
            "DRUST://t-abc/schema",      // scheme case → url lowercases → as_str != raw
            "https://t-abc/schema",      // wrong scheme
        ] {
            assert_eq!(
                parse_resource_uri(bad, "t-abc").unwrap_err().code.0,
                -32002,
                "{bad}"
            );
        }
    }
}
