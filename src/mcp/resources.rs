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

/// The parsed, tenant-checked resource identity. Static entries (M2); Task 3 adds
/// the record/history templates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceUri {
    /// `drust://<t>/schema` — the `get_schema_overview` payload (bootstrap first stop).
    Schema,
    /// `drust://<t>/schema.md` — the same overview as a Markdown table (token-lean).
    SchemaMd,
    /// `drust://<t>/collections` — names + descriptions + row counts.
    Collections,
    /// `drust://<t>/openapi.json` — service-tier OpenAPI 3.1 (codegen).
    OpenApi,
    /// `drust://<t>/types.ts` — TypeScript Row/Insert/Update interfaces (codegen).
    TypesTs,
    /// `drust://<t>/zod.ts` — Zod runtime validators (codegen).
    ZodTs,
    /// `drust://<t>/functions` — edge-function inventory.
    Functions,
    /// `drust://<t>/rpcs` — stored-RPC inventory.
    Rpcs,
    /// `drust://<t>/cron` — cron-job inventory.
    Cron,
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
        ["schema.md"] => Ok(ResourceUri::SchemaMd),
        ["collections"] => Ok(ResourceUri::Collections),
        ["openapi.json"] => Ok(ResourceUri::OpenApi),
        ["types.ts"] => Ok(ResourceUri::TypesTs),
        ["zod.ts"] => Ok(ResourceUri::ZodTs),
        ["functions"] => Ok(ResourceUri::Functions),
        ["rpcs"] => Ok(ResourceUri::Rpcs),
        ["cron"] => Ok(ResourceUri::Cron),
        _ => Err(not_found(raw)),
    }
}

/// The resources advertised in `resources/list` (all static; templates are NOT
/// listed — they surface via `resources/templates/list` in Task 3).
pub fn static_resource_list(t: &str) -> Vec<Resource> {
    let e = |path: &str, name: &str, desc: &str, mime: &str| {
        RawResource::new(format!("drust://{t}/{path}"), name.to_string())
            .with_description(desc.to_string())
            .with_mime_type(mime.to_string())
            .no_annotation()
    };
    vec![
        e(
            "schema",
            "schema",
            "Full tenant schema overview (collections, fields, indexes, caps, RPCs) — the bootstrap first stop.",
            "application/json",
        ),
        e(
            "schema.md",
            "schema (markdown)",
            "The schema overview as a Markdown table — usually more token-lean than the JSON.",
            "text/markdown",
        ),
        e(
            "collections",
            "collections",
            "Collection names, descriptions and row counts.",
            "application/json",
        ),
        e(
            "openapi.json",
            "openapi",
            "Service-tier OpenAPI 3.1 spec (all CRUD + search + aggregate).",
            "application/json",
        ),
        e(
            "types.ts",
            "types.ts",
            "TypeScript Row / Insert / Update interfaces.",
            "text/typescript",
        ),
        e(
            "zod.ts",
            "zod.ts",
            "Zod runtime validators for every collection.",
            "text/typescript",
        ),
        e(
            "functions",
            "functions",
            "Edge-function inventory.",
            "application/json",
        ),
        e("rpcs", "rpcs", "Stored-RPC inventory.", "application/json"),
        e("cron", "cron", "Cron-job inventory.", "application/json"),
    ]
}

/// Build the service-tier codegen IR (descriptions included — MCP is service-only).
async fn codegen_ir(s: &DrustMcp) -> Result<crate::codegen::ir::CodegenIr, McpError> {
    crate::codegen::build_ir(&s.inner().pool, s.tenant_id(), s.public_base_url(), true)
        .await
        .map_err(internal)
}

/// Render the `get_schema_overview` JSON (`{tenant, collections:[…], rpcs:[…]}`)
/// as a compact Markdown table. Defensive: missing keys are skipped.
fn schema_json_to_md(v: &serde_json::Value) -> String {
    let mut out = String::new();
    if let Some(t) = v.get("tenant").and_then(|x| x.as_str()) {
        out.push_str(&format!("# Tenant `{t}` schema\n\n"));
    }
    if let Some(cols) = v.get("collections").and_then(|x| x.as_array()) {
        for c in cols {
            let name = c.get("name").and_then(|x| x.as_str()).unwrap_or("?");
            out.push_str(&format!("## `{name}`\n\n"));
            if let Some(fields) = c.get("fields").and_then(|x| x.as_array()) {
                out.push_str("| field | type | nullable | pk |\n|---|---|---|---|\n");
                for f in fields {
                    let fname = f.get("name").and_then(|x| x.as_str()).unwrap_or("?");
                    let ty = f.get("sql_type").and_then(|x| x.as_str()).unwrap_or("?");
                    let nul = f.get("nullable").and_then(|x| x.as_bool()).unwrap_or(false);
                    let pk = f.get("pk").and_then(|x| x.as_bool()).unwrap_or(false);
                    out.push_str(&format!("| {fname} | {ty} | {nul} | {pk} |\n"));
                }
                out.push('\n');
            }
            for (label, key) in [("anon_caps", "anon_caps"), ("user_caps", "user_caps")] {
                if let Some(val) = c.get(key) {
                    out.push_str(&format!("- {label}: {val}\n"));
                }
            }
            if let Some(of) = c.get("owner_field").filter(|x| !x.is_null()) {
                out.push_str(&format!("- owner_field: {of}\n"));
            }
            out.push('\n');
        }
    }
    if let Some(rpcs) = v.get("rpcs").and_then(|x| x.as_array())
        && !rpcs.is_empty()
    {
        out.push_str("## Stored RPCs\n\n");
        for r in rpcs {
            let rn = r.get("name").and_then(|x| x.as_str()).unwrap_or("?");
            out.push_str(&format!("- `{rn}`\n"));
        }
    }
    out
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
/// Strip credential-bearing free-form fields from a config-inventory value
/// before it becomes an **auto-fetchable** resource (spec §3 — a client may pull
/// a resource into context WITHOUT an explicit model call, unlike a tool). An
/// RPC `sql` body or param `default` can embed a hardcoded secret; the inventory
/// (names / shape / mode) is what a bootstrapping agent needs, and the full body
/// stays available via the explicit `list_rpc` / `call_rpc` tools. Operates on
/// the JSON array of RPC objects (as `get_schema_overview` and the `rpcs`
/// resource both carry it).
fn redact_rpc_array(rpcs: &mut serde_json::Value) {
    let Some(arr) = rpcs.as_array_mut() else {
        return;
    };
    for r in arr {
        let Some(obj) = r.as_object_mut() else {
            continue;
        };
        obj.remove("sql");
        if let Some(params) = obj.get_mut("params").and_then(|p| p.as_array_mut()) {
            for p in params {
                if let Some(po) = p.as_object_mut() {
                    po.remove("default");
                }
            }
        }
    }
}

/// Strip `payload_json` from the cron inventory — a cron payload is free-form
/// tenant JSON that can carry a token/secret (spec §3). Shape: `{"jobs":[…]}`.
fn redact_cron(jobs: &mut serde_json::Value) {
    let Some(arr) = jobs.get_mut("jobs").and_then(|j| j.as_array_mut()) else {
        return;
    };
    for j in arr {
        if let Some(obj) = j.as_object_mut() {
            obj.remove("payload_json");
        }
    }
}

pub async fn render_resource(
    s: &DrustMcp,
    uri: &ResourceUri,
) -> Result<(String, &'static str), McpError> {
    let json = |v: &serde_json::Value| -> Result<(String, &'static str), McpError> {
        Ok((
            serde_json::to_string(v).map_err(internal)?,
            "application/json",
        ))
    };
    match uri {
        ResourceUri::Schema => {
            let mut v = exploration::get_schema_overview(s)
                .await
                .map_err(internal)?;
            if let Some(rpcs) = v.get_mut("rpcs") {
                redact_rpc_array(rpcs);
            }
            json(&v)
        }
        ResourceUri::SchemaMd => {
            let v = exploration::get_schema_overview(s)
                .await
                .map_err(internal)?;
            Ok((schema_json_to_md(&v), "text/markdown"))
        }
        ResourceUri::Collections => {
            json(&exploration::list_collections(s).await.map_err(internal)?)
        }
        ResourceUri::OpenApi => {
            let ir = codegen_ir(s).await?;
            json(&crate::codegen::openapi::render_openapi(&ir))
        }
        ResourceUri::TypesTs => {
            let ir = codegen_ir(s).await?;
            Ok((
                crate::codegen::typescript::render_typescript(&ir),
                "text/typescript",
            ))
        }
        ResourceUri::ZodTs => {
            let ir = codegen_ir(s).await?;
            Ok((crate::codegen::zod::render_zod(&ir), "text/typescript"))
        }
        ResourceUri::Functions => json(
            &crate::mcp::tools::functions::list_functions(s)
                .await
                .map_err(internal)?,
        ),
        ResourceUri::Rpcs => {
            // Mirror the `list_rpc` tool: registry read on a pooled reader.
            let rows = s
                .inner()
                .pool
                .with_reader(|c| {
                    crate::rpc::registry::list(c).map_err(|e| {
                        rusqlite::Error::SqliteFailure(
                            rusqlite::ffi::Error::new(1),
                            Some(e.to_string()),
                        )
                    })
                })
                .await
                .map_err(internal)?;
            let mut v = serde_json::to_value(&rows).map_err(internal)?;
            redact_rpc_array(&mut v);
            json(&v)
        }
        ResourceUri::Cron => {
            let mut v = crate::mcp::tools::cron::list_cron_jobs(s)
                .await
                .map_err(internal)?;
            redact_cron(&mut v);
            json(&v)
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
    fn parses_all_static_paths() {
        use ResourceUri::*;
        for (path, want) in [
            ("schema", Schema),
            ("schema.md", SchemaMd),
            ("collections", Collections),
            ("openapi.json", OpenApi),
            ("types.ts", TypesTs),
            ("zod.ts", ZodTs),
            ("functions", Functions),
            ("rpcs", Rpcs),
            ("cron", Cron),
        ] {
            let uri = format!("drust://t-abc/{path}");
            assert_eq!(parse_resource_uri(&uri, "t-abc").unwrap(), want, "{path}");
        }
    }

    #[test]
    fn rejects_cross_tenant_uri() {
        let e = parse_resource_uri("drust://t-other/schema", "t-abc").unwrap_err();
        assert_eq!(e.code.0, -32002);
    }

    #[test]
    fn redact_rpc_array_strips_sql_and_param_defaults() {
        // spec §3: an auto-fetchable resource must not carry a credential that a
        // stored RPC could embed in its SQL body or a param default.
        let mut v = serde_json::json!([
            {"name": "r1", "sql": "SELECT 'SECRET_TOKEN_abc'",
             "params": [{"name": "k", "default": "SECRET_DEFAULT_xyz"}]}
        ]);
        redact_rpc_array(&mut v);
        let s = v.to_string();
        assert!(
            !s.contains("SECRET_TOKEN_abc"),
            "sql body must be stripped: {s}"
        );
        assert!(
            !s.contains("SECRET_DEFAULT_xyz"),
            "param default must be stripped: {s}"
        );
        assert!(s.contains("r1"), "name is preserved");
        assert!(s.contains("\"k\""), "param name is preserved");
    }

    #[test]
    fn redact_cron_strips_payload_json() {
        let mut v = serde_json::json!({"jobs": [
            {"name": "j1", "schedule": "* * * * *", "payload_json": "{\"token\":\"SECRET_PAYLOAD\"}"}
        ]});
        redact_cron(&mut v);
        let s = v.to_string();
        assert!(
            !s.contains("SECRET_PAYLOAD"),
            "cron payload must be stripped: {s}"
        );
        assert!(s.contains("j1"), "job name is preserved");
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
