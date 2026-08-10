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

/// The parsed, tenant-checked resource identity. The first nine are static
/// (M2); the last four are the M4 templates (parsed + validated here so
/// `render_resource` only ever sees an already-authorized shape).
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
    // ── M4 templates ──
    /// `drust://<t>/collections/{c}/schema` — one collection's full schema.
    CollectionSchema { collection: String },
    /// `drust://<t>/collections/{c}/records{?page,per_page,sort,order}` — a page of rows.
    Records {
        collection: String,
        page: Option<u32>,
        per_page: Option<u32>,
        sort: Option<String>,
        order: Option<String>,
    },
    /// `drust://<t>/collections/{c}/records/{id}` — one row by integer id.
    Record { collection: String, id: i64 },
    /// `drust://<t>/rpcs/{name}` — one stored RPC's metadata (sql/defaults redacted).
    Rpc { name: String },
}

fn not_found(uri: &str) -> McpError {
    McpError::resource_not_found(format!("no such resource: {uri}"), None)
}

/// A parsed-but-empty target (unknown collection / missing row / missing rpc)
/// maps to the same `-32002` — the render layer must NOT become an existence
/// oracle, and a genuinely-absent resource is "not found" all the same.
fn missing() -> McpError {
    McpError::resource_not_found("no such resource".to_string(), None)
}

fn internal(e: impl std::fmt::Display) -> McpError {
    McpError::internal_error(e.to_string(), None)
}

/// Map a reader's `anyhow` error: an unknown-collection signal → `-32002`
/// (not an existence oracle — parse already rejected protected/ill-formed
/// names), everything else → internal. Substring is a SECONDARY contract here
/// (the parser is the primary gate); `list_records` reliably `bail!`s
/// `COLLECTION_NOT_FOUND` for a valid-but-absent collection.
fn map_reader_err(e: anyhow::Error) -> McpError {
    let s = e.to_string();
    if s.contains("COLLECTION_NOT_FOUND") || s.contains("no such collection") {
        McpError::resource_not_found(s, None)
    } else {
        McpError::internal_error(s, None)
    }
}

/// `identifier()` + protected-collection guard for a `{collection}` segment.
/// Rejects `_system_*` (else the template becomes an existence oracle for
/// protected tables) and any non-identifier → `-32002`.
fn valid_collection(c: &str, raw: &str) -> Result<(), McpError> {
    crate::mcp::tools::schema::identifier(c).map_err(|_| not_found(raw))?;
    if crate::storage::schema::is_protected_collection(c) {
        return Err(not_found(raw));
    }
    Ok(())
}

/// `identifier()` for a `{name}`/`{field}` segment (no collection-protection
/// semantics — a stored RPC named `_system_*` would simply not resolve).
fn valid_ident(name: &str, raw: &str) -> Result<(), McpError> {
    crate::mcp::tools::schema::identifier(name).map_err(|_| not_found(raw))
}

/// Parse a CANONICAL i64 (drust ids are `INTEGER PRIMARY KEY AUTOINCREMENT`).
/// One row ⇒ exactly one URI: `05` / `+5` / ` 5` round-trip to a different
/// string and are rejected, so SQLite affinity can never alias `/records/05`
/// onto id 5 (codex D2).
fn parse_canonical_i64(s: &str, raw: &str) -> Result<i64, McpError> {
    let n: i64 = s.parse().map_err(|_| not_found(raw))?;
    if n.to_string() != s {
        return Err(not_found(raw));
    }
    Ok(n)
}

/// Parse the `records` template's query. `as_str()==raw` canonicalizes the PATH
/// but url's form-decoding (`query_pairs()`) still re-decodes `%xx` and `+` in
/// the QUERY past that check (codex D1: `?p%61ge=2` → key `page`). So force the
/// raw query to literal ASCII — reject any `%`/`+` — then `query_pairs()`
/// decoded == raw and is safe. Unknown/duplicate keys and unparseable values
/// are rejected (deny-by-default); `per_page` clamps to 1..=200, `page` to ≥1.
#[allow(clippy::type_complexity)]
fn parse_records_query(
    u: &url::Url,
    raw: &str,
) -> Result<(Option<u32>, Option<u32>, Option<String>, Option<String>), McpError> {
    let Some(q) = u.query() else {
        return Ok((None, None, None, None));
    };
    if q.contains('%') || q.contains('+') {
        return Err(not_found(raw));
    }
    let (mut page, mut per_page, mut sort, mut order) = (None, None, None, None);
    let mut seen = std::collections::HashSet::new();
    for (k, v) in u.query_pairs() {
        if !seen.insert(k.to_string()) {
            return Err(not_found(raw)); // duplicate key
        }
        match k.as_ref() {
            "page" => page = Some(v.parse::<u32>().map_err(|_| not_found(raw))?.max(1)),
            "per_page" => {
                per_page = Some(v.parse::<u32>().map_err(|_| not_found(raw))?.clamp(1, 200))
            }
            "sort" => {
                valid_ident(v.as_ref(), raw)?; // list_records re-checks the field vs schema
                sort = Some(v.to_string());
            }
            "order" => {
                if v.as_ref() != "asc" && v.as_ref() != "desc" {
                    return Err(not_found(raw));
                }
                order = Some(v.to_string());
            }
            _ => return Err(not_found(raw)), // unknown key
        }
    }
    Ok((page, per_page, sort, order))
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
    // Authority + path canonicalization. `as_str()==raw` rejects EVERY url
    // rewrite — most importantly literal AND `%2e`-encoded dot-segments, both
    // of which url resolves before serializing (empirically confirmed on url
    // 2.5.8), so `…/a/../schema` and `…/a/%2e%2e/schema` both serialize to
    // `…/schema` ≠ raw → rejected. Query is per-route (below), NOT blanket.
    if u.scheme() != "drust"
        || !u.username().is_empty()
        || u.password().is_some()
        || u.port().is_some()
        || u.fragment().is_some()
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
    // Every segment: non-empty and %-free. `as_str()==raw` already killed
    // path-normalization; the no-`%` rule closes the encodings url KEEPS
    // verbatim (`%2f`, `%00`, `%5c`) so a segment can never smuggle a slash /
    // NUL / dot past the structural match below.
    if segs.iter().any(|s| s.is_empty() || s.contains('%')) {
        return Err(not_found(raw));
    }
    let has_query = u.query().is_some();
    match segs.as_slice() {
        // ── static (no query) ──
        ["schema"] if !has_query => Ok(ResourceUri::Schema),
        ["schema.md"] if !has_query => Ok(ResourceUri::SchemaMd),
        ["collections"] if !has_query => Ok(ResourceUri::Collections),
        ["openapi.json"] if !has_query => Ok(ResourceUri::OpenApi),
        ["types.ts"] if !has_query => Ok(ResourceUri::TypesTs),
        ["zod.ts"] if !has_query => Ok(ResourceUri::ZodTs),
        ["functions"] if !has_query => Ok(ResourceUri::Functions),
        ["rpcs"] if !has_query => Ok(ResourceUri::Rpcs),
        ["cron"] if !has_query => Ok(ResourceUri::Cron),
        // ── M4 templates ──
        ["collections", c, "schema"] if !has_query => {
            valid_collection(c, raw)?;
            Ok(ResourceUri::CollectionSchema {
                collection: c.to_string(),
            })
        }
        ["collections", c, "records"] => {
            valid_collection(c, raw)?;
            let (page, per_page, sort, order) = parse_records_query(&u, raw)?;
            Ok(ResourceUri::Records {
                collection: c.to_string(),
                page,
                per_page,
                sort,
                order,
            })
        }
        ["collections", c, "records", id] if !has_query => {
            valid_collection(c, raw)?;
            Ok(ResourceUri::Record {
                collection: c.to_string(),
                id: parse_canonical_i64(id, raw)?,
            })
        }
        ["rpcs", name] if !has_query => {
            valid_ident(name, raw)?;
            Ok(ResourceUri::Rpc {
                name: name.to_string(),
            })
        }
        _ => Err(not_found(raw)),
    }
}

/// The URI templates advertised via `resources/templates/list`. history +
/// function-logs are DELIBERATELY absent (codex D4 / spec §3): a resource may
/// be auto-pulled into model context, and old row snapshots / function stdout
/// can carry secrets — those stay behind the explicit `get_record_history` /
/// `get_function_logs` tools.
pub fn resource_template_list(t: &str) -> Vec<rmcp::model::ResourceTemplate> {
    let e = |tmpl: &str, name: &str, desc: &str| {
        rmcp::model::RawResourceTemplate::new(format!("drust://{t}/{tmpl}"), name.to_string())
            .with_description(desc.to_string())
            .with_mime_type("application/json".to_string())
            .no_annotation()
    };
    vec![
        e(
            "collections/{collection}/schema",
            "collection schema",
            "One collection's full schema — fields, indexes, caps, owner_field, RLS policies.",
        ),
        e(
            "collections/{collection}/records{?page,per_page,sort,order}",
            "collection records",
            "A page of rows (service view). per_page clamps to 200; the body carries a \
             resource_uri_template for per-row links.",
        ),
        e(
            "collections/{collection}/records/{id}",
            "single record",
            "One row addressed by its integer id.",
        ),
        e(
            "rpcs/{name}",
            "stored RPC",
            "One stored RPC's metadata (name, params, mode). SQL body and param defaults are redacted.",
        ),
    ]
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
pub(crate) fn schema_json_to_md(v: &serde_json::Value) -> String {
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

/// Strip credential-bearing free-form fields from a config-inventory value
/// before it becomes an **auto-fetchable** resource (spec §3 — a client may pull
/// a resource into context WITHOUT an explicit model call, unlike a tool). An
/// RPC `sql` body or param `default` can embed a hardcoded secret; the inventory
/// (names / shape / mode) is what a bootstrapping agent needs, and the full body
/// stays available via the explicit `list_rpc` / `call_rpc` tools. `redact_rpc_obj`
/// handles one RPC object; `redact_rpc_array` maps it over the inventory array.
fn redact_rpc_obj(r: &mut serde_json::Value) {
    let Some(obj) = r.as_object_mut() else {
        return;
    };
    obj.remove("sql");
    // #950: a query-kind RPC's body lives in `query_json` instead — same
    // secret-embedding class (a filter literal can be a credential), so it
    // leaves the auto-fetchable resource by the same rule as `sql`.
    obj.remove("query_json");
    if let Some(params) = obj.get_mut("params").and_then(|p| p.as_array_mut()) {
        for p in params {
            if let Some(po) = p.as_object_mut() {
                po.remove("default");
            }
        }
    }
}

fn redact_rpc_array(rpcs: &mut serde_json::Value) {
    let Some(arr) = rpcs.as_array_mut() else {
        return;
    };
    for r in arr {
        redact_rpc_obj(r);
    }
}

/// Strip secrets from the cron inventory. Shape: `{"jobs":[…]}`.
///
/// `payload_json` is free-form tenant JSON and can carry a token (spec §3).
/// `last_error` is worse: it is whatever the failed run stringified, and
/// rusqlite's `SqlInputError` Display embeds the whole failing statement, so a
/// cron job pointing at an RPC that fails to prepare would leak the RPC's SQL
/// through a resource — and a resource is auto-fetchable into model context,
/// unlike a tool the model has to decide to call. The `rpcs` resource strips
/// that same SQL deliberately.
///
/// The signal survives as a boolean: the reader still learns the job is failing
/// (and `last_status` is untouched) and can call `list_cron_jobs`, an explicit
/// tool call, for the detail.
fn redact_cron(jobs: &mut serde_json::Value) {
    let Some(arr) = jobs.get_mut("jobs").and_then(|j| j.as_array_mut()) else {
        return;
    };
    for j in arr {
        if let Some(obj) = j.as_object_mut() {
            obj.remove("payload_json");
            let had_error = obj.remove("last_error").is_some_and(|v| !v.is_null());
            obj.insert(
                "last_error_present".into(),
                serde_json::Value::Bool(had_error),
            );
        }
    }
}

/// Test seam for `redact_cron`, which is otherwise private to the resource
/// renderer.
#[doc(hidden)]
pub fn redact_cron_for_test(jobs: &mut serde_json::Value) {
    redact_cron(jobs)
}

/// Render a parsed resource to `(body, mime)` by calling the existing reader fn
/// — same path, same `_system_*` protection as the corresponding tool. An absent
/// target (unknown collection / missing row / missing rpc) → `-32002` via
/// `missing()`.
///
/// Size posture (codex impl-review CONCERN #6): `cap_body` (applied by the
/// caller) bounds the OUTPUT that enters model context, NOT peak render memory —
/// a row with a multi-MB text field is materialized in full before truncation.
/// This is accepted, not a new amplification: every template reads exactly the
/// same rows the `list_records` / `search_collection` tools already return
/// UNCAPPED (the resource is strictly tighter — it truncates), it is service-
/// only, blobs are elided to `{"__blob_bytes": n}` (never their content), and
/// pages are bounded to `per_page ≤ 200`. A streaming byte-budget reader would
/// be the fix if this surface ever admits an untrusted caller.
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
        ResourceUri::CollectionSchema { collection } => {
            let v = exploration::describe_collection(s, collection)
                .await
                .map_err(internal)?;
            // describe_collection returns Ok({"error_code":"COLLECTION_NOT_FOUND"})
            // for a missing collection (codex D5) — never an Err — so the
            // string mapper never sees it. Detect the sentinel explicitly.
            if v.get("error_code").is_some() {
                return Err(missing());
            }
            json(&v)
        }
        ResourceUri::Records {
            collection,
            page,
            per_page,
            sort,
            order,
        } => {
            let sort_spec = sort.as_ref().map(|f| crate::query::list_builder::SortSpec {
                field: f.clone(),
                // list_builder's own default dir is "desc"; mirror it
                // when only a field was given.
                dir: order.clone().unwrap_or_else(|| "desc".to_string()),
            });
            let args = crate::mcp::tools::read::ListRecordsArgs {
                collection: collection.clone(),
                filter: None,
                sort: sort_spec,
                page: *page,
                per_page: *per_page,
                select: None,
            };
            let mut v = crate::mcp::tools::read::list_records(s, args)
                .await
                .map_err(map_reader_err)?;
            // Top-level (never per-row — codex D3): the default projection omits
            // `id` and `resource_link` is a legal user column, so a row-level
            // link would be absent-or-colliding. This template tells the model
            // how to address a single row it selected `id` for.
            if let Some(o) = v.as_object_mut() {
                o.insert(
                    "resource_uri_template".into(),
                    serde_json::Value::String(format!(
                        "drust://{}/collections/{}/records/{{id}}",
                        s.tenant_id(),
                        collection
                    )),
                );
            }
            json(&v)
        }
        ResourceUri::Record { collection, id } => {
            match read_one_record(s, collection, *id).await? {
                Some(row) => json(&serde_json::json!({ "record": row })),
                None => Err(missing()),
            }
        }
        ResourceUri::Rpc { name } => {
            let name_owned = name.clone();
            let found = s
                .inner()
                .pool
                .with_reader(move |c| {
                    crate::rpc::registry::lookup(c, &name_owned).map_err(|e| {
                        rusqlite::Error::SqliteFailure(
                            rusqlite::ffi::Error::new(1),
                            Some(e.to_string()),
                        )
                    })
                })
                .await
                .map_err(internal)?;
            match found {
                Some(rpc) => {
                    let mut v = serde_json::to_value(&rpc).map_err(internal)?;
                    // Same spec §3 redaction as the `rpcs` list resource.
                    redact_rpc_obj(&mut v);
                    json(&v)
                }
                None => Err(missing()),
            }
        }
    }
}

/// Dedicated single-row reader for the `Record{c,id}` template. The `/list`
/// filter path CANNOT serve this — `vector_filter::compile` only accepts
/// declared fields, so `{"id": …}` is `FILTER_UNKNOWN_FIELD` (codex D2). MCP is
/// service-only, so — exactly like the REST `get_handler` service path — there
/// is no owner/policy filter. Plain `prepare` (NOT `prepare_cached`): `SELECT *`
/// column set shifts under `add_field`/`drop_field` (v1.43 invariant). Vector
/// columns are hidden via `materialize_row`. Unknown collection OR absent row →
/// `Ok(None)` → `-32002`.
async fn read_one_record(
    s: &DrustMcp,
    collection: &str,
    id: i64,
) -> Result<Option<serde_json::Value>, McpError> {
    let pool = s.inner().pool.clone();
    let cache = pool.schema_cache.clone();
    let coll = collection.to_string();
    // Schema load + row read in ONE closure so a concurrent drop_collection
    // cannot land between them (a dropped table would else surface as a 500
    // instead of -32002). Unknown collection → Ok(None) → -32002.
    pool.with_reader(move |c| -> rusqlite::Result<Option<serde_json::Value>> {
        use rusqlite::OptionalExtension;
        let Some(schema) = cache.ensure_loaded(c, &coll)? else {
            return Ok(None);
        };
        let vector_names: std::collections::HashSet<String> = schema
            .vector_fields
            .iter()
            .map(|v| v.name.clone())
            .collect();
        let sql = format!(
            "SELECT * FROM \"{}\" WHERE id = ?1",
            coll.replace('"', "\"\"")
        );
        let mut stmt = c.prepare(&sql)?;
        let cols: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
        stmt.query_row([id], |r| {
            crate::mcp::tools::write::materialize_row(r, &cols, &vector_names)
        })
        .optional()
    })
    .await
    .map_err(internal)
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
             "params": [{"name": "k", "default": "SECRET_DEFAULT_xyz"}]},
            // #950: a query-kind row's body is `query_json`, not `sql` — same
            // secret-embedding class (a filter literal can be a credential),
            // so it must be stripped by the same rule.
            {"name": "r2", "kind": "query", "sql": "",
             "query_json": "{\"collection\":\"posts\",\"filter\":{\"token\":\"SECRET_TEMPLATE_qrs\"}}"}
        ]);
        redact_rpc_array(&mut v);
        let s = v.to_string();
        assert!(
            !s.contains("SECRET_TOKEN_abc"),
            "sql body must be stripped: {s}"
        );
        assert!(
            !s.contains("SECRET_TEMPLATE_qrs"),
            "query_json template must be stripped: {s}"
        );
        assert!(s.contains("r2"), "query-row name is preserved");
        assert!(s.contains("query"), "kind is preserved");
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
