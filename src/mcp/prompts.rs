//! v1.56 M3 — MCP Prompts. Hand-written (rmcp's `#[prompt_router]` macro would
//! shadow the hand-written `ServerHandler` methods and can't embed per-tenant
//! schema). Each prompt is a short, task-shaped **User** message that points at
//! the tenant's tools + `drust://…` resources rather than re-embedding long
//! prose (which would drift against the server instructions), and — where it helps
//! — embeds the tenant's own schema/definition block.
//!
//! Credential posture: a prompt is fetched by an EXPLICIT `get_prompt` call
//! (tool-like, behind the account endpoint's tenant check — NOT auto-fetched like a resource),
//! so a prompt body embeds only what the caller can already see via a tool. The
//! embedded blocks mirror existing service tools exactly — `bootstrap` runs
//! `get_schema_overview` through `schema_json_to_md` (collection/field names +
//! caps + RPC *names* only — never RPC SQL / param defaults), and
//! `secure_collection` embeds the same `describe_collection` JSON the tool
//! returns. A prompt is therefore not a NEW exposure surface: no bearer tokens,
//! no RPC SQL, no cron payloads. (A tenant-authored field `default_value` or
//! description rides along in `describe_collection` — but that is the tenant's
//! own data, already visible via the `describe_collection` tool.)

use crate::mcp::server::DrustMcp;
use rmcp::ErrorData as McpError;
use rmcp::model::{GetPromptResult, Prompt, PromptArgument, PromptMessage, PromptMessageRole};

/// The edge-function guest contract, embedded VERBATIM from the SDK template so
/// the `write_edge_function` prompt hands an MCP client the ACTUAL WIT + skeleton
/// instead of pointing at an SDK it cannot fetch (crates.io has no drust crate,
/// and drust serves the WIT over no endpoint — the exact gap that made "see the
/// template" a dead end). `include_str!` binds the same files `runtime.rs`'s
/// `bindgen!` compiles against, so the prompt can never drift from the runtime.
/// Public, tenant-neutral template content — no tenant data, no credentials — so
/// it respects the credential posture in this module's header.
const EDGE_WIT: &str = include_str!("../../sdk/edge-function-template/wit/world.wit");
const EDGE_LIB_RS: &str = include_str!("../../sdk/edge-function-template/src/lib.rs");

/// The prompts advertised via `prompts/list`. Bodies are built lazily in
/// [`render_prompt`] (they embed live per-tenant schema).
pub fn prompt_list() -> Vec<Prompt> {
    let arg = |name: &str, desc: &str| {
        PromptArgument::new(name)
            .with_description(desc.to_string())
            .with_required(true)
    };
    vec![
        Prompt::new(
            "bootstrap",
            Some("Orient on this tenant: the current data model + the core do/don't rules."),
            None,
        ),
        Prompt::new(
            "design_collection",
            Some("Design a new collection for a stated purpose."),
            Some(vec![arg(
                "purpose",
                "What the collection is for, e.g. 'blog posts with tags and an author'.",
            )]),
        ),
        Prompt::new(
            "secure_collection",
            Some("Review and tighten one collection's access (caps, owner_field, RLS)."),
            Some(vec![arg("collection", "The collection to secure.")]),
        ),
        Prompt::new(
            "debug_write",
            Some("Diagnose a failing write on one collection, methodically."),
            Some(vec![arg(
                "collection",
                "The collection whose write is failing.",
            )]),
        ),
        Prompt::new(
            "write_edge_function",
            Some("Scaffold an edge function for a trigger."),
            Some(vec![arg(
                "trigger",
                "The trigger, e.g. 'record.created on orders' or 'file.uploaded'.",
            )]),
        ),
        Prompt::new(
            "review_history",
            Some("Inspect the change history of one collection."),
            Some(vec![arg("collection", "The collection to review.")]),
        ),
    ]
}

fn one_user_message(body: String) -> GetPromptResult {
    GetPromptResult::new(vec![PromptMessage::new_text(PromptMessageRole::User, body)])
}

fn internal(e: impl std::fmt::Display) -> McpError {
    McpError::internal_error(e.to_string(), None)
}

/// Build the requested prompt. Unknown name / missing required arg → `-32602`
/// (`invalid_params`). `s` supplies the tenant + pool for the embedded schema.
pub async fn render_prompt(
    s: &DrustMcp,
    name: &str,
    args: &Option<serde_json::Map<String, serde_json::Value>>,
) -> Result<GetPromptResult, McpError> {
    let t = s.tenant_id();
    let arg = |k: &str| -> Result<String, McpError> {
        args.as_ref()
            .and_then(|m| m.get(k))
            .and_then(|v| v.as_str())
            .filter(|x| !x.is_empty())
            .map(|x| x.to_string())
            .ok_or_else(|| {
                McpError::invalid_params(format!("missing required argument: {k}"), None)
            })
    };

    match name {
        "bootstrap" => {
            let v = crate::mcp::tools::exploration::get_schema_overview(s)
                .await
                .map_err(internal)?;
            let md = crate::mcp::resources::schema_json_to_md(&v);
            Ok(one_user_message(format!(
                "You are connected to drust tenant `{t}` — a multi-tenant SQLite BaaS. \
                 Here is its current data model:\n\n{md}\n\
                 Core rules for acting here:\n\
                 1. To READ, prefer `list_records` (structured filter/sort/paginate) over `query` \
                    (raw SELECT). On MCP you are the service identity, so owner_field, caps and \
                    RLS policies narrow neither of them.\n\
                 2. `_system_*` collections are off-limits to the record tools.\n\
                 3. Before any destructive op (`delete_record`, `drop_collection`, `drop_index`), \
                    call it with `dry_run: true` first and read the blast radius. No other tool \
                    has `dry_run`: insert, update and upsert always run for real.\n\
                 4. Everything here is also addressable as a resource: \
                    `resources/templates/list`; `drust://{t}/schema` is this overview and \
                    `drust://{t}/collections/<c>/records/<id>` is a single row.\n"
            )))
        }
        "design_collection" => {
            let purpose = arg("purpose")?;
            Ok(one_user_message(format!(
                "Design a new drust collection for: {purpose}\n\n\
                 Use `create_collection` with typed fields (text / integer / real / boolean / \
                 datetime / json / vector). Add inline constraints where they apply (min / max / enum / max_length), \
                 foreign keys (`foreign_key`), and SQL defaults for timestamps. Read \
                 `drust://{t}/schema.md` first to avoid name clashes, then `create_index` on the \
                 columns you will filter or sort by. Decide access up front: `set_anon_caps` / \
                 `set_user_caps` (default `[select]`), `set_owner_field` for per-user rows, and \
                 `set_policy` for row-level rules."
            )))
        }
        "secure_collection" => {
            let coll = arg("collection")?;
            let d = crate::mcp::tools::exploration::describe_collection(s, &coll)
                .await
                .map_err(internal)?;
            if d.get("error_code").is_some() {
                return Err(McpError::invalid_params(
                    format!(
                        "no such collection: {}",
                        crate::mcp::account_audit::shown_name(&coll)
                    ),
                    None,
                ));
            }
            let block = serde_json::to_string_pretty(&d).unwrap_or_default();
            Ok(one_user_message(format!(
                "Review and tighten access on collection `{coll}` in tenant `{t}`.\n\n\
                 Current definition:\n\n```json\n{block}\n```\n\n\
                 Checklist: is `anon_caps` minimal (ideally `[select]`, or empty for private data)? \
                 Should `user_caps` differ from anon? Is `owner_field` set when rows are per-user \
                 (writes auto-scope to the owner; foreign rows return 404)? Do you need per-op \
                 `set_policy` (RLS) for finer read/write rules? Apply changes with `set_anon_caps` / \
                 `set_user_caps` / `set_owner_field` / `set_policy` — service tokens always bypass."
            )))
        }
        "debug_write" => {
            let coll = arg("collection")?;
            Ok(one_user_message(format!(
                "A write to `{coll}` (tenant `{t}`) is failing. Work it methodically:\n\
                 1. `describe_collection {coll}` — confirm field names, types, NOT NULL, CHECK \
                    constraints (min/max/enum/max_length) and foreign keys.\n\
                 2. Read the failed call's `error_code` and `suggested_fix` (the JSON text of its \
                    isError result). Of the record tools only \
                    `delete_record` has `dry_run`; `insert_record` / `update_record` do not, so \
                    re-sending one runs it for real.\n\
                 3. If an earlier attempt's reply was lost, check `recent_writes` (or re-read \
                    with `list_records`) whether it already committed before writing again.\n\
                 4. Usual causes: a CHECK / enum / max_length violation, a missing FK parent, a \
                    missing required field, or a service insert that did not populate `owner_field` \
                    on an owner-scoped collection."
            )))
        }
        "write_edge_function" => {
            let trigger = arg("trigger")?;
            Ok(one_user_message(format!(
                "Author a drust edge function for trigger: {trigger} (tenant `{t}`).\n\n\
                 Edge functions are wasm32-wasip2 Component-Model guests, run in-process on \
                 `record.created` / `record.updated` / `record.deleted` (per collection) or \
                 `file.uploaded`. The WIT below IS the contract: the `host` imports it lists are \
                 the ONLY capabilities a guest has — no filesystem, no ambient network. \
                 `http-fetch` is the sole outbound-network op.\n\n\
                 ---- wit/world.wit (host interface; the `http-fetch` signature is here) ----\n\
                 {wit}\n\
                 ---- src/lib.rs (guest skeleton; `handle` is the entrypoint) ----\n\
                 {lib}\n\
                 ---- Cargo.toml ----\n\
                 [lib] crate-type = [\"cdylib\"]; dependencies: wit-bindgen = \"0.58\", \
                 serde_json = \"1\".\n\n\
                 Build it, then ask the user to upload the .wasm: this connection holds no \
                 tenant key and MCP has no function upload tool. The tenant's Functions page \
                 in the admin UI shows the upload command, which needs the service key from \
                 the tenant's API Keys page.\n\
                 rustup target add wasm32-wasip2\n\
                 cargo build --target wasm32-wasip2 --release\n\n\
                 GOTCHA — the #1 first-run failure: `http-fetch` is DENY-BY-DEFAULT. The upload \
                 succeeds, but every `http-fetch` returns `EGRESS_NOT_ALLOWLISTED` until you \
                 allowlist the EXACT origin (scheme://host[:port]) for system `function` \
                 (private/loopback IPs stay blocked regardless). Call `get_egress_allowlist`, \
                 append {{\"system\":\"function\",\"uri\":\"https://api.example.com\"}} to its \
                 `entries`, then call `set_egress_allowlist` with the FULL list — it REPLACES the \
                 whole allowlist, never merges.\n\n\
                 Once uploaded: manage/observe with `list_functions` / `set_function_active` / \
                 `invoke_function` / `get_function_logs`.",
                wit = EDGE_WIT,
                lib = EDGE_LIB_RS,
            )))
        }
        "review_history" => {
            let coll = arg("collection")?;
            Ok(one_user_message(format!(
                "Review the change history of `{coll}` (tenant `{t}`).\n\n\
                 Call `get_record_history` with `collection: \"{coll}\"` (optionally `record_id` to \
                 scope to one row, and `limit` up to 200). Each entry carries `op` \
                 (insert / update / delete), the full `old` and `new` row snapshots, and the actor. \
                 Use it to see who changed what, and to diff a row across time. History capture is \
                 per-collection — toggle it with `set_audit_enabled`."
            )))
        }
        other => Err(McpError::invalid_params(
            format!(
                "no such prompt: {}",
                crate::mcp::account_audit::shown_name(other)
            ),
            None,
        )),
    }
}

/// The prompts the account-level endpoint advertises: the same six, each
/// taking a required `tenant` first, since one server serves every tenant.
pub(crate) fn account_prompt_list() -> Vec<Prompt> {
    prompt_list()
        .into_iter()
        .map(|mut p| {
            let tenant = PromptArgument::new("tenant")
                .with_description(crate::mcp::account::TENANT_PROPERTY_DESCRIPTION.to_string())
                .with_required(true);
            let mut args = vec![tenant];
            args.extend(p.arguments.take().unwrap_or_default());
            p.arguments = Some(args);
            p
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_prompts_take_tenant_first() {
        let list = account_prompt_list();
        assert_eq!(list.len(), 6);
        for p in &list {
            let a = p.arguments.as_ref().unwrap();
            assert_eq!(a[0].name, "tenant", "{}", p.name);
            assert_eq!(a[0].required, Some(true));
            assert_eq!(
                a[0].description.as_deref(),
                Some(crate::mcp::account::TENANT_PROPERTY_DESCRIPTION)
            );
            assert_eq!(
                a.len(),
                if p.name == "bootstrap" { 1 } else { 2 },
                "{}",
                p.name
            );
        }
        assert!(
            prompt_list()
                .iter()
                .all(|p| p.arguments.as_ref().is_none_or(|a| a[0].name != "tenant"))
        );
    }

    /// A minimal `DrustMcp` over a fresh tenant database (the handler's own
    /// fixture is private to its test module). `functions: None` is deliberate
    /// (invariant 13): rendering a prompt needs no dispatcher.
    async fn prompt_fixture() -> (DrustMcp, tempfile::TempDir) {
        use std::sync::Arc;
        let tmp = tempfile::tempdir().unwrap();
        let tenants = Arc::new(crate::storage::pool::TenantRegistry::new(
            tmp.path().to_path_buf(),
            2,
        ));
        let rooms_cfg = crate::tenant::rooms::RoomsConfig::test_defaults();
        let bucket = rooms_cfg.bucket();
        let mcp = DrustMcp::new(
            "blog",
            tenants.get_or_create("blog").unwrap(),
            crate::tenant::events::EventBus::new(),
            crate::tenant::WebhookDispatcher::new(tenants.clone(), None),
            None,
            String::new(),
            Arc::new([0u8; 32]),
            None,
            52_428_800,
            1_000_000,
            Arc::new(tokio::sync::Mutex::new(
                crate::safety::audit_db::open_audit_db_memory().unwrap(),
            )),
            crate::tenant::rooms::RoomBus::new(),
            bucket,
            rooms_cfg,
            None,
            None,
        );
        (mcp, tmp)
    }

    /// The served prompt texts carry no step that needs a tenant key: the
    /// bootstrap names only the resource templates, and the edge-function
    /// recipe sends the user to the admin UI to upload.
    #[tokio::test]
    async fn prompt_texts_are_the_account_texts() {
        let (s, _tmp) = prompt_fixture().await;
        let text = |r: GetPromptResult| match &r.messages[0].content {
            rmcp::model::PromptMessageContent::Text { text } => text.clone(),
            other => panic!("not text: {other:?}"),
        };
        let b = text(render_prompt(&s, "bootstrap", &None).await.unwrap());
        assert!(b.contains("`resources/templates/list`"), "{b}");
        assert!(!b.contains("`resources/list` +"), "{b}");
        let mut args = serde_json::Map::new();
        args.insert("trigger".into(), serde_json::json!("record.created"));
        let e = text(
            render_prompt(&s, "write_edge_function", &Some(args))
                .await
                .unwrap(),
        );
        assert!(
            e.contains("Build it, then ask the user to upload the .wasm"),
            "{e}"
        );
        assert!(!e.contains("service-token") && !e.contains("curl"), "{e}");
        assert_eq!(e.matches("GOTCHA — the #1 first-run failure").count(), 1);
    }
}
