//! The audit rows the account-level MCP endpoint writes: one per tool call
//! and per resource read that passed the tenant check, and one host row per
//! refusal.
//!
//! Every row naming a tenant is written only after that caller passed the
//! tenant check; denials are host rows (`tenant = "-"`). Caller-supplied
//! strings (tenant, collection, URI, tool and prompt names) are recorded only
//! when they have the shape of what they claim to be, otherwise as
//! `<invalid>`, so a credential pasted into the wrong argument never lands in
//! the audit log. A tenant id can be recycled between the tenant check and
//! the write, so a row is keyed by the id string, not by the incarnation that
//! was checked.
//!
//! A row carries the tool name, the error code, the duration, the grant id
//! and a collection name: never an argument value, a message, a token, a hash
//! or an address.

use serde_json::{Map, Value, json};

use crate::mgmt::mcp_oauth::caller::McpCaller;
use crate::safety::audit::AuditEntry;

/// The `auth_method` of every row naming a tenant.
pub(crate) const AUTH_METHOD: &str = "mcp_oauth";
/// The longest collection name kept in `extra.collection`.
pub(crate) const COLLECTION_MAX_CHARS: usize = 128;
/// The longest URI kept in `extra.uri`; also caps `extra.name`.
pub(crate) const URI_MAX_CHARS: usize = 256;
/// What a caller-supplied string that fails its shape check is recorded as.
pub(crate) const INVALID: &str = "<invalid>";
/// `auth_method` of a request authenticated by an upload ticket.
pub(crate) const UPLOAD_TICKET_AUTH_METHOD: &str = "mcp_upload_ticket";

/// Where a refused account-level request came in.
pub(crate) enum DeniedSurface<'a> {
    /// A `tools/call` of this tool name.
    Tool(&'a str),
    /// A `resources/read` of this URI.
    Resource(&'a str),
    /// A `prompts/get` of this prompt name.
    Prompt(&'a str),
    /// The upload-URL tool.
    UploadTool,
    /// An upload request that presented a ticket.
    UploadTicket,
}

/// `s` when it is a valid tenant id, `<invalid>` otherwise.
fn safe_tenant(s: &str) -> &str {
    if crate::storage::tenant_db::validate_tenant_id(s).is_ok() {
        s
    } else {
        INVALID
    }
}

/// `s` cut to `max` characters when it is an identifier, `None` otherwise.
fn safe_ident(s: &str, max: usize) -> Option<String> {
    crate::mcp::tools::schema::identifier(s)
        .is_ok()
        .then(|| s.chars().take(max).collect())
}

/// `s` when it is a drust resource URI of a tenant-shaped host that the
/// resource parser accepts for that host, `<invalid>` otherwise (the caller
/// cuts it to `URI_MAX_CHARS`).
fn safe_uri(s: &str) -> &str {
    let ok = url::Url::parse(s).ok().is_some_and(|u| {
        u.host_str().is_some_and(|host| {
            crate::storage::tenant_db::validate_tenant_id(host).is_ok()
                && crate::mcp::resources::parse_resource_uri(s, host).is_ok()
        })
    });
    if ok { s } else { INVALID }
}

/// `s` when it names one of the prompts, `<invalid>` otherwise.
fn safe_prompt(s: &str) -> &str {
    if crate::mcp::prompts::prompt_list()
        .iter()
        .any(|p| p.name == s)
    {
        s
    } else {
        INVALID
    }
}

fn cut(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// The success row shape shared by tool calls and resource reads, before
/// its `extra` is filled in.
fn tenant_row(
    tenant: &str,
    op: &str,
    caller: &McpCaller,
    error_code: Option<&str>,
    ms: u64,
) -> AuditEntry {
    let mut e = match error_code {
        None => AuditEntry::success(tenant, "-", op, ms),
        Some(c) => AuditEntry::failure(tenant, "-", op, ms, c, c),
    };
    e.auth_method = Some(AUTH_METHOD.to_string());
    e.actor_admin_id = Some(caller.admin_id());
    e.actor_email_snapshot = Some(caller.admin_label().to_string());
    e
}

/// One tool call that passed the tenant check. `tenant` is the checked id and
/// `op` the tool name (or [`audit_op`]'s); both come from the server, not the
/// caller. `error_code` is also the row's message, so no message text is
/// stored. The collection is kept only when it is an identifier.
pub(crate) fn call_entry(
    tenant: &str,
    op: &str,
    caller: &McpCaller,
    error_code: Option<&str>,
    ms: u64,
    collection: Option<&str>,
) -> AuditEntry {
    let mut extra = Map::new();
    extra.insert("grant_id".into(), json!(caller.grant_id()));
    if let Some(c) = collection.and_then(|c| safe_ident(c, COLLECTION_MAX_CHARS)) {
        extra.insert("collection".into(), Value::String(c));
    }
    tenant_row(tenant, op, caller, error_code, ms).with_extra(Value::Object(extra))
}

/// The row of a `create_upload_url` call that issued a ticket: the tenant
/// row of a call, plus the size limit, the visibility and whether a path was
/// declared. Never the ticket, its hash, the path or the file name.
pub(crate) fn ticket_issued_entry(
    tenant: &str,
    caller: &McpCaller,
    max_bytes: i64,
    public: bool,
    has_path: bool,
) -> AuditEntry {
    call_entry(tenant, "create_upload_url", caller, None, 0, None).with_extra(json!({
        "max_bytes": max_bytes,
        "visibility": if public { "public" } else { "private" },
        "has_path": has_path,
    }))
}

/// One refusal at or before the tenant check: a host row (`tenant = "-"`,
/// `op = "mcp_denied"`) with the refused surface and, when the caller sent
/// one, the tenant it asked for.
pub(crate) fn denied_entry(
    admin_id: Option<i64>,
    grant_id: Option<i64>,
    surface: DeniedSurface<'_>,
    requested_tenant: Option<&str>,
    code: &str,
) -> AuditEntry {
    let (kind, name) = match surface {
        DeniedSurface::Tool(n) => (
            "tool",
            Some(safe_ident(n, URI_MAX_CHARS).unwrap_or_else(|| INVALID.to_string())),
        ),
        DeniedSurface::Resource(u) => ("resource", Some(cut(safe_uri(u), URI_MAX_CHARS))),
        DeniedSurface::Prompt(n) => ("prompt", Some(safe_prompt(n).to_string())),
        DeniedSurface::UploadTool => ("upload_tool", Some("create_upload_url".to_string())),
        DeniedSurface::UploadTicket => ("upload_ticket", None),
    };
    let mut extra = Map::new();
    extra.insert("surface".into(), json!(kind));
    if let Some(n) = name {
        extra.insert("name".into(), Value::String(n));
    }
    if let Some(t) = requested_tenant {
        extra.insert("requested_tenant".into(), json!(safe_tenant(t)));
    }
    if let Some(g) = grant_id {
        extra.insert("grant_id".into(), json!(g));
    }
    let mut e = AuditEntry::failure("-", "-", "mcp_denied", 0, code, code);
    e.actor_admin_id = admin_id;
    e.with_extra(Value::Object(extra))
}

/// One upload-ticket request that passed every ticket check, on the ticket's
/// tenant. Status maps as in the bearer layer: 2xx and 3xx are `ok`, anything
/// else is `HTTP_<status>`.
pub(crate) fn ticket_use_entry(
    tenant: &str,
    admin_id: i64,
    grant_id: i64,
    token_hint: &str,
    op: &str,
    status: axum::http::StatusCode,
    ms: u64,
) -> AuditEntry {
    let mut e = if status.is_success() || status.is_redirection() {
        AuditEntry::success(tenant, token_hint, op, ms)
    } else {
        AuditEntry::failure(
            tenant,
            token_hint,
            op,
            ms,
            &format!("HTTP_{}", status.as_u16()),
            "",
        )
    };
    e.auth_method = Some(UPLOAD_TICKET_AUTH_METHOD.to_string());
    e.actor_admin_id = Some(admin_id);
    e.with_extra(json!({"grant_id": grant_id}))
}

/// One resource read that passed the tenant check. The URI is kept only when
/// the resource parser accepts it.
pub(crate) fn resource_read_entry(
    tenant: &str,
    caller: &McpCaller,
    uri: &str,
    ms: u64,
) -> AuditEntry {
    let extra = json!({"grant_id": caller.grant_id(), "uri": cut(safe_uri(uri), URI_MAX_CHARS)});
    tenant_row(tenant, "mcp.resource.read", caller, None, ms).with_extra(extra)
}

/// The row's `op`: the tool name, or `<tool>.dry_run` for a call with
/// `dry_run: true` (a preview changed nothing, so it must never read as a
/// write).
pub(crate) fn audit_op(tool: &str, args: &Map<String, Value>) -> String {
    if args.get("dry_run") == Some(&Value::Bool(true)) {
        format!("{tool}.dry_run")
    } else {
        tool.to_string()
    }
}

/// The collection a call names: `name` for `create_collection`, `collection`
/// for every other tool; strings only (the shape check is in [`call_entry`]).
pub(crate) fn audit_collection<'a>(tool: &str, args: &'a Map<String, Value>) -> Option<&'a str> {
    let key = if tool == "create_collection" {
        "name"
    } else {
        "collection"
    };
    args.get(key).and_then(Value::as_str)
}

/// The `tenant` string argument, if any (the shape check is in
/// [`denied_entry`]).
pub(crate) fn requested_tenant(args: &Map<String, Value>) -> Option<&str> {
    args.get("tenant").and_then(Value::as_str)
}

/// The error code of a tool result: `None` for a result that is not an
/// isError (a data tool may return a user column named `error_code`); for an
/// isError, its body's `error_code` when that is an UPPER_SNAKE code of at
/// most 64 characters, `INTERNAL` otherwise.
pub(crate) fn result_error_code(r: &rmcp::model::CallToolResult) -> Option<String> {
    if r.is_error != Some(true) {
        return None;
    }
    let code = r
        .content
        .first()
        .and_then(|c| c.as_text())
        .and_then(|t| serde_json::from_str::<Value>(&t.text).ok())
        .and_then(|v| {
            v.get("error_code")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .filter(|c| {
            c.len() <= 64
                && c.chars().next().is_some_and(|f| f.is_ascii_uppercase())
                && c.chars()
                    .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
        });
    Some(code.unwrap_or_else(|| "INTERNAL".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mgmt::mcp_oauth::caller::McpCaller;
    use serde_json::{Map, Value, json};

    fn obj(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn call_entry_success_fields() {
        let c = McpCaller::for_tests(7, 42);
        let e = call_entry("blog", "insert_record", &c, None, 12, Some("posts"));
        assert_eq!(
            (e.tenant.as_str(), e.token_hint.as_str(), e.op.as_str()),
            ("blog", "-", "insert_record")
        );
        assert_eq!((e.status.as_str(), e.duration_ms), ("ok", 12));
        assert_eq!(e.error_code, None);
        assert_eq!(e.auth_method.as_deref(), Some("mcp_oauth"));
        assert_eq!(e.actor_admin_id, Some(7));
        assert_eq!(e.actor_email_snapshot.as_deref(), Some(c.admin_label()));
        assert_eq!(e.collection, None);
        assert_eq!(
            Value::Object(e.extra),
            json!({"grant_id": 42, "collection": "posts"})
        );
    }

    #[test]
    fn call_entry_failure_keeps_the_code_not_a_message() {
        let c = McpCaller::for_tests(7, 42);
        let e = call_entry(
            "blog",
            "insert_record",
            &c,
            Some("COLLECTION_NOT_FOUND"),
            3,
            None,
        );
        assert_eq!(e.status, "error");
        assert_eq!(e.error_code.as_deref(), Some("COLLECTION_NOT_FOUND"));
        assert_eq!(e.error_message.as_deref(), Some("COLLECTION_NOT_FOUND"));
        assert_eq!(Value::Object(e.extra), json!({"grant_id": 42}));
    }

    #[test]
    fn denied_entry_is_a_host_row() {
        let e = denied_entry(
            Some(7),
            Some(42),
            DeniedSurface::Tool("insert_record"),
            Some("other"),
            "TENANT_NOT_FOUND",
        );
        assert_eq!(
            (
                e.tenant.as_str(),
                e.token_hint.as_str(),
                e.op.as_str(),
                e.status.as_str()
            ),
            ("-", "-", "mcp_denied", "error")
        );
        assert_eq!(e.error_code.as_deref(), Some("TENANT_NOT_FOUND"));
        assert_eq!(e.actor_admin_id, Some(7));
        assert_eq!(e.actor_email_snapshot, None);
        assert_eq!(e.auth_method, None);
        assert_eq!(
            Value::Object(e.extra),
            json!({"surface": "tool", "name": "insert_record", "requested_tenant": "other", "grant_id": 42})
        );
    }

    #[test]
    fn denied_entry_names_each_surface() {
        let x = |s| Value::Object(denied_entry(None, None, s, None, "TENANT_NOT_FOUND").extra);
        assert_eq!(
            x(DeniedSurface::Resource("drust://a/schema")),
            json!({"surface": "resource", "name": "drust://a/schema"})
        );
        assert_eq!(
            x(DeniedSurface::Prompt("bootstrap")),
            json!({"surface": "prompt", "name": "bootstrap"})
        );
        assert_eq!(
            x(DeniedSurface::UploadTool),
            json!({"surface": "upload_tool", "name": "create_upload_url"})
        );
        assert_eq!(
            x(DeniedSurface::UploadTicket),
            json!({"surface": "upload_ticket"})
        );
        assert_eq!(
            x(DeniedSurface::Tool("Not A Tool")),
            json!({"surface": "tool", "name": "<invalid>"})
        );
        assert_eq!(
            x(DeniedSurface::Resource("drust://{tenant}/schema")),
            json!({"surface": "resource", "name": "<invalid>"})
        );
        assert_eq!(
            x(DeniedSurface::Prompt("no_such_prompt")),
            json!({"surface": "prompt", "name": "<invalid>"})
        );
        let e = denied_entry(
            None,
            None,
            DeniedSurface::UploadTicket,
            None,
            "TENANT_NOT_FOUND",
        );
        assert_eq!(e.actor_admin_id, None);
    }

    #[test]
    fn resource_read_entry_fields() {
        let c = McpCaller::for_tests(7, 42);
        let e = resource_read_entry("blog", &c, "drust://blog/schema.md", 5);
        assert_eq!(
            (e.tenant.as_str(), e.op.as_str(), e.status.as_str()),
            ("blog", "mcp.resource.read", "ok")
        );
        assert_eq!(e.auth_method.as_deref(), Some("mcp_oauth"));
        assert_eq!(e.actor_admin_id, Some(7));
        assert_eq!(e.collection, None);
        assert_eq!(
            Value::Object(e.extra),
            json!({"grant_id": 42, "uri": "drust://blog/schema.md"})
        );
    }

    #[test]
    fn entries_sanitize_caller_strings() {
        let c = McpCaller::for_tests(1, 2);
        let long = "a".repeat(300);
        let e = call_entry("t", "insert_record", &c, None, 0, Some(&long));
        assert_eq!(e.extra["collection"].as_str().unwrap().chars().count(), 128);
        let e = call_entry("t", "insert_record", &c, None, 0, Some(&"é".repeat(300)));
        assert!(e.extra.get("collection").is_none());
        let uri = format!("drust://a/collections/{}/schema", "c".repeat(400));
        let r = resource_read_entry("a", &c, &uri, 0);
        assert_eq!(r.extra["uri"].as_str().unwrap().chars().count(), 256);
        let d = denied_entry(
            Some(1),
            Some(2),
            DeniedSurface::Resource(&uri),
            Some(&"x".repeat(100)),
            "TENANT_NOT_FOUND",
        );
        assert_eq!(d.extra["name"].as_str().unwrap().chars().count(), 256);
        assert_eq!(d.extra["requested_tenant"], "<invalid>");
        let odd = format!("drust://a/{}", "ü".repeat(500));
        let d = denied_entry(
            Some(1),
            Some(2),
            DeniedSurface::Resource(&odd),
            Some("Bad_Id"),
            "TENANT_NOT_FOUND",
        );
        assert_eq!(
            (
                d.extra["name"].as_str(),
                d.extra["requested_tenant"].as_str()
            ),
            (Some("<invalid>"), Some("<invalid>"))
        );
        // The host audit key is a reserved id: a refused call naming it never
        // records a requested tenant that reads as the host key.
        let d = denied_entry(
            Some(1),
            Some(2),
            DeniedSurface::Resource("drust://-/schema"),
            Some("-"),
            "TENANT_NOT_FOUND",
        );
        assert_eq!(
            (
                d.tenant.as_str(),
                d.extra["name"].as_str(),
                d.extra["requested_tenant"].as_str()
            ),
            ("-", Some("<invalid>"), Some("<invalid>"))
        );
    }

    /// The string below only has the shape of a tenant key; it is not one.
    #[test]
    fn credential_shaped_caller_strings_never_reach_a_row() {
        let c = McpCaller::for_tests(1, 2);
        let k = concat!("drust_", "NotARealKey", "0123456789abcdefABCDEF-_xyz");
        let in_host = format!("drust://{k}/schema");
        let in_path = format!("drust://t/collections/{k}/schema");
        let rows = [
            call_entry("t", "insert_record", &c, Some("X"), 0, Some(k)),
            denied_entry(
                Some(1),
                Some(2),
                DeniedSurface::Tool(k),
                Some(k),
                "TENANT_NOT_FOUND",
            ),
            denied_entry(
                Some(1),
                Some(2),
                DeniedSurface::Resource(&in_host),
                Some(k),
                "TENANT_NOT_FOUND",
            ),
            denied_entry(
                Some(1),
                Some(2),
                DeniedSurface::Resource(&in_path),
                Some("t"),
                "TENANT_NOT_FOUND",
            ),
            denied_entry(
                Some(1),
                Some(2),
                DeniedSurface::Prompt(k),
                Some(k),
                "TENANT_NOT_FOUND",
            ),
            resource_read_entry("t", &c, &in_path, 0),
        ];
        for e in rows {
            assert!(
                !serde_json::to_string(&e).unwrap().contains(k),
                "a row carries the caller string"
            );
        }
    }

    #[test]
    fn audit_op_marks_only_boolean_dry_runs() {
        assert_eq!(
            audit_op("delete_record", &obj(json!({"dry_run": true}))),
            "delete_record.dry_run"
        );
        assert_eq!(
            audit_op("drop_index", &obj(json!({"dry_run": true}))),
            "drop_index.dry_run"
        );
        assert_eq!(
            audit_op("delete_record", &obj(json!({"dry_run": false}))),
            "delete_record"
        );
        assert_eq!(
            audit_op("delete_record", &obj(json!({"dry_run": "true"}))),
            "delete_record"
        );
        assert_eq!(audit_op("insert_record", &obj(json!({}))), "insert_record");
    }

    #[test]
    fn audit_collection_reads_create_collection_name() {
        assert_eq!(
            audit_collection("insert_record", &obj(json!({"collection": "posts"}))),
            Some("posts")
        );
        assert_eq!(
            audit_collection(
                "create_collection",
                &obj(json!({"name": "posts", "collection": "x"}))
            ),
            Some("posts")
        );
        assert_eq!(
            audit_collection("call_rpc", &obj(json!({"name": "r"}))),
            None
        );
        assert_eq!(
            audit_collection("insert_record", &obj(json!({"collection": 5}))),
            None
        );
        assert_eq!(
            requested_tenant(&obj(json!({"tenant": "blog"}))),
            Some("blog")
        );
        assert_eq!(requested_tenant(&obj(json!({"tenant": 5}))), None);
    }

    #[test]
    fn result_error_code_reads_only_is_error_bodies() {
        use rmcp::model::{CallToolResult, Content};
        let ok = CallToolResult::success(vec![Content::text(r#"{"error_code":"X"}"#)]);
        assert_eq!(result_error_code(&ok), None);
        let err = CallToolResult::error(vec![Content::text(
            r#"{"error_code":"COLLECTION_NOT_FOUND","message":"m"}"#,
        )]);
        assert_eq!(
            result_error_code(&err).as_deref(),
            Some("COLLECTION_NOT_FOUND")
        );
        let plain = CallToolResult::error(vec![Content::text("boom")]);
        assert_eq!(result_error_code(&plain).as_deref(), Some("INTERNAL"));
        assert_eq!(
            result_error_code(&CallToolResult::error(vec![])).as_deref(),
            Some("INTERNAL")
        );
        let long = CallToolResult::error(vec![Content::text(
            json!({"error_code": "A".repeat(200)}).to_string(),
        )]);
        assert_eq!(result_error_code(&long).as_deref(), Some("INTERNAL"));
        let lower = CallToolResult::error(vec![Content::text(r#"{"error_code":"not_a_code"}"#)]);
        assert_eq!(result_error_code(&lower).as_deref(), Some("INTERNAL"));
    }

    #[test]
    fn ticket_use_entry_maps_status_like_the_bearer_layer() {
        use axum::http::StatusCode;
        let ok = ticket_use_entry(
            "t1",
            7,
            9,
            "drust_upl_ab\u{2026}",
            "POST /uploads",
            StatusCode::CREATED,
            5,
        );
        assert_eq!(
            (ok.status.as_str(), ok.error_code.as_deref(), ok.duration_ms),
            ("ok", None, 5)
        );
        assert_eq!(
            (ok.tenant.as_str(), ok.token_hint.as_str(), ok.op.as_str()),
            ("t1", "drust_upl_ab\u{2026}", "POST /uploads")
        );
        assert_eq!(
            (
                ok.auth_method.as_deref(),
                ok.actor_admin_id,
                ok.actor_email_snapshot.as_deref()
            ),
            (Some("mcp_upload_ticket"), Some(7), None)
        );
        assert_eq!(Value::Object(ok.extra.clone()), json!({"grant_id": 9}));
        let redirect = ticket_use_entry("t1", 7, 9, "h", "HEAD /uploads/x", StatusCode::FOUND, 0);
        assert_eq!(redirect.status, "ok");
        let nf = ticket_use_entry(
            "t1",
            7,
            9,
            "h",
            "PATCH /uploads/x",
            StatusCode::NOT_FOUND,
            0,
        );
        assert_eq!(
            (
                nf.status.as_str(),
                nf.error_code.as_deref(),
                nf.error_message.as_deref()
            ),
            ("error", Some("HTTP_404"), Some(""))
        );
    }

    #[test]
    fn ticket_issued_entry_carries_only_the_four_extra_keys() {
        let c = crate::mgmt::mcp_oauth::caller::McpCaller::for_tests(7, 42);
        let e = ticket_issued_entry("blog", &c, 1024, true, false);
        assert_eq!(
            (
                e.tenant.as_str(),
                e.token_hint.as_str(),
                e.op.as_str(),
                e.status.as_str()
            ),
            ("blog", "-", "create_upload_url", "ok")
        );
        assert_eq!(e.auth_method.as_deref(), Some("mcp_oauth"));
        assert_eq!(e.actor_admin_id, Some(7));
        assert_eq!(e.actor_email_snapshot.as_deref(), Some(c.admin_label()));
        assert_eq!(e.error_code, None);
        let keys: Vec<&str> = e.extra.keys().map(String::as_str).collect();
        assert_eq!(keys, ["grant_id", "max_bytes", "visibility", "has_path"]);
        assert_eq!(
            serde_json::Value::Object(e.extra.clone()),
            serde_json::json!({"grant_id":42,"max_bytes":1024,"visibility":"public","has_path":false})
        );
        assert_eq!(
            ticket_issued_entry("blog", &c, 0, false, true).extra["visibility"],
            "private"
        );
    }
}
